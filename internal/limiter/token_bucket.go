package limiter

import (
	"net/http"
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var tokenBucketLua = redis.NewScript(`
	local key = KEYS[1]
	local limit = tonumber(ARGV[1])        
	local refill_rate = tonumber(ARGV[2])  
	local now = tonumber(ARGV[3])          
	local requested = tonumber(ARGV[4])    

	local data = redis.call("HMGET", key, "tokens", "last_refilled")
	local tokens = tonumber(data[1])
	local last_refilled = tonumber(data[2])

	if not tokens then
		tokens = limit
		last_refilled = now
	else
		local delta = math.max(0, now - last_refilled)
		local tokens_to_add = delta * refill_rate
		tokens = math.min(limit, tokens + tokens_to_add)
		last_refilled = now
	end

	if tokens >= requested then
		tokens = tokens - requested
		redis.call("HMSET", key, "tokens", tokens, "last_refilled", last_refilled)
		redis.call("EXPIRE", key, math.ceil(limit / refill_rate) * 2)
		return {1, math.floor(tokens)} -- 1 = Allowed, remaining tokens
	else
		redis.call("HMSET", key, "tokens", tokens, "last_refilled", last_refilled)
		redis.call("EXPIRE", key, math.ceil(limit / refill_rate) * 2)
		return {0, math.floor(tokens)} -- 0 = Denied, remaining tokens
	end
`)

type RedisTokenBucket struct {
	rdb        *redis.Client
	capacity   int
	refillRate float64
}

func NewRedisTokenBucket(rdb *redis.Client, capacity int, refillRate float64) *RedisTokenBucket{
	return &RedisTokenBucket{
		rdb:        rdb,
		capacity:   capacity,
		refillRate: refillRate,
	}
}

func (tb *RedisTokenBucket) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		clientKey := r.Header.Get("X-User-ID")
		if clientKey == ""{
			clientKey = r.RemoteAddr
		}

		redisKey := fmt.Sprintf("rate_limit:tb:%s", clientKey)
		now := time.Now().Unix()

		ctx, cancel := context.WithTimeout(r.Context(), 50*time.Millisecond)
		defer cancel()

		res, err := tokenBucketLua.Run(ctx, tb.rdb, []string{redisKey}, tb.capacity, tb.refillRate, now, 1).Result()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"Rate limiter backend unavailable"}`))
			return
		}

		results, ok := res.([]interface{})
		if !ok || len(results) < 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"Invalid response from rate limiter script"}`))
			return
		}

		allowed := results[0].(int64) == 1
		remaining := results[1].(int64)

		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", tb.capacity))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"Rate limit exceeded (Token Bucket)."}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}
package limiter

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

var slidingWindowLua = redis.NewScript(`
	local key = KEYS[1]
	local now = tonumber(ARGV[1])          
	local window = tonumber(ARGV[2])       
	local limit = tonumber(ARGV[3])        
	local clear_before = now - window

	redis.call("ZREMRANGEBYSCORE", key, "-inf", clear_before)

	local current_requests = redis.call("ZCARD", key)

	if current_requests < limit then
		-- Add unique member using timestamp + random microsecond fallback or request ID
		redis.call("ZADD", key, now, now .. "-" .. math.random(1000, 9999))
		redis.call("EXPIRE", key, math.ceil(window / 1000) * 2)
		return {1, limit - current_requests - 1} -- Allowed (1 = true), remaining quota
	else
		redis.call("EXPIRE", key, math.ceil(window / 1000) * 2)
		return {0, 0} -- Denied (0 = false), 0 remaining quota
	end
`)

type RedisSlidingWindow struct{
	rdb *redis.Client
	limit int
	window time.Duration
}

func NewRedisSlidingWindow(rdb *redis.Client, limit int, window time.Duration) *RedisSlidingWindow{
	return &RedisSlidingWindow{
		rdb: rdb,
		limit: limit,
		window: window,
	}
}

func (sw *RedisSlidingWindow) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientKey := r.Header.Get("X-User-ID")
		if clientKey == "" {
			clientKey = r.RemoteAddr
		}

		redisKey := fmt.Sprintf("rate_limit:sw:%s", clientKey)
		now := time.Now().UnixNano() / int64(time.Millisecond)
		windowMs := sw.window.Milliseconds()

		ctx, cancel := context.WithTimeout(r.Context(), 50*time.Millisecond)
		defer cancel()

		res, err := slidingWindowLua.Run(ctx, sw.rdb, []string{redisKey}, now, windowMs, sw.limit).Result()
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

		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", sw.limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"Rate limit exceeded (Sliding Window Log)."}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}
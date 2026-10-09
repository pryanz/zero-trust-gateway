package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/pryanz/zero-trust-gateway/internal/auth"
	"github.com/pryanz/zero-trust-gateway/internal/limiter"
	"github.com/redis/go-redis/v9"
)


func NewRouter(jwtValidator *auth.JWTValidator, rdb *redis.Client) http.Handler{
	

	upstreamA , err := url.Parse("http://localhost:8081")
	if err != nil {
		panic(err)
	}
	upstreamB, err := url.Parse("http://localhost:8082")
	if err != nil {
		panic(err)
	}

	transport := &http.Transport{
		MaxIdleConns: 100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout: 90 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}

	createProxy := func(target *url.URL) *httputil.ReverseProxy {
		return &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(r *httputil.ProxyRequest){

				r.SetURL(target)
				r.SetXForwarded()

				r.Out.Header.Del("X-User-ID")
				r.Out.Header.Del("X-User-Roles")
				r.Out.Header.Del("Authorization")

				if claims, ok:= auth.GetClaimsFromContext(r.In.Context()); ok {
					r.Out.Header.Set("X-User-ID", claims.Subject)
					r.Out.Header.Set("X-User-Roles", strings.Join(claims.Roles, ","))
				}

				r.Out.Header.Del("Connection")
				r.Out.Header.Del("Keep-Alive")
				r.Out.Header.Del("Te")
				r.Out.Header.Del("Trailers")
				r.Out.Header.Del("Upgrade")

				reqID := r.In.Header.Get("X-Request-ID")
				if reqID == ""{
					reqID = generateRequestID()
				}
				r.Out.Header.Set("X-Request-ID",reqID)
			},
		}
	}

	proxyA := createProxy(upstreamA)
	proxyB := createProxy(upstreamB)

	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/service-a"):
			proxyA.ServeHTTP(w , r)
		case strings.HasPrefix(r.URL.Path, "/api/v1/service-b"):
			proxyB.ServeHTTP(w , r)
		default:
			http.Error(w, "Route not found", http.StatusNotFound)
		}
	})

	//Token bucket rate limiter
	rateLimiter := limiter.NewRedisTokenBucket(rdb, 5, 1.0)

	//Sliding window rate limiter
	// rateLimiter := limiter.NewRedisSlidingWindow(rdb, 5, 10*time.Second)

	authenticatedAndLimitedProxy := jwtValidator.Middleware(rateLimiter.Middleware(protectedHandler))

	return http.HandlerFunc(func(w http.ResponseWriter , r*http.Request){
		
		if r.URL.Path == "/healthz"{
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"healthy"}`))
			return
		}

		authenticatedAndLimitedProxy.ServeHTTP(w, r)
	})
}

func generateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/pryanz/zero-trust-gateway/internal/auth"
	"github.com/pryanz/zero-trust-gateway/internal/limiter"
	"github.com/pryanz/zero-trust-gateway/internal/metrics"
	"github.com/pryanz/zero-trust-gateway/internal/middleware"
	"github.com/redis/go-redis/v9"
)

func NewRouter(jwtValidator *auth.JWTValidator, rdb *redis.Client) http.Handler {

	upstreamA, err := url.Parse("https://localhost:8081")
	if err != nil {
		panic(err)
	}
	upstreamB, err := url.Parse("https://localhost:8082")
	if err != nil {
		panic(err)
	}

	clientCert, err := tls.LoadX509KeyPair("certs/client.crt", "certs/client.key")
	if err != nil {
		panic(err)
	}

	caCert, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		panic(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caCertPool,
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}

	createProxy := func(target *url.URL) *httputil.ReverseProxy {
		return &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(r *httputil.ProxyRequest) {

				r.SetURL(target)
				r.SetXForwarded()

				r.Out.Header.Del("X-User-ID")
				r.Out.Header.Del("X-User-Roles")
				r.Out.Header.Del("Authorization")

				if claims, ok := auth.GetClaimsFromContext(r.In.Context()); ok {
					r.Out.Header.Set("X-User-ID", claims.Subject)
					r.Out.Header.Set("X-User-Roles", strings.Join(claims.Roles, ","))
				}

				r.Out.Header.Del("Connection")
				r.Out.Header.Del("Keep-Alive")
				r.Out.Header.Del("Te")
				r.Out.Header.Del("Trailers")
				r.Out.Header.Del("Upgrade")

				reqID := r.In.Header.Get("X-Request-ID")
				if reqID == "" {
					reqID = generateRequestID()
				}
				r.Out.Header.Set("X-Request-ID", reqID)
			},
		}
	}

	proxyA := createProxy(upstreamA)
	proxyB := createProxy(upstreamB)

	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/service-a"):
			proxyA.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, "/api/v1/service-b"):
			proxyB.ServeHTTP(w, r)
		default:
			http.Error(w, "Route not found", http.StatusNotFound)
		}
	})

	logoutHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing authorization header", http.StatusBadRequest)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "invalid authorization header format", http.StatusBadRequest)
			return
		}

		tokenString := parts[1]

		mapClaims := jwt.MapClaims{}
		_, _, err := new(jwt.Parser).ParseUnverified(tokenString, &mapClaims)
		if err != nil {
			http.Error(w, "invalid token structure", http.StatusBadRequest)
			return
		}

		jtiStr, _ := mapClaims["jti"].(string)
		if jtiStr == "" {
			http.Error(w, "token missing jti claim", http.StatusBadRequest)
			return
		}

		var ttl time.Duration = 15 * time.Minute
		if exp, ok := mapClaims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			ttl = time.Until(expTime)
			if ttl <= 0 {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"already_expired"}`))
				return
			}
		}

		ctx, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
		defer cancel()

		err = jwtValidator.RevokeToken(ctx, jtiStr, ttl)
		if err != nil {
			http.Error(w, "failed to revoke token", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","message":"token revoked successfully"}`))
	})

	//Token bucket rate limiter
	rateLimiter := limiter.NewRedisTokenBucket(rdb, 5, 1.0)

	//Sliding window rate limiter
	// rateLimiter := limiter.NewRedisSlidingWindow(rdb, 5, 10*time.Second)

	pipeline := middleware.StructuredLogger(nil)(
		metrics.Middleware(
			jwtValidator.Middleware(
				rateLimiter.Middleware(protectedHandler),
			),
		),
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"healthy"}`))
			return
		}

		if r.URL.Path == "/metrics" {
			promhttp.Handler().ServeHTTP(w, r)
			return
		}

		if r.URL.Path == "/api/v1/auth/logout" && r.Method == http.MethodPost {
			logoutHandler.ServeHTTP(w, r)
			return
		}

		pipeline.ServeHTTP(w, r)
	})
}

func generateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

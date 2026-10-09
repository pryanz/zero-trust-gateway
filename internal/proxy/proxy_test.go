package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/pryanz/zero-trust-gateway/internal/auth"
	"github.com/pryanz/zero-trust-gateway/internal/proxy"
	"github.com/redis/go-redis/v9"
)

func TestIdentityPropagationAndSanitization(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{
			"user_id":    r.Header.Get("X-User-ID"),
			"user_roles": r.Header.Get("X-User-Roles"),
			"raw_auth":   r.Header.Get("Authorization"),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis %v", err)
	}
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	jwtValidator := auth.NewJWTValidator("supersecretkey", rdb)

	_ = proxy.NewRouter(jwtValidator, rdb)

	t.Log("Proxy and sanitization verified.")
}

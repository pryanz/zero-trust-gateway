package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pryanz/zero-trust-gateway/internal/auth"
	"github.com/pryanz/zero-trust-gateway/internal/proxy"
	"github.com/redis/go-redis/v9"
)

func TestMain(m *testing.M) {

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("failed to get current file path")
	}

	projectRoot := filepath.Join(filepath.Dir(filename), "../..")
	scriptPath := filepath.Join(projectRoot, "scripts", "generate_certs.sh")

	cmd := exec.Command("bash", scriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		panic("failed to execute certificate generation script: " + err.Error())
	}

	os.Exit(m.Run())
}
func TestIdentityE2EAndSanitization(t *testing.T) {

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis %v", err)
	}
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	jwtValidator := auth.NewJWTValidator("supersecretkey", rdb)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{
			"user_id":    r.Header.Get("X-User-ID"),
			"user_roles": r.Header.Get("X-User-Roles"),
			"raw_auth":   r.Header.Get("Authorization"),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	gatewayHandler := proxy.NewRouter(jwtValidator, rdb)
	gatewayServer := httptest.NewServer(gatewayHandler)
	defer gatewayServer.Close()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "user123",
		"roles": []string{"user"},
		"jti":   "test-jti-456",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte("supersecretkey"))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	client := gatewayServer.Client()

	req, _ := http.NewRequest(http.MethodGet, gatewayServer.URL+"/api/v1/service-a/test", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	logoutReq, _ := http.NewRequest(http.MethodPost, gatewayServer.URL+"/api/v1/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+tokenString)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout failed: %v", err)
	}
	defer logoutResp.Body.Close()

	if logoutResp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 on logout, got %d", logoutResp.StatusCode)
	}
}

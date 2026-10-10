package middleware

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pryanz/zero-trust-gateway/internal/auth"
)

type responseRecorder struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (rec *responseRecorder) WriteHeader(statusCode int) {
	rec.statusCode = statusCode
	rec.ResponseWriter.WriteHeader(statusCode)
}

func (rec *responseRecorder) Write(b []byte) (int, error) {
	if rec.statusCode == 0 {
		rec.statusCode = http.StatusOK
	}
	n, err := rec.ResponseWriter.Write(b)
	rec.bytesWritten += int64(n)
	return n, err
}

type LogEntry struct {
	Timestamp  string  `json:"timestamp"`
	RequestID  string  `json:"request_id"`
	ClientIP   string  `json:"client_ip"`
	Method     string  `json:"method"`
	Path       string  `json:"path"`
	Status     int     `json:"status"`
	DurationMs float64 `json:"duration_ms"`
	BytesSent  int64   `json:"bytes_sent"`
	UserID     string  `json:"user_id,omitempty"`
	UserRoles  string  `json:"user_roles,omitempty"`
	UserAgent  string  `json:"user_agent"`
}

func StructuredLogger(jsonLogger *log.Logger) func(http.Handler) http.Handler {
	if jsonLogger == nil {
		jsonLogger = log.New(os.Stdout, "", 0)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			rec := &responseRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(rec, r)

			duration := time.Since(start)

			clientIP := r.Header.Get("X-Forwarded-For")
			if clientIP == "" {
				host, _, err := net.SplitHostPort(r.RemoteAddr)
				if err == nil {
					clientIP = host
				} else {
					clientIP = r.RemoteAddr
				}
			}

			userID := ""
			userRoles := ""
			if claims, ok := auth.GetClaimsFromContext(r.Context()); ok {
				userID = claims.Subject
				if len(claims.Roles) > 0 {
					userRoles = claims.Roles[0]
				}
			}

			entry := LogEntry{
				Timestamp:  start.UTC().Format(time.RFC3339Nano),
				RequestID:  r.Header.Get("X-Request-ID"),
				ClientIP:   clientIP,
				Method:     r.Method,
				Path:       r.URL.Path,
				Status:     rec.statusCode,
				DurationMs: float64(duration.Microseconds()) / 1000.0,
				BytesSent:  rec.bytesWritten,
				UserID:     userID,
				UserRoles:  userRoles,
				UserAgent:  r.UserAgent(),
			}

			payload, err := json.Marshal(entry)
			if err == nil {
				jsonLogger.Println(string(payload))
			}
		})
	}
}

package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_http_requests_total",
			Help: "Total number of HTTP requests processed by the gateway",
		},
		[]string{"method", "path", "status"},
	)

	RateLimitBlocksTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_ratelimit_blocks_total",
			Help: "Total number of requests blocked by ratelimiting (429)",
		},
		[]string{"path"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gateway_http_request_duration_seconds",
			Help:    "Latency histogram for proxy requests",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
)

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *responseRecorder) WriteHeader(statusCode int) {
	rec.statusCode = statusCode
	rec.ResponseWriter.WriteHeader(statusCode)
}

func (rec *responseRecorder) Write(b []byte) (int, error) {
	if rec.statusCode == 0 {
		rec.statusCode = http.StatusOK
	}
	return rec.ResponseWriter.Write(b)
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rec := &responseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(rec, r)

		duration := time.Since(start).Seconds()
		statusStr := strconv.Itoa(rec.statusCode)

		HTTPRequestsTotal.WithLabelValues(r.Method, r.URL.Path, statusStr).Inc()
		HTTPRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)

		if rec.statusCode == http.StatusTooManyRequests {
			RateLimitBlocksTotal.WithLabelValues(r.URL.Path).Inc()
		}
	})
}

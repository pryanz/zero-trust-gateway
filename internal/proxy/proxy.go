package proxy

import (
	"encoding/hex"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
	"crypto/rand"
)


func NewRouter() http.Handler{
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

	return http.HandlerFunc(func(w http.ResponseWriter , r*http.Request){
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/service-a"):
			proxyA.ServeHTTP(w , r)
		case strings.HasPrefix(r.URL.Path, "/api/v1/service-b"):
			proxyB.ServeHTTP(w , r)
		case r.URL.Path == "/healthz":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"healthy"}`))
		default:
			http.Error(w, "Route not found", http.StatusNotFound)
		}
	})
}

func generateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
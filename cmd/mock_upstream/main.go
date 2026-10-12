package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	port := "8081" //default fallback port

	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "mTLS required: no client certificate presented", http.StatusUnauthorized)
			return
		}

		clientCN := r.TLS.PeerCertificates[0].Subject.CommonName
		userID := r.Header.Get("X-User-ID")
		userRoles := r.Header.Get("X-User-Roles")
		reqID := r.Header.Get("X-Request-ID")

		log.Printf("[Upstream :%s] %s %s | UserID: %s | Roles: %s | ReqID : %s | ClientCN : %s",
			port, r.Method, r.URL.Path, userID, userRoles, reqID, clientCN)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok", "port":"%s", "path":"%s", "user_id":"%s", "roles":"%s", "request_id":"%s"}`, port, r.URL.Path, userID, userRoles, reqID)
	})

	caCert, err := os.ReadFile("certs/ca.crt")
	if err != nil {
		log.Fatalf("failed to read ca.crt: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	server := &http.Server{
		Addr:      ":" + port,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Starting secure mTLS upstream on port %s", port)
	if err := server.ListenAndServeTLS("certs/server.crt", "certs/server.key"); err != nil {
		log.Fatalf("Upstream failed: %v", err)
	}
}

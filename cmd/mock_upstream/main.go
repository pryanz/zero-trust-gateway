package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main(){
	port := "8081" //default fallback port

	if len(os.Args) > 1{
		port = os.Args[1]
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r*http.Request){

		userID := r.Header.Get("X-User-ID")
		userRoles := r.Header.Get("X-User-Roles")
		reqID := r.Header.Get("X-Request-ID")

		log.Printf("[Upstream :%s] %s %s | UserID: %s | Roles: %s | ReqID : %s",
					port, r.Method, r.URL.Path,userID, userRoles, reqID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok", "port":"%s", "path":"%s", "user_id":"%s", "roles":"%s", "request_id":"%s"}`, port, r.URL.Path, userID, userRoles, reqID)
	})

	log.Printf("Mock upstream running on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Upstream failed: %v", err)
	}
}

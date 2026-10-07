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
		log.Printf("[Upstream :%s] %s %s | X-Request-ID: %s | X-Forwarded-For: %s",
					port, r.Method, r.URL.Path, r.Header.Get("X-Request-ID"), r.Header.Get("X-Forwarded-For"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok", "port":"%s", "path":"%s"}`, port, r.URL.Path)
	})

	log.Printf("Mock upstream running on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Upstream failed: %v", err)
	}
}

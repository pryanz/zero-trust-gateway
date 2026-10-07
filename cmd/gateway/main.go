package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"github.com/pryanz/zero-trust-gateway/internal/proxy"
)

func main(){
	proxyHandler := proxy.NewRouter()
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      proxyHandler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func(){
		log.Println("Starting server on public API on :8080")
		if err:= srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed){
			log.Fatalf("Gateway failed: %v",err)
		}
	}()
	
	<-ctx.Done()
	log.Println("Shutdown signal received, closing gateway gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err:= srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v",err)
	}

	log.Println("Gateway exited cleanly")
}
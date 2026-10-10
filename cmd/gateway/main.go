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

	"github.com/joho/godotenv"
	"github.com/pryanz/zero-trust-gateway/internal/auth"
	"github.com/pryanz/zero-trust-gateway/internal/proxy"
	"github.com/redis/go-redis/v9"
)

func main() {

	if err := godotenv.Load(); err != nil {
		log.Println("no .env found, Relying on system environment variables")
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "",
		DB:       0,
	})

	ctxPing, cancelPing := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelPing()
	if err := rdb.Ping(ctxPing).Err(); err != nil {
		log.Printf("Warning: Redis connection failed (%v. Operating without revocation cache.", err)
	} else {
		log.Println("Connected to Redis successfully.")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("FATAL: JWT_SECRET environment variable is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	validator := auth.NewJWTValidator(jwtSecret, rdb)

	proxyHandler := proxy.NewRouter(validator, rdb)
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      proxyHandler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("Starting Zero trust gateway on :%s", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Gateway failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutdown signal received, closing gateway gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Gateway exited cleanly")
}

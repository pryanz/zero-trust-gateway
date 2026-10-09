package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

func main(){
	if err := godotenv.Load(); err != nil{
		log.Println("no .env found, Relying on system environment variables")
	}

	secretStr := os.Getenv("JWT_SECRET")
	if secretStr == ""{
		log.Fatal("JWT_SECRET environment variable is required")
	}

	secret := []byte(secretStr)

	if len(os.Args) < 2{
		fmt.Println("Usage:")
		fmt.Println(" go run cmd/token_gen/main.go issue <sub/used_id> <role> <jti>")
		fmt.Println(" go run cmd/token_gen/main.go revoke <jti>")
		return
	}

	action := os.Args[1]

	switch action {
		case "issue":
			sub := "user123"
			role := "user"
			jti := "token-jti-001"
			
			if len(os.Args) > 2 { sub = os.Args[2]}
			if len(os.Args) > 3 { role = os.Args[3]}
			if len(os.Args) > 4 { jti = os.Args[4]}

			claims := jwt.MapClaims{
				"sub":sub,
				"role":role,
				"jti":jti,
				"exp":time.Now().Add(1*time.Hour).Unix(),
				"iat": time.Now().Unix(),
			}

			token:= jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString(secret)
			if err != nil{
				log.Fatalf("Failed to sign token :%v", err)
			}

			fmt.Println(tokenString)
		
		case "revoke":
			if len(os.Args) < 3{
				log.Fatal("Please provide JTI to revoke")
			}
			jti := os.Args[2]

			redisAddr := os.Getenv("REDIS_ADDR")
			if redisAddr == ""{
				redisAddr = "localhost:6379"
			}

			rdb := redis.NewClient(&redis.Options{Addr: redisAddr})

			ctx := context.Background()

			err := rdb.Set(ctx, "revoked:"+jti, "true", 1*time.Hour).Err()
			if err != nil {
				log.Fatalf("Failed to revoke token in Redis: %v", err)
			}

			fmt.Printf("Successfully revoked JTI '%s' in Redis\n",jti)
	}
}
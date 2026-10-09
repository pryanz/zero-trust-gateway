package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

var (
		ErrMissingToken 	 = errors.New("missing authorization header")
		ErrInvalidToken 	 = errors.New("invalid or forged token")
		ErrExpiredToken 	 = errors.New("token has expired")
		ErrRevokedToken 	 = errors.New("token has been revoked")
		ErrAlgorithmMismatch = errors.New("unexpected signing algorithm")
)

type JWTValidator struct {
	secretKey []byte
	redisClient *redis.Client
}

func NewJWTValidator(secret string, redisClient *redis.Client) *JWTValidator{
	return &JWTValidator{
		secretKey: []byte(secret),
		redisClient: redisClient,
	}
}

func(v *JWTValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == ""{
			http.Error(w, ErrMissingToken.Error(), http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok{
				return nil, fmt.Errorf("%w: %v", ErrAlgorithmMismatch, token.Header["alg"])
			}
			return v.secretKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, ErrInvalidToken.Error(), http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, ErrInvalidToken.Error(), http.StatusUnauthorized)
			return
		}

		if v.redisClient != nil {
			if jti, ok := claims["jti"].(string); ok && jti != ""{
				ctx, cancel := context.WithTimeout(r.Context(), 50*time.Millisecond)
				defer cancel()

				revoked , err:= v.redisClient.Get(ctx, "revoked:"+jti).Result()

				if err != nil && !errors.Is(err, redis.Nil) {
					http.Error(w, "authentication verification unavailable", http.StatusServiceUnavailable)
					return
				}
				if err == nil && revoked == "true" {
					http.Error(w, ErrRevokedToken.Error(), http.StatusUnauthorized)
					return
				}
			}
		}

		if sub, ok := claims["sub"].(string); ok{
			r.Header.Set("X-User-ID", sub)
		}
		if role, ok := claims["role"].(string); ok{
			r.Header.Set("X-User-Role", role)
		}

		next.ServeHTTP(w, r)
	})
}
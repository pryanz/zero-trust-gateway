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

type JWTClaims struct{
	Subject string `json:"sub"`
	Roles []string `json:"roles"`
	JTI string `json:"jti"`
}

type contextKey string

const claimsContextKey contextKey = "jwt_claims"

func GetClaimsFromContext(ctx context.Context) (*JWTClaims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*JWTClaims)
	return claims, ok
}

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

		mapClaims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, ErrInvalidToken.Error(), http.StatusUnauthorized)
			return
		}

		jtiStr, _ := mapClaims["jti"].(string)
		if v.redisClient != nil && jtiStr == "" {
			ctx, cancel := context.WithTimeout(r.Context(), 50*time.Millisecond)
			defer cancel()

			revoked , err:= v.redisClient.Get(ctx, "revoked:"+jtiStr).Result()

			if err != nil && !errors.Is(err, redis.Nil) {
				http.Error(w, "authentication verification unavailable", http.StatusServiceUnavailable)
				return
			}
			if err == nil && revoked == "true" {
				http.Error(w, ErrRevokedToken.Error(), http.StatusUnauthorized)
				return
			}
			
		}
		claims := &JWTClaims{
			JTI: jtiStr,
		}

		if sub, ok := mapClaims["sub"].(string); ok{
			claims.Subject = sub
		}

		if role, ok := mapClaims["role"].(string); ok{
			claims.Roles = []string{role}
		} else if rolesRaw , ok := mapClaims["roles"].([]interface{}); ok {
			for _, r := range rolesRaw {
				if rStr , ok := r.(string); ok {
					claims.Roles = append(claims.Roles , rStr)
				}
			}
		}

		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
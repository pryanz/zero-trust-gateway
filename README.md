# Zero-Trust API Gateway

> A security-first API gateway in Go — implementing zero-trust principles through JWT authentication, real-time token revocation, mTLS upstream transport, and Redis-backed rate limiting.

[![Go Version](https://img.shields.io/badge/Go-1.27.1-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![CI](https://img.shields.io/github/actions/workflow/status/pryanz/zero-trust-gateway/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/pryanz/zero-trust-gateway/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](./LICENSE)

---

## Overview

This gateway acts as the single, hardened entry point between untrusted external clients and trusted internal microservices. Every request must carry a cryptographically signed JWT, pass a Redis revocation check, and clear a rate limiter before being forwarded to upstream services over **mutual TLS (mTLS)**.

Design goal: fill the gap between heavyweight gateways (Kong, Envoy) and bare `httputil.ReverseProxy` — minimal, fast, auditable, and security-first.

---

## Key Features

### JWT Authentication (HMAC)
- Validates HMAC-family signatures (HS256/384/512) using a shared `JWT_SECRET`
- Rejects tokens missing a `jti` claim
- Rejects expired tokens before further processing
- Supports both `role` (string) and `roles` (array) claims
- Propagates validated claims (`sub`, `roles`, `jti`) via Go `context`

### Real-Time Token Revocation
- Token `jti` is checked against a Redis denylist (`revoked:<jti>`) with a **50ms timeout**
- `POST /api/v1/auth/logout` revokes tokens by writing to Redis with the remaining TTL from `exp` (falls back to 15 minutes if `exp` is absent)
- Keys auto-expire — no storage leaks

### Header Sanitization & Request Tracking
- **Strips** client-supplied `Authorization`, `X-User-ID`, `X-User-Roles`, and hop-by-hop headers (`Connection`, `Keep-Alive`, `Te`, `Trailers`, `Upgrade`)
- **Injects** trusted `X-User-ID` and `X-User-Roles` from validated JWT claims
- **Generates** a unique `X-Request-ID` (16-byte crypto-random hex) if missing, sets it on response headers, forwards it upstream, and records it across all access logs

### mTLS Upstream Proxying
- Routes `/api/v1/service-a/*` → `https://localhost:8081` and `/api/v1/service-b/*` → `https://localhost:8082`
- Gateway presents a client certificate; upstreams enforce `tls.RequireAndVerifyClientCert`
- `ResponseHeaderTimeout: 5s` prevents slow upstream responses from exhausting goroutines

### Dual Rate Limiters (Redis Lua)
Two atomic Lua-scripted rate limiters, swappable via a single line in `proxy.go`:

| Algorithm | Default? | Key Characteristics |
|:---|:---:|:---|
| **Token Bucket** | ✅ | Allows short bursts; refills at configurable rate. Keys scoped to JWT `sub` (or IP fallback) |
| **Sliding Window Log** | — | Strict per-window quota using sorted sets. Keys scoped to JWT `sub` (or IP fallback) |

Both set `X-RateLimit-Limit` and `X-RateLimit-Remaining` response headers.

### Observability
- **Prometheus metrics** at `/metrics`: `gateway_http_requests_total`, `gateway_http_request_duration_seconds`, `gateway_ratelimit_blocks_total`
- **Structured JSON access logs**: `timestamp`, `request_id`, `client_ip`, `method`, `path`, `status`, `duration_ms`, `bytes_sent`, `user_id`, `user_roles`, `user_agent`

### Resilience & Timeouts
- **Fail-closed security on Redis outage** — startup ping warns if Redis is unavailable; runtime requests fail closed (`503 Service Unavailable` for token verification, `500` for rate limiting) to prevent revoked token bypass
- **Graceful shutdown** on `SIGINT`/`SIGTERM` with a 5-second drain window
- **Timeouts enforced** — `ReadTimeout` (5s), `WriteTimeout` (10s), `IdleTimeout` (120s), and upstream `ResponseHeaderTimeout` (5s)

---

## Request Pipeline

```
Client → Router → Structured Logger → Prometheus Metrics → JWT Auth (+ Redis revocation check)
       → Rate Limiter (Token Bucket / Sliding Window) → Reverse Proxy (header sanitization + mTLS) → Upstream
```

Unauthenticated endpoints (`/healthz`, `/metrics`, `/api/v1/auth/logout`) bypass the protected pipeline.

See [DESIGN.md](./DESIGN.md) for the full architecture diagram and STRIDE threat model.

---

## Threat Model (STRIDE)

| Category | Attack Vector | Mitigation |
|:---|:---|:---|
| **Spoofing** | Forged identity headers | `X-User-ID` / `X-User-Roles` stripped and re-injected from JWT only |
| **Tampering** | Malicious hop-by-hop headers stripping internal auth | All hop-by-hop and sensitive headers stripped before upstream dispatch |
| **Repudiation** | Requests that can't be correlated across services | Cryptographically unique `X-Request-ID` in every request and log entry |
| **Information Disclosure** | Upstream errors leaking internals | Go's `ReverseProxy` returns `502` on upstream connection failures |
| **Denial of Service** | Slowloris / response hang exhausting goroutines | `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `ResponseHeaderTimeout` enforced |

> **Note:** `X-Forwarded-For` is appended (via Go's `SetXForwarded`) rather than overwritten. If your deployment is behind a trusted load balancer, this is standard; if the gateway is directly internet-facing, consider adding explicit `X-Forwarded-For` sanitization.

---

## Tech Stack

| Component | Technology |
|:---|:---|
| Language | Go 1.27.1 |
| JWT | `github.com/golang-jwt/jwt/v5` |
| Redis | `github.com/redis/go-redis/v9` |
| Metrics | `github.com/prometheus/client_golang` |
| Config | `github.com/joho/godotenv` |
| Test Redis | `github.com/alicebob/miniredis/v2` |
| Certificates | OpenSSL (via `scripts/generate_certs.sh`) |
| CI | GitHub Actions (race detector enabled) |
| Load Testing | `wrk` + Lua scripts |

---

## Getting Started

### Prerequisites

- **Go 1.22+** — [Download](https://go.dev/dl/)
- **Redis** — `docker run -p 6379:6379 redis:alpine` or local install
- **OpenSSL** — for mTLS cert generation

### Setup

```bash
# 1. Clone
git clone https://github.com/pryanz/zero-trust-gateway.git
cd zero-trust-gateway

# 2. Install deps
go mod download

# 3. Generate mTLS certificates
chmod +x scripts/generate_certs.sh
./scripts/generate_certs.sh

# 4. Configure environment
cp .env.example .env
# Edit .env with your generated JWT_SECRET
```

`.env` reference:
```env
PORT=8080
REDIS_ADDR=localhost:6379
JWT_SECRET=<your-256-bit-hex-secret>
```

> ⚠️ **Never commit a real secret to source control.** Generate a fresh secret with `openssl rand -hex 32`.

### Run

```bash
# Start mock upstreams (separate terminals)
go run cmd/mock_upstream/main.go 8081
go run cmd/mock_upstream/main.go 8082

# Start the gateway
go run cmd/gateway/main.go
```

### Quick Test

```bash
# Health check
curl http://localhost:8080/healthz

# Unauthenticated (expect 401)
curl -i http://localhost:8080/api/v1/service-a/test

# Issue a token and make an authenticated request
TOKEN=$(go run cmd/token_gen/main.go issue alice user my-jti-001)
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/service-a/test

# Revoke the token (logout)
curl -i -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/auth/logout
```

---

## Token Utilities

```bash
# Issue a token
go run cmd/token_gen/main.go issue <subject> <role> <jti>

# Revoke a token by JTI (writes directly to Redis)
go run cmd/token_gen/main.go revoke <jti>

# For benchmarking
export BENCHMARK_JWT=$(go run cmd/token_gen/main.go issue bench_user user bench-jti-999)
```

---

## Testing & CI

```bash
go test -v -race ./...
```

- Uses [`miniredis`](https://github.com/alicebob/miniredis) — **no external Redis required**
- `TestMain` auto-generates mTLS certs before tests run
- CI runs on every push/PR to `main` with the race detector enabled ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))

---

## Benchmarks

Run with `wrk` on a dual-core dev machine (2 threads, 50 connections, 20s):

| Scenario | Requests/sec | Avg Latency |
|:---|---:|---:|
| Unauthenticated (fast-path 401) | 48,489 RPS | 1.25 ms |
| Full auth pipeline (JWT + Redis + Rate Limiter) | 12,946 RPS | 4.04 ms |

| Rate Limiter | Requests/sec | Avg Latency |
|:---|---:|---:|
| Token Bucket *(default)* | 19,562 RPS | 5.29 ms |
| Sliding Window Log | 18,248 RPS | 5.59 ms |

Raw results in [`benchmarks/`](./benchmarks/).

---

## Project Structure

```
zero-trust-gateway/
├── cmd/
│   ├── gateway/main.go           # Server entrypoint, graceful shutdown
│   ├── mock_upstream/main.go     # mTLS-enforcing test upstream
│   └── token_gen/main.go        # CLI: issue and revoke JWTs
├── internal/
│   ├── auth/jwt.go              # HMAC validation, Redis revocation, claims extraction
│   ├── limiter/
│   │   ├── token_bucket.go      # Token Bucket (Lua) — default
│   │   └── sliding_window.go    # Sliding Window Log (Lua) — alternative
│   ├── metrics/metrics.go       # Prometheus counters & histograms
│   ├── middleware/logging.go    # Structured JSON access logger
│   └── proxy/
│       ├── proxy.go             # Router, mTLS transport, header sanitization
│       └── proxy_test.go        # E2E tests with miniredis + httptest
├── scripts/generate_certs.sh    # OpenSSL CA, server, client cert generation
├── benchmarks/                  # Raw wrk output files
├── benchmark.lua                # wrk Lua script for authenticated load tests
├── DESIGN.md                    # Full architecture diagram & STRIDE analysis
├── .env                         # Local environment variables (gitignored)
├── .env.example                 # Example configuration template
└── LICENSE                      # MIT
```

---

## License

[MIT](./LICENSE)

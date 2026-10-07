# Architecture & Logical Component Map

1. CLIENT (Untrusted - Zone 0)
   - Sends raw HTTP requests over the public internet.

2. GO API GATEWAY (Policy Enforcement Point - Zone 1)
   - Listens on port :8080.
   - Internal Pipeline:
     a. Timeout Enforcer (prevents connection leaks)
     b. Header Sanitizer & X-Request-ID Injector
     c. JWT Authenticator & Redis Revocation Check
     d. Atomic Token Bucket Rate Limiter
     e. RBAC Authorization Policy Checker (Default Deny)
     f. Reverse Proxy Dispatcher (httputil)

3. STATE STORAGE (Control Plane)
   - Redis (:6379): Keeps token denylist and distributed rate-limit counters.

4. UPSTREAM SERVICES (Trusted Internal Network - Zone 2)
   - Upstream Service A (:8081): /api/v1/service-a/*
   - Upstream Service B (:8082): /api/v1/service-b/*

## Threat Model (STRIDE)

| STRIDE Threat Category | Potential Risk / Attack Vector | Gateway Mitigation Strategy |
| :--- | :--- | :--- |
| **Spoofing** | Attacker crafts a fake `X-Forwarded-For: 1.1.1.1` header to bypass IP restrictions or impersonate trusted clients. | Gateway strips client-supplied `X-Forwarded-For` or appends true TCP remote IP (`r.RemoteAddr`). |
| **Tampering** | Attacker sends malicious `Connection: close, X-Custom` headers to strip internal authorization headers passed to upstreams. | Gateway strips all hop-by-hop and custom connection headers before dispatching to upstreams (RFC 9110). |
| **Repudiation** | An unauthorized or anomalous request occurs on an upstream, but logs cannot be correlated to a specific gateway request. | Gateway generates/injects a unique `X-Request-ID` header into every request context and forwards it to upstreams. |
| **Information Disclosure** | Upstream failure causes gateway to leak stack traces, runtime errors, or internal network topology to external clients. | Custom error handler in gateway converts upstream/internal panics into clean, generic HTTP error responses (e.g., `502 Bad Gateway`). |
| **Denial of Service** | Attacker opens HTTP connections and sends data extremely slowly (Slowloris) or causes upstream response hangs to exhaust gateway goroutines. | Enforce strict `http.Server` timeouts (`ReadTimeout`, `WriteTimeout`, `IdleTimeout`) and `http.Transport` `ResponseHeaderTimeout`. |
| **Elevation of Privilege** | Attacker uses path traversal (e.g., `/api/v1/service-a/../../admin`) to access unauthorized internal endpoints. | Gateway sanitizes and cleans request URL paths (`path.Clean`) before routing or policy evaluation. |

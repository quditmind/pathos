package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"pathos/internal/platform/httpx"
)

// Policy holds the rules per request class.
type Policy struct {
	Auth      Rule // /api/auth/* per client IP (login, callback)
	Anonymous Rule // other unauthenticated API calls per client IP
	Read      Rule // authenticated GET/HEAD per user
	Write     Rule // authenticated mutations per user
	Webhook   Rule // per SCM connection
	MCP       Rule // per bearer token
}

// DefaultPolicy is sized for interactive use plus automation through the
// API; tune with PATHOS_RATE_LIMIT_* settings.
func DefaultPolicy() Policy {
	return Policy{
		Auth:      Rule{PerSecond: 1, Burst: 20},
		Anonymous: Rule{PerSecond: 5, Burst: 50},
		Read:      Rule{PerSecond: 25, Burst: 150},
		Write:     Rule{PerSecond: 5, Burst: 40},
		Webhook:   Rule{PerSecond: 50, Burst: 200},
		MCP:       Rule{PerSecond: 10, Burst: 60},
	}
}

// Middleware enforces a Policy. UserID returns the authenticated user, if
// any (the session middleware runs first).
type Middleware struct {
	Limiter Limiter
	Policy  Policy
	UserID  func(context.Context) (uuid.UUID, bool)
	Log     *slog.Logger

	lastErrLog atomic.Int64
}

// classify returns the bucket key and rule for a request; ok=false means
// the request is not limited (static assets, health checks).
func (m *Middleware) classify(r *http.Request) (key string, rule Rule, ok bool) {
	p := r.URL.Path
	ip := httpx.ClientIP(r)
	switch {
	case strings.HasPrefix(p, "/api/auth/") && p != "/api/auth/logout":
		// Login and callback; logout is an ordinary authenticated call.
		return "auth:" + ip, m.Policy.Auth, true
	case strings.HasPrefix(p, "/api/webhooks/"):
		// /api/webhooks/{provider}/{connection}
		parts := strings.Split(strings.Trim(p, "/"), "/")
		conn := ""
		if len(parts) >= 4 {
			conn = parts[3]
		}
		return "hook:" + conn, m.Policy.Webhook, true
	case p == "/mcp":
		tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if tok == "" {
			return "anon:" + ip, m.Policy.Anonymous, true
		}
		h := sha256.Sum256([]byte(tok))
		return "mcp:" + hex.EncodeToString(h[:12]), m.Policy.MCP, true
	case strings.HasPrefix(p, "/api/"):
		if uid, ok := m.UserID(r.Context()); ok {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				return "r:" + uid.String(), m.Policy.Read, true
			}
			return "w:" + uid.String(), m.Policy.Write, true
		}
		return "anon:" + ip, m.Policy.Anonymous, true
	}
	return "", Rule{}, false
}

// Wrap returns the limiting handler. Backend errors fail open (the API
// stays available if Valkey is briefly unreachable) and are logged at most
// once a minute.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, rule, ok := m.classify(r)
		if !ok || rule.PerSecond <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		d, err := m.Limiter.Allow(r.Context(), key, rule)
		if err != nil {
			if now := time.Now().Unix(); m.Log != nil && now-m.lastErrLog.Swap(now) >= 60 {
				m.Log.Warn("rate limiter unavailable; allowing requests", "err", err)
			}
			next.ServeHTTP(w, r)
			return
		}
		if !d.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(RetryAfterSeconds(d.RetryAfter)))
			httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":      httpx.E(http.StatusTooManyRequests, "rate_limited", "too many requests; retry later"),
				"request_id": httpx.RequestID(r),
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

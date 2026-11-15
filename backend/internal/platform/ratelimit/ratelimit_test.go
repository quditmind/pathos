package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGCRABurstAndRefill(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := NewMemory()
	m.Now = func() time.Time { return now }
	rule := Rule{PerSecond: 2, Burst: 5}
	allowed := 0
	for range 20 {
		if d, _ := m.Allow(context.Background(), "k", rule); d.Allowed {
			allowed++
		}
	}
	if allowed < 5 || allowed > 6 {
		t.Fatalf("burst allowed %d, want 5-6", allowed)
	}
	d, _ := m.Allow(context.Background(), "k", rule)
	if d.Allowed || d.RetryAfter <= 0 || d.RetryAfter > time.Second {
		t.Fatalf("denied request should carry a short retry: %+v", d)
	}
	now = now.Add(d.RetryAfter)
	if d, _ := m.Allow(context.Background(), "k", rule); !d.Allowed {
		t.Fatal("request after Retry-After should pass")
	}
	// Sustained: 2/s over 10 seconds.
	allowed = 0
	for i := range 100 {
		now = now.Add(100 * time.Millisecond)
		if d, _ := m.Allow(context.Background(), "k", rule); d.Allowed {
			allowed++
		}
		_ = i
	}
	if allowed < 19 || allowed > 21 {
		t.Fatalf("sustained allowed %d in 10s, want ~20", allowed)
	}
	// Keys are independent.
	if d, _ := m.Allow(context.Background(), "other", rule); !d.Allowed {
		t.Fatal("independent key throttled")
	}
}

func TestMiddlewareClassesAndHeaders(t *testing.T) {
	user := uuid.New()
	mw := &Middleware{
		Limiter: NewMemory(),
		Policy:  Policy{Auth: Rule{1, 2}, Anonymous: Rule{1, 2}, Read: Rule{1, 3}, Write: Rule{1, 1}, Webhook: Rule{1, 2}, MCP: Rule{1, 2}},
		UserID: func(ctx context.Context) (uuid.UUID, bool) {
			v, ok := ctx.Value(ctxUser{}).(uuid.UUID)
			return v, ok
		},
	}
	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	do := func(method, path string, authed bool, hdr ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "10.0.0.1:1"
		r.Header.Set("X-Forwarded-For", "198.51.100.7")
		if len(hdr) == 2 {
			r.Header.Set(hdr[0], hdr[1])
		}
		if authed {
			r = r.WithContext(context.WithValue(r.Context(), ctxUser{}, user))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	count := func(n int, f func() *httptest.ResponseRecorder) (ok, limited int) {
		for range n {
			if rec := f(); rec.Code == 429 {
				limited++
				if rec.Header().Get("Retry-After") == "" {
					t.Error("429 without Retry-After")
				}
			} else {
				ok++
			}
		}
		return
	}
	if ok, _ := count(10, func() *httptest.ResponseRecorder { return do("GET", "/api/auth/login", false) }); ok > 3 {
		t.Errorf("auth endpoint allowed %d", ok)
	}
	// Reads and writes have separate budgets per user.
	if ok, _ := count(10, func() *httptest.ResponseRecorder { return do("GET", "/api/v1/findings", true) }); ok > 4 {
		t.Errorf("reads allowed %d", ok)
	}
	if rec := do("POST", "/api/v1/findings/x/status", true); rec.Code != 204 {
		t.Errorf("first write should pass despite exhausted reads: %d", rec.Code)
	}
	// MCP tokens are separate buckets.
	if rec := do("POST", "/mcp", false, "Authorization", "Bearer pathos_pat_a"); rec.Code != 204 {
		t.Error("mcp token a")
	}
	if rec := do("POST", "/mcp", false, "Authorization", "Bearer pathos_pat_b"); rec.Code != 204 {
		t.Error("mcp token b")
	}
	// Static assets and health checks are never limited.
	if ok, _ := count(20, func() *httptest.ResponseRecorder { return do("GET", "/healthz", false) }); ok != 20 {
		t.Error("health checks must not be limited")
	}
}

type ctxUser struct{}

type failing struct{}

func (failing) Allow(context.Context, string, Rule) (Decision, error) {
	return Decision{}, context.DeadlineExceeded
}

func TestFailOpen(t *testing.T) {
	mw := &Middleware{Limiter: failing{}, Policy: DefaultPolicy(), UserID: func(context.Context) (uuid.UUID, bool) { return uuid.Nil, false }}
	rec := httptest.NewRecorder()
	mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/me", nil))
	if rec.Code != 204 {
		t.Fatalf("backend failure should fail open, got %d", rec.Code)
	}
}

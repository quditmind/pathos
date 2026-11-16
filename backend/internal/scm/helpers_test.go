package scm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// memStore is an in-memory TokenStore that, like the real one, serializes
// refreshes and persists the result.
type memStore struct {
	mu      sync.Mutex
	tok     OAuthToken
	calls   int // refresh callbacks that changed the token
	invoked int // RefreshLocked invocations
}

func (s *memStore) Current(context.Context) (OAuthToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tok, nil
}

func (s *memStore) RefreshLocked(ctx context.Context, f func(context.Context, OAuthToken) (OAuthToken, error)) (OAuthToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invoked++
	nt, err := f(ctx, s.tok)
	if err != nil {
		return OAuthToken{}, err
	}
	if nt.AccessToken != s.tok.AccessToken {
		s.calls++
	}
	s.tok = nt
	return nt, nil
}

func tokenJSON(t *testing.T, tok OAuthToken) []byte {
	t.Helper()
	b, err := json.Marshal(tok)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func future(d time.Duration) *time.Time { x := time.Now().Add(d); return &x }

// fake is an httptest server with a request log.
type fake struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []string
}

func newFake(t *testing.T, h func(f *fake, w http.ResponseWriter, r *http.Request)) *fake {
	t.Helper()
	f := &fake{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r.Method+" "+r.URL.RequestURI())
		f.mu.Unlock()
		h(f, w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fake) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func (f *fake) count(prefix string) int {
	n := 0
	for _, r := range f.requests() {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func basicOf(r *http.Request) (string, string) {
	u, p, _ := r.BasicAuth()
	return u, p
}

func status(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"message":"secret-body-should-not-leak"}`))
}

func mustNew(t *testing.T, cfg Config) FullClient {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// tamperedTokens returns page tokens that must be rejected for q.
func tamperedTokens(provider string, q RepoQuery, base string) map[string]string {
	other := q
	other.Search = q.Search + "x"
	return map[string]string{
		"garbage":       "!!not-base64!!",
		"bad json":      base64.RawURLEncoding.EncodeToString([]byte("{")),
		"other host":    encodeCursor(provider, q, "https://evil.example/steal?page=2", 0),
		"other path":    encodeCursor(provider, q, base+"/user/emails?page=2", 0),
		"with userinfo": encodeCursor(provider, q, strings.Replace(base, "://", "://u:p@", 1)+"/x", 0),
		"other query":   encodeCursor(provider, other, base+"/x", 0),
		"too long":      strings.Repeat("a", maxPageTokenLen+1),
	}
}

func assertInvalidTokens(t *testing.T, d Discoverer, provider string, q RepoQuery, base string) {
	t.Helper()
	for name, tok := range tamperedTokens(provider, q, base) {
		qq := q
		qq.PageToken = tok
		if _, err := d.ListRepositoriesPage(context.Background(), qq); !errors.Is(err, ErrInvalidPageToken) {
			t.Errorf("tampered token %q: want ErrInvalidPageToken, got %v", name, err)
		}
	}
}

func assertNoLeak(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		return
	}
	for _, s := range append(secrets, "secret-body-should-not-leak") {
		if s != "" && strings.Contains(err.Error(), s) {
			t.Errorf("error %q leaks %q", err, s)
		}
	}
}

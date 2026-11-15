package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONStrict(t *testing.T) {
	type body struct {
		Email string `json:"email"`
	}
	cases := []struct {
		name, ct, in string
		ok           bool
	}{
		{"valid", "application/json", `{"email":"a@b.c"}`, true},
		{"unknown field", "application/json", `{"email":"a","x":1}`, false},
		{"trailing data", "application/json", `{"email":"a"}{"email":"b"}`, false},
		{"wrong content type", "text/plain", `{"email":"a"}`, false},
		{"malformed", "application/json", `{"email":`, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(c.in))
		r.Header.Set("Content-Type", c.ct)
		var b body
		err := DecodeJSON(httptest.NewRecorder(), r, &b)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
		var apiErr *Error
		if err != nil && !errors.As(err, &apiErr) {
			t.Errorf("%s: error should be an *Error", c.name)
		}
	}
}

func TestClientIPUsesRightmostForwardedFor(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "172.18.0.5:1234"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	if got := ClientIP(r); got != "203.0.113.9" {
		t.Errorf("got %s", got)
	}
	r.Header.Del("X-Forwarded-For")
	if got := ClientIP(r); got != "172.18.0.5" {
		t.Errorf("got %s", got)
	}
}

func TestMiddlewareRecoversAndSetsHeaders(t *testing.T) {
	h := Middleware(discardLogger(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	r.Header.Set("X-Request-Id", "bad id with spaces")
	h.ServeHTTP(rec, r)
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "boom") {
		t.Fatalf("panic must yield a generic 500, got %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("security headers missing")
	}
	if id := rec.Header().Get("X-Request-Id"); id == "" || strings.Contains(id, " ") {
		t.Errorf("invalid client request id must be replaced, got %q", id)
	}
}

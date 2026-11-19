package scm

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func init() {
	// The provider fakes answer Retry-After: 60; tests do not wait that long.
	MaxRetryAfter = 2 * time.Second
}

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		v    string
		want time.Duration
		ok   bool
	}{
		{"", 0, false}, {"5", 5 * time.Second, true}, {"0", 0, true}, {"-1", 0, false}, {"soon", 0, false},
		{now.Add(30 * time.Second).Format(http.TimeFormat), 30 * time.Second, true},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0, true},
	}
	for _, c := range cases {
		h := http.Header{}
		if c.v != "" {
			h.Set("Retry-After", c.v)
		}
		got, ok := RetryAfter(h, now)
		if got != c.want || ok != c.ok {
			t.Errorf("%q: got %v %v, want %v %v", c.v, got, ok, c.want, c.ok)
		}
	}
}

// A listing call waits for Retry-After on 429 (and on a rate-limited 403)
// and then succeeds; a write is never retried; a wait longer than
// MaxRetryAfter is not attempted.
func TestListingHonoursRetryAfter(t *testing.T) {
	var calls atomic.Int32
	var retryIn string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", retryIn)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"octo","id":1}`))
	}))
	defer srv.Close()
	a := &api{hc: srv.Client(), auth: bearerAuth{tok: "t", k: AuthPAT}}

	retryIn = "1"
	start := time.Now()
	var out map[string]any
	if _, err := a.get(context.Background(), srv.URL+"/user", &out); err != nil || out["login"] != "octo" {
		t.Fatalf("get after Retry-After: %v %v", out, err)
	}
	if time.Since(start) < 900*time.Millisecond || calls.Load() != 2 {
		t.Errorf("did not wait for Retry-After: %v, %d calls", time.Since(start), calls.Load())
	}

	calls.Store(0)
	retryIn = "1"
	if _, err := a.do(context.Background(), http.MethodPost, srv.URL+"/x", []byte("{}"), "application/json", nil); !errors.Is(err, ErrRateLimited) || calls.Load() != 1 {
		t.Errorf("write retried: %v, %d calls", err, calls.Load())
	}

	calls.Store(0)
	retryIn = strconv.Itoa(int(MaxRetryAfter/time.Second) + 30)
	if _, err := a.get(context.Background(), srv.URL+"/user", &out); !errors.Is(err, ErrRateLimited) || calls.Load() != 1 {
		t.Errorf("long Retry-After was waited for: %v, %d calls", err, calls.Load())
	}

	// The caller's deadline is respected.
	calls.Store(0)
	retryIn = "1"
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := a.get(ctx, srv.URL+"/user", &out); !errors.Is(err, ErrRateLimited) {
		t.Errorf("deadline: %v", err)
	}
}

func gitlabSign(key []byte, id, ts string, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(id + "." + ts + "."))
	m.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func TestGitLabSigningToken(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	token := []byte("whsec_" + base64.StdEncoding.EncodeToString(key))
	body := []byte(`{"object_kind":"push"}`)
	now := time.Unix(1_800_000_000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	sig := gitlabSign(key, "msg_1", ts, body)

	if err := VerifyGitLabSignature(token, "msg_1", ts, sig, body, now); err != nil {
		t.Fatalf("valid signature refused: %v", err)
	}
	// Several signatures (key rotation): any valid v1 entry passes.
	if err := VerifyGitLabSignature(token, "msg_1", ts, "v1,AAAA "+sig, body, now); err != nil {
		t.Errorf("second signature refused: %v", err)
	}
	for name, c := range map[string]struct {
		id, ts, sig string
		body        []byte
		now         time.Time
	}{
		"tampered body":    {"msg_1", ts, sig, []byte(`{"object_kind":"tag_push"}`), now},
		"other id":         {"msg_2", ts, sig, body, now},
		"replayed old":     {"msg_1", ts, sig, body, now.Add(6 * time.Minute)},
		"future timestamp": {"msg_1", ts, sig, body, now.Add(-6 * time.Minute)},
		"missing":          {"msg_1", ts, "", body, now},
		"wrong version":    {"msg_1", ts, "v2," + sig[3:], body, now},
		"bad timestamp":    {"msg_1", "yesterday", sig, body, now},
	} {
		if err := VerifyGitLabSignature(token, c.id, c.ts, c.sig, c.body, c.now); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	for _, bad := range []string{"", "abc", "whsec_", "whsec_!!!", "whsec_" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := ParseGitLabSigningToken(bad); err == nil {
			t.Errorf("token %q accepted", bad)
		}
	}
}

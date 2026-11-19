package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"pathos/internal/platform/crypto"
)

var codeRe = regexp.MustCompile(`^PTH-[A-Z]+-[0-9]{4}$`)

func serve(t *testing.T, h http.HandlerFunc) (*httptest.ResponseRecorder, map[string]any, string) {
	t.Helper()
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	rec := httptest.NewRecorder()
	Middleware(log, h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/x", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %s", rec.Body)
	}
	return rec, body, logs.String()
}

func TestErrorEnvelope(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		status   int
		legacy   string
		code     string
		mustLog  bool
		hasField bool
	}{
		{"not found keeps its legacy code", ErrNotFound, 404, "not_found", "PTH-PLAT-0004", false, false},
		{"explicit code", E(429, "rate_limited", "daily limit").WithDiag("PTH-AI-1008"), 429, "rate_limited", "PTH-AI-1008", false, false},
		{"validation fields kept", &Error{Status: 422, Code: "validation_failed", Message: "bad", Fields: map[string]string{"name": "required"}}, 422, "validation_failed", "PTH-PLAT-0003", false, true},
		{"unknown error", errors.New("boom: secret=hunter2"), 500, "internal", "PTH-PLAT-0001", true, false},
		{"decryption failure", fmt.Errorf("reveal: %w", crypto.ErrDecrypt), 500, "internal", "PTH-PLAT-1013", true, false},
		{"unmapped legacy code uses the status", E(409, "something_new", "x"), 409, "something_new", "PTH-PLAT-0005", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, body, logs := serve(t, func(w http.ResponseWriter, r *http.Request) {
				WriteError(w, r, slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), c.err)
			})
			if rec.Code != c.status {
				t.Fatalf("status %d", rec.Code)
			}
			e := body["error"].(map[string]any)
			rid := rec.Header().Get("X-Request-Id")
			if e["code"] != c.legacy || e["error_code"] != c.code || !codeRe.MatchString(e["error_code"].(string)) {
				t.Errorf("codes: %v", e)
			}
			if body["request_id"] != rid || e["request_id"] != rid || rid == "" {
				t.Errorf("request id at both levels: %v / %v / %s", body["request_id"], e["request_id"], rid)
			}
			for _, k := range []string{"title", "message", "cause", "probable_causes", "impact", "actions", "verify", "docs_url"} {
				if _, ok := e[k]; !ok {
					t.Errorf("missing %s", k)
				}
			}
			if !strings.HasPrefix(e["docs_url"].(string), "/help/troubleshooting/") {
				t.Errorf("docs_url %v", e["docs_url"])
			}
			if _, ok := e["fields"]; ok != c.hasField {
				t.Errorf("fields: %v", e["fields"])
			}
			if strings.Contains(rec.Body.String(), "hunter2") {
				t.Error("internal error text leaked to the client")
			}
			// The access log line of the request carries both ids.
			if !strings.Contains(logs, `"error_code":"`+c.code+`"`) || !strings.Contains(logs, `"request_id":"`+rid+`"`) {
				t.Errorf("access log lacks error_code/request_id: %s", logs)
			}
		})
	}
}

func TestErrorLogLineCarriesCode(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	rec := httptest.NewRecorder()
	Middleware(log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, r, log, errors.New("db down"))
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if !strings.Contains(line, `"error_code":"PTH-PLAT-0001"`) || !strings.Contains(line, `"request_id":`) {
			t.Errorf("log line without error_code and request_id: %s", line)
		}
	}
}

func TestPanicEnvelope(t *testing.T) {
	rec, body, _ := serve(t, func(http.ResponseWriter, *http.Request) { panic("boom") })
	if rec.Code != 500 || body["error"].(map[string]any)["error_code"] != "PTH-PLAT-0001" {
		t.Fatalf("panic: %d %v", rec.Code, body)
	}
}

func TestSharedErrorsAreNotModified(t *testing.T) {
	_ = ErrNotFound.WithDiag("PTH-SCAN-1008").WithCause("x")
	if ErrNotFound.Diag != "" || ErrNotFound.Cause != "" {
		t.Fatal("WithDiag/WithCause must copy")
	}
}

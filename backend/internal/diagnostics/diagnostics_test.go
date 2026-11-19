package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/ai"
	"pathos/internal/authz"
	"pathos/internal/platform/buildinfo"
	"pathos/internal/platform/httpx"
)

// stubAI records what it was sent; it never calls a real provider.
type stubAI struct {
	in  []ai.TroubleshootInput
	out ai.TroubleshootOutput
	err error
}

func (s *stubAI) Troubleshoot(_ context.Context, _ uuid.UUID, in ai.TroubleshootInput) (ai.TroubleshootResult, error) {
	s.in = append(s.in, in)
	if s.err != nil {
		return ai.TroubleshootResult{}, s.err
	}
	return ai.TroubleshootResult{Output: s.out, Provider: ai.SelfHosted, Model: "local-test-model"}, nil
}

func newService(p *authz.Principal, a Troubleshooter) http.Handler {
	s := &Service{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Principal: func(context.Context) *authz.Principal { return p }}
	if a != nil {
		s.AI = a
	}
	mux := http.NewServeMux()
	s.RegisterPublic(mux)
	s.Register(mux)
	return httpx.Middleware(s.Log, mux)
}

func do(t *testing.T, h http.Handler, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestMetaUnauthenticated(t *testing.T) {
	code, out := do(t, newService(nil, nil), "GET", "/api/v1/meta", nil)
	if code != 200 || len(out) != 3 || out["product"] != "PATHOS" || out["vendor"] != "Quditmind" || out["version"] != buildinfo.Version {
		t.Fatalf("unauthenticated meta must hold product, vendor and version only: %d %v", code, out)
	}
}

func TestCodesNeedAuthentication(t *testing.T) {
	if code, out := do(t, newService(nil, nil), "GET", "/api/v1/diagnostics/codes", nil); code != 401 || out["error"].(map[string]any)["error_code"] != "PTH-AUTH-1001" {
		t.Fatalf("codes without a principal: %d %v", code, out)
	}
	p := &authz.Principal{UserID: uuid.New(), OrganizationID: uuid.New()}
	code, out := do(t, newService(p, nil), "GET", "/api/v1/diagnostics/codes", nil)
	if code != 200 || len(out["items"].([]any)) < 60 || len(out["areas"].([]any)) < 10 {
		t.Fatalf("codes: %d", code)
	}
	first := out["items"].([]any)[0].(map[string]any)
	for _, k := range []string{"code", "area", "category", "severity", "title", "description", "confirmed_cause", "probable_causes", "impact", "actions", "verify", "docs_slug", "docs_url", "ai_help"} {
		if _, ok := first[k]; !ok {
			t.Errorf("catalogue entry lacks %s", k)
		}
	}
}

func TestTroubleshootWithStubAI(t *testing.T) {
	p := &authz.Principal{UserID: uuid.New(), OrganizationID: uuid.New()}
	stub := &stubAI{out: ai.TroubleshootOutput{LikelyCause: "The private CA is missing from the API image.", ProbableCauses: []string{"TLS inspection proxy"},
		Actions: []string{"Install the CA bundle in the api container."}, Verify: []string{"Test the connection."}}}
	h := newService(p, stub)
	secret := "ghp_" + strings.Repeat("A", 36)
	code, out := do(t, h, "POST", "/api/v1/diagnostics/troubleshoot", map[string]any{"code": "PTH-CONN-1004", "request_id": "abc",
		"message": "x509: certificate signed by unknown authority token=" + secret,
		"context": map[string]string{"connection_kind": "github", "log": "Authorization: Bearer " + secret + "\n```go\nfunc main() {}\n```", "BAD KEY": "dropped"}})
	if code != 200 || out["source"] != "ai" || out["error_code"] != "PTH-CONN-1004" || out["request_id"] != "abc" || out["model"] != "local-test-model" {
		t.Fatalf("ai answer: %d %v", code, out)
	}
	cause := out["cause"].(map[string]any)
	if cause["confirmed"] != false || cause["text"] != "The private CA is missing from the API image." {
		t.Errorf("AI conclusions are never confirmed: %v", cause)
	}
	if a := out["actions"].([]any); len(a) != 1 || a[0] != "Install the CA bundle in the api container." {
		t.Errorf("actions: %v", a)
	}
	if len(stub.in) != 1 {
		t.Fatal("stub not called")
	}
	sent, _ := json.Marshal(stub.in[0])
	if strings.Contains(string(sent), secret) || strings.Contains(string(sent), "func main") || strings.Contains(string(sent), "BAD KEY") {
		t.Errorf("secrets, code or unknown keys sent to the AI: %s", sent)
	}
	if strings.Contains(out["message"].(string), secret) {
		t.Error("the response echoes a secret")
	}
	if len(stub.in[0].Actions) == 0 || stub.in[0].Title == "" {
		t.Error("the catalogue entry must be sent as context")
	}
}

func TestTroubleshootFallsBackToCatalogue(t *testing.T) {
	p := &authz.Principal{UserID: uuid.New(), OrganizationID: uuid.New()}
	for name, a := range map[string]Troubleshooter{
		"AI off":            nil,
		"AI not configured": &stubAI{err: ai.ErrNotConfigured},
		"AI failed":         &stubAI{err: errors.New("connection refused")},
	} {
		t.Run(name, func(t *testing.T) {
			code, out := do(t, newService(p, a), "POST", "/api/v1/diagnostics/troubleshoot", map[string]any{"code": "PTH-PLAT-1001"})
			if code != 200 || out["source"] != "catalogue" || out["ai_unavailable"] == "" || len(out["actions"].([]any)) == 0 || out["title"] != "Database unreachable" {
				t.Fatalf("catalogue fallback: %d %v", code, out)
			}
		})
	}
	// Codes without AI help never call the AI.
	stub := &stubAI{}
	if code, out := do(t, newService(p, stub), "POST", "/api/v1/diagnostics/troubleshoot", map[string]any{"code": "PTH-PLAT-0004"}); code != 200 || out["source"] != "catalogue" || len(stub.in) != 0 {
		t.Fatalf("no AI help: %d %v %d", code, out, len(stub.in))
	}
}

func TestTroubleshootValidation(t *testing.T) {
	p := &authz.Principal{UserID: uuid.New(), OrganizationID: uuid.New()}
	h := newService(p, nil)
	if code, out := do(t, h, "POST", "/api/v1/diagnostics/troubleshoot", map[string]any{"code": "not_found"}); code != 422 || out["error"].(map[string]any)["error_code"] != "PTH-PLAT-0003" {
		t.Errorf("legacy short codes are not accepted: %d %v", code, out)
	}
	if code, _ := do(t, h, "POST", "/api/v1/diagnostics/troubleshoot", map[string]any{"code": "PTH-PLAT-0001", "extra": 1}); code != 400 {
		t.Errorf("unknown fields: %d", code)
	}
	if code, _ := do(t, newService(nil, nil), "POST", "/api/v1/diagnostics/troubleshoot", map[string]any{"code": "PTH-PLAT-0001"}); code != 401 {
		t.Errorf("unauthenticated: %d", code)
	}
}

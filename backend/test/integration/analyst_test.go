//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/ai"
	"pathos/internal/analyst"
	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/posture"
	"pathos/internal/secrets"
)

func TestAISecurityAnalyst(t *testing.T) {
	ctx := t.Context()
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	fake := &fakeProvider{}
	aiSvc := &ai.Service{DB: appPool, Authz: az, Secrets: &secrets.Store{Keys: kr}, Log: log, Principal: auth.PrincipalFrom,
		NewProvider: func(ai.Config) (ai.Provider, error) { return fake, nil }}
	svc := &analyst.Service{DB: appPool, Authz: az, AI: aiSvc, Posture: &posture.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom},
		Log: log, Principal: auth.PrincipalFrom}
	mux := http.NewServeMux()
	aiSvc.Register(mux)
	svc.Register(mux)
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any, []byte) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req.WithContext(auth.WithPrincipal(req.Context(), p)))
		b, _ := io.ReadAll(rec.Body)
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		return rec.Code, out, b
	}
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	// A default AI configuration (another test may have created one).
	var configs int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM ai_configurations WHERE organization_id = $1 AND is_default`, orgID).Scan(&configs)
	if configs == 0 {
		_, prov, _ := call(admin, "POST", "/api/v1/ai/providers", map[string]any{"name": "Analyst test", "kind": "anthropic", "api_key": "sk-ant-x"})
		if code, out, _ := call(admin, "POST", "/api/v1/ai/configurations", map[string]any{"name": "Default", "provider_id": prov["id"], "effort": "low",
			"approval_policy": "false_positives", "categories": []string{"sast"}, "min_severity": "medium"}); code != 201 {
			t.Fatalf("configuration: %d %v", code, out)
		}
	}

	analystUser := reviewUser(t, "security_analyst")
	other := reviewUser(t, "security_analyst")
	viewer := reviewUser(t, "viewer")
	repo := createRepo(t, "an-"+uuid.NewString()[:6])
	sqli := insertRiskFinding(t, repo, "sast", "critical", 95, true, "", "", "")
	if _, err := appPool.Exec(ctx, `UPDATE findings SET title = 'SQL injection in orders export (token AKIAABCDEFGHIJKLMNOP)' WHERE id = $1`, sqli); err != nil {
		t.Fatal(err)
	}
	insertRiskFinding(t, repo, "sca", "medium", 30, false, "lodash", "4.17.20", "")

	// --- conversation -----------------------------------------------------------
	if code, _, _ := call(viewer, "POST", "/api/v1/ai/analyst/conversations", map[string]any{}); code != 403 {
		t.Errorf("viewer lacks ai.review: %d", code)
	}
	_, conv, _ := call(analystUser, "POST", "/api/v1/ai/analyst/conversations", map[string]any{})
	cid := conv["id"].(string)
	bogus := uuid.NewString()
	fake.response = fmt.Sprintf(`{"answer":"Fix the **SQL injection** first: it is actively exploited.","cited_findings":["%s","%s"],"follow_up_questions":["Which repositories are exposed?"]}`,
		sqli, bogus)
	code, out, _ := call(analystUser, "POST", "/api/v1/ai/analyst/conversations/"+cid+"/messages", map[string]any{"question": "Which SQL injection should we fix first?"})
	if code != 200 {
		t.Fatalf("ask: %d %v", code, out)
	}
	msgs := out["messages"].([]any)
	answer := msgs[len(msgs)-1].(map[string]any)
	cites := answer["citations"].([]any)
	if len(msgs) != 2 || len(cites) != 1 || cites[0].(map[string]any)["id"] != sqli.String() {
		t.Fatalf("only findings given to the model can be cited: %v", answer)
	}
	if answer["context_findings"].(float64) < 1 || answer["model"] == "" {
		t.Errorf("provenance: %v", answer)
	}
	fake.mu.Lock()
	prompt := fake.prompts[len(fake.prompts)-1]
	fake.mu.Unlock()
	if !strings.Contains(prompt.User, sqli.String()) || !strings.Contains(prompt.User, "<untrusted_evidence") {
		t.Error("the matching finding is in the fenced context")
	}
	if strings.Contains(prompt.User, "AKIAABCDEFGHIJKLMNOP") {
		t.Error("secret-looking values are redacted before they reach the model")
	}
	_, got, _ := call(analystUser, "GET", "/api/v1/ai/analyst/conversations/"+cid, nil)
	if !strings.HasPrefix(got["title"].(string), "Which SQL injection") {
		t.Errorf("the first question names the conversation: %v", got["title"])
	}
	if code, _, _ := call(other, "GET", "/api/v1/ai/analyst/conversations/"+cid, nil); code != 404 {
		t.Errorf("conversations are private: %d", code)
	}
	fake.response = `{"answer":"","cited_findings":[],"follow_up_questions":[]}`
	if code, _, _ := call(analystUser, "POST", "/api/v1/ai/analyst/conversations/"+cid+"/messages", map[string]any{"question": "Anything else?"}); code != 502 {
		t.Errorf("an empty answer is refused: %d", code)
	}

	// --- reports ----------------------------------------------------------------------
	fake.response = `{"summary":"Two open findings; one is actively exploited.","key_risks":["SQL injection in orders export"],"recommendations":["Fix it this week."]}`
	code, rep, _ := call(analystUser, "POST", "/api/v1/ai/reports", map[string]any{"kind": "executive", "scope_type": "repository", "scope_id": repo})
	if code != 201 || rep["narrative"] == nil {
		t.Fatalf("report: %d %v", code, rep)
	}
	facts := rep["facts"].(map[string]any)
	if facts["open_actively_exploited"].(float64) != 1 || len(facts["riskiest_findings"].([]any)) != 2 {
		t.Errorf("figures computed by PATHOS: %v", facts)
	}
	_, _, md := call(analystUser, "GET", "/api/v1/ai/reports/"+rep["id"].(string)+"/markdown", nil)
	if !strings.Contains(string(md), "## Figures") || !strings.Contains(string(md), "Fix it this week.") {
		t.Errorf("markdown: %s", md)
	}
	code, plain, _ := call(analystUser, "POST", "/api/v1/ai/reports", map[string]any{"kind": "technical", "scope_type": "repository", "scope_id": repo, "narrative": false})
	if code != 201 || plain["narrative"] != nil {
		t.Errorf("figures-only report: %d %v", code, plain)
	}
	elsewhere := scoped("security_analyst", authz.Scope{Type: authz.ScopeRepository, ID: createRepo(t, "an2-"+uuid.NewString()[:6])})
	if code, _, _ := call(elsewhere, "GET", "/api/v1/ai/reports/"+rep["id"].(string), nil); code != 404 {
		t.Errorf("a scoped user cannot read another person's report: %d", code)
	}
	if code, _, _ := call(analystUser, "POST", "/api/v1/ai/reports", map[string]any{"kind": "board", "scope_type": "organization"}); code != 400 {
		t.Errorf("unknown kind: %d", code)
	}

	// --- usage ---------------------------------------------------------------------------
	if code, _, _ := call(analystUser, "GET", "/api/v1/ai/usage", nil); code != 403 {
		t.Errorf("usage needs ai.configure: %d", code)
	}
	_, usage, _ := call(admin, "GET", "/api/v1/ai/usage?days=7", nil)
	features := map[string]bool{}
	for _, f := range usage["by_feature"].([]any) {
		features[f.(map[string]any)["key"].(string)] = true
	}
	if !features["analyst"] || !features["report"] {
		t.Errorf("usage by feature: %v", usage["by_feature"])
	}
}

//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/scans"
)

func TestScanGateEndpoint(t *testing.T) {
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	svc := &scans.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	mux := http.NewServeMux()
	svc.Register(mux)
	do := func(p *authz.Principal, req *http.Request) (int, map[string]any) {
		t.Helper()
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	analyst := reviewUser(t, "security_analyst")
	repo := createRepo(t, "gate-"+uuid.NewString()[:6])

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range map[string]string{"repository_id": repo.String(), "tool": "Gate CI", "category": "sast"} {
		_ = mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("file", "report.json")
	_, _ = fw.Write([]byte(`{"findings":[
		{"rule_id":"sqli","title":"SQL injection","severity":"critical","file_path":"a.go","start_line":3},
		{"rule_id":"weak","title":"Weak hash","severity":"low","file_path":"b.go","start_line":9}]}`))
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/v1/imports/results", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	code, imp := do(analyst, req)
	if code != 201 {
		t.Fatalf("import: %d %v", code, imp)
	}
	jobID := imp["scan_job_id"].(string)
	gate := func(p *authz.Principal, query string) (int, map[string]any) {
		return do(p, httptest.NewRequest("GET", "/api/v1/scans/"+jobID+"/gate"+query, nil))
	}

	code, g := gate(analyst, "?fail_on=high")
	if code != 200 || g["passed"] != false || g["threshold_count"].(float64) < 1 || g["finished"] != true || g["scope"] != "new" {
		t.Fatalf("fail_on=high: %d %v", code, g)
	}
	if sev := g["by_severity"].(map[string]any); sev["critical"].(float64) != 1 || sev["low"].(float64) != 1 {
		t.Errorf("by_severity: %v", sev)
	}
	if rs := g["reasons"].([]any); len(rs) == 0 {
		t.Error("a failed gate gives reasons")
	}
	code, g = gate(analyst, "")
	if code != 200 || g["fail_on"] != "none" || g["threshold_count"].(float64) != 0 {
		t.Fatalf("default: %d %v", code, g)
	}
	if len(g["blocking_policies"].([]any)) == 0 && g["gate_failed"] == false && g["passed"] != true {
		t.Errorf("no threshold, no policy: passes: %v", g)
	}
	if code, g = gate(analyst, "?fail_on=critical&scope=all"); code != 200 || g["passed"] != false || g["scope"] != "all" {
		t.Errorf("scope all: %d %v", code, g)
	}
	if code, _ := gate(analyst, "?fail_on=urgent"); code != 400 {
		t.Errorf("invalid fail_on: %d", code)
	}
	if code, _ := gate(analyst, "?scope=some"); code != 400 {
		t.Errorf("invalid scope: %d", code)
	}
	if code, _ := gate(scoped("viewer", authz.Scope{Type: authz.ScopeRegion, ID: uuid.New()}), "?fail_on=high"); code != 404 {
		t.Errorf("out of scope must 404, got %d", code)
	}
	if code, _ := do(analyst, httptest.NewRequest("GET", "/api/v1/scans/"+uuid.NewString()+"/gate", nil)); code != 404 {
		t.Errorf("unknown scan: %d", code)
	}
}

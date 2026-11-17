//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/scans"
)

func TestImportsAndCustomRules(t *testing.T) {
	ctx := t.Context()
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
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		return do(p, req)
	}
	upload := func(p *authz.Principal, path string, fields map[string]string, content []byte) (int, map[string]any) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for k, v := range fields {
			_ = mw.WriteField(k, v)
		}
		fw, _ := mw.CreateFormFile("file", "report.json")
		_, _ = fw.Write(content)
		_ = mw.Close()
		req := httptest.NewRequest("POST", path, &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		return do(p, req)
	}
	analyst := reviewUser(t, "security_analyst")
	viewer := reviewUser(t, "viewer")
	admin := reviewUser(t, "platform_admin")
	repo := createRepo(t, "imp-"+uuid.NewString()[:6])
	sarif, _ := os.ReadFile("../../internal/scanners/testdata/opengrep.sarif")

	// --- results import ---------------------------------------------------
	fields := map[string]string{"repository_id": repo.String(), "tool": "Semgrep Pro", "category": "sast"}
	if code, _ := upload(viewer, "/api/v1/imports/results", fields, sarif); code != 403 {
		t.Errorf("viewer cannot import: %d", code)
	}
	code, out := upload(analyst, "/api/v1/imports/results", fields, sarif)
	if code != 201 || out["status"] != "succeeded" || out["records"].(float64) == 0 || out["scanner_key"] != "import-sast-semgrep-pro" {
		t.Fatalf("sarif import: %d %v", code, out)
	}
	jobID := out["scan_job_id"].(string)
	var trigger, status string
	_ = appPool.QueryRow(ctx, `SELECT trigger, status FROM scan_jobs WHERE id = $1`, jobID).Scan(&trigger, &status)
	if trigger != "import" || status != "succeeded" {
		t.Errorf("import execution: %s %s", trigger, status)
	}
	var imported int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND 'import-sast-semgrep-pro' = ANY(scanner_keys) AND status = 'open'`, repo).Scan(&imported)
	if imported == 0 {
		t.Fatal("imported findings are stored with their tool")
	}
	code, out = upload(analyst, "/api/v1/imports/results", fields, []byte(`{"unknown":true}`))
	if code != 422 || out["import"].(map[string]any)["status"] != "failed" {
		t.Errorf("invalid report recorded as failed: %d %v", code, out)
	}
	if code, _ := upload(analyst, "/api/v1/imports/results", map[string]string{"repository_id": repo.String(), "tool": "x", "category": "nope"}, sarif); code != 400 {
		t.Errorf("invalid category: %d", code)
	}

	// A partial import never resolves; a complete one resolves what is missing.
	one := []byte(`{"findings":[{"rule_id":"other","title":"Something else","severity":"low","file_path":"a.go"}]}`)
	if code, _ := upload(analyst, "/api/v1/imports/results", fields, one); code != 201 {
		t.Fatalf("partial import: %d", code)
	}
	var open int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND 'import-sast-semgrep-pro' = ANY(scanner_keys) AND status = 'open'`, repo).Scan(&open)
	if open != imported+1 {
		t.Errorf("partial import keeps findings open: %d vs %d", open, imported+1)
	}
	full := map[string]string{"repository_id": repo.String(), "tool": "Semgrep Pro", "category": "sast", "resolve_missing": "true"}
	if code, _ := upload(analyst, "/api/v1/imports/results", full, one); code != 201 {
		t.Fatalf("complete import: %d", code)
	}
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND 'import-sast-semgrep-pro' = ANY(scanner_keys) AND status = 'open'`, repo).Scan(&open)
	if open != 1 {
		t.Errorf("complete import resolves missing findings: %d open", open)
	}
	// Generic JSON with a DAST category.
	dast := []byte(`{"findings":[{"title":"Missing CSP","severity":"medium","url":"https://app.example/"}]}`)
	if code, out := upload(analyst, "/api/v1/imports/results", map[string]string{"repository_id": repo.String(), "tool": "ZAP CI", "category": "dast"}, dast); code != 201 {
		t.Fatalf("dast import: %d %v", code, out)
	}
	var cat, path string
	_ = appPool.QueryRow(ctx, `SELECT category, file_path FROM findings WHERE repository_id = $1 AND 'import-dast-zap-ci' = ANY(scanner_keys)`, repo).Scan(&cat, &path)
	if cat != "dast" || path != "https://app.example/" {
		t.Errorf("dast finding: %s %s", cat, path)
	}

	// --- SBOM import -------------------------------------------------------
	spdx := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"lodash","versionInfo":"4.17.20","licenseConcluded":"MIT",
		"externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.20"}]},{"name":"openssl","versionInfo":"3.0.1"}]}`)
	code, out = upload(analyst, "/api/v1/imports/sbom", map[string]string{"repository_id": repo.String()}, spdx)
	if code != 201 || out["records"].(float64) != 2 || out["format"] != "spdx" {
		t.Fatalf("sbom import: %d %v", code, out)
	}
	var comps int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM sbom_components WHERE repository_id = $1 AND source = 'import'`, repo).Scan(&comps)
	if comps != 2 {
		t.Errorf("components: %d", comps)
	}
	if code, _ := upload(analyst, "/api/v1/imports/sbom", map[string]string{"repository_id": repo.String()}, []byte(`{"x":1}`)); code != 422 {
		t.Errorf("invalid sbom: %d", code)
	}
	code, hist := call(analyst, "GET", "/api/v1/imports/history?repository_id="+repo.String(), nil)
	if code != 200 || len(hist["items"].([]any)) < 6 {
		t.Errorf("history: %d %v", code, hist)
	}

	// --- custom rules ------------------------------------------------------
	rule := "rules:\n  - id: acme.go.exec\n    languages: [go]\n    severity: ERROR\n    message: exec of user input\n    pattern: exec.Command($X)\n"
	if code, _ := call(analyst, "POST", "/api/v1/custom-rules", map[string]any{"name": "Acme", "content": rule}); code != 403 {
		t.Errorf("analyst cannot manage rules: %d", code)
	}
	if code, out := call(admin, "POST", "/api/v1/custom-rules", map[string]any{"name": "Bad", "content": "rules: ["}); code != 422 {
		t.Errorf("invalid rules: %d %v", code, out)
	}
	name := "Acme " + uuid.NewString()[:6]
	code, rr := call(admin, "POST", "/api/v1/custom-rules", map[string]any{"name": name, "content": rule})
	if code != 201 || rr["version"].(float64) != 1 {
		t.Fatalf("create rule: %d %v", code, rr)
	}
	if code, _ := call(admin, "POST", "/api/v1/custom-rules", map[string]any{"name": name + "2", "content": rule}); code != 422 {
		t.Errorf("rule ids must be unique across enabled files: %d", code)
	}
	code, rr = call(admin, "PUT", "/api/v1/custom-rules/"+rr["id"].(string), map[string]any{"content": strings.Replace(rule, "ERROR", "WARNING", 1), "change_note": "lower"})
	if code != 200 || rr["version"].(float64) != 2 {
		t.Fatalf("update rule: %d %v", code, rr)
	}
	// New executions pin the rule version and the worker receives it.
	res, err := scans.Enqueue(ctx, appPool, orgID, repo, "manual", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var snap []byte
	_ = appPool.QueryRow(ctx, `SELECT config_snapshot FROM scan_jobs WHERE id = $1`, res.JobID).Scan(&snap)
	var cfg struct {
		CustomRules []struct {
			Name    string `json:"name"`
			Version int    `json:"version"`
		} `json:"custom_rules"`
	}
	_ = json.Unmarshal(snap, &cfg)
	pinned := false
	for _, c := range cfg.CustomRules {
		pinned = pinned || (c.Name == name && c.Version == 2)
	}
	if !pinned {
		t.Errorf("snapshot pins the rule version: %s", snap)
	}
	code, vers := call(viewer, "GET", "/api/v1/custom-rules/"+rr["id"].(string)+"/versions", nil)
	if code != 200 || len(vers["items"].([]any)) != 2 {
		t.Errorf("versions: %d %v", code, vers)
	}
}

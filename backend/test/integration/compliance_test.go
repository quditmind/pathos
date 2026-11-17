//go:build integration

package integration

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/compliance"
)

func TestComplianceViews(t *testing.T) {
	ctx := t.Context()
	cs := &compliance.Service{DB: appPool, Log: log, Principal: auth.PrincipalFrom}
	mux := newMux(cs.Register)
	call := func(p *authz.Principal, path string) (int, map[string]any) {
		req := httptest.NewRequest("GET", path, nil).WithContext(auth.WithPrincipal(ctx, p))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	repo := createRepo(t, "pci-"+uuid.NewString()[:6])
	if _, err := appPool.Exec(ctx, `INSERT INTO repository_compliance_scopes (organization_id, repository_id, scope_key) VALUES ($1, $2, 'pci_dss')`, orgID, repo); err != nil {
		t.Fatal(err)
	}
	// One open critical SCA finding and one hard-coded secret.
	for _, f := range []struct{ cat, sev, cwe string }{{"sca", "critical", ""}, {"secrets", "high", "CWE-798"}} {
		cwe := []string{}
		if f.cwe != "" {
			cwe = []string{f.cwe}
		}
		if _, err := appPool.Exec(ctx, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, severity, cwe)
			VALUES ($1, $2, $3, $4, $5, '{test}', 'r', 't', $6, $7)`, uuid.New(), orgID, repo, uuid.NewString(), f.cat, f.sev, cwe); err != nil {
			t.Fatal(err)
		}
	}
	code, list := call(admin, "/api/v1/compliance/frameworks")
	if code != 200 || len(list["items"].([]any)) != len(compliance.Frameworks) || list["note"] == nil {
		t.Fatalf("list: %d %v", code, list)
	}
	code, pci := call(admin, "/api/v1/compliance/frameworks/pci_dss_4")
	if code != 200 || pci["repositories_in_scope"].(float64) < 1 {
		t.Fatalf("pci: %d %v", code, pci)
	}
	byID := map[string]map[string]any{}
	for _, c := range pci["controls"].([]any) {
		m := c.(map[string]any)
		byID[m["id"].(string)] = m
	}
	if byID["6.3.3"]["status"] != "failing" || byID["8.6.2"]["status"] != "failing" {
		t.Errorf("patch and hard-coded password controls fail: %v %v", byID["6.3.3"], byID["8.6.2"])
	}
	if byID["8.6.2"]["by_severity"].(map[string]any)["high"].(float64) < 1 {
		t.Errorf("by severity: %v", byID["8.6.2"])
	}
	// The findings list filters by control (same mapping and scope).
	h := newScanHarness(t)
	if code, fl := h.user(admin, "GET", "/api/v1/findings?repository_id="+repo.String()+"&control=pci_dss_4:8.6.2", nil); code != 200 || len(fl["items"].([]any)) != 1 {
		t.Errorf("control filter: %d %v", code, fl)
	}
	if code, _ := h.user(admin, "GET", "/api/v1/findings?control=pci_dss_4:99", nil); code != 400 {
		t.Errorf("unknown control: %d", code)
	}
	if code, _ := call(admin, "/api/v1/compliance/frameworks/nist_800_53"); code != 404 {
		t.Errorf("unknown framework: %d", code)
	}
	// Out-of-scope users see no repositories and nothing failing.
	other := scoped("viewer", authz.Scope{Type: authz.ScopeRegion, ID: uuid.New()})
	if code, o := call(other, "/api/v1/compliance/frameworks/pci_dss_4"); code != 200 || o["repositories_in_scope"].(float64) != 0 || o["failing"].(float64) != 0 {
		t.Errorf("scoped view: %d %v", code, o)
	}
}

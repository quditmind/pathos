//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/releases"
)

func TestReleasesVEXAndComponentPolicies(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	svc := &releases.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	mux := newMux(svc.Register)
	raw := func(p *authz.Principal, method, path string, body any) (int, []byte) {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(b)).WithContext(auth.WithPrincipal(ctx, p))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.Bytes()
	}
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any) {
		code, b := raw(p, method, path, body)
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		return code, out
	}
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	admin.Email = "importer@acme.test"
	reviewer := principalWithRole(t, authz.RoleSuperAdmin)
	reviewer.Email = "reviewer@acme.test"
	outsider := scoped("viewer", authz.Scope{Type: authz.ScopeRepository, ID: uuid.New()})

	tag := uuid.NewString()[:6]
	repo := createRepo(t, "rel-"+tag)
	app := uuid.Must(uuid.NewV7())
	must(relExec(t, `INSERT INTO applications (id, organization_id, name) VALUES ($1, $2, $3)`, app, orgID, "Payments "+tag))
	must(relExec(t, `UPDATE repositories SET application_id = $1 WHERE id = $2`, app, repo))

	// A successful scan with an inventory and three vulnerable components.
	var pv uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT current_version_id FROM scan_profiles WHERE organization_id = $1 AND is_default`, orgID).Scan(&pv)
	job, res := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	must(relExec(t, `INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, ref, commit_sha, status, finished_at)
		VALUES ($1, $2, $3, $4, 'manual', 'main', 'abc123', 'succeeded', now())`, job, orgID, repo, pv))
	must(relExec(t, `INSERT INTO scan_results (id, organization_id, scan_job_id, scanner_key, status) VALUES ($1, $2, $3, 'trivy-fs', 'succeeded')`, res, orgID, job))
	for _, c := range [][3]string{{"lodash", "4.17.20", "MIT"}, {"requests", "2.0.0", "Apache-2.0"}, {"gpl-thing", "1.0.0", "GPL-3.0-only"}} {
		must(relExec(t, `INSERT INTO sbom_components (organization_id, repository_id, scan_job_id, name, version, purl, licenses)
			VALUES ($1, $2, $3, $4, $5, $6, ARRAY[$7])`, orgID, repo, job, c[0], c[1], "pkg:npm/"+c[0]+"@"+c[1], c[2]))
	}
	finding := func(cve, pkg, ver, sev string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		must(relExec(t, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, severity,
			cve, package_name, package_version, fixed_version)
			VALUES ($1, $2, $3, $4, 'sca', '{trivy-fs}', $5, $6, $7, $5, $8, $9, '9.9.9')`, id, orgID, repo, uuid.NewString(), cve, cve+" in "+pkg, sev, pkg, ver))
		must(relExec(t, `INSERT INTO finding_occurrences (id, organization_id, finding_id, scan_result_id, commit_sha) VALUES ($1, $2, $3, $4, 'abc123')`,
			uuid.Must(uuid.NewV7()), orgID, id, res))
		return id
	}
	fLodash := finding("CVE-2021-23337", "lodash", "4.17.20", "high")
	fReq := finding("CVE-2023-32681", "requests", "2.0.0", "medium")

	// Versions: only repos.manage may create; the snapshot freezes the scan.
	base := "/api/v1/applications/" + app.String() + "/versions"
	if code, _ := call(outsider, "POST", base, map[string]any{"version": "2.3.1"}); code != 403 && code != 404 {
		t.Errorf("outsider creates a version: %d", code)
	}
	code, out := call(admin, "POST", base, map[string]any{"version": "2.3.1", "description": "release"})
	if code != 201 {
		t.Fatalf("create version: %d %v", code, out)
	}
	ver := out["version"].(map[string]any)
	vid := ver["id"].(string)
	if ver["component_count"].(float64) != 3 || ver["repository_count"].(float64) != 1 || ver["open_findings"].(float64) != 2 {
		t.Errorf("snapshot counts: %v", ver)
	}
	if code, _ := call(admin, "POST", base, map[string]any{"version": "2.3.1"}); code != 409 {
		t.Errorf("duplicate version: %d", code)
	}
	code, detail := call(admin, "GET", base+"/"+vid, nil)
	if code != 200 || len(detail["findings"].([]any)) != 2 || detail["repositories"].([]any)[0].(map[string]any)["commit_sha"] != "abc123" {
		t.Fatalf("version detail: %d %v", code, detail)
	}
	if code, _ := call(outsider, "GET", base+"/"+vid, nil); code != 404 && code != 403 {
		t.Errorf("outsider reads a version: %d", code)
	}

	// Portfolio: which versions contain lodash, and which carry the CVE.
	code, pf := call(admin, "GET", "/api/v1/portfolio/component-versions?name=lodash&version=4.17.20", nil)
	if code != 200 || len(pf["versions"].([]any)) != 1 || len(pf["repositories"].([]any)) < 1 {
		t.Errorf("portfolio by name: %d %v", code, pf)
	}
	_, pf = call(admin, "GET", "/api/v1/portfolio/component-versions?cve=cve-2023-32681", nil)
	if len(pf["versions"].([]any)) != 1 {
		t.Errorf("portfolio by CVE: %v", pf)
	}

	// Export: OpenVEX and CycloneDX for the version and the repository.
	code, body := raw(admin, "GET", base+"/"+vid+"/vex?format=openvex", nil)
	if code != 200 || !strings.Contains(string(body), "https://openvex.dev/ns/v0.2.0") || !strings.Contains(string(body), "CVE-2021-23337") {
		t.Fatalf("openvex export: %d %s", code, body)
	}
	code, body = raw(admin, "GET", "/api/v1/repositories/"+repo.String()+"/vex?format=cyclonedx", nil)
	if code != 200 || !strings.Contains(string(body), `"specVersion": "1.6"`) || !strings.Contains(string(body), `"exploitable"`) {
		t.Fatalf("cyclonedx export: %d %s", code, body)
	}

	// Import: not_affected for lodash, fixed for requests, affected for an
	// unknown CVE. Nothing changes until another person approves.
	doc := map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://example/vex/1", "author": "Vendor", "timestamp": "2026-11-01T00:00:00Z", "version": 1,
		"statements": []map[string]any{
			{"vulnerability": map[string]any{"name": "CVE-2021-23337"}, "products": []map[string]any{{"@id": "pkg:npm/lodash@4.17.20"}},
				"status": "not_affected", "justification": "vulnerable_code_not_in_execute_path", "impact_statement": "template() is never called"},
			{"vulnerability": map[string]any{"name": "CVE-2023-32681"}, "products": []map[string]any{{"@id": "pkg:npm/requests"}}, "status": "fixed"},
			{"vulnerability": map[string]any{"name": "CVE-1999-0001"}, "status": "affected", "action_statement": "x"},
		},
	}
	code, imp := call(admin, "POST", "/api/v1/repositories/"+repo.String()+"/vex?filename=vendor.json", doc)
	if code != 201 || imp["suggestions"].(float64) != 2 || imp["unmatched"].(float64) != 1 || imp["format"] != "openvex" {
		t.Fatalf("import: %d %v", code, imp)
	}
	var st string
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, fLodash).Scan(&st)
	if st != "open" {
		t.Fatalf("import must not change findings: %s", st)
	}
	_, list := call(admin, "GET", "/api/v1/vex-suggestions?status=pending&import_id="+imp["import_id"].(string), nil)
	items := list["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("suggestions: %v", list)
	}
	ids := map[string]string{}
	for _, it := range items {
		m := it.(map[string]any)
		ids[m["vex_status"].(string)] = m["id"].(string)
		if m["can_decide"] != false || m["cannot_decide_reason"] == "" {
			t.Errorf("the importer cannot decide: %v", m)
		}
	}
	if code, _ := call(admin, "POST", "/api/v1/vex-suggestions/"+ids["not_affected"]+"/approve", map[string]any{}); code != 403 {
		t.Errorf("importer approves own suggestion: %d", code)
	}
	code, dec := call(reviewer, "POST", "/api/v1/vex-suggestions/"+ids["not_affected"]+"/approve", map[string]any{"note": "checked"})
	if code != 200 || dec["status"] != "approved" {
		t.Fatalf("approve: %d %v", code, dec)
	}
	var reason string
	_ = appPool.QueryRow(ctx, `SELECT f.status, h.reason FROM findings f JOIN finding_status_history h ON h.finding_id = f.id AND h.to_status = 'false_positive'
		WHERE f.id = $1`, fLodash).Scan(&st, &reason)
	if st != "false_positive" || !strings.Contains(reason, "VEX not_affected") {
		t.Errorf("approved not_affected: %s %q", st, reason)
	}
	if code, _ := call(reviewer, "POST", "/api/v1/vex-suggestions/"+ids["not_affected"]+"/reject", nil); code != 409 {
		t.Errorf("decided twice: %d", code)
	}
	// "fixed" is informational: only a scan resolves a finding.
	if code, dec := call(reviewer, "POST", "/api/v1/vex-suggestions/"+ids["fixed"]+"/approve", nil); code != 200 {
		t.Fatalf("approve fixed: %d %v", code, dec)
	}
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, fReq).Scan(&st)
	if st != "open" {
		t.Errorf("an approved fixed statement must not mark the finding fixed: %s", st)
	}
	var audits int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('vex.import', 'vex_suggestion.approve') AND created_at > now() - interval '1 hour'`).Scan(&audits)
	if audits < 3 {
		t.Errorf("audit entries: %d", audits)
	}
	// The version export now reflects the decision.
	_, body = raw(admin, "GET", base+"/"+vid+"/vex?format=openvex", nil)
	if !strings.Contains(string(body), `"not_affected"`) {
		t.Errorf("version export after approval: %s", body)
	}

	// Component policies: a licence policy flags the GPL component; a
	// severity policy flags requests (medium) but not lodash (now closed).
	if code, _ := call(outsider, "POST", "/api/v1/component-policies", map[string]any{}); code != 403 {
		t.Errorf("outsider creates a policy: %d", code)
	}
	code, pol := call(admin, "POST", "/api/v1/component-policies", map[string]any{"name": "No GPL " + tag, "condition_kind": "license",
		"params": map[string]any{"licenses": []string{"GPL-3.0-only"}}, "violation_state": "fail"})
	if code != 201 || pol["open_violations"].(float64) < 1 {
		t.Fatalf("create licence policy: %d %v", code, pol)
	}
	_, vl := call(admin, "GET", "/api/v1/component-policy-violations?policy_id="+pol["id"].(string)+"&repository_id="+repo.String(), nil)
	if v := vl["items"].([]any); len(v) != 1 || v[0].(map[string]any)["component"] != "gpl-thing" {
		t.Errorf("licence violations: %v", vl)
	}
	code, sp := call(admin, "POST", "/api/v1/component-policies", map[string]any{"name": "Vulnerable " + tag, "condition_kind": "vulnerability_severity",
		"params": map[string]any{"min_severity": "medium"}})
	if code != 201 {
		t.Fatalf("severity policy: %d %v", code, sp)
	}
	_, vl = call(admin, "GET", "/api/v1/component-policy-violations?policy_id="+sp["id"].(string)+"&repository_id="+repo.String(), nil)
	if v := vl["items"].([]any); len(v) != 1 || v[0].(map[string]any)["component"] != "requests" {
		t.Errorf("severity violations: %v", vl)
	}
	// Removing the component resolves its violation on re-evaluation.
	must(relExec(t, `DELETE FROM sbom_components WHERE repository_id = $1 AND name = 'gpl-thing'`, repo))
	if code, _ := call(admin, "POST", "/api/v1/component-policies/evaluate", nil); code != 200 {
		t.Fatalf("evaluate: %d", code)
	}
	_, vl = call(admin, "GET", "/api/v1/component-policy-violations?state=resolved&policy_id="+pol["id"].(string), nil)
	if len(vl["items"].([]any)) != 1 {
		t.Errorf("resolved violations: %v", vl)
	}

	// Deleting a version.
	if code, _ := call(admin, "DELETE", base+"/"+vid, nil); code != 204 {
		t.Errorf("delete version: %d", code)
	}
}

func relExec(t *testing.T, sql string, args ...any) error {
	t.Helper()
	_, err := appPool.Exec(t.Context(), sql, args...)
	return err
}

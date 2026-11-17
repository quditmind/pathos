//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/intel"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/posture"
	"pathos/internal/risk"
	"pathos/internal/scans"
	"pathos/internal/vuln"
)

func TestVulnIntelligencePhase4(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	scanSvc := &scans.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom, BootstrapToken: bootstrap, OrgID: orgID}
	vulnSvc := &vuln.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	postureSvc := &posture.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	h := &scanHarness{t: t, api: newMux(func(m *http.ServeMux) { scanSvc.Register(m); vulnSvc.Register(m); postureSvc.Register(m) }),
		internal: scanSvc.InternalHandler()}
	admin := reviewUser(t, "platform_admin")
	analyst := reviewUser(t, "security_analyst")
	manager := reviewUser(t, "security_manager") // accepts risk
	suffix := uuid.NewString()[:6]
	repo := createRepo(t, "p4-"+suffix)
	if _, err := appPool.Exec(ctx, `UPDATE repositories SET public_exposure = 'yes', production_url = 'https://shop.example.test' WHERE id = $1`, repo); err != nil {
		t.Fatal(err)
	}

	// --- a scan with an SBOM (demo -> lodash, minimist) -------------------------
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	jobID := q["job_id"].(string)
	raw, _ := os.ReadFile("../../internal/scanners/testdata/syft.cdx.json")
	if err := db.InTx(ctx, appPool, func(tx pgx.Tx) error {
		_, err := vuln.StoreSBOM(ctx, tx, orgID, repo, uuid.MustParse(jobID), raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cve := fmt.Sprintf("CVE-2098-%d", 10000+time.Now().UnixNano()%90000000)
	lodash := insertRiskFinding(t, repo, "sca", "high", 70, false, "lodash", "4.17.20", cve)
	minimist := insertRiskFinding(t, repo, "sca", "high", 70, false, "minimist", "1.2.5", "")
	sast1 := insertLocatedFinding(t, repo, "opengrep", "app.js", 10, "CWE-89")
	sast2 := insertLocatedFinding(t, repo, "import-sast-semgrep-pro", "app.js", 12, "CWE-89")
	insertLocatedFinding(t, repo, "import-sast-semgrep-pro", "other.js", 12, "CWE-89")

	// --- OSV record imported offline: vendor CVSS and an exploit reference -----
	osv := fmt.Sprintf(`{"id":"GHSA-%s-xxxx-xxxx","aliases":["%s"],"summary":"Prototype pollution","details":"Long description",
	  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	  "references":[{"type":"EVIDENCE","url":"https://exploit.example/poc"},{"type":"ADVISORY","url":"https://advisory.example"}],
	  "database_specific":{"cwe_ids":["CWE-1321"]}}`, "c"+suffix[:3], cve)
	run, err := intel.Load(ctx, appPool, intel.OSV, "file", nil, []byte(osv))
	if err != nil || run.Records != 1 {
		t.Fatalf("OSV import: %v %+v", err, run)
	}
	var vector string
	var cvss *float64
	_ = appPool.QueryRow(ctx, `SELECT cvss_vector, cvss::float8 FROM findings WHERE id = $1`, lodash).Scan(&vector, &cvss)
	if vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" || cvss != nil && *cvss != 9.8 {
		t.Errorf("vendor CVSS filled: %q %v", vector, cvss)
	}
	if _, err := risk.Recompute(ctx, appPool, orgID, 10000); err != nil {
		t.Fatal(err)
	}
	var exploit bool
	_ = appPool.QueryRow(ctx, `SELECT exploit_available FROM findings WHERE id = $1`, lodash).Scan(&exploit)
	if !exploit {
		t.Error("an EVIDENCE reference counts as an exploit")
	}
	v, err := intel.LookupVuln(ctx, appPool, cve)
	if err != nil || v == nil || v.ExploitRefs != 1 || len(v.CWEs) != 1 {
		t.Errorf("lookup by alias: %v %+v", err, v)
	}

	// --- reachability from the worker's code inventory -----------------------
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "p4-" + suffix, "family": "core"})
	token := reg["token"].(string)
	leased := false
	for i := 0; i < 30 && !leased; i++ {
		code, j := h.worker(token, "POST", "/internal/worker/v1/lease", map[string]any{})
		if code != 200 {
			break
		}
		if j["job_id"] == jobID {
			leased = true
			break
		}
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+j["job_id"].(string)+"/complete", map[string]any{"status": "failed", "error": "test drain"})
	}
	if !leased {
		t.Fatal("job not leased")
	}
	code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/imports", map[string]any{"version": 1, "files_scanned": 3,
		"imports": map[string][]string{"npm": {"lodash"}}, "strings": map[string][]string{"npm": {}}})
	if code != 200 || out["findings_updated"].(float64) < 2 {
		t.Fatalf("imports: %d %v", code, out)
	}
	reach := func(id uuid.UUID) (string, string) {
		var r, b string
		_ = appPool.QueryRow(ctx, `SELECT reachability, reachability_basis FROM findings WHERE id = $1`, id).Scan(&r, &b)
		return r, b
	}
	if r, b := reach(lodash); r != "reachable" || b == "" {
		t.Errorf("lodash is imported: %s %q", r, b)
	}
	if r, b := reach(minimist); r != "not_reachable" || b == "" {
		t.Errorf("minimist is not used: %s %q", r, b)
	}
	if code, _ := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/imports", map[string]any{"version": 2}); code != 400 {
		t.Errorf("unknown inventory version: %d", code)
	}

	// --- attack paths ------------------------------------------------------------
	if _, err := risk.Recompute(ctx, appPool, orgID, 10000); err != nil {
		t.Fatal(err)
	}
	_, ap := h.user(admin, "GET", "/api/v1/posture/attack-paths?min_risk=0&limit=500", nil)
	paths := map[string]map[string]any{}
	for _, it := range ap["items"].([]any) {
		m := it.(map[string]any)
		paths[m["finding_id"].(string)] = m
	}
	lp := paths[lodash.String()]
	if lp == nil || lp["entry"] != "exposed_repository" || len(lp["steps"].([]any)) != 4 {
		t.Fatalf("reachable dependency of an exposed repository is an attack path: %v", lp)
	}
	if lp["exploit_available"] != true {
		t.Errorf("exploit flag on the path: %v", lp)
	}
	if paths[minimist.String()] != nil {
		t.Error("an unreachable dependency is not an attack path")
	}
	if paths[sast1.String()] == nil {
		t.Error("a code finding in an exposed repository is an attack path")
	}

	// --- correlation -----------------------------------------------------------------
	_, rel := h.user(admin, "GET", "/api/v1/findings/"+sast1.String()+"/related", nil)
	items := rel["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["id"] != sast2.String() || items[0].(map[string]any)["relation"] != "same_location" {
		t.Errorf("same location from another tool: %v", rel)
	}

	// --- suppression rules (four eyes) -----------------------------------------------
	rule := map[string]any{"name": "Generated code " + suffix, "scope_type": "repository", "scope_id": repo, "match_path": "app.js",
		"match_category": "sast", "decision": "false_positive", "justification": "app.js is generated from a schema and never deployed",
		"expires_at": time.Now().AddDate(0, 3, 0).Format(time.RFC3339)}
	if code, _ := h.user(analyst, "POST", "/api/v1/suppression-rules", map[string]any{"name": "too broad", "scope_type": "organization",
		"match_category": "sast", "decision": "accepted_risk", "justification": strings20, "expires_at": time.Now().AddDate(0, 1, 0)}); code != 400 {
		t.Errorf("a category alone is too broad: %d", code)
	}
	if code, _ := h.user(analyst, "POST", "/api/v1/suppression-rules", map[string]any{"name": "x", "scope_type": "repository", "scope_id": repo,
		"match_path": "*", "decision": "accepted_risk", "justification": strings20, "expires_at": time.Now().AddDate(0, 1, 0)}); code != 400 {
		t.Errorf("a pattern that matches everything: %d", code)
	}
	if code, _ := h.user(analyst, "POST", "/api/v1/suppression-rules", map[string]any{"name": "x", "scope_type": "repository", "scope_id": repo,
		"match_path": "app.js", "decision": "accepted_risk", "justification": strings20, "expires_at": time.Now().AddDate(2, 0, 0)}); code != 400 {
		t.Errorf("expiry beyond a year: %d", code)
	}
	_, pv := h.user(analyst, "POST", "/api/v1/suppression-rules/preview", rule)
	if pv["matching_open_findings"].(float64) != 2 {
		t.Errorf("preview: %v", pv)
	}
	code, created := h.user(analyst, "POST", "/api/v1/suppression-rules", rule)
	if code != 201 || created["status"] != "pending" {
		t.Fatalf("propose: %d %v", code, created)
	}
	ruleID := created["id"].(string)
	var st string
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, sast1).Scan(&st)
	if st != "open" {
		t.Error("a pending rule changes nothing")
	}
	if code, _ := h.user(analyst, "POST", "/api/v1/suppression-rules/"+ruleID+"/approve", nil); code != 403 && code != 409 {
		t.Errorf("the proposer cannot approve: %d", code)
	}
	code, dec := h.user(manager, "POST", "/api/v1/suppression-rules/"+ruleID+"/approve", map[string]any{"note": "agreed"})
	if code != 200 || dec["findings_changed"].(float64) != 2 {
		t.Fatalf("approve: %d %v", code, dec)
	}
	var source, reason string
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, sast1).Scan(&st)
	_ = appPool.QueryRow(ctx, `SELECT source, reason FROM finding_status_history WHERE finding_id = $1 ORDER BY created_at DESC LIMIT 1`, sast1).Scan(&source, &reason)
	if st != "false_positive" || source != "suppression_rule" || reason == "" {
		t.Errorf("decided through the lifecycle with history: %s %s %q", st, source, reason)
	}
	// A finding detected later matching the rule gets the decision when its
	// scan finishes.
	late := insertLocatedFinding(t, repo, "opengrep", "app.js", 40, "CWE-79")
	if err := db.InTx(ctx, appPool, func(tx pgx.Tx) error {
		_, err := vuln.ApplyActiveRules(ctx, tx, orgID, repo)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, late).Scan(&st)
	if st != "false_positive" {
		t.Errorf("later finding: %s", st)
	}
	// Revocation reopens everything the rule decided.
	code, rv := h.user(manager, "POST", "/api/v1/suppression-rules/"+ruleID+"/revoke", map[string]any{"note": "schema changed"})
	if code != 200 || rv["findings_changed"].(float64) != 3 {
		t.Fatalf("revoke: %d %v", code, rv)
	}
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, sast1).Scan(&st)
	if st != "open" {
		t.Errorf("reopened: %s", st)
	}
	// Expiry: an approved accepted-risk rule past its date reopens findings.
	rule2 := map[string]any{"name": "CVE accepted " + suffix, "scope_type": "repository", "scope_id": repo, "match_cve": cve,
		"decision": "accepted_risk", "justification": "compensating WAF rule blocks the payload", "expires_at": time.Now().AddDate(0, 0, 7)}
	_, c2 := h.user(analyst, "POST", "/api/v1/suppression-rules", rule2)
	r2 := c2["id"].(string)
	h.user(manager, "POST", "/api/v1/suppression-rules/"+r2+"/approve", nil)
	var until *time.Time
	_ = appPool.QueryRow(ctx, `SELECT status, accepted_until FROM findings WHERE id = $1`, lodash).Scan(&st, &until)
	if st != "accepted_risk" || until == nil {
		t.Errorf("accepted risk with its expiry: %s %v", st, until)
	}
	if _, err := appPool.Exec(ctx, `UPDATE suppression_rules SET expires_at = now() - interval '1 minute' WHERE id = $1`, r2); err != nil {
		t.Fatal(err)
	}
	if n, err := vuln.ExpireSuppressionRules(ctx, appPool); err != nil || n < 1 {
		t.Fatalf("expire: %v %d", err, n)
	}
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, lodash).Scan(&st)
	if st != "open" {
		t.Errorf("reopened at expiry: %s", st)
	}
	_, list := h.user(analyst, "GET", "/api/v1/suppression-rules", nil)
	if len(list["items"].([]any)) < 2 {
		t.Errorf("rules listed: %v", list)
	}
}

const strings20 = "a justification of more than twenty characters"

func insertLocatedFinding(t *testing.T, repo uuid.UUID, scanner, path string, line int, cwe string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(t.Context(), `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id,
		title, description, severity, file_path, start_line, cwe, risk_score, risk_dirty)
		VALUES ($1, $2, $3, $4, 'sast', ARRAY[$5], 'sqli', 'SQL injection', '', 'high', $6, $7, ARRAY[$8], 60, false)`,
		id, orgID, repo, uuid.NewString(), scanner, path, line, cwe); err != nil {
		t.Fatal(err)
	}
	return id
}

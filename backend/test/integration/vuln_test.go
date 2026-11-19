//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/vuln"
)

func TestVulnerabilityManagement(t *testing.T) {
	ctx := t.Context()
	svc := &vuln.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log, Principal: auth.PrincipalFrom}
	mux := http.NewServeMux()
	svc.Register(mux)
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	mkUser := func(role string) *authz.Principal {
		var uid uuid.UUID
		email := role + "-" + uuid.NewString()[:6] + "@vm.test"
		_ = appPool.QueryRow(ctx, `INSERT INTO users (id, organization_id, email, status) VALUES (gen_random_uuid(), $1, $2, 'active') RETURNING id`, orgID, email).Scan(&uid)
		p := principalWithRole(t, role)
		p.UserID, p.Email = uid, email
		return p
	}
	analyst, manager := mkUser("security_analyst"), mkUser("security_manager")
	repo := createRepo(t, "vm-"+uuid.NewString()[:6])
	statusOf := func(id uuid.UUID) (st string, rec int, until *time.Time) {
		_ = appPool.QueryRow(ctx, `SELECT status, recurrence_count, accepted_until FROM findings WHERE id = $1`, id).Scan(&st, &rec, &until)
		return
	}

	// SLA deadline set on insert from policy (critical = 7 days).
	f := insertFinding(t, repo, "critical", "")
	var due, first time.Time
	_ = appPool.QueryRow(ctx, `SELECT sla_due_at, first_seen_at FROM findings WHERE id = $1`, f).Scan(&due, &first)
	if d := due.Sub(first); d != 7*24*time.Hour {
		t.Errorf("critical SLA should be 7 days, got %v", d)
	}

	// Transitions and their rules.
	if code, _ := call(analyst, "POST", "/api/v1/findings/"+f.String()+"/status", map[string]any{"status": "accepted_risk"}); code != 409 {
		t.Errorf("accepted_risk only via workflow: %d", code)
	}
	if code, _ := call(analyst, "POST", "/api/v1/findings/"+f.String()+"/status", map[string]any{"status": "in_progress"}); code != 204 {
		t.Fatalf("open -> in_progress: %d", code)
	}
	if code, _ := call(analyst, "POST", "/api/v1/findings/"+f.String()+"/status", map[string]any{"status": "false_positive"}); code != 400 {
		t.Errorf("false positive needs a reason: %d", code)
	}
	if code, _ := call(analyst, "POST", "/api/v1/findings/"+f.String()+"/status", map[string]any{"status": "false_positive", "reason": "test fixture only"}); code != 403 {
		t.Errorf("critical FP needs accept_risk: %d", code)
	}
	if code, _ := call(principalWithRole(t, "viewer"), "POST", "/api/v1/findings/"+f.String()+"/status", map[string]any{"status": "open"}); code != 403 {
		t.Errorf("viewer cannot triage: %d", code)
	}

	// Assignment.
	if code, _ := call(analyst, "POST", "/api/v1/findings/"+f.String()+"/assign", map[string]any{"assignee_id": analyst.UserID}); code != 204 {
		t.Errorf("assign: %d", code)
	}
	if code, _ := call(analyst, "POST", "/api/v1/findings/"+f.String()+"/assign", map[string]any{"assignee_id": uuid.New()}); code != 400 {
		t.Errorf("unknown assignee: %d", code)
	}

	// Bulk is atomic: one invalid transition rolls back all.
	g1, g2 := insertFinding(t, repo, "medium", ""), insertFinding(t, repo, "medium", "")
	_, _ = appPool.Exec(ctx, `UPDATE findings SET status = 'fixed' WHERE id = $1`, g2)
	if code, _ := call(analyst, "POST", "/api/v1/findings/bulk", map[string]any{"finding_ids": []uuid.UUID{g1, g2}, "action": "status", "status": "in_progress"}); code != 409 {
		t.Errorf("bulk with invalid transition: %d", code)
	}
	if st, _, _ := statusOf(g1); st != "open" {
		t.Errorf("bulk must roll back, g1=%s", st)
	}

	// Recurrence: a fixed finding detected again reopens and counts.
	err := db.InTx(ctx, appPool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE findings SET status = 'open' WHERE id = $1`, g2)
		return err
	})
	if st, rec, _ := statusOf(g2); err != nil || st != "open" || rec != 1 {
		t.Errorf("recurrence: %s %d %v", st, rec, err)
	}

	// Risk acceptance: request, four-eyes approval, expiry.
	exp := time.Now().Add(30 * 24 * time.Hour)
	code, ra := call(analyst, "POST", "/api/v1/findings/"+g1.String()+"/risk-acceptance", map[string]any{"justification": "Compensating WAF rule in place", "expires_at": exp})
	if code != 201 {
		t.Fatalf("request acceptance: %d %v", code, ra)
	}
	if code, _ := call(analyst, "POST", "/api/v1/findings/"+g1.String()+"/risk-acceptance", map[string]any{"justification": "again and again", "expires_at": exp}); code != 409 {
		t.Errorf("duplicate request: %d", code)
	}
	if code, _ := call(analyst, "POST", "/api/v1/risk-acceptances/"+ra["id"].(string)+"/approve", nil); code != 403 {
		t.Errorf("analyst lacks accept_risk: %d", code)
	}
	requesterMgr := mkUser("security_manager")
	_, ra2 := call(requesterMgr, "POST", "/api/v1/findings/"+f.String()+"/risk-acceptance", map[string]any{"justification": "Accepted until refactor lands", "expires_at": exp})
	if code, _ := call(requesterMgr, "POST", "/api/v1/risk-acceptances/"+ra2["id"].(string)+"/approve", nil); code != 409 {
		t.Errorf("requester cannot approve own acceptance: %d", code)
	}
	if code, _ := call(manager, "POST", "/api/v1/risk-acceptances/"+ra["id"].(string)+"/approve", map[string]any{"note": "ok for 30 days"}); code != 204 {
		t.Fatalf("approve: %d", code)
	}
	if st, _, until := statusOf(g1); st != "accepted_risk" || until == nil {
		t.Fatalf("accepted: %s %v", st, until)
	}
	_, _ = ownerPool.Exec(ctx, `UPDATE risk_acceptances SET expires_at = now() - interval '1 minute' WHERE id = $1`, ra["id"])
	if n, err := vuln.ExpireAcceptances(ctx, appPool); err != nil || n < 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	if st, _, until := statusOf(g1); st != "open" || until != nil {
		t.Errorf("expired acceptance must reopen: %s %v", st, until)
	}

	// History: every change, with actor and source; append-only.
	_, h := call(analyst, "GET", "/api/v1/findings/"+g1.String()+"/history", nil)
	items := h["items"].([]any)
	last := items[len(items)-1].(map[string]any)
	if last["to_status"] != "open" || last["source"] != "expiry" {
		t.Errorf("history should end with the expiry reopen: %v", last)
	}
	var sources []string
	for _, it := range items {
		sources = append(sources, it.(map[string]any)["source"].(string))
	}
	_, hf := call(analyst, "GET", "/api/v1/findings/"+f.String()+"/history", nil)
	fi := hf["items"].([]any)
	if e := fi[len(fi)-1].(map[string]any); e["actor"] == nil || e["source"] != "user" || e["to_status"] != "in_progress" {
		t.Errorf("manual change must be attributed: %v", e)
	}
	if _, err := appPool.Exec(ctx, `UPDATE finding_status_history SET reason = 'x'`); err == nil {
		t.Error("history must be append-only for the app role")
	}

	// SLA policy changes recompute deadlines.
	if code, _ := call(principalWithRole(t, authz.RoleSuperAdmin), "PUT", "/api/v1/sla-policies", map[string]any{"critical": 3}); code != 204 {
		t.Fatalf("put SLA: %d", code)
	}
	_ = appPool.QueryRow(ctx, `SELECT sla_due_at FROM findings WHERE id = $1`, f).Scan(&due)
	if d := due.Sub(first); d != 3*24*time.Hour {
		t.Errorf("SLA recompute: %v", d)
	}
	call(principalWithRole(t, authz.RoleSuperAdmin), "PUT", "/api/v1/sla-policies", map[string]any{"critical": 7})

	// SBOM inventory from the real Syft fixture, plus license policy.
	raw, err := os.ReadFile("../../internal/scanners/testdata/syft.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	var job uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT id FROM scan_jobs LIMIT 1`).Scan(&job)
	if job == uuid.Nil {
		job = uuid.New()
	}
	err = db.InTx(ctx, appPool, func(tx pgx.Tx) error {
		n, err := vuln.StoreSBOM(ctx, tx, orgID, repo, job, raw)
		if err == nil && n < 2 {
			t.Errorf("expected components, got %d", n)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = appPool.Exec(ctx, `INSERT INTO sbom_components (organization_id, repository_id, scan_job_id, name, version, licenses)
		VALUES ($1, $2, $3, 'copyleft-lib', '1.0.0', '{AGPL-3.0-only}')`, orgID, repo, job)
	_, comps := call(analyst, "GET", "/api/v1/sbom/components?q=lodash&repository_id="+repo.String(), nil)
	if items := comps["items"].([]any); len(items) != 1 || items[0].(map[string]any)["version"] != "4.17.20" {
		t.Errorf("component search: %v", comps)
	}
	_, viol := call(analyst, "GET", "/api/v1/sbom/components?license=deny&repository_id="+repo.String(), nil)
	if items := viol["items"].([]any); len(items) != 1 || items[0].(map[string]any)["name"] != "copyleft-lib" {
		t.Errorf("license violations: %v", viol)
	}
	// Licences are merged across every row of a component (whatever the
	// licence filter), and open SCA findings of the package are counted.
	_, _ = appPool.Exec(ctx, `INSERT INTO sbom_components (organization_id, repository_id, scan_job_id, name, version, licenses)
		VALUES ($1, $2, $3, 'copyleft-lib', '1.0.0', '{MIT}')`, orgID, repo, job)
	_, _ = appPool.Exec(ctx, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, severity,
		package_name, package_version) VALUES ($1, $2, $3, $4, 'sca', '{osv-scanner}', 'GHSA-x', 'vulnerable copyleft-lib', 'high', 'copyleft-lib', '1.0.0')`,
		uuid.New(), orgID, repo, uuid.NewString())
	_, viol = call(analyst, "GET", "/api/v1/sbom/components?license=deny&repository_id="+repo.String(), nil)
	if items := viol["items"].([]any); len(items) != 1 || fmt.Sprint(items[0].(map[string]any)["licenses"]) != "[AGPL-3.0-only MIT]" ||
		items[0].(map[string]any)["open_vulnerabilities"] != float64(1) {
		t.Errorf("component licences and open vulnerabilities: %v", viol)
	}
}

//go:build integration

package integration

// PATHOS 3.0 M8: security gates at every stage, rule 7 ("no gate blocks
// without a policy"), exceptions and approvals, and decision C6 (pull
// request checks need an explicit block or warn; existing repositories
// migrated to an explicit policy with their behaviour).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"pathos/internal/authz"
	"pathos/internal/gates"
	"pathos/internal/identity"
	"pathos/internal/platform/db"
	"pathos/internal/policy"
	"pathos/internal/remediation"
	"pathos/internal/scans"
	"pathos/migrations"
)

// m8Harness is the scan harness with the gates, policies and remediation
// APIs mounted, and the remediation worker routes on the worker API.
type m8Harness struct {
	*scanHarness
	rem *remediation.Service
}

func newM8Harness(t *testing.T) *m8Harness {
	t.Helper()
	h := newScanHarness(t)
	rem := &remediation.Service{DB: appPool, Authz: h.svc.Authz, Log: log, Principal: h.svc.Principal,
		ScannerConfig: h.svc.ScannerConfigFor, CloneCredential: h.svc.CloneCredential}
	h.svc.WorkerRoutes = []func(*http.ServeMux){rem.RegisterWorker}
	h.internal = h.svc.InternalHandler()
	rem.Register(h.api)
	(&gates.Service{DB: appPool, Authz: h.svc.Authz, Log: log, Principal: h.svc.Principal}).Register(h.api)
	(&policy.Service{DB: appPool, Authz: h.svc.Authz, Log: log, Principal: h.svc.Principal}).Register(h.api)
	return &m8Harness{scanHarness: h, rem: rem}
}

// realPrincipal creates an active user with a system role at organization
// scope (decisions, exceptions and owners reference real users).
func realPrincipal(t *testing.T, role string) *authz.Principal {
	t.Helper()
	u, err := identity.CreateUser(t.Context(), appPool, identity.User{OrganizationID: orgID,
		Email: role + "-" + uuid.NewString()[:8] + "@m8.test", Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	p := principalWithRole(t, role)
	p.UserID, p.Email = u.ID, u.Email
	return p
}

// seedFinding inserts an open finding of a repository.
func seedFinding(t *testing.T, repo uuid.UUID, severity, category, rule, file string, scanners []string, job *uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(t.Context(), `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title,
		description, severity, file_path, start_line, first_scan_job_id, last_scan_job_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'Use parameterised queries.', $9, $10, 10, $11, $11)`,
		id, orgID, repo, uuid.NewString(), category, scanners, rule, rule+" in "+file, severity, file, job); err != nil {
		t.Fatal(err)
	}
	return id
}

func seedPolicy(t *testing.T, name string, cond policy.Conditions, act policy.Actions) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	c, _ := json.Marshal(cond)
	a, _ := json.Marshal(act)
	if _, err := appPool.Exec(t.Context(), `INSERT INTO security_policies (id, organization_id, name, conditions, actions) VALUES ($1, $2, $3, $4, $5)`,
		id, orgID, name+"-"+uuid.NewString()[:6], c, a); err != nil {
		t.Fatal(err)
	}
	return id
}

func reasonCodes(d map[string]any) []string {
	var out []string
	for _, r := range d["reasons"].([]any) {
		out = append(out, r.(map[string]any)["code"].(string))
	}
	return out
}

func TestM8GatesEveryStage(t *testing.T) {
	ctx := t.Context()
	h := newM8Harness(t)
	admin := realPrincipal(t, authz.RoleSuperAdmin)
	approver := realPrincipal(t, "security_manager")
	dev := realPrincipal(t, "developer")
	viewer := realPrincipal(t, "viewer")
	repo := createRepo(t, "gates-"+uuid.NewString()[:6])
	seedFinding(t, repo, "critical", "sast", "sqli", "app/db.go", []string{"opengrep"}, nil)
	seedFinding(t, repo, "low", "sast", "weak-hash", "app/hash.go", []string{"opengrep"}, nil)
	sha := strings.Repeat("ab", 20)

	// Behind the flag: absent while off.
	setFlag(t, "remediation_workspace", false)
	if code, out := h.user(admin, "POST", "/api/v1/gates/evaluate", map[string]any{"stage": "deploy", "repository_id": repo}); code != 404 || errCode(out) != "PTH-PLAT-1007" {
		t.Fatalf("flag off: %d %v", code, out)
	}
	setFlag(t, "remediation_workspace", true)

	evaluate := func(p *authz.Principal, stage string, extra map[string]any) map[string]any {
		t.Helper()
		body := map[string]any{"stage": stage, "repository_id": repo, "commit_sha": sha}
		for k, v := range extra {
			body[k] = v
		}
		code, d := h.user(p, "POST", "/api/v1/gates/evaluate", body)
		if code != 200 {
			t.Fatalf("evaluate %s: %d %v", stage, code, d)
		}
		return d
	}
	// No gate at any stage: pass, recorded as "no policy".
	for _, st := range []string{"ide", "pre-commit", "ci", "release", "deploy"} {
		d := evaluate(dev, st, nil)
		if d["outcome"] != "pass" || len(d["policy_ids"].([]any)) != 0 || !slices.Contains(reasonCodes(d), "no_policy") {
			t.Errorf("%s without gates: %v", st, d)
		}
	}

	// A policy matching the critical finding, and a gate per stage.
	// Scoped to this repository so other tests' findings are not affected.
	pol := seedPolicy(t, "m8-critical", policy.Conditions{MinSeverity: "critical", RepositoryIDs: []string{repo.String()}}, policy.Actions{Notify: true})
	never := seedPolicy(t, "m8-never", policy.Conditions{CWE: []string{"CWE-9999"}, RepositoryIDs: []string{repo.String()}}, policy.Actions{Notify: true})
	gate := func(stage, mode string, policyID uuid.UUID, allow bool) string {
		t.Helper()
		code, g := h.user(admin, "POST", "/api/v1/gates", map[string]any{"name": "m8 " + stage + " " + mode + " " + uuid.NewString()[:4], "stage": stage,
			"policy_id": policyID, "mode": mode, "allow_exceptions": allow, "repository_id": repo})
		if code != 201 {
			t.Fatalf("create gate %s: %d %v", stage, code, g)
		}
		return g["id"].(string)
	}
	// Rule 7 at the API: a gate needs an existing policy.
	if code, out := h.user(admin, "POST", "/api/v1/gates", map[string]any{"name": "no policy", "stage": "ci", "mode": "block"}); code != 422 || errCode(out) != "PTH-GATE-1101" {
		t.Errorf("gate without policy: %d %v", code, out)
	}
	if code, _ := h.user(viewer, "POST", "/api/v1/gates", map[string]any{"name": "x", "stage": "ci", "mode": "block", "policy_id": pol}); code != 403 {
		t.Errorf("viewer creates gate: %d", code)
	}
	gate("ide", "warn", pol, true)
	gate("pre_commit", "block", pol, true)
	gate("ci", "warn", pol, true)
	gate("ci", "block", never, true) // matches nothing
	releaseGate := gate("release", "require_approval", pol, true)
	deployGate := gate("deploy", "block", pol, true)

	want := map[string]string{"ide": "warn", "pre-commit": "block", "ci": "warn", "release": "approval_required", "deploy": "block"}
	decisions := map[string]map[string]any{}
	for st, outcome := range want {
		d := evaluate(dev, st, nil)
		decisions[st] = d
		if d["outcome"] != outcome {
			t.Errorf("%s: outcome %v, want %s (%v)", st, d["outcome"], outcome, d["reasons"])
		}
		if ids := d["policy_ids"].([]any); len(ids) != 1 || ids[0] != pol.String() {
			t.Errorf("%s: policy ids %v", st, ids)
		}
		ev := d["evidence"].(map[string]any)
		if ev["scope"] != "open" || ev["by_severity"].(map[string]any)["critical"].(float64) != 1 || len(ev["finding_ids"].([]any)) != 1 {
			t.Errorf("%s: evidence %v", st, ev)
		}
	}
	if !slices.Contains(reasonCodes(decisions["ci"]), "policy_not_matched") {
		t.Errorf("ci: the non-matching block gate is reported: %v", decisions["ci"]["reasons"])
	}

	// Pull request stage: the latest finished check of the pull request.
	res, err := scans.EnqueueWith(ctx, appPool, orgID, repo, "pull_request", "feature/m8", sha, nil, scans.EnqueueOpts{PullRequest: 41})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE scan_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1`, res.JobID); err != nil {
		t.Fatal(err)
	}
	check := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO pr_checks (id, organization_id, repository_id, scan_job_id, pull_request, head_ref, head_sha, gate_severity, status, finished_at)
		VALUES ($1, $2, $3, $4, 41, 'feature/m8', $5, 'none', 'passed', now())`, check, orgID, repo, res.JobID, sha); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO pr_findings (id, pr_check_id, fingerprint, scanner_key, category, rule_id, title, severity, is_new)
		VALUES ($1, $2, 'fp-new', 'opengrep', 'sast', 'sqli', 'new sqli', 'critical', true)`, uuid.Must(uuid.NewV7()), check); err != nil {
		t.Fatal(err)
	}
	d := evaluate(dev, "pull-request", map[string]any{"pull_request": 41})
	if d["outcome"] != "pass" || d["evidence"].(map[string]any)["scope"] != "new" {
		t.Errorf("pull request without pull_request gates: %v", d)
	}
	gate("pull_request", "block", pol, true)
	d = evaluate(dev, "pull_request", map[string]any{"pull_request": 41})
	if d["outcome"] != "block" || d["scan_job_id"] != res.JobID.String() {
		t.Errorf("pull request gate: %v", d)
	}
	if code, out := h.user(dev, "POST", "/api/v1/gates/evaluate", map[string]any{"stage": "pull_request", "repository_id": repo, "pull_request": 999}); code != 409 || errCode(out) != "PTH-GATE-1107" {
		t.Errorf("no finished check: %d %v", code, out)
	}
	// CI with a scan: findings first reported by it.
	if code, out := h.user(dev, "POST", "/api/v1/gates/evaluate", map[string]any{"stage": "ci", "repository_id": repo, "scan_id": res.JobID}); code != 200 ||
		out["evidence"].(map[string]any)["scope"] != "new" || out["outcome"] != "pass" {
		t.Errorf("ci with scan: %d %v", code, out)
	}

	// Disabled policy: its gates are skipped (no block without an enforcing policy).
	if _, err := appPool.Exec(ctx, `UPDATE security_policies SET enabled = false WHERE id = $1`, pol); err != nil {
		t.Fatal(err)
	}
	d = evaluate(dev, "deploy", nil)
	if d["outcome"] != "pass" || !slices.Contains(reasonCodes(d), "policy_disabled") {
		t.Errorf("disabled policy: %v", d)
	}
	if _, err := appPool.Exec(ctx, `UPDATE security_policies SET enabled = true WHERE id = $1`, pol); err != nil {
		t.Fatal(err)
	}
	// A policy used by a gate cannot be deleted.
	if code, out := h.user(admin, "DELETE", "/api/v1/security-policies/"+pol.String(), nil); code != 409 || errCode(out) != "PTH-GATE-1108" {
		t.Errorf("delete policy in use: %d %v", code, out)
	}

	// Decisions log: filters and visibility.
	code, list := h.user(viewer, "GET", "/api/v1/gates/decisions?stage=deploy&outcome=block&repository_id="+repo.String(), nil)
	if code != 200 || len(list["items"].([]any)) == 0 {
		t.Fatalf("decisions log: %d %v", code, list)
	}
	for _, it := range list["items"].([]any) {
		m := it.(map[string]any)
		if m["stage"] != "deploy" || m["outcome"] != "block" {
			t.Errorf("filter: %v", m)
		}
	}

	// --- exceptions: expiry, four eyes, audit ---------------------------------
	blocked := decisions["deploy"]
	exp := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	code, ex := h.user(dev, "POST", "/api/v1/gates/decisions/"+blocked["id"].(string)+"/exceptions", map[string]any{"reason": "Hotfix for the incident, fix tracked", "expires_at": exp})
	if code != 201 || ex["status"] != "requested" || ex["kind"] != "exception" || ex["gate_id"] != deployGate {
		t.Fatalf("request exception: %d %v", code, ex)
	}
	exID := ex["id"].(string)
	// The requester cannot decide it, even with the permission.
	devApprover := realPrincipal(t, "security_manager")
	code, ex2 := h.user(devApprover, "POST", "/api/v1/gates/decisions/"+blocked["id"].(string)+"/exceptions", map[string]any{"reason": "second request by a manager", "expires_at": exp})
	if code != 201 {
		t.Fatalf("second request: %d %v", code, ex2)
	}
	if code, out := h.user(devApprover, "POST", "/api/v1/gate-exceptions/"+ex2["id"].(string)+"/approve", map[string]any{"note": "self"}); code != 409 || errCode(out) != "PTH-GATE-1103" {
		t.Errorf("self approval: %d %v", code, out)
	}
	if _, err := appPool.Exec(ctx, `UPDATE gate_exceptions SET status = 'approved', decided_by = requested_by, decided_at = now() WHERE id = $1`, ex2["id"]); err == nil || !db.IsCheckViolation(err) {
		t.Errorf("database must refuse self approval: %v", err)
	}
	if code, _ := h.user(dev, "POST", "/api/v1/gate-exceptions/"+exID+"/approve", map[string]any{"note": "no"}); code != 403 && code != 409 {
		t.Errorf("developer approves: %d", code)
	}
	// Still blocked until approved.
	if d := evaluate(dev, "deploy", nil); d["outcome"] != "block" {
		t.Errorf("requested exception does not apply: %v", d["outcome"])
	}
	code, ex = h.user(approver, "POST", "/api/v1/gate-exceptions/"+exID+"/approve", map[string]any{"note": "approved for the hotfix window"})
	if code != 200 || ex["status"] != "approved" || ex["decided_by_email"] != approver.Email {
		t.Fatalf("approve: %d %v", code, ex)
	}
	if code, out := h.user(approver, "POST", "/api/v1/gate-exceptions/"+exID+"/approve", map[string]any{"note": "again"}); code != 409 || errCode(out) != "PTH-GATE-1104" {
		t.Errorf("approve twice: %d %v", code, out)
	}
	d = evaluate(dev, "deploy", nil)
	if d["outcome"] != "exception_applied" || !slices.Contains(reasonCodes(d), "exception_applied") || len(d["exceptions"].([]any)) != 1 {
		t.Errorf("approved exception: %v", d)
	}
	// Another commit: the exception was scoped to the decision's commit.
	if d := evaluate(dev, "deploy", map[string]any{"commit_sha": strings.Repeat("cd", 20)}); d["outcome"] != "block" {
		t.Errorf("exception scope: %v", d["outcome"])
	}
	var audited int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE organization_id = $1 AND action IN ('gate_exception.request', 'gate_exception.approve')
		AND target_id = $2`, orgID, exID).Scan(&audited)
	if audited != 2 {
		t.Errorf("exception request and approval audited: %d", audited)
	}
	// Expired: the gate blocks again.
	if _, err := ownerPool.Exec(ctx, `UPDATE gate_exceptions SET created_at = now() - interval '2 days', expires_at = now() - interval '1 minute' WHERE id = $1`, exID); err != nil {
		t.Fatal(err)
	}
	if d := evaluate(dev, "deploy", nil); d["outcome"] != "block" {
		t.Errorf("expired exception: %v", d["outcome"])
	}
	var st string
	_ = appPool.QueryRow(ctx, `SELECT status FROM gate_exceptions WHERE id = $1`, exID).Scan(&st)
	if st != "expired" {
		t.Errorf("exception status after expiry: %s", st)
	}

	// Approval: require_approval gate → approval → exception_applied.
	rel := evaluate(dev, "release", nil)
	code, ap := h.user(dev, "POST", "/api/v1/gates/decisions/"+rel["id"].(string)+"/exceptions", map[string]any{"reason": "release 2.4 sign-off requested", "expires_at": exp})
	if code != 201 || ap["kind"] != "approval" || ap["gate_id"] != releaseGate {
		t.Fatalf("request approval: %d %v", code, ap)
	}
	if code, _ := h.user(approver, "POST", "/api/v1/gate-exceptions/"+ap["id"].(string)+"/approve", map[string]any{"note": "signed off"}); code != 200 {
		t.Fatalf("approve approval: %d", code)
	}
	if d := evaluate(dev, "release", nil); d["outcome"] != "exception_applied" || !slices.Contains(reasonCodes(d), "approval_granted") {
		t.Errorf("approved release: %v", d)
	}
	// A gate without exceptions refuses requests.
	if _, err := appPool.Exec(ctx, `UPDATE security_gates SET allow_exceptions = false WHERE id = $1`, deployGate); err != nil {
		t.Fatal(err)
	}
	if code, out := h.user(dev, "POST", "/api/v1/gates/decisions/"+blocked["id"].(string)+"/exceptions", map[string]any{"reason": "please let me deploy", "expires_at": exp}); code != 409 || errCode(out) != "PTH-GATE-1102" {
		t.Errorf("exceptions not allowed: %d %v", code, out)
	}
	for _, c := range []struct {
		p   *authz.Principal
		can bool
	}{{devApprover, false}, {approver, true}} {
		code, exl := h.user(c.p, "GET", "/api/v1/gate-exceptions?status=requested", nil)
		if code != 200 {
			t.Fatalf("exceptions list: %d", code)
		}
		seen := false
		for _, e := range exl["items"].([]any) {
			m := e.(map[string]any)
			if m["id"] == ex2["id"] {
				seen = true
				if m["can_decide"] != c.can {
					t.Errorf("can_decide for %s: %v", c.p.Email, m["can_decide"])
				}
			}
		}
		if !seen {
			t.Errorf("requested exception listed for %s", c.p.Email)
		}
	}
}

// Rule 7 in the database: a blocking decision without a policy, a gate
// without a policy, and changes to recorded decisions are refused; and no
// blocking decision in the whole suite lacks an existing policy.
func TestM8NoGateBlocksWithoutPolicy(t *testing.T) {
	ctx := t.Context()
	repo := createRepo(t, "rule7-"+uuid.NewString()[:6])
	for _, outcome := range []string{"block", "approval_required"} {
		for _, pool := range []struct {
			name string
			p    *pgxpool.Pool
		}{{"app", appPool}, {"owner", ownerPool}} {
			_, err := pool.p.Exec(ctx, `INSERT INTO gate_decisions (id, organization_id, stage, repository_id, outcome) VALUES ($1, $2, 'deploy', $3, $4)`,
				uuid.Must(uuid.NewV7()), orgID, repo, outcome)
			if err == nil || !db.IsCheckViolation(err) || !strings.Contains(err.Error(), "gate_decisions_block_needs_policy") {
				t.Errorf("%s: %s decision without a policy stored: %v", pool.name, outcome, err)
			}
		}
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO security_gates (id, organization_id, name, stage, mode) VALUES ($1, $2, 'no policy', 'ci', 'block')`,
		uuid.Must(uuid.NewV7()), orgID); err == nil {
		t.Error("gate without a policy stored")
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO security_gates (id, organization_id, name, stage, mode, policy_id) VALUES ($1, $2, 'ghost policy', 'ci', 'block', $3)`,
		uuid.Must(uuid.NewV7()), orgID, uuid.Must(uuid.NewV7())); err == nil || !db.IsForeignKeyViolation(err) {
		t.Errorf("gate with a missing policy: %v", err)
	}
	// Pass and warn need no policy.
	id := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO gate_decisions (id, organization_id, stage, repository_id, outcome) VALUES ($1, $2, 'ide', $3, 'pass')`, id, orgID, repo); err != nil {
		t.Fatal(err)
	}
	// Append-only.
	if _, err := appPool.Exec(ctx, `UPDATE gate_decisions SET outcome = 'block', policy_ids = ARRAY[$2::uuid] WHERE id = $1`, id, uuid.Must(uuid.NewV7())); err == nil {
		t.Error("decision changed")
	}
	// The service: Evaluate with every stage and no gate → pass.
	for _, st := range gates.Stages {
		if st == gates.StagePullRequest {
			continue
		}
		err := db.InTx(ctx, appPool, func(tx pgx.Tx) error {
			d, err := gates.Evaluate(ctx, tx, gates.Input{OrgID: orgID, Stage: st, RepositoryID: &repo})
			if err == nil && (d.Outcome != gates.OutcomePass || d.Blocks()) {
				t.Errorf("%s without gate: %s", st, d.Outcome)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Across everything the suite recorded so far.
	var bad int
	if err := appPool.QueryRow(ctx, `SELECT count(*) FROM gate_decisions d WHERE d.outcome IN ('block', 'approval_required')
		AND (cardinality(d.policy_ids) = 0 OR EXISTS (SELECT 1 FROM unnest(d.policy_ids) p WHERE NOT EXISTS (SELECT 1 FROM security_policies s WHERE s.id = p)))`).Scan(&bad); err != nil {
		t.Fatal(err)
	}
	if bad != 0 {
		t.Errorf("%d blocking decisions without an existing policy", bad)
	}
}

// C6: the migration turns every repository with pull request checks into
// an explicit policy with the behaviour it had. Run on a fresh database
// migrated to the version before M8's C6 migration, with legacy rows.
func TestM8C6MigrationKeepsBehaviour(t *testing.T) {
	ctx := t.Context()
	base := os.Getenv("PATHOS_TEST_DATABASE_URL")
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	name := "pathos_c6_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name+` OWNER pathos_owner`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(context.Background(), `DROP DATABASE `+name+` WITH (FORCE)`) }()
	pool, err := pgxpool.New(ctx, withDB(base, name, "pathos_owner", "owner"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer func(c *sql.DB) { _ = c.Close() }(sqlDB)
	prov, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prov.UpTo(ctx, 56); err != nil {
		t.Fatal("migrate to 56:", err)
	}
	org := uuid.Must(uuid.NewV7())
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'Legacy', 'legacy')`, org); err != nil {
		t.Fatal(err)
	}
	type legacy struct {
		enabled  bool
		severity string
	}
	repos := map[string]legacy{"high": {true, "high"}, "critical": {true, "critical"}, "low": {true, "low"}, "none": {true, "none"},
		"off": {false, "medium"}, "off-default": {false, "high"}}
	ids := map[string]uuid.UUID{}
	for k, l := range repos {
		id := uuid.Must(uuid.NewV7())
		ids[k] = id
		if _, err := pool.Exec(ctx, `INSERT INTO repositories (id, organization_id, source_type, external_id, full_name, name, url, clone_url,
			pr_checks_enabled, pr_gate_severity) VALUES ($1, $2, 'upload', $3, $4, $4, '', '', $5, $6)`, id, org, uuid.NewString(), "legacy/"+k, l.enabled, l.severity); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := prov.Up(ctx); err != nil {
		t.Fatal("migrate to latest:", err)
	}
	for k, l := range repos {
		var mode *string
		if err := pool.QueryRow(ctx, `SELECT pr_gate_mode FROM repositories WHERE id = $1`, ids[k]).Scan(&mode); err != nil {
			t.Fatal(err)
		}
		var policies, gatesN int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM security_policies WHERE managed_repository_id = $1`, ids[k]).Scan(&policies)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM security_gates WHERE repository_id = $1`, ids[k]).Scan(&gatesN)
		switch {
		case !l.enabled:
			if mode != nil || policies != 0 || gatesN != 0 {
				t.Errorf("%s (disabled) must stay without a choice: mode %v, %d policies, %d gates", k, mode, policies, gatesN)
			}
		case l.severity == "none":
			// It never blocked on severity: warn, no policy.
			if mode == nil || *mode != "warn" || policies != 0 || gatesN != 0 {
				t.Errorf("%s: mode %v, %d policies, %d gates", k, mode, policies, gatesN)
			}
		default:
			if mode == nil || *mode != "block" || policies != 1 || gatesN != 1 {
				t.Fatalf("%s: mode %v, %d policies, %d gates", k, mode, policies, gatesN)
			}
			// Exactly the threshold, this repository only, blocking, at the
			// pull request stage, enabled; the same definition the settings
			// API writes (gates.SyncRepositoryPRGate).
			var same bool
			var stage, gmode string
			var managed, enabled bool
			if err := pool.QueryRow(ctx, `SELECT p.conditions = jsonb_build_object('min_severity', $2::text, 'repository_ids', jsonb_build_array($3::text))
				AND p.actions = '{"block": true}'::jsonb AND p.enabled AND p.managed_by = 'repository_pr_gate', g.stage, g.mode, g.managed, g.enabled
				FROM security_policies p JOIN security_gates g ON g.policy_id = p.id WHERE p.managed_repository_id = $1`, ids[k], l.severity, ids[k].String()).
				Scan(&same, &stage, &gmode, &managed, &enabled); err != nil {
				t.Fatal(err)
			}
			if !same || stage != "pull_request" || gmode != "block" || !managed || !enabled {
				t.Errorf("%s: policy %v, gate %s %s managed=%v enabled=%v", k, same, stage, gmode, managed, enabled)
			}
		}
	}
	// New: enabling without an explicit choice is refused by the database.
	if _, err := pool.Exec(ctx, `UPDATE repositories SET pr_checks_enabled = true WHERE id = $1`, ids["off"]); err == nil || !db.IsCheckViolation(err) {
		t.Errorf("enabling without block or warn: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE repositories SET pr_checks_enabled = true, pr_gate_mode = 'warn' WHERE id = $1`, ids["off"]); err != nil {
		t.Errorf("enabling with a choice: %v", err)
	}
}

// C6 parity: with the generated policy, the gates engine blocks exactly the
// pull requests the old threshold blocked (any new finding at or above the
// threshold); warn mode never blocks. New repositories need a choice.
func TestM8C6PullRequestParity(t *testing.T) {
	ctx := t.Context()
	h := newM8Harness(t)
	setFlag(t, "remediation_workspace", true)
	admin := realPrincipal(t, authz.RoleSuperAdmin)
	sevs := []string{"critical", "high", "medium", "low", "info"}
	rank := func(s string) int { return len(sevs) - slices.Index(sevs, s) }
	mixes := [][]string{{}, {"info"}, {"low"}, {"medium", "low"}, {"high"}, {"critical", "info"}}
	pr := 100
	for _, mode := range []string{"block", "warn"} {
		for _, thr := range []string{"critical", "high", "medium", "low"} {
			repo := createRepo(t, "c6-"+mode+"-"+thr+"-"+uuid.NewString()[:4])
			if code, st := h.user(admin, "PUT", "/api/v1/repositories/"+repo.String()+"/pr-settings",
				map[string]any{"enabled": true, "gate_severity": thr, "gate_mode": mode}); code != 200 || st["gate_mode"] != mode || st["policy_id"] == nil {
				t.Fatalf("settings %s %s: %d %v", mode, thr, code, st)
			}
			for _, mix := range mixes {
				pr++
				sha := strings.Repeat("0", 32) + strings.Repeat("1", 8)
				res, err := scans.EnqueueWith(ctx, appPool, orgID, repo, "pull_request", "feature/p", sha, nil, scans.EnqueueOpts{PullRequest: pr})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := appPool.Exec(ctx, `UPDATE scan_jobs SET status = 'succeeded', finished_at = now() WHERE id = $1`, res.JobID); err != nil {
					t.Fatal(err)
				}
				check := uuid.Must(uuid.NewV7())
				if _, err := appPool.Exec(ctx, `INSERT INTO pr_checks (id, organization_id, repository_id, scan_job_id, pull_request, head_sha, gate_severity, gate_mode)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, check, orgID, repo, res.JobID, pr, sha, thr, mode); err != nil {
					t.Fatal(err)
				}
				legacyBlocks := false
				for i, sev := range mix {
					legacyBlocks = legacyBlocks || rank(sev) >= rank(thr)
					if _, err := appPool.Exec(ctx, `INSERT INTO pr_findings (id, pr_check_id, fingerprint, scanner_key, category, title, severity, is_new)
						VALUES ($1, $2, $3, 'opengrep', 'sast', 't', $4, true)`, uuid.Must(uuid.NewV7()), check, "fp"+strconv.Itoa(i), sev); err != nil {
						t.Fatal(err)
					}
				}
				r := repo
				var d gates.Decision
				err = db.InTx(ctx, appPool, func(tx pgx.Tx) error {
					d, err = gates.Evaluate(ctx, tx, gates.Input{OrgID: orgID, Stage: gates.StagePullRequest, RepositoryID: &r, PRCheckID: &check, ScanJobID: &res.JobID, PullRequest: pr})
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
				// The repository's own gate (security policies with the block
				// action of other tests may also apply; they did before too).
				effect := "missing"
				for _, g := range d.Gates {
					if g.Managed {
						effect = g.Effect
					}
				}
				want := gates.OutcomePass
				if legacyBlocks {
					want = map[string]string{"block": gates.OutcomeBlock, "warn": gates.OutcomeWarn}[mode]
				}
				if effect != want {
					t.Errorf("%s at %s with %v: threshold gate %s, want %s (legacy blocks: %v)", mode, thr, mix, effect, want, legacyBlocks)
				}
				if mode == "block" && legacyBlocks && !d.Blocks() {
					t.Errorf("block at %s with %v: decision %s", thr, mix, d.Outcome)
				}
			}
		}
	}

	// New repositories: enabling needs block or warn (no default).
	repo := createRepo(t, "c6-new-"+uuid.NewString()[:6])
	code, out := h.user(admin, "PUT", "/api/v1/repositories/"+repo.String()+"/pr-settings", map[string]any{"enabled": true, "gate_severity": "high"})
	if code != 422 || errCode(out) != "PTH-GATE-1106" {
		t.Fatalf("enable without a choice: %d %v", code, out)
	}
	var enabled bool
	_ = appPool.QueryRow(ctx, `SELECT pr_checks_enabled FROM repositories WHERE id = $1`, repo).Scan(&enabled)
	if enabled {
		t.Fatal("pull request checks enabled without a choice")
	}
	if code, st := h.user(admin, "PUT", "/api/v1/repositories/"+repo.String()+"/pr-settings", map[string]any{"enabled": true, "gate_severity": "high", "gate_mode": "block"}); code != 200 || st["gate_id"] == nil {
		t.Fatalf("enable with block: %d %v", code, st)
	}
	// An older client changing only the threshold keeps the choice.
	code, st := h.user(admin, "PUT", "/api/v1/repositories/"+repo.String()+"/pr-settings", map[string]any{"enabled": true, "gate_severity": "critical"})
	if code != 200 || st["gate_mode"] != "block" {
		t.Fatalf("threshold only: %d %v", code, st)
	}
	var minSev string
	_ = appPool.QueryRow(ctx, `SELECT conditions->>'min_severity' FROM security_policies WHERE id = $1`, st["policy_id"]).Scan(&minSev)
	if minSev != "critical" {
		t.Errorf("managed policy follows the settings: %s", minSev)
	}
	// The generated policy and gate are managed in the settings only.
	if code, out := h.user(admin, "PUT", "/api/v1/security-policies/"+st["policy_id"].(string), map[string]any{"name": "x", "conditions": map[string]any{"min_severity": "low"},
		"actions": map[string]any{"block": true}}); code != 409 || errCode(out) != "PTH-GATE-1105" {
		t.Errorf("edit managed policy: %d %v", code, out)
	}
	if code, out := h.user(admin, "DELETE", "/api/v1/security-policies/"+st["policy_id"].(string), nil); code != 409 || errCode(out) != "PTH-GATE-1105" {
		t.Errorf("delete managed policy: %d %v", code, out)
	}
	if code, out := h.user(admin, "DELETE", "/api/v1/gates/"+st["gate_id"].(string), nil); code != 409 || errCode(out) != "PTH-GATE-1105" {
		t.Errorf("delete managed gate: %d %v", code, out)
	}
	// Managed policies never act on branch findings by themselves.
	if err := db.InTx(ctx, appPool, func(tx pgx.Tx) error { _, err := policy.Evaluate(ctx, tx, orgID, &repo); return err }); err != nil {
		t.Fatal(err)
	}
	var violations int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM policy_violations WHERE policy_id = $1`, st["policy_id"]).Scan(&violations)
	if violations != 0 {
		t.Errorf("managed policy recorded %d violations", violations)
	}
	// Turning the threshold to none disables the managed gate.
	if code, _ := h.user(admin, "PUT", "/api/v1/repositories/"+repo.String()+"/pr-settings", map[string]any{"enabled": true, "gate_severity": "none", "gate_mode": "warn"}); code != 200 {
		t.Fatal("threshold none")
	}
	var gEnabled, pEnabled bool
	_ = appPool.QueryRow(ctx, `SELECT g.enabled, p.enabled FROM security_gates g JOIN security_policies p ON p.id = g.policy_id WHERE g.id = $1`, st["gate_id"]).Scan(&gEnabled, &pEnabled)
	if gEnabled || pEnabled {
		t.Errorf("threshold none: gate %v policy %v", gEnabled, pEnabled)
	}
}

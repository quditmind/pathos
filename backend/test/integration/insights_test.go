//go:build integration

package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/insights"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/policy"
	"pathos/internal/vuln"
)

func TestMaterialChangesAndAttribution(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	(&insights.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}).Register(h.api)
	// A real user (audit, identity links) with every permission in memory;
	// no super_admin assignment (that would change bootstrap tests).
	admin := reviewUser(t, "platform_admin")
	admin.Grants = principalWithRole(t, authz.RoleSuperAdmin).Grants
	analyst := reviewUser(t, "security_analyst") // scans.read, no insights.people
	suffix := uuid.NewString()[:6]
	repo := createRepo(t, "mc-"+suffix)
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "mc-" + suffix, "family": "core"})
	token := reg["token"].(string)
	t.Cleanup(func() {
		_, _ = appPool.Exec(ctx, `DELETE FROM developer_insight_settings WHERE organization_id = $1`, orgID)
	})

	// Attribution is off by default; only settings.manage may switch it.
	if code, st := h.user(admin, "GET", "/api/v1/insights/settings", nil); code != 200 || st["attribution_enabled"] != false {
		t.Fatalf("default settings: %d %v", code, st)
	}
	if code, _ := h.user(analyst, "GET", "/api/v1/insights/settings", nil); code != 403 {
		t.Errorf("analyst reads settings: %d", code)
	}
	if code, _ := h.user(admin, "GET", "/api/v1/insights/developers", nil); code != 409 {
		t.Errorf("people views while disabled: %d", code)
	}

	// --- first scan: baseline -----------------------------------------------
	sha1, sha2 := strings.Repeat("1", 40), strings.Repeat("2", 40)
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	job1 := q["job_id"].(string)
	j := h.leaseJob(token, job1)
	if j["previous_commit_sha"] != nil || j["collect_authors"] != nil {
		t.Fatalf("first lease: %v", j)
	}
	raw, _ := os.ReadFile("../../internal/scanners/testdata/syft.cdx.json")
	storeSBOM := func(job string) {
		if err := db.InTx(ctx, appPool, func(tx pgx.Tx) error {
			_, err := vuln.StoreSBOM(ctx, tx, orgID, repo, uuid.MustParse(job), raw)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	storeSBOM(job1)
	if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+job1+"/changes", map[string]any{"version": 1, "status": "baseline",
		"reason": "first scan", "head_sha": sha1, "changes": []any{}}); code != 200 || out["material_changes"].(float64) != 0 {
		t.Fatalf("baseline upload: %d %v", code, out)
	}
	if code, _ := h.worker(token, "POST", "/internal/worker/v1/jobs/"+job1+"/changes", map[string]any{"version": 9, "status": "computed"}); code != 400 {
		t.Errorf("bad report version: %d", code)
	}
	if code, _ := h.worker(token, "POST", "/internal/worker/v1/jobs/"+job1+"/complete", map[string]any{"status": "succeeded", "commit_sha": sha1}); code != 200 {
		t.Fatalf("complete job1: %d", code)
	}
	var depStatus string
	_ = appPool.QueryRow(ctx, `SELECT dependency_status FROM material_change_runs WHERE scan_job_id = $1`, job1).Scan(&depStatus)
	if depStatus != "baseline" {
		t.Errorf("first SBOM is the dependency baseline: %q", depStatus)
	}
	// Forget one dependency so the next SBOM has a "new" one.
	if _, err := appPool.Exec(ctx, `UPDATE material_dependency_baselines SET components = components[2:] WHERE repository_id = $1`, repo); err != nil {
		t.Fatal(err)
	}

	// --- enable attribution --------------------------------------------------
	if code, _ := h.user(analyst, "PUT", "/api/v1/insights/settings", map[string]any{"attribution_enabled": true}); code != 403 {
		t.Errorf("analyst enables attribution: %d", code)
	}
	if code, st := h.user(admin, "PUT", "/api/v1/insights/settings", map[string]any{"attribution_enabled": true}); code != 200 || st["attribution_enabled"] != true {
		t.Fatalf("enable: %d %v", code, st)
	}

	// --- second scan: material changes and commits ---------------------------
	_, q = h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	job2 := q["job_id"].(string)
	j = h.leaseJob(token, job2)
	if j["previous_commit_sha"] != sha1 || j["collect_authors"] != true {
		t.Fatalf("second lease: %v", j)
	}
	storeSBOM(job2)
	report := map[string]any{"version": 1, "status": "computed", "base_sha": sha1, "head_sha": sha2, "files_changed": 3,
		"commits_complete": true,
		"changes": []map[string]any{
			{"category": "auth", "rule_id": "auth.spring-security", "file_path": "src/Security.java", "change_type": "modified", "side": "added",
				"start_line": 12, "end_line": 12, "match_count": 1, "snippet": `.permitAll() // password=hunter2hunter2`, "explanation": "x"},
			{"category": "cicd", "rule_id": "cicd.pipeline", "file_path": ".github/workflows/ci.yml", "change_type": "added", "side": "file"},
			{"category": "auth", "rule_id": "made.up", "file_path": "x"},                  // unknown rule: dropped
			{"category": "dependency", "rule_id": "dependency.new", "file_path": "y"}, // only the API computes these
		},
		"commits": []map[string]any{
			{"sha": strings.Repeat("b", 40), "author_name": "Bob Dev", "authored_at": "2026-11-18T10:00:00Z", "files": []string{"src/Security.java"}},
			{"sha": strings.Repeat("a", 40), "author_name": "Alice Dev", "authored_at": "2026-11-17T10:00:00Z", "files": []string{"src/Security.java", "app.js"}},
		}}
	code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+job2+"/changes", report)
	if code != 200 || out["material_changes"].(float64) != 3 {
		t.Fatalf("changes upload: %d %v", code, out)
	}
	var evSev string
	if err := appPool.QueryRow(ctx, `SELECT severity FROM notification_events WHERE event_key = 'change.material' AND subject_id = $1`, job2).Scan(&evSev); err != nil || evSev != "high" {
		t.Errorf("change.material event: %v %q", err, evSev)
	}

	// Findings: one new in the auth file (Bob, newest commit touching it),
	// one fixed in app.js (Alice).
	newF := insertLocatedFinding(t, repo, "opengrep", "src/Security.java", 12, "CWE-285")
	oldF := insertLocatedFinding(t, repo, "opengrep", "app.js", 3, "CWE-89")
	if _, err := appPool.Exec(ctx, `UPDATE findings SET first_scan_job_id = $2, last_scan_job_id = $2 WHERE id = $1`, newF, job2); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE findings SET first_scan_job_id = $2, last_scan_job_id = $2, first_seen_at = now() - interval '48 hours'
		WHERE id = $1`, oldF, job1); err != nil {
		t.Fatal(err)
	}
	if code, _ := h.worker(token, "POST", "/internal/worker/v1/jobs/"+job2+"/complete", map[string]any{"status": "succeeded", "commit_sha": sha2}); code != 200 {
		t.Fatalf("complete job2: %d", code)
	}
	if err := db.InTx(ctx, appPool, func(tx pgx.Tx) error {
		if err := db.SetChangeContext(ctx, tx, nil, "scanner", "no longer detected by a successful scan"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE findings SET status = 'fixed', resolved_at = now() WHERE id = $1`, oldF)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	in, fx, err := insights.Attribute(ctx, appPool, orgID, uuid.MustParse(job2))
	if err != nil || in != 1 || fx != 1 {
		t.Fatalf("attribute: %d %d %v", in, fx, err)
	}

	// --- material change views -----------------------------------------------
	code, sc := h.user(analyst, "GET", "/api/v1/scans/"+job2+"/material-changes", nil)
	if code != 200 || sc["run"].(map[string]any)["status"] != "computed" {
		t.Fatalf("scan changes: %d %v", code, sc)
	}
	items := sc["items"].([]any)
	if len(items) != 3 {
		t.Fatalf("items: %v", items)
	}
	var dep, authChange map[string]any
	for _, it := range items {
		m := it.(map[string]any)
		switch m["category"] {
		case "dependency":
			dep = m
		case "auth":
			authChange = m
		}
		if m["author_name"] != nil {
			t.Errorf("author shown without insights.people: %v", m)
		}
	}
	if dep == nil || dep["detail"] == "" {
		t.Errorf("new dependency from the SBOM: %v", dep)
	}
	if authChange == nil || strings.Contains(authChange["snippet"].(string), "hunter2hunter2") || authChange["level"] != "high" {
		t.Errorf("auth change (redacted, high): %v", authChange)
	}
	_, sc = h.user(admin, "GET", "/api/v1/scans/"+job2+"/material-changes", nil)
	for _, it := range sc["items"].([]any) {
		if m := it.(map[string]any); m["category"] == "auth" && m["author_name"] != "Bob Dev" {
			t.Errorf("author for insights.people: %v", m)
		}
	}
	code, rc := h.user(admin, "GET", "/api/v1/repositories/"+repo.String()+"/material-changes?category=auth", nil)
	if code != 200 || len(rc["items"].([]any)) != 1 || len(rc["runs"].([]any)) != 2 {
		t.Errorf("repository changes: %d %v", code, rc)
	}
	if code, _ := h.user(admin, "GET", "/api/v1/repositories/"+repo.String()+"/material-changes?category=nope", nil); code != 400 {
		t.Errorf("bad category: %d", code)
	}
	if code, rules := h.user(analyst, "GET", "/api/v1/material-changes/rules", nil); code != 200 || len(rules["items"].([]any)) < 15 {
		t.Errorf("rules: %d", code)
	}

	// --- policy condition: findings that landed with an auth change ---------
	var args []any
	where, err := policy.Where(policy.Conditions{MaterialChangeCategories: []string{"auth"}}, policy.FindingColumns, &args)
	if err != nil {
		t.Fatal(err)
	}
	args = append(args, repo)
	var matched []uuid.UUID
	rows, err := appPool.Query(ctx, `SELECT f.id FROM findings f JOIN repositories r ON r.id = f.repository_id WHERE `+where+
		` AND f.repository_id = $2`, args...)
	if err != nil {
		t.Fatal(err)
	}
	matched, _ = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if len(matched) != 1 || matched[0] != newF {
		t.Errorf("policy condition matched %v, want %s", matched, newF)
	}

	// --- people views ----------------------------------------------------------
	if code, _ := h.user(analyst, "GET", "/api/v1/insights/developers", nil); code != 403 {
		t.Errorf("analyst sees people: %d", code)
	}
	code, dv := h.user(admin, "GET", "/api/v1/insights/developers?days=30", nil)
	devs := map[string]map[string]any{}
	for _, it := range dv["items"].([]any) {
		m := it.(map[string]any)
		devs[m["author_name"].(string)] = m
	}
	if code != 200 || devs["Bob Dev"]["introduced"].(float64) != 1 || devs["Alice Dev"]["fixed"].(float64) != 1 {
		t.Fatalf("developers: %d %v", code, dv)
	}
	if mttf, _ := devs["Alice Dev"]["mean_time_to_fix_hours"].(float64); mttf < 47 || mttf > 49 {
		t.Errorf("mean time to fix: %v", devs["Alice Dev"])
	}

	// Link Bob to the analyst and put the analyst in a team.
	code, link := h.user(admin, "POST", "/api/v1/insights/identities", map[string]any{"author_name": "Bob Dev", "user_id": analyst.UserID})
	if code != 201 {
		t.Fatalf("link: %d %v", code, link)
	}
	if code, _ := h.user(admin, "POST", "/api/v1/insights/identities", map[string]any{"author_name": "bob dev", "user_id": admin.UserID}); code != 409 {
		t.Errorf("duplicate link: %d", code)
	}
	team := uuid.New()
	if _, err := appPool.Exec(ctx, `INSERT INTO teams (id, organization_id, name) VALUES ($1, $2, $3)`, team, orgID, "Payments "+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO team_members (organization_id, team_id, user_id) VALUES ($1, $2, $3)`, orgID, team, analyst.UserID); err != nil {
		t.Fatal(err)
	}
	_, tv := h.user(admin, "GET", "/api/v1/insights/teams", nil)
	found := false
	for _, it := range tv["items"].([]any) {
		m := it.(map[string]any)
		if m["name"] == "Payments "+suffix && m["introduced"].(float64) == 1 && m["developers"].(float64) == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("team view: %v", tv)
	}
	_, idv := h.user(admin, "GET", "/api/v1/insights/identities", nil)
	if len(idv["items"].([]any)) != 1 || !slicesContainsAny(idv["unlinked_authors"].([]any), "Alice Dev") {
		t.Errorf("identities: %v", idv)
	}
	if code, tr := h.user(admin, "GET", "/api/v1/insights/trend?days=30&author=Bob%20Dev", nil); code != 200 || len(tr["items"].([]any)) < 4 {
		t.Errorf("trend: %d %v", code, tr)
	}
	var audited int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('insights.settings.update', 'insights.identity.link') AND organization_id = $1
		AND created_at > now() - interval '1 hour'`, orgID).Scan(&audited)
	if audited < 2 {
		t.Errorf("audit entries: %d", audited)
	}

	// --- turning attribution off erases people data ---------------------------
	// Includes the author of a finding's introducing commit (git blame).
	if _, err := appPool.Exec(ctx, `UPDATE findings SET introduced_status = 'known', introduced_commit_sha = $2, introduced_author = 'Bob Dev'
		WHERE id = (SELECT id FROM findings WHERE organization_id = $1 LIMIT 1)`, orgID, strings.Repeat("d", 40)); err != nil {
		t.Fatal(err)
	}
	if code, _ := h.user(admin, "PUT", "/api/v1/insights/settings", map[string]any{"attribution_enabled": false}); code != 200 {
		t.Fatal("disable")
	}
	var n int
	_ = appPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM finding_attribution WHERE organization_id = $1) + (SELECT count(*) FROM scan_commits WHERE organization_id = $1)
		+ (SELECT count(*) FROM developer_identities WHERE organization_id = $1) + (SELECT count(*) FROM material_changes WHERE organization_id = $1 AND author_name <> '')
		+ (SELECT count(*) FROM findings WHERE organization_id = $1 AND introduced_author <> '')`,
		orgID).Scan(&n)
	if n != 0 {
		t.Errorf("people data left after disabling: %d rows", n)
	}
	// While off, commits sent by a worker are not stored.
	if _, err := insights.StoreChanges(ctx, appPool, orgID, uuid.MustParse(job2), insights.ChangeReport{Version: 1, Status: "computed",
		Commits: []insights.Commit{{SHA: strings.Repeat("c", 40), AuthorName: "Eve"}}}); err != nil {
		t.Fatal(err)
	}
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM scan_commits WHERE scan_job_id = $1`, job2).Scan(&n)
	if n != 0 {
		t.Errorf("commits stored while attribution is off: %d", n)
	}
}

func slicesContainsAny(v []any, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}

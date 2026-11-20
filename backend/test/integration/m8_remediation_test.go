//go:build integration

package integration

// PATHOS 3.0 M8: remediation workspace, fix verification (closes only on
// proof, regression report) and the "fix merged → targeted rescan" loop.

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/platform/db"
)

// seedScan records a finished scan of the scan branch with a commit and
// the scanners that ran in it.
func seedScan(t *testing.T, repo uuid.UUID, commit string, scanners ...string) uuid.UUID {
	t.Helper()
	ctx := t.Context()
	var pv uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT current_version_id FROM scan_profiles WHERE organization_id = $1 AND is_default`, orgID).Scan(&pv)
	job := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, ref, commit_sha, status, finished_at)
		VALUES ($1, $2, $3, $4, 'manual', 'main', $5, 'succeeded', now())`, job, orgID, repo, pv, commit); err != nil {
		t.Fatal(err)
	}
	for _, s := range scanners {
		if _, err := appPool.Exec(ctx, `INSERT INTO scan_results (id, organization_id, scan_job_id, scanner_key, status) VALUES ($1, $2, $3, $4, 'succeeded')`,
			uuid.Must(uuid.NewV7()), orgID, job, s); err != nil {
			t.Fatal(err)
		}
	}
	return job
}

func TestM8RemediationWorkspace(t *testing.T) {
	ctx := t.Context()
	h := newM8Harness(t)
	setFlag(t, "remediation_workspace", true)
	admin := realPrincipal(t, authz.RoleSuperAdmin)
	owner := realPrincipal(t, "developer")
	// Verifying queues a rescan: remediation.manage and scans.run.
	engineer := realPrincipal(t, "appsec_engineer")
	viewer := realPrincipal(t, "viewer")
	repo := createRepo(t, "rem-"+uuid.NewString()[:6])
	before := strings.Repeat("a1", 20)
	scan1 := seedScan(t, repo, before, "opengrep", "trivy-fs")
	sqli := seedFinding(t, repo, "critical", "sast", "go.sqli", "app/db.go", []string{"opengrep"}, &scan1)
	xss := seedFinding(t, repo, "high", "sast", "go.xss", "app/web.go", []string{"opengrep"}, &scan1)
	hash := seedFinding(t, repo, "medium", "sast", "go.weak-hash", "app/web.go", []string{"opengrep"}, &scan1)
	dep := seedFinding(t, repo, "high", "sca", "CVE-2099-0001", "go.sum", []string{"trivy-fs"}, &scan1)
	if _, err := appPool.Exec(ctx, `UPDATE findings SET package_name = 'golang.org/x/net', package_version = '0.1.0', fixed_version = '0.7.0, 0.8.0',
		sla_due_at = now() + interval '7 days' WHERE id = $1`, dep); err != nil {
		t.Fatal(err)
	}
	imported := seedFinding(t, repo, "low", "sast", "imp.rule", "app/x.go", []string{"import-sast-x"}, &scan1)

	// Flag off: absent.
	setFlag(t, "remediation_workspace", false)
	if code, out := h.user(admin, "GET", "/api/v1/remediation/items", nil); code != 404 || errCode(out) != "PTH-PLAT-1007" {
		t.Fatalf("flag off: %d %v", code, out)
	}
	setFlag(t, "remediation_workspace", true)

	// --- create, one per finding or grouped -------------------------------------
	if code, _ := h.user(viewer, "POST", "/api/v1/remediation/items", map[string]any{"finding_ids": []uuid.UUID{sqli}}); code != 403 {
		t.Errorf("viewer creates: %d", code)
	}
	code, out := h.user(admin, "POST", "/api/v1/remediation/items", map[string]any{"finding_ids": []uuid.UUID{sqli, dep}, "mode": "per_finding"})
	if code != 201 || len(out["items"].([]any)) != 2 {
		t.Fatalf("per finding: %d %v", code, out)
	}
	items := map[string]map[string]any{}
	for _, it := range out["items"].([]any) {
		m := it.(map[string]any)
		items[m["kind"].(string)] = m
	}
	sqliItem, depItem := items["code_fix"], items["dependency_upgrade"]
	if sqliItem == nil || depItem == nil || sqliItem["priority"] != "critical" || depItem["due_source"] != "sla" || depItem["due_at"] == nil {
		t.Fatalf("items: %v", out)
	}
	if code, out := h.user(admin, "POST", "/api/v1/remediation/items", map[string]any{"finding_ids": []uuid.UUID{sqli}}); code != 409 || errCode(out) != "PTH-REM-1103" {
		t.Errorf("finding already tracked: %d %v", code, out)
	}
	code, out = h.user(admin, "POST", "/api/v1/remediation/items", map[string]any{"finding_ids": []uuid.UUID{xss, hash}, "mode": "group",
		"title": "Harden app/web.go", "root_cause": "No output encoding helper"})
	if code != 201 || len(out["items"].([]any)) != 1 {
		t.Fatalf("group: %d %v", code, out)
	}
	webItem := out["items"].([]any)[0].(map[string]any)
	if webItem["finding_count"].(float64) != 2 || webItem["priority"] != "high" || len(webItem["affected_files"].([]any)) != 1 {
		t.Errorf("group item: %v", webItem)
	}
	code, out = h.user(admin, "POST", "/api/v1/remediation/items", map[string]any{"finding_ids": []uuid.UUID{imported}})
	if code != 201 {
		t.Fatalf("imported item: %d %v", code, out)
	}
	impItem := out["items"].([]any)[0].(map[string]any)

	// --- list, filters, saved views, bulk assign -------------------------------------
	code, list := h.user(viewer, "GET", "/api/v1/remediation/items?repository_id="+repo.String()+"&unassigned=true&sort=priority", nil)
	if code != 200 || list["total"].(float64) != 4 || list["items"].([]any)[0].(map[string]any)["priority"] != "critical" {
		t.Fatalf("list: %d %v", code, list)
	}
	code, list = h.user(viewer, "GET", "/api/v1/remediation/items?repository_id="+repo.String()+"&q=web.go", nil)
	if code != 200 || list["total"].(float64) != 1 {
		t.Errorf("search by file: %d %v", code, list)
	}
	code, view := h.user(viewer, "POST", "/api/v1/remediation/views", map[string]any{"name": "Critical work", "filters": map[string]string{"priority": "critical", "status": "active"}})
	if code != 201 {
		t.Fatalf("save view: %d %v", code, view)
	}
	if code, _ := h.user(viewer, "POST", "/api/v1/remediation/views", map[string]any{"name": "bad", "filters": map[string]string{"drop": "table"}}); code != 400 {
		t.Errorf("unknown filter: %d", code)
	}
	if code, vs := h.user(viewer, "GET", "/api/v1/remediation/views", nil); code != 200 || len(vs["items"].([]any)) == 0 {
		t.Errorf("views: %d %v", code, vs)
	}
	if code, _ := h.user(admin, "DELETE", "/api/v1/remediation/views/"+view["id"].(string), nil); code != 404 {
		t.Errorf("only the owner deletes a view: %d", code)
	}
	if code, _ := h.user(viewer, "DELETE", "/api/v1/remediation/views/"+view["id"].(string), nil); code != 204 {
		t.Errorf("delete view: %d", code)
	}
	code, out = h.user(admin, "POST", "/api/v1/remediation/items/bulk", map[string]any{"ids": []any{sqliItem["id"], webItem["id"]}, "owner_id": owner.UserID, "status": "in_progress"})
	if code != 200 || out["updated"].(float64) != 2 {
		t.Fatalf("bulk: %d %v", code, out)
	}
	code, list = h.user(owner, "GET", "/api/v1/remediation/items?owner_id="+owner.UserID.String(), nil)
	if code != 200 || list["total"].(float64) != 2 || list["items"].([]any)[0].(map[string]any)["owner_email"] != owner.Email {
		t.Errorf("assigned: %d %v", code, list)
	}

	// --- closing needs proof ------------------------------------------------------
	if code, out := h.user(owner, "PATCH", "/api/v1/remediation/items/"+sqliItem["id"].(string), map[string]any{"status": "closed"}); code != 409 || errCode(out) != "PTH-REM-1101" {
		t.Errorf("close by hand: %d %v", code, out)
	}
	if _, err := appPool.Exec(ctx, `UPDATE remediation_items SET status = 'closed', closed_at = now() WHERE id = $1`, sqliItem["id"]); err == nil || !db.IsCheckViolation(err) {
		t.Errorf("database closes without a verification: %v", err)
	}
	// Detail: guidance (labelled), verifiability.
	code, det := h.user(owner, "GET", "/api/v1/remediation/items/"+depItem["id"].(string), nil)
	if code != 200 {
		t.Fatalf("detail: %d %v", code, det)
	}
	foundUpgrade := false
	for _, g := range det["guidance"].([]any) {
		gm := g.(map[string]any)
		if gm["source"] == "dependency_upgrade" && gm["evidence"] == "scanner" && strings.Contains(gm["text"].(string), "to 0.7.0") {
			foundUpgrade = true
		}
	}
	if !foundUpgrade {
		t.Errorf("dependency guidance from depfix: %v", det["guidance"])
	}
	code, det = h.user(owner, "GET", "/api/v1/remediation/items/"+impItem["id"].(string), nil)
	if code != 200 || det["can_verify"] != false || !strings.Contains(det["verify_unavailable_reason"].(string), "imported report") {
		t.Errorf("imported finding cannot be rescanned: %v %v", det["can_verify"], det["verify_unavailable_reason"])
	}
	if code, _ := h.user(owner, "POST", "/api/v1/remediation/items/"+impItem["id"].(string)+"/verify", nil); code != 403 {
		t.Errorf("developer without scans.run verifies: %d", code)
	}
	if code, out := h.user(engineer, "POST", "/api/v1/remediation/items/"+impItem["id"].(string)+"/verify", nil); code != 409 || errCode(out) != "PTH-REM-1102" {
		t.Errorf("verify imported: %d %v", code, out)
	}

	// --- targeted rescan by a worker --------------------------------------------
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "rem-" + uuid.NewString()[:6], "family": "core",
		"scanners": map[string]string{"opengrep": "1.2.3", "trivy-fs": "0.50"}})
	token := reg["token"].(string)
	lease := func() map[string]any {
		t.Helper()
		code, job := h.worker(token, "POST", "/internal/worker/v1/remediation-lease", map[string]any{})
		if code != 200 {
			t.Fatalf("lease: %d %v", code, job)
		}
		return job
	}
	result := func(job map[string]any, body map[string]any) int {
		code, _ := h.worker(token, "POST", "/internal/worker/v1/remediation-jobs/"+job["verification_id"].(string)+"/result", body)
		return code
	}
	after := strings.Repeat("b2", 20)
	r := func(rule, file string, line int) map[string]any {
		return map[string]any{"rule_id": rule, "file": file, "line": line, "title": rule}
	}
	verify := func(item map[string]any) map[string]any {
		t.Helper()
		code, v := h.user(engineer, "POST", "/api/v1/remediation/items/"+item["id"].(string)+"/verify", nil)
		if code != 202 || v["status"] != "queued" {
			t.Fatalf("verify: %d %v", code, v)
		}
		return v
	}
	itemStatus := func(item map[string]any) string {
		var s string
		_ = appPool.QueryRow(ctx, `SELECT status FROM remediation_items WHERE id = $1`, item["id"]).Scan(&s)
		return s
	}

	// 1. Still present after the fix. The item's owner (a developer, no
	// scans.run) may verify their own item; another developer may not.
	other := realPrincipal(t, "developer")
	if code, _ := h.user(other, "POST", "/api/v1/remediation/items/"+webItem["id"].(string)+"/verify", nil); code != 403 {
		t.Errorf("non-owner developer verifies: %d", code)
	}
	if code, d := h.user(other, "GET", "/api/v1/remediation/items/"+webItem["id"].(string), nil); code != 200 || d["can_request_verification"] != false {
		t.Errorf("non-owner can_request_verification: %d %v", code, d["can_request_verification"])
	}
	if code, d := h.user(owner, "GET", "/api/v1/remediation/items/"+webItem["id"].(string), nil); code != 200 || d["can_request_verification"] != true {
		t.Errorf("owner can_request_verification: %d %v", code, d["can_request_verification"])
	}
	code, v1 := h.user(owner, "POST", "/api/v1/remediation/items/"+webItem["id"].(string)+"/verify", nil)
	if code != 202 || v1["status"] != "queued" || v1["requested_by_email"] != owner.Email {
		t.Fatalf("owner verifies own item: %d %v", code, v1)
	}
	if itemStatus(webItem) != "verifying" {
		t.Errorf("status while verifying: %s", itemStatus(webItem))
	}
	if code, out := h.user(engineer, "POST", "/api/v1/remediation/items/"+webItem["id"].(string)+"/verify", nil); code != 409 || errCode(out) != "PTH-REM-1104" {
		t.Errorf("second verification: %d %v", code, out)
	}
	if code, _ := h.user(owner, "PATCH", "/api/v1/remediation/items/"+webItem["id"].(string), map[string]any{"status": "open"}); code != 409 {
		t.Errorf("status change while verifying: %d", code)
	}
	job := lease()
	files, _ := job["files"].([]any)
	if job["verification_id"] != v1["id"] || job["before_commit"] != before || job["ref"] != "main" || len(files) != 1 || files[0] != "app/web.go" ||
		job["scanners"].(map[string]any)["opengrep"] == nil || job["credential"] == nil {
		t.Fatalf("leased job: %v", job)
	}
	if code, _ := h.worker(token, "POST", "/internal/worker/v1/remediation-jobs/"+uuid.NewString()+"/result", map[string]any{"status": "completed"}); code != 404 {
		t.Errorf("unknown verification: %d", code)
	}
	beforeRes := []any{r("go.xss", "app/web.go", 10), r("go.weak-hash", "app/web.go", 30)}
	if code := result(job, map[string]any{"status": "completed", "before_commit": before, "after_commit": after, "scanner_versions": map[string]string{"opengrep": "1.2.3"},
		"results": map[string]any{"opengrep": map[string]any{"before": beforeRes, "after": []any{r("go.xss", "app/web.go", 12)}}}}); code != 204 {
		t.Fatalf("result: %d", code)
	}
	if code := result(job, map[string]any{"status": "completed"}); code != 409 {
		t.Errorf("result twice: %d", code)
	}
	code, vs := h.user(owner, "GET", "/api/v1/remediation/items/"+webItem["id"].(string)+"/verifications", nil)
	got := vs["items"].([]any)[0].(map[string]any)
	if code != 200 || got["result"] != "still_present" || got["status"] != "completed" || itemStatus(webItem) != "in_progress" {
		t.Fatalf("still present: %d %v (item %s)", code, got, itemStatus(webItem))
	}
	if got["after"].(map[string]any)["commit"] != after || got["before"].(map[string]any)["scan_job_id"] != scan1.String() ||
		got["before"].(map[string]any)["result_count"].(float64) != 2 || got["after"].(map[string]any)["result_count"].(float64) != 1 {
		t.Errorf("before/after evidence: %v %v", got["before"], got["after"])
	}
	// Finished evidence is immutable.
	if _, err := appPool.Exec(ctx, `UPDATE remediation_verifications SET result = 'fixed' WHERE id = $1`, got["id"]); err == nil {
		t.Error("verification evidence changed")
	}

	// 2. Gone, but a new result in the affected file: regression reported, not closed.
	verify(webItem)
	job = lease()
	result(job, map[string]any{"status": "completed", "before_commit": before, "after_commit": after,
		"results": map[string]any{"opengrep": map[string]any{"before": beforeRes, "after": []any{r("go.open-redirect", "app/web.go", 40)}}}})
	_, vs = h.user(owner, "GET", "/api/v1/remediation/items/"+webItem["id"].(string)+"/verifications", nil)
	got = vs["items"].([]any)[0].(map[string]any)
	regs := got["regressions"].([]any)
	if got["result"] != "regressed" || len(regs) != 1 || regs[0].(map[string]any)["rule_id"] != "go.open-redirect" || itemStatus(webItem) == "closed" {
		t.Fatalf("regressed: %v (item %s)", got, itemStatus(webItem))
	}

	// 3. A failed rescan changes nothing but is recorded.
	verify(webItem)
	job = lease()
	result(job, map[string]any{"status": "failed", "failure_reason": "clone failed: token=ghp_secretsecretsecretsecretsecret12345"})
	_, vs = h.user(owner, "GET", "/api/v1/remediation/items/"+webItem["id"].(string)+"/verifications", nil)
	got = vs["items"].([]any)[0].(map[string]any)
	if got["status"] != "failed" || got["result"] != nil || strings.Contains(got["failure_reason"].(string), "ghp_secret") || itemStatus(webItem) != "in_progress" {
		t.Fatalf("failed: %v (item %s)", got, itemStatus(webItem))
	}

	// 4. Proven gone: the item closes, with the proving verification.
	verify(webItem)
	job = lease()
	result(job, map[string]any{"status": "completed", "before_commit": before, "after_commit": after,
		"results": map[string]any{"opengrep": map[string]any{"before": beforeRes, "after": []any{}}}})
	var closedBy *uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT closed_by_verification_id FROM remediation_items WHERE id = $1`, webItem["id"]).Scan(&closedBy)
	_, vs = h.user(owner, "GET", "/api/v1/remediation/items/"+webItem["id"].(string)+"/verifications", nil)
	got = vs["items"].([]any)[0].(map[string]any)
	if itemStatus(webItem) != "closed" || closedBy == nil || closedBy.String() != got["id"] || got["result"] != "fixed" {
		t.Fatalf("fixed: item %s closed by %v; %v", itemStatus(webItem), closedBy, got)
	}
	for _, f := range got["findings"].([]any) {
		fm := f.(map[string]any)
		if fm["reproduced"] != true || fm["removed"] != true || fm["status_before"] != "in_progress" && fm["status_before"] != "open" {
			t.Errorf("per-finding evidence: %v", fm)
		}
	}
	// Findings are resolved by scans only.
	var fst string
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, xss).Scan(&fst)
	if fst != "open" {
		t.Errorf("verification changed the finding: %s", fst)
	}
	var closedAudit int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'remediation_item.closed' AND target_id = $1`, webItem["id"]).Scan(&closedAudit)
	if closedAudit != 1 {
		t.Errorf("closing audited: %d", closedAudit)
	}

	// --- verification with a finished scan of the repository -----------------------
	// A scan where the dependency finding is gone (trivy-fs ran) but a new
	// finding appeared in go.sum: regression.
	scan2 := seedScan(t, repo, after, "trivy-fs")
	newDep := seedFinding(t, repo, "medium", "sca", "CVE-2099-0002", "go.sum", []string{"trivy-fs"}, &scan2)
	code, v := h.user(engineer, "POST", "/api/v1/remediation/items/"+depItem["id"].(string)+"/verify", map[string]any{"scan_job_id": scan2})
	if code != 202 || v["status"] != "completed" || v["result"] != "regressed" || len(v["regressions"].([]any)) != 1 || v["trigger"] != "existing_scan" {
		t.Fatalf("existing scan with regression: %d %v", code, v)
	}
	if _, err := appPool.Exec(ctx, `DELETE FROM findings WHERE id = $1`, newDep); err != nil {
		t.Fatal(err)
	}
	// A scan in which the finding's scanner did not run proves nothing.
	scan3 := seedScan(t, repo, after, "gitleaks")
	if code, v := h.user(engineer, "POST", "/api/v1/remediation/items/"+depItem["id"].(string)+"/verify", map[string]any{"scan_job_id": scan3}); code != 202 || v["result"] != "inconclusive" {
		t.Errorf("scanner did not run: %d %v", code, v)
	}
	// Still reported by the scan.
	scan4 := seedScan(t, repo, after, "trivy-fs")
	var res4 uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT id FROM scan_results WHERE scan_job_id = $1`, scan4).Scan(&res4)
	if _, err := appPool.Exec(ctx, `INSERT INTO finding_occurrences (id, organization_id, finding_id, scan_result_id, file_path) VALUES ($1, $2, $3, $4, 'go.sum')`,
		uuid.Must(uuid.NewV7()), orgID, dep, res4); err != nil {
		t.Fatal(err)
	}
	if code, v := h.user(engineer, "POST", "/api/v1/remediation/items/"+depItem["id"].(string)+"/verify", map[string]any{"scan_job_id": scan4}); code != 202 || v["result"] != "still_present" {
		t.Errorf("still in the scan: %d %v", code, v)
	}
	scan5 := seedScan(t, repo, after, "trivy-fs")
	if code, v := h.user(engineer, "POST", "/api/v1/remediation/items/"+depItem["id"].(string)+"/verify", map[string]any{"scan_job_id": scan5}); code != 202 || v["result"] != "fixed" {
		t.Fatalf("gone in the scan: %d %v", code, v)
	}
	if itemStatus(depItem) != "closed" {
		t.Errorf("dependency item closed: %s", itemStatus(depItem))
	}
	// Reopen is allowed (a regression found later).
	if code, it := h.user(owner, "PATCH", "/api/v1/remediation/items/"+depItem["id"].(string), map[string]any{"status": "open"}); code != 200 || it["status"] != "open" || it["closed_at"] != nil {
		t.Errorf("reopen: %d %v", code, it)
	}

	// --- feedback loop: a merged fix pull request queues a targeted rescan ---------
	fixPR := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO fix_pull_requests (id, organization_id, repository_id, kind, package_name, target_version, grouping, status, pr_url)
		VALUES ($1, $2, $3, 'ai_code', 'app/db.go', 'ai-fix', 'finding', 'open', 'https://github.com/acme/x/pull/7')`, fixPR, orgID, repo); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO fix_pull_request_findings (fix_pull_request_id, finding_id) VALUES ($1, $2)`, fixPR, sqli); err != nil {
		t.Fatal(err)
	}
	code, it := h.user(owner, "GET", "/api/v1/remediation/items/"+sqliItem["id"].(string), nil)
	if code != 200 || it["fix_pull_request"] == nil || it["fix_pull_request"].(map[string]any)["pr_url"] != "https://github.com/acme/x/pull/7" {
		t.Fatalf("fix PR linked from the finding: %v", it["fix_pull_request"])
	}
	if n, err := h.rem.QueueMergedFixPRs(ctx); err != nil || n != 0 {
		t.Fatalf("open fix PR queues nothing: %d %v", n, err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE fix_pull_requests SET status = 'merged', finished_at = now() WHERE id = $1`, fixPR); err != nil {
		t.Fatal(err)
	}
	if n, err := h.rem.QueueMergedFixPRs(ctx); err != nil || n != 1 {
		t.Fatalf("merged fix PR: %d %v", n, err)
	}
	if n, _ := h.rem.QueueMergedFixPRs(ctx); n != 0 {
		t.Errorf("queued twice: %d", n)
	}
	var trig, vst string
	var vpr *uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT trigger, status, fix_pull_request_id FROM remediation_verifications WHERE item_id = $1 ORDER BY created_at DESC LIMIT 1`,
		sqliItem["id"]).Scan(&trig, &vst, &vpr)
	if trig != "fix_pr_merged" || vst != "queued" || vpr == nil || *vpr != fixPR || itemStatus(sqliItem) != "verifying" {
		t.Fatalf("feedback verification: %s %s %v item %s", trig, vst, vpr, itemStatus(sqliItem))
	}
	job = lease()
	result(job, map[string]any{"status": "completed", "before_commit": before, "after_commit": after,
		"results": map[string]any{"opengrep": map[string]any{"before": []any{r("go.sqli", "app/db.go", 10)}, "after": []any{}}}})
	if itemStatus(sqliItem) != "closed" {
		t.Errorf("merged and proven: %s", itemStatus(sqliItem))
	}
	// A merged fix of an item that cannot be rescanned records why.
	if _, err := appPool.Exec(ctx, `UPDATE remediation_items SET fix_pull_request_id = $2 WHERE id = $1`, impItem["id"], fixPR); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE fix_pull_requests SET finished_at = now() WHERE id = $1`, fixPR); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	_, _ = h.rem.QueueMergedFixPRs(ctx)
	var reason string
	_ = appPool.QueryRow(ctx, `SELECT failure_reason FROM remediation_verifications WHERE item_id = $1 AND trigger = 'fix_pr_merged' ORDER BY created_at DESC LIMIT 1`,
		impItem["id"]).Scan(&reason)
	if !strings.Contains(reason, "imported report") {
		t.Errorf("unverifiable merged fix: %q", reason)
	}
	// Flag off for the organization: the loop leaves it alone.
	setFlag(t, "remediation_workspace", false)
	defer setFlag(t, "remediation_workspace", true)
	if n, _ := h.rem.QueueMergedFixPRs(ctx); n != 0 {
		t.Errorf("loop with the flag off: %d", n)
	}
}

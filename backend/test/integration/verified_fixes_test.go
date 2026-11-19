//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/ai"
	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

// Verified AI fixes through the API and the worker protocol, with a stub AI
// provider (no real AI call) and a fake SCM. The worker side (applying the
// diff, re-running the scanner, running tests) is covered by
// internal/worker/aifix_test.go; here the worker results are posted the way
// a worker reports them.

const aiFixSource = "import subprocess\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n\ndef load(data):\n    return yaml.load(data)\n" +
	"def ev(expr):\n    API_KEY = \"fake-key-value-0000\"\n    return eval(expr)\n"

func aiFixDiff(path, newLine string) string {
	return "--- a/" + path + "\n+++ b/" + path + "\n@@ -2,2 +2,2 @@\n def run(cmd):\n-    subprocess.call(cmd, shell=True)\n+    " + newLine + "\n"
}

func waitAIFix(t *testing.T, id string, want ...string) (string, string) {
	t.Helper()
	var st, reason string
	for i := 0; i < 100; i++ {
		_ = appPool.QueryRow(t.Context(), `SELECT status, failure_reason FROM ai_fix_proposals WHERE id = $1`, id).Scan(&st, &reason)
		for _, w := range want {
			if st == w {
				return st, reason
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("AI fix %s: status %q (%s), want %v", id, st, reason, want)
	return "", ""
}

func TestVerifiedAIFixes(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	pw := &fakePRWriter{branches: map[string]string{}, commits: map[string][]scm.FileChange{}, state: scm.PROpen}
	h.svc.FixPRTarget = func(context.Context, uuid.UUID, uuid.UUID) (scm.PullRequestWriter, scm.RepoRef, string, error) {
		return pw, scm.RepoRef{FullName: "acme/x"}, "main", nil
	}
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	fake := &fakeProvider{}
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	aiSvc := &ai.Service{DB: appPool, Authz: az, Secrets: &secrets.Store{Keys: kr}, Log: log, Principal: auth.PrincipalFrom,
		NewProvider: func(ai.Config) (ai.Provider, error) { return fake, nil }}
	aiMux := http.NewServeMux()
	aiSvc.Register(aiMux)
	aiCall := func(p *authz.Principal, method, path string, body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(auth.WithPrincipal(req.Context(), p))
		rec := httptest.NewRecorder()
		aiMux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	h.svc.AIFix = aiSvc
	var reads []string
	h.svc.ReadSource = func(_ context.Context, _, _ uuid.UUID, commit, path string) ([]byte, error) {
		reads = append(reads, commit+":"+path)
		return []byte(aiFixSource), nil
	}

	// Other tests may have configured AI: their default is set aside and
	// restored afterwards.
	var prevDefault *uuid.UUID
	_ = appPool.QueryRow(ctx, `UPDATE ai_configurations SET is_default = false WHERE organization_id = $1 AND is_default AND archived_at IS NULL
		RETURNING id`, orgID).Scan(&prevDefault)
	var myConfig string
	t.Cleanup(func() {
		bg := context.Background()
		if myConfig != "" {
			_, _ = appPool.Exec(bg, `UPDATE ai_configurations SET is_default = false, archived_at = now() WHERE id = $1`, myConfig)
		}
		if prevDefault != nil {
			_, _ = appPool.Exec(bg, `UPDATE ai_configurations SET is_default = true WHERE id = $1`, *prevDefault)
		}
	})

	admin := principalWithRole(t, authz.RoleSuperAdmin)
	analyst := principalWithRole(t, "security_analyst") // ai.fix + findings.triage, no repos.manage
	developer := scoped("developer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID})
	viewer := principalWithRole(t, "viewer")

	// A scan produces SAST findings (opengrep) at a known commit.
	repo := createRepo(t, "aifix-"+uuid.NewString()[:6])
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "aifix-sast-" + uuid.NewString()[:6], "family": "sast",
		"scanners": map[string]string{"opengrep": "1.0"}})
	sastToken := reg["token"].(string)
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	job := h.leaseJob(sastToken, q["job_id"].(string))
	jobID := job["job_id"].(string)
	h.worker(sastToken, "POST", "/internal/worker/v1/jobs/"+jobID+"/results", map[string]any{
		"scanner": "opengrep", "version": "1.0", "status": "succeeded", "output_gzip": fixture(t, "opengrep.sarif")})
	const scanned = "89abcdef0123456789abcdef0123456789abcdef"
	h.worker(sastToken, "POST", "/internal/worker/v1/jobs/"+jobID+"/complete", map[string]any{"status": "succeeded", "commit_sha": scanned})
	var findingID uuid.UUID
	var rule, file string
	if err := appPool.QueryRow(ctx, `SELECT id, rule_id, file_path FROM findings WHERE repository_id = $1 AND rule_id LIKE '%subprocess-shell-true'`, repo).
		Scan(&findingID, &rule, &file); err != nil {
		t.Fatalf("no shell=True finding: %v", err)
	}
	fp := "/api/v1/findings/" + findingID.String() + "/ai-fixes"

	// No provider configured: unavailable, with a clear reason; never on by default.
	code, el := h.user(analyst, "GET", fp, nil)
	if code != 200 || el["available"] != false || !strings.Contains(el["reason"].(string), "No AI provider is configured") || el["can_request"] != true {
		t.Fatalf("eligibility without AI: %d %v", code, el)
	}
	if code, r := h.user(analyst, "POST", fp, nil); code != 422 || !strings.Contains(errMsg(r), "No AI provider") {
		t.Errorf("request without AI: %d %v", code, r)
	}
	_, prov := aiCall(admin, "POST", "/api/v1/ai/providers", map[string]any{"name": "Local model", "kind": "self_hosted", "base_url": "http://ollama:11434/v1"})
	code, cfg := aiCall(admin, "POST", "/api/v1/ai/configurations", map[string]any{"name": "Fixes " + uuid.NewString()[:6], "provider_id": prov["id"],
		"model": "qwen-coder", "is_default": true, "send_code_context": false, "redaction_patterns": []string{`fake-key-value-\d+`}})
	if code != 201 {
		t.Fatalf("configuration: %d %v", code, cfg)
	}
	myConfig = cfg["id"].(string)
	if _, el = h.user(analyst, "GET", fp, nil); el["available"] != false || !strings.Contains(el["reason"].(string), "does not allow sending source code") {
		t.Errorf("code not allowed: %v", el)
	}
	if code, _ := aiCall(admin, "PUT", "/api/v1/ai/configurations/"+myConfig, map[string]any{"provider_id": prov["id"], "model": "qwen-coder",
		"send_code_context": true, "redaction_patterns": []string{`fake-key-value-\d+`}}); code != 200 {
		t.Fatalf("enable code: %d", code)
	}
	if code, el = h.user(analyst, "GET", fp, nil); code != 200 || el["available"] != true || el["scanner"] != "opengrep" || el["can_open_pr"] != false {
		t.Fatalf("eligibility: %d %v", code, el)
	}
	if _, el = h.user(viewer, "GET", fp, nil); el["can_request"] != false {
		t.Errorf("viewer can request: %v", el)
	}
	// Permission checks: ai.fix is required.
	if code, _ := h.user(developer, "POST", fp, nil); code != 403 {
		t.Errorf("developer (no ai.fix): %d", code)
	}

	// 1. A correct fix: proposed, verified by the worker, opened as a PR by a person.
	fake.mu.Lock()
	fake.response = `{"summary":"Pass an argument list instead of a shell string.","diff":` + jsonString(aiFixDiff(file, "subprocess.call(shlex.split(cmd))")) + `}`
	fake.mu.Unlock()
	code, fx := h.user(analyst, "POST", fp, nil)
	if code != 202 || fx["status"] != "generating" {
		t.Fatalf("request: %d %v", code, fx)
	}
	fixID := fx["id"].(string)
	if code, _ := h.user(analyst, "POST", fp, nil); code != 409 {
		t.Errorf("second request while one is in flight: %d", code)
	}
	waitAIFix(t, fixID, "queued")
	if len(reads) == 0 || reads[len(reads)-1] != scanned+":"+file {
		t.Errorf("source read: %v", reads)
	}
	fake.mu.Lock()
	prompt := fake.prompts[len(fake.prompts)-1]
	fake.mu.Unlock()
	if strings.Contains(prompt.User, "fake-key-value-0000") || !strings.Contains(prompt.User, "subprocess.call(cmd, shell=True)") ||
		!strings.Contains(prompt.User, rule) || prompt.Model != "qwen-coder" {
		t.Errorf("prompt (secret must be redacted, code and rule present): %s", prompt.User)
	}
	_, detail := h.user(viewer, "GET", "/api/v1/ai-fixes/"+fixID, nil)
	if detail["diff"] == "" || detail["provider"] != "self_hosted" || len(detail["transmitted_sha256"].(string)) != 64 {
		t.Errorf("detail: %v", detail)
	}
	if steps := detail["steps"].([]any); steps[0].(map[string]any)["status"] != "passed" || steps[3].(map[string]any)["status"] != "skipped" {
		t.Errorf("steps after proposal: %v", steps)
	}

	// Only a worker with the finding's scanner leases the verification.
	_, reg = h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "aifix-core-" + uuid.NewString()[:6], "family": "core",
		"scanners": map[string]string{"gitleaks": "8"}})
	coreToken := reg["token"].(string)
	if code, _ := h.worker(coreToken, "POST", "/internal/worker/v1/ai-fix-lease", map[string]any{}); code != 204 {
		t.Errorf("worker without opengrep leased: %d", code)
	}
	code, lease := h.worker(sastToken, "POST", "/internal/worker/v1/ai-fix-lease", map[string]any{})
	if code != 200 || lease["fix_id"] != fixID || lease["phase"] != "verify" || lease["commit_sha"] != scanned || lease["file_path"] != file ||
		lease["rule_id"] != rule || lease["credential"] == nil || !strings.Contains(lease["diff"].(string), "shlex.split") {
		t.Fatalf("lease: %d %v", code, lease)
	}
	if code, _ := h.worker(coreToken, "POST", "/internal/worker/v1/ai-fix-jobs/"+fixID+"/result", map[string]any{"phase": "verify", "status": "passed"}); code != 409 {
		t.Errorf("foreign worker result: %d", code)
	}
	patched := strings.Replace(aiFixSource, "subprocess.call(cmd, shell=True)", "subprocess.call(shlex.split(cmd))", 1)
	verifyResult := func(status, reason string, files []map[string]string) map[string]any {
		return map[string]any{"phase": "verify", "status": status, "failure_reason": reason, "base_commit": scanned,
			"steps": []map[string]string{{"key": "apply", "status": "passed", "detail": "1 hunk(s) applied"},
				{"key": "scan", "status": map[bool]string{true: "passed", false: "failed"}[status == "passed"], "detail": reason},
				{"key": "policy", "status": "failed", "detail": "a worker cannot change the policy step"}},
			"scan_evidence":      map[string]any{"scanner": "opengrep", "verdict": map[string]any{"reproduced": true, "removed": status == "passed"}},
			"before_report_gzip": fixture(t, "opengrep.sarif"), "after_report_gzip": gzB64([]byte(`{"version":"2.1.0","runs":[]}`)), "files": files}
	}
	good := []map[string]string{{"path": file, "content_base64": base64.StdEncoding.EncodeToString([]byte(patched))}}
	if code, r := h.worker(sastToken, "POST", "/internal/worker/v1/ai-fix-jobs/"+fixID+"/result", verifyResult("passed", "", good)); code != 204 {
		t.Fatalf("result: %d %v", code, r)
	}
	waitAIFix(t, fixID, "verified")
	_, detail = h.user(viewer, "GET", "/api/v1/ai-fixes/"+fixID, nil)
	steps := detail["steps"].([]any)
	if steps[0].(map[string]any)["status"] != "passed" || steps[1].(map[string]any)["status"] != "passed" || steps[2].(map[string]any)["status"] != "passed" ||
		detail["has_reports"] != true || detail["base_commit"] != scanned {
		t.Errorf("verified detail: %v", detail)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/ai-fixes/"+fixID+"/reports/before", nil).WithContext(auth.WithPrincipal(ctx, viewer))
	h.api.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "subprocess-shell-true") {
		t.Errorf("before report: %d", rec.Code)
	}

	// Opening the PR: needs findings.triage + repos.manage, and the repository's opt-in.
	pr := "/api/v1/ai-fixes/" + fixID + "/pull-request"
	if code, _ := h.user(analyst, "POST", pr, nil); code != 403 {
		t.Errorf("analyst without repos.manage: %d", code)
	}
	if code, r := h.user(admin, "POST", pr, nil); code != 422 || !strings.Contains(errMsg(r), "not enabled") {
		t.Errorf("fix PRs disabled: %d %v", code, r)
	}
	if code, _ := h.user(admin, "PUT", "/api/v1/repositories/"+repo.String()+"/fix-pr-settings", map[string]any{"enabled": true, "grouping": "finding"}); code != 200 {
		t.Fatalf("enable fix PRs: %d", code)
	}
	code, opened := h.user(admin, "POST", pr, nil)
	// The pull request is created in the background; on a fast machine it
	// may already be open when the response is built.
	if st := opened["status"]; code != 202 || opened["kind"] != "ai_code" || (st != "creating" && st != "open") {
		t.Fatalf("open PR: %d %v", code, opened)
	}
	waitFixStatus(t, opened["id"].(string), "open")
	pw.mu.Lock()
	last := pw.prs[len(pw.prs)-1]
	if !strings.HasPrefix(last.Branch, scm.FixBranchPrefix+"ai-") || pw.branches[last.Branch] != scanned || len(pw.commits[last.Branch]) != 1 ||
		string(pw.commits[last.Branch][0].Content) != patched || !strings.Contains(last.Body, "AI-proposed fix") || !strings.Contains(last.Body, "later scan") ||
		!strings.Contains(last.Title, "verified by PATHOS") {
		t.Errorf("pull request: %+v", last)
	}
	pw.mu.Unlock()
	if code, _ := h.user(admin, "POST", pr, nil); code != 409 {
		t.Errorf("second PR: %d", code)
	}
	var status string
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, findingID).Scan(&status)
	if status != "open" {
		t.Errorf("opening a PR must not resolve the finding: %s", status)
	}
	_, el = h.user(admin, "GET", fp, nil)
	if p0 := el["proposals"].([]any)[0].(map[string]any); p0["pull_request"] == nil || p0["pull_request"].(map[string]any)["status"] != "open" {
		t.Errorf("proposal PR: %v", p0)
	}

	// 2. A wrong fix: the scanner still reports the finding, so it fails and cannot become a PR.
	fake.mu.Lock()
	fake.response = `{"summary":"Strip the command.","diff":` + jsonString(aiFixDiff(file, "subprocess.call(cmd.strip(), shell=True)")) + `}`
	fake.mu.Unlock()
	_, fx = h.user(analyst, "POST", fp, nil)
	wrongID := fx["id"].(string)
	waitAIFix(t, wrongID, "queued")
	h.worker(sastToken, "POST", "/internal/worker/v1/ai-fix-lease", map[string]any{})
	h.worker(sastToken, "POST", "/internal/worker/v1/ai-fix-jobs/"+wrongID+"/result",
		verifyResult("failed", "the scanner still reports rule "+rule+" in "+file+" after the fix", nil))
	if _, reason := waitAIFix(t, wrongID, "failed"); !strings.Contains(reason, "still reports") {
		t.Errorf("wrong fix reason: %s", reason)
	}
	if code, _ := h.user(admin, "POST", "/api/v1/ai-fixes/"+wrongID+"/pull-request", nil); code != 422 {
		t.Errorf("PR from a failed fix: %d", code)
	}

	// 3. A fix touching a forbidden file is rejected before any worker sees it.
	fake.mu.Lock()
	fake.response = `{"summary":"Also tweak the build.","diff":` + jsonString(aiFixDiff(file, "subprocess.call(shlex.split(cmd))")+
		"--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1 +1 @@\n-on: push\n+on: pull_request_target\n") + `}`
	fake.mu.Unlock()
	_, fx = h.user(analyst, "POST", fp, nil)
	forbiddenID := fx["id"].(string)
	if _, reason := waitAIFix(t, forbiddenID, "rejected"); !strings.Contains(reason, "outside the finding's directory") {
		t.Errorf("forbidden file reason: %s", reason)
	}
	if code, _ := h.worker(sastToken, "POST", "/internal/worker/v1/ai-fix-lease", map[string]any{}); code != 204 {
		t.Errorf("a rejected fix was leased: %d", code)
	}

	// 4. Tests enabled for the repository (repos.manage); the fix breaks them.
	settings := "/api/v1/repositories/" + repo.String() + "/ai-fix-settings"
	if code, _ := h.user(analyst, "PUT", settings, map[string]any{"test_runner": "go"}); code != 403 {
		t.Errorf("analyst enables tests: %d", code)
	}
	if code, _ := h.user(admin, "PUT", settings, map[string]any{"test_runner": "make"}); code != 400 {
		t.Errorf("unknown runner: %d", code)
	}
	if code, st := h.user(admin, "PUT", settings, map[string]any{"test_runner": "go"}); code != 200 || st["test_runner"] != "go" {
		t.Fatalf("enable tests: %d %v", code, st)
	}
	fake.mu.Lock()
	fake.response = `{"summary":"Use an argument list.","diff":` + jsonString(aiFixDiff(file, "subprocess.call(shlex.split(cmd))")) + `}`
	fake.mu.Unlock()
	_, fx = h.user(analyst, "POST", fp, nil)
	testID := fx["id"].(string)
	waitAIFix(t, testID, "queued")
	h.worker(sastToken, "POST", "/internal/worker/v1/ai-fix-lease", map[string]any{})
	h.worker(sastToken, "POST", "/internal/worker/v1/ai-fix-jobs/"+testID+"/result", verifyResult("passed", "", good))
	waitAIFix(t, testID, "tests_queued")
	if code, _ := h.worker(sastToken, "POST", "/internal/worker/v1/ai-fix-lease", map[string]any{}); code != 204 {
		t.Errorf("tests leased by a non-fuzz worker: %d", code)
	}
	if code, _ := h.user(admin, "POST", "/api/v1/ai-fixes/"+testID+"/pull-request", nil); code != 422 {
		t.Errorf("PR before tests finished: %d", code)
	}
	_, reg = h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "aifix-fuzz-" + uuid.NewString()[:6], "family": "fuzz",
		"scanners": map[string]string{"go-fuzz": "1"}})
	fuzzToken := reg["token"].(string)
	code, lease = h.worker(fuzzToken, "POST", "/internal/worker/v1/ai-fix-lease", map[string]any{})
	if code != 200 || lease["fix_id"] != testID || lease["phase"] != "test" || lease["test_runner"] != "go" || lease["commit_sha"] != scanned {
		t.Fatalf("test lease: %d %v", code, lease)
	}
	if code, _ := h.worker(fuzzToken, "POST", "/internal/worker/v1/ai-fix-jobs/"+testID+"/result", map[string]any{"phase": "verify", "status": "passed"}); code != 400 {
		t.Errorf("wrong phase accepted: %d", code)
	}
	h.worker(fuzzToken, "POST", "/internal/worker/v1/ai-fix-jobs/"+testID+"/result", map[string]any{"phase": "test", "status": "failed",
		"failure_reason": "the tests pass without the fix and fail with it (exit 1)",
		"steps":          []map[string]string{{"key": "tests", "status": "failed", "detail": "the tests pass without the fix and fail with it (exit 1)"}},
		"test_log":       "=== tests without the fix (exit 0) ===\nok\n=== tests with the fix (exit 1) ===\n--- FAIL: TestRun\x00\n"})
	if _, reason := waitAIFix(t, testID, "failed"); !strings.Contains(reason, "fail with it") {
		t.Errorf("broken tests reason: %s", reason)
	}
	_, detail = h.user(viewer, "GET", "/api/v1/ai-fixes/"+testID, nil)
	if !strings.Contains(detail["test_log"].(string), "FAIL: TestRun") || detail["steps"].([]any)[3].(map[string]any)["status"] != "failed" {
		t.Errorf("test evidence: %v", detail)
	}

	// Rate limit per user.
	for i := 0; i < 10; i++ {
		_, _ = appPool.Exec(ctx, `INSERT INTO ai_fix_proposals (id, organization_id, repository_id, finding_id, status, scanner_key, file_path, requested_by)
			VALUES (gen_random_uuid(), $1, $2, $3, 'failed', 'opengrep', 'app.py', $4)`, orgID, repo, findingID, analyst.UserID)
	}
	if code, _ := h.user(analyst, "POST", fp, nil); code != 429 {
		t.Errorf("rate limit: %d", code)
	}

	var audits int
	_ = appPool.QueryRow(ctx, `SELECT count(DISTINCT action) FROM audit_logs WHERE target_id = $1 AND action IN ('ai_fix.request', 'ai_fix.proposed',
		'ai_fix.verified', 'ai_fix.failed', 'ai_fix.rejected', 'ai_fix.pull_request', 'ai_fix.rate_limited')`, findingID.String()).Scan(&audits)
	if audits != 7 {
		t.Errorf("audited actions: %d of 7", audits)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

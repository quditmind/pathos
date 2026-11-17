//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/policy"
	"pathos/internal/review"
	"pathos/internal/scm"
)

func TestSecurityPolicies(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	ps := &policy.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	mux := newMux(ps.Register)
	call := func(p *authz.Principal, method, path string, body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(auth.WithPrincipal(ctx, p))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	viewer := scoped("viewer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID})
	h := newScanHarness(t)
	statuses := &fakeStatuses{}
	h.svc.StatusWriter = func(context.Context, uuid.UUID, uuid.UUID) (scm.StatusWriter, scm.RepoRef, error) {
		return statuses, scm.RepoRef{FullName: "acme/x"}, nil
	}
	repo := createRepo(t, "policy-"+uuid.NewString()[:6])
	tag := uuid.NewString()[:6]

	// Validation and permissions.
	def := map[string]any{"name": "No high SCA " + tag, "conditions": map[string]any{"min_severity": "high", "categories": []string{"sca"},
		"repository_ids": []string{repo.String()}}, "actions": map[string]any{"block": true, "require_review": true, "sla_days": 3, "notify": true}}
	if code, _ := call(viewer, "POST", "/api/v1/security-policies", def); code != 403 {
		t.Errorf("viewer cannot create policies: %d", code)
	}
	if code, out := call(admin, "POST", "/api/v1/security-policies", map[string]any{"name": "x", "conditions": map[string]any{}, "actions": map[string]any{"block": true}}); code != 400 {
		t.Errorf("empty conditions: %d %v", code, out)
	}
	code, pol := call(admin, "POST", "/api/v1/security-policies", def)
	if code != 201 || pol["applies_to_pull_requests"] != true {
		t.Fatalf("create: %d %v", code, pol)
	}
	pid := pol["id"].(string)
	if code, _ := call(admin, "POST", "/api/v1/security-policies", def); code != 409 {
		t.Errorf("duplicate name: %d", code)
	}

	// A scan of the repository: new high SCA findings violate the policy,
	// so the execution's gate fails.
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "pol-" + tag, "family": "core"})
	token := reg["token"].(string)
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	job := h.leaseJob(token, q["job_id"].(string))
	jid := job["job_id"].(string)
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{
		"scanner": "trivy-fs", "version": "t", "status": "succeeded", "output_gzip": fixture(t, "trivy-fs.sarif")})
	if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/complete", map[string]any{"status": "succeeded"}); code != 200 {
		t.Fatalf("complete: %d %v", code, out)
	}
	var gate bool
	_ = appPool.QueryRow(ctx, `SELECT gate_failed FROM scan_jobs WHERE id = $1`, jid).Scan(&gate)
	if !gate {
		t.Error("a new finding violating a blocking policy fails the gate")
	}
	var gateEvent string
	_ = appPool.QueryRow(ctx, `SELECT message FROM scan_job_events WHERE scan_job_id = $1 AND stage = 'finalize' AND message LIKE 'security gate failed%'`, jid).Scan(&gateEvent)
	if !strings.Contains(gateEvent, "No high SCA "+tag) {
		t.Errorf("gate event names the policy: %q", gateEvent)
	}
	var matching, violations int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND category = 'sca' AND severity IN ('critical','high') AND status = 'open'`, repo).Scan(&matching)
	_, vs := call(admin, "GET", "/api/v1/security-policies/"+pid+"/violations", nil)
	violations = len(vs["items"].([]any))
	if matching == 0 || violations != matching {
		t.Fatalf("violations %d, matching findings %d", violations, matching)
	}
	// SLA tightened to 3 days.
	var late int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM policy_violations v JOIN findings f ON f.id = v.finding_id
		WHERE v.policy_id = $1 AND (f.sla_due_at IS NULL OR f.sla_due_at > f.first_seen_at + interval '3 days')`, pid).Scan(&late)
	if late != 0 {
		t.Errorf("SLA tightened for every violation, %d not", late)
	}
	// One notification per repository.
	var events int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE event_key = 'policy.violated' AND payload->>'policy_id' = $1`, pid).Scan(&events)
	if events != 1 {
		t.Errorf("policy.violated events: %d", events)
	}
	// Human Eye queues the violating findings, citing the policy.
	rs := &review.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom, Evidence: &memBlobs{m: map[string][]byte{}}}
	if _, err := rs.Ingest(ctx, orgID); err != nil {
		t.Fatal(err)
	}
	var queued int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM human_reviews hr JOIN policy_violations v ON v.finding_id = hr.finding_id
		WHERE v.policy_id = $1 AND hr.source_reason = $2`, pid, "Required by security policy: No high SCA "+tag).Scan(&queued)
	if queued != violations {
		t.Errorf("reviews required by policy: %d of %d", queued, violations)
	}
	// Re-evaluation is idempotent: no second notification.
	if code, _ := call(admin, "POST", "/api/v1/security-policies/evaluate", nil); code != 200 {
		t.Errorf("evaluate: %d", code)
	}
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE event_key = 'policy.violated' AND payload->>'policy_id' = $1`, pid).Scan(&events)
	if events != 1 {
		t.Errorf("notified once: %d", events)
	}
	// Preview of a draft and the finding's policies.
	code, pv := call(viewer, "POST", "/api/v1/security-policies/preview", map[string]any{"conditions": map[string]any{"min_severity": "high", "categories": []string{"sca"},
		"repository_ids": []string{repo.String()}}})
	if code != 200 || int(pv["matching"].(float64)) != matching {
		t.Errorf("preview: %d %v", code, pv)
	}
	fid := vs["items"].([]any)[0].(map[string]any)["finding_id"].(string)
	if code, fp := call(viewer, "GET", "/api/v1/findings/"+fid+"/policies", nil); code != 200 || len(fp["items"].([]any)) != 1 {
		t.Errorf("finding policies: %d %v", code, fp)
	}
	other := scoped("viewer", authz.Scope{Type: authz.ScopeRegion, ID: uuid.New()})
	if code, _ := call(other, "GET", "/api/v1/findings/"+fid+"/policies", nil); code != 404 {
		t.Errorf("out of scope: %d", code)
	}

	// Pull requests: report-only severity gate, but a blocking SAST policy
	// fails the check.
	h.user(admin, "PUT", "/api/v1/repositories/"+repo.String()+"/pr-settings", map[string]any{"enabled": true, "gate_severity": "none"})
	code, sast := call(admin, "POST", "/api/v1/security-policies", map[string]any{"name": "No SAST " + tag,
		"conditions": map[string]any{"categories": []string{"sast"}, "repository_ids": []string{repo.String()}}, "actions": map[string]any{"block": true}})
	if code != 201 {
		t.Fatalf("sast policy: %d %v", code, sast)
	}
	h.svc.OnWebhookEvent(ctx, orgID, repo, scm.WebhookEvent{Kind: "pull_request", Ref: "feature/p", CommitSHA: "abcdefabcdefabcdefabcdefabcdefabcdefabcd", PullRequest: 9})
	var checkJob string
	_ = appPool.QueryRow(ctx, `SELECT scan_job_id FROM pr_checks WHERE repository_id = $1 AND pull_request = 9`, repo).Scan(&checkJob)
	prJob := h.leaseJob(token, checkJob)
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+prJob["job_id"].(string)+"/results", map[string]any{
		"scanner": "opengrep", "version": "t", "status": "succeeded", "output_gzip": fixture(t, "opengrep.sarif")})
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+prJob["job_id"].(string)+"/complete", map[string]any{"status": "succeeded"})
	var st, summary string
	_ = appPool.QueryRow(ctx, `SELECT status, summary FROM pr_checks WHERE scan_job_id = $1`, checkJob).Scan(&st, &summary)
	if st != "failed" || !strings.Contains(summary, "Blocked by policy No SAST "+tag) {
		t.Errorf("PR blocked by policy: %s %q", st, summary)
	}

	// Disabling resolves the open violations; deleting is audited.
	def["enabled"] = false
	if code, out := call(admin, "PUT", "/api/v1/security-policies/"+pid, def); code != 200 || out["open_violations"].(float64) != 0 || out["version"].(float64) != 2 {
		t.Errorf("disable: %d %v", code, out)
	}
	if code, _ := call(admin, "DELETE", "/api/v1/security-policies/"+sast["id"].(string), nil); code != 204 {
		t.Errorf("delete: %d", code)
	}
	var audits int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE target_type = 'security_policy' AND target_id IN ($1, $2) AND created_at > $3`,
		pid, sast["id"], time.Now().Add(-time.Hour)).Scan(&audits)
	if audits != 4 {
		t.Errorf("create x2, update, delete audited: %d", audits)
	}
}

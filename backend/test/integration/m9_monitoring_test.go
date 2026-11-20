//go:build integration

package integration

// PATHOS 3.0 M9: continuous monitoring feed, architecture drift and the
// lifecycle feedback loops 1-7, each triggered by its source event and
// checked by its target effect (docs/user-guide/monitoring.md).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/ai"
	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/compliance"
	"pathos/internal/feedback"
	"pathos/internal/gates"
	"pathos/internal/intel"
	"pathos/internal/inventory"
	"pathos/internal/monitoring"
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/policy"
	"pathos/internal/releases"
	"pathos/internal/remediation"
	"pathos/internal/review"
	"pathos/internal/risk"
	"pathos/internal/scm"
	"pathos/internal/secrets"
	"pathos/internal/threatmodel"
	"pathos/internal/vuln"
)

// m9Harness wires the services as internal/server does: the scan service
// (worker API), CodeGraph, threat models, the feedback loops, remediation,
// gates, policies, notifications and the monitoring API.
type m9Harness struct {
	*graphHarness
	tm    *threatmodel.Service
	loops *feedback.Loops
	rem   *remediation.Service
	store *secrets.Store
}

func newM9Harness(t *testing.T) *m9Harness {
	t.Helper()
	h := newGraphHarness(t)
	tm := &threatmodel.Service{DB: appPool, Authz: h.svc.Authz, Log: log, Principal: auth.PrincipalFrom}
	tm.Register(h.api)
	loops := &feedback.Loops{DB: appPool, Log: log, Threats: tm}
	h.graph.OnSnapshotReady = loops.OnSnapshotReady
	h.svc.OnScanFinished = func(ctx context.Context, org, job uuid.UUID) {
		loops.OnScanFinished(ctx, org, job)
		h.graph.OnScanFinished(ctx, org, job)
	}
	rem := &remediation.Service{DB: appPool, Authz: h.svc.Authz, Log: log, Principal: h.svc.Principal,
		ScannerConfig: h.svc.ScannerConfigFor, CloneCredential: h.svc.CloneCredential}
	h.svc.WorkerRoutes = []func(*http.ServeMux){rem.RegisterWorker}
	h.internal = h.svc.InternalHandler()
	rem.Register(h.api)
	(&gates.Service{DB: appPool, Authz: h.svc.Authz, Log: log, Principal: h.svc.Principal}).Register(h.api)
	(&policy.Service{DB: appPool, Authz: h.svc.Authz, Log: log, Principal: h.svc.Principal}).Register(h.api)
	(&monitoring.Service{DB: appPool, Authz: h.svc.Authz, Log: log, Principal: auth.PrincipalFrom}).Register(h.api)
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	store := &secrets.Store{Keys: kr}
	(&notify.Service{DB: appPool, Authz: h.svc.Authz, Secrets: store, Log: log, Principal: auth.PrincipalFrom, BaseURL: "https://pathos.test"}).Register(h.api)
	return &m9Harness{graphHarness: h, tm: tm, loops: loops, rem: rem, store: store}
}

func m9Flags(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		setFlag(t, n, true)
	}
	t.Cleanup(func() {
		for _, n := range names {
			setFlag(t, n, false)
		}
	})
}

// m9App creates an application with one repository.
func m9App(t *testing.T, prefix string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	repo := createRepo(t, prefix+"-"+uuid.NewString()[:6])
	app := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(t.Context(), `INSERT INTO applications (id, organization_id, name, criticality) VALUES ($1, $2, $3, 'high')`,
		app, orgID, "M9 "+prefix+" "+uuid.NewString()[:6]); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(t.Context(), `UPDATE repositories SET application_id = $2 WHERE id = $1`, repo, app); err != nil {
		t.Fatal(err)
	}
	return app, repo
}

// feed returns the feed events of a repository (or application) of a type.
func (h *m9Harness) feed(p *authz.Principal, query string) []map[string]any {
	h.t.Helper()
	code, b := h.user(p, "GET", "/api/v1/monitoring/events?"+query, nil)
	if code != 200 {
		h.t.Fatalf("feed %s: %d %v", query, code, b)
	}
	out := []map[string]any{}
	for _, x := range b["items"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

// completeGraphJob plays the graph worker for a queued discovery execution.
func (h *m9Harness) completeGraphJob(token, jobID, commit string, doc []byte) {
	t := h.t
	t.Helper()
	job := leaseJob(t, h.scanHarness, token, jobID)
	if job["kind"] != "codegraph" {
		t.Fatalf("lease kind: %v", job["kind"])
	}
	if code, r := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/results", map[string]any{"scanner": "pathos-graph",
		"version": "test", "status": "succeeded", "duration_ms": 1000, "output_gzip": gzB64(doc)}); code != 200 {
		t.Fatalf("upload graph: %d %v", code, r)
	}
	if code, r := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/complete", map[string]any{"status": "succeeded", "commit_sha": commit}); code != 200 {
		t.Fatalf("complete: %d %v", code, r)
	}
}

// graphV3 is fixture v2 with dependency changes: redis 5.0.8 → 5.0.9 and
// a new component (test data).
func graphV3(t *testing.T) []byte {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal(graphFixture(t, "fixture-graph-v2.json"), &d); err != nil {
		t.Fatal(err)
	}
	nodes := d["nodes"].([]any)
	for _, n := range nodes {
		m := n.(map[string]any)
		if m["key"] == "comp:pkg:pypi/redis" {
			a := m["attrs"].(map[string]any)
			a["version"], a["purl"] = "5.0.9", "pkg:pypi/redis@5.0.9"
		}
	}
	d["nodes"] = append(nodes, map[string]any{"key": "comp:pkg:pypi/requests", "type": "component", "label": "requests", "parent": "",
		"layer": "dependency", "attrs": map[string]any{"ecosystem": "pypi", "file": "requirements.txt", "purl": "pkg:pypi/requests@2.32.3",
			"source": "sbom", "technology": "pypi", "version": "2.32.3"}})
	d["edges"] = append(d["edges"].([]any), map[string]any{"source": "repository", "target": "comp:pkg:pypi/requests", "type": "depends_on",
		"evidence": "verified", "evidence_refs": []any{map[string]any{"kind": "sbom", "ref": "pkg:pypi/requests@2.32.3", "detail": "declared in requirements.txt"}}})
	raw, _ := json.Marshal(d)
	return raw
}

func TestM9MonitoringAPI(t *testing.T) {
	ctx := t.Context()
	h := newM9Harness(t)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	viewer := scoped("viewer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID})
	_, repo := m9App(t, "api")

	// Behind the flag: absent, and nothing is recorded.
	setFlag(t, monitoring.Flag, false)
	for _, path := range []string{"/api/v1/monitoring/events", "/api/v1/monitoring/drift", "/api/v1/monitoring/settings", "/api/v1/monitoring/summary"} {
		if code, b := h.user(admin, "GET", path, nil); code != 404 || errCode(b) != "PTH-PLAT-1007" {
			t.Errorf("flag off %s: %d %v", path, code, b)
		}
	}
	if id, err := monitoring.Record(ctx, appPool, monitoring.Event{OrgID: orgID, RepositoryID: &repo, Type: monitoring.TypeFindingsNew, Title: "x"}); err != nil || id != uuid.Nil {
		t.Errorf("recorded with the flag off: %v %v", id, err)
	}
	m9Flags(t, monitoring.Flag)

	// Settings: drift alerts off by default; settings.manage to change.
	if code, b := h.user(viewer, "GET", "/api/v1/monitoring/settings", nil); code != 200 || b["drift_alerts"] != false {
		t.Errorf("default settings: %d %v", code, b)
	}
	if code, _ := h.user(viewer, "PUT", "/api/v1/monitoring/settings", map[string]any{"drift_alerts": true}); code != 403 {
		t.Errorf("viewer changed settings: %d", code)
	}
	if code, b := h.user(admin, "PUT", "/api/v1/monitoring/settings", map[string]any{"drift_alert_min_severity": "info"}); code != 422 || errCode(b) != "PTH-MON-1102" {
		t.Errorf("invalid severity: %d %v", code, b)
	}

	// Recorded events, filters and keyset pagination.
	for i, sev := range []string{"low", "high", "critical"} {
		if _, err := monitoring.Record(ctx, appPool, monitoring.Event{OrgID: orgID, RepositoryID: &repo, Type: monitoring.TypeFindingsNew,
			Severity: sev, Title: fmt.Sprintf("api event %d", i), Evidence: map[string]any{"marker": "m9-api"}}); err != nil {
			t.Fatal(err)
		}
	}
	q := "repository_id=" + repo.String()
	if got := h.feed(admin, q+"&severity=high,critical"); len(got) != 2 {
		t.Errorf("severity filter: %d", len(got))
	}
	code, page := h.user(admin, "GET", "/api/v1/monitoring/events?"+q+"&limit=2", nil)
	if code != 200 || len(page["items"].([]any)) != 2 || page["next_cursor"] == nil {
		t.Fatalf("page 1: %d %v", code, page)
	}
	first := page["items"].([]any)[0].(map[string]any)
	if first["title"] != "api event 2" || first["loop"].(float64) != 7 || first["evidence_label"] != "verified" || first["application_id"] == nil {
		t.Errorf("newest first with loop, label and application: %v", first)
	}
	if got := h.feed(admin, q+"&limit=2&cursor="+page["next_cursor"].(string)); len(got) != 1 {
		t.Errorf("page 2: %d", len(got))
	}
	for _, bad := range []string{"type=nope", "severity=urgent", "loop=9", "since=yesterday", "limit=0", "cursor=x"} {
		if code, b := h.user(admin, "GET", "/api/v1/monitoring/events?"+bad, nil); code != 400 || errCode(b) != "PTH-MON-1101" {
			t.Errorf("%s: %d %v", bad, code, b)
		}
	}
	// Scope: a user of another business unit sees none of them.
	other := scoped("viewer", authz.Scope{Type: authz.ScopeBusinessUnit, ID: uuid.New()})
	if got := h.feed(other, q); len(got) != 0 {
		t.Errorf("out-of-scope user sees %d events", len(got))
	}
	repoViewer := scoped("viewer", authz.Scope{Type: authz.ScopeRepository, ID: repo})
	if got := h.feed(repoViewer, q); len(got) != 3 {
		t.Errorf("repository-scoped user sees %d events", len(got))
	}
	// CSV export: stamped, header row first.
	req := httptest.NewRequest("GET", "/api/v1/monitoring/events?format=csv&"+q, nil).WithContext(auth.WithPrincipal(ctx, admin))
	rec := httptest.NewRecorder()
	h.api.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "created_at,type,loop") || !strings.Contains(rec.Header().Get("X-PATHOS-Generated-By"), "PATHOS v") {
		t.Errorf("csv: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	// Summary.
	if code, b := h.user(admin, "GET", "/api/v1/monitoring/summary?days=7", nil); code != 200 || b["by_type"].(map[string]any)["findings.new"] == nil {
		t.Errorf("summary: %d %v", code, b)
	}
}

// TestM9LoopsArchitecture: loop 1 (new commit → rediscovery), loop 2
// (dependency change → reassessment), loop 3 (architecture change →
// threat model), architecture drift with evidence and drift alerts.
func TestM9LoopsArchitecture(t *testing.T) {
	quietNotifications(t)
	ctx := t.Context()
	h := newM9Harness(t)
	m9Flags(t, "codegraph", "threat_models", monitoring.Flag, "onboarding", "lifecycle_overview")
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	if code, b := h.user(admin, "PUT", "/api/v1/codegraph/settings", map[string]any{"auto_rebuild": true, "min_interval_minutes": 0, "keep_snapshots": 10}); code != 200 {
		t.Fatalf("settings: %d %v", code, b)
	}
	t.Cleanup(func() {
		h.user(admin, "PUT", "/api/v1/codegraph/settings", map[string]any{"auto_rebuild": true, "min_interval_minutes": 60, "keep_snapshots": 10})
		h.user(admin, "PUT", "/api/v1/threat-models/settings", map[string]any{"auto_update": true})
		h.user(admin, "PUT", "/api/v1/monitoring/settings", map[string]any{"drift_alerts": false, "drift_alert_min_severity": "high"})
	})
	app, repo := m9App(t, "loops")
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "graph-m9-" + uuid.NewString()[:6], "family": "graph",
		"scanners": map[string]string{"pathos-graph": "test"}})
	token := reg["token"].(string)
	rq := "repository_id=" + repo.String()

	// Baseline snapshot: a drift record without a comparison, no event.
	sid1 := h.runGraphBuild(admin, app, repo, token, strings.Repeat("a", 40), graphFixture(t, "fixture-graph.json"))
	var baseline bool
	if err := appPool.QueryRow(ctx, `SELECT from_snapshot_id IS NULL AND NOT has_changes FROM architecture_drifts WHERE to_snapshot_id = $1`, sid1).Scan(&baseline); err != nil || !baseline {
		t.Fatalf("baseline drift: %v %v", baseline, err)
	}
	if got := h.feed(admin, rq+"&type=architecture.drift"); len(got) != 0 {
		t.Errorf("baseline drift event: %v", got)
	}

	// An approved threat model of the application.
	author, approver := tmUser(t, "appsec_engineer"), tmUser(t, "security_manager")
	code, b := h.user(author, "POST", "/api/v1/threat-models", map[string]any{"application_id": app, "title": "M9 model", "generate": true})
	if code != 201 {
		t.Fatalf("threat model: %d %v", code, b)
	}
	modelID := b["model"].(map[string]any)["id"].(string)
	if _, err := appPool.Exec(ctx, `UPDATE threat_models SET status = 'approved', submitted_by = $2, submitted_at = now(), approved_by = $3, approved_at = now()
		WHERE id = $1`, modelID, author.UserID, approver.UserID); err != nil {
		t.Fatal(err)
	}
	var approvedThreats int
	var approvedAt any
	_ = appPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM threats WHERE threat_model_id = $1), updated_at FROM threat_models WHERE id = $1`, modelID).
		Scan(&approvedThreats, &approvedAt)

	// Loop 1: a push webhook on the scan branch queues a scan; when the
	// scan of the new commit finishes (the worker API calls the
	// OnScanFinished hook), a CodeGraph rediscovery is queued.
	commit2 := strings.Repeat("b", 40)
	h.svc.OnWebhookEvent(ctx, orgID, repo, scm.WebhookEvent{Kind: "push", Ref: "main", CommitSHA: commit2})
	var pushJob uuid.UUID
	if err := appPool.QueryRow(ctx, `SELECT id FROM scan_jobs WHERE repository_id = $1 AND trigger = 'push' AND status = 'queued'`, repo).Scan(&pushJob); err != nil {
		t.Fatal("the push did not queue a scan:", err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE scan_jobs SET status = 'succeeded', commit_sha = $2, started_at = now(), finished_at = now() WHERE id = $1`, pushJob, commit2); err != nil {
		t.Fatal(err)
	}
	h.svc.OnScanFinished(ctx, orgID, pushJob)
	var sid2, graphJob string
	if err := appPool.QueryRow(ctx, `SELECT id::text, scan_job_id::text FROM codegraph_snapshots WHERE repository_id = $1 AND trigger = 'scan' AND status = 'queued'`, repo).
		Scan(&sid2, &graphJob); err != nil {
		t.Fatal("loop 1: no rediscovery queued:", err)
	}
	ev := h.feed(admin, rq+"&type=rediscovery.queued")
	if len(ev) != 1 || ev[0]["evidence"].(map[string]any)["scan_job_id"] != pushJob.String() || ev[0]["subject_id"] != sid2 {
		t.Fatalf("loop 1 feed: %v", ev)
	}

	// The rediscovery runs: v3 adds a route, an internet-facing crossing
	// (fixture v2) and changes dependencies.
	h.completeGraphJob(token, graphJob, commit2, graphV3(t))
	var st string
	_ = appPool.QueryRow(ctx, `SELECT status FROM codegraph_snapshots WHERE id = $1`, sid2).Scan(&st)
	if st != "ready" && st != "partial" {
		t.Fatalf("snapshot %s", st)
	}

	// Architecture drift with evidence (snapshot ids and commit).
	drifts := h.feed(admin, rq+"&type=architecture.drift")
	if len(drifts) != 1 {
		t.Fatalf("drift events: %v", drifts)
	}
	dev := drifts[0]["evidence"].(map[string]any)
	if dev["from_snapshot_id"] != sid1 || dev["to_snapshot_id"] != sid2 || dev["commit"] != commit2 {
		t.Errorf("drift evidence: %v", dev)
	}
	code, dl := h.user(admin, "GET", "/api/v1/monitoring/drift?application_id="+app.String(), nil)
	if code != 200 || len(dl["items"].([]any)) != 1 {
		t.Fatalf("drift timeline: %d %v", code, dl)
	}
	dr := dl["items"].([]any)[0].(map[string]any)
	counts := dr["counts"].(map[string]any)
	if counts["added_routes"] == nil || counts["added_components"].(float64) != 1 || counts["changed_components"].(float64) != 1 {
		t.Errorf("drift counts: %v", counts)
	}
	code, dd := h.user(admin, "GET", "/api/v1/monitoring/drift/"+dr["id"].(string), nil)
	if code != 200 {
		t.Fatalf("drift detail: %d %v", code, dd)
	}
	sawRoute, sawEdgeEvidence := false, false
	for _, x := range dd["items"].([]any) {
		it := x.(map[string]any)
		if it["category"] == "route" && it["change"] == "added" && strings.Contains(it["key"].(string), "DELETE") {
			sawRoute = true
		}
		if (it["category"] == "boundary_crossing" || it["category"] == "internet_exposure") && len(it["evidence"].([]any)) > 0 {
			sawEdgeEvidence = true
		}
		if it["evidence_label"] == "" {
			t.Errorf("drift item without evidence label: %v", it)
		}
	}
	if !sawRoute || !sawEdgeEvidence {
		t.Errorf("drift detail route=%v edge evidence=%v: %v", sawRoute, sawEdgeEvidence, dd["items"])
	}
	if other := scoped("viewer", authz.Scope{Type: authz.ScopeBusinessUnit, ID: uuid.New()}); true {
		if code, _ := h.user(other, "GET", "/api/v1/monitoring/drift/"+dr["id"].(string), nil); code != 404 {
			t.Errorf("out-of-scope drift detail: %d", code)
		}
	}

	// Loop 2: the dependency change was reassessed.
	deps := h.feed(admin, rq+"&type=dependency.changed")
	if len(deps) != 1 {
		t.Fatalf("loop 2 feed: %v", deps)
	}
	det := deps[0]["details"].(map[string]any)
	if det["added"].(float64) != 1 || det["changed"].(float64) != 1 || det["not_in_scanned_sbom"].(float64) != 2 {
		t.Errorf("loop 2 details: %v", det)
	}

	// Loop 3: the approved model is unchanged; a new draft version was
	// generated from the new snapshot and is recorded in the feed.
	var status string
	var threatsNow int
	var updatedAt any
	_ = appPool.QueryRow(ctx, `SELECT status, (SELECT count(*) FROM threats WHERE threat_model_id = $1), updated_at FROM threat_models WHERE id = $1`, modelID).
		Scan(&status, &threatsNow, &updatedAt)
	if status != "approved" || threatsNow != approvedThreats || fmt.Sprint(updatedAt) != fmt.Sprint(approvedAt) {
		t.Errorf("approved model changed: %s %d/%d %v/%v", status, threatsNow, approvedThreats, updatedAt, approvedAt)
	}
	var draftID string
	if err := appPool.QueryRow(ctx, `SELECT id::text FROM threat_models WHERE lineage_id = (SELECT lineage_id FROM threat_models WHERE id = $1)
		AND version = 2 AND status = 'draft' AND $2 = ANY(codegraph_snapshot_ids)`, modelID, sid2).Scan(&draftID); err != nil {
		t.Fatal("loop 3: no regenerated draft:", err)
	}
	tmEv := h.feed(admin, "application_id="+app.String()+"&type=threat_model.updated")
	if len(tmEv) != 1 || tmEv[0]["subject_id"] != draftID || tmEv[0]["details"].(map[string]any)["approved_version"].(float64) != 1 {
		t.Fatalf("loop 3 feed: %v", tmEv)
	}

	// Drift alerts: off by default (no notification); on, a drift at or
	// above the minimum severity is sent through the notification channels.
	var alerts int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE event_key = 'architecture.drift' AND repository_id = $1`, repo).Scan(&alerts)
	if alerts != 0 {
		t.Errorf("drift alert sent while off: %d", alerts)
	}
	if code, b := h.user(admin, "PUT", "/api/v1/monitoring/settings", map[string]any{"drift_alerts": true, "drift_alert_min_severity": "low"}); code != 200 || b["drift_alerts"] != true {
		t.Fatalf("enable alerts: %d %v", code, b)
	}
	// Automatic threat model updates off: the next architecture change
	// marks the model for review instead.
	if code, b := h.user(admin, "PUT", "/api/v1/threat-models/settings", map[string]any{"auto_update": false}); code != 200 {
		t.Fatalf("tm settings: %d %v", code, b)
	}
	sid3 := h.runGraphBuild(admin, app, repo, token, strings.Repeat("c", 40), graphFixture(t, "fixture-graph.json"))
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE event_key = 'architecture.drift' AND repository_id = $1`, repo).Scan(&alerts)
	if alerts != 1 {
		t.Errorf("drift alert not queued: %d", alerts)
	}
	_, _ = appPool.Exec(ctx, `UPDATE notification_events SET processed_at = now() WHERE event_key = 'architecture.drift' AND repository_id = $1`, repo)
	rv := h.feed(admin, "application_id="+app.String()+"&type=threat_model.review_needed")
	if len(rv) != 1 || rv[0]["evidence"].(map[string]any)["snapshot_id"] != sid3 {
		t.Errorf("review needed: %v", rv)
	}
	var drafts int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM threat_models WHERE id = $1 AND $2 = ANY(codegraph_snapshot_ids)`, draftID, sid3).Scan(&drafts)
	if drafts != 0 {
		t.Error("the draft was regenerated although automatic updates are off")
	}

	// Lifecycle phases count the new modules (no "arrives in").
	inv := newInventoryAPI(t)
	code, lc := inv(admin, "GET", "/api/v1/applications/"+app.String()+"/lifecycle")
	if code != 200 {
		t.Fatalf("lifecycle: %d %v", code, lc)
	}
	ph := map[string]map[string]any{}
	for _, x := range lc["phases"].([]any) {
		m := x.(map[string]any)
		ph[m["key"].(string)] = m
	}
	if m := ph["discover"]["metrics"].(map[string]any); m["codegraph_snapshots"].(float64) < 3 {
		t.Errorf("discover: %v", ph["discover"])
	}
	if m := ph["threat_model"]["metrics"].(map[string]any); ph["threat_model"]["has_data"] != true || m["threat_models"].(float64) != 1 || m["threats"].(float64) == 0 {
		t.Errorf("threat model phase: %v", ph["threat_model"])
	}
	if m := ph["report"]["metrics"].(map[string]any); m["monitoring_events"].(float64) == 0 || m["drift_changes"].(float64) < 2 {
		t.Errorf("report phase: %v", ph["report"])
	}
}

// newInventoryAPI serves the inventory routes (lifecycle).
func newInventoryAPI(t *testing.T) func(p *authz.Principal, method, path string) (int, map[string]any) {
	mux := http.NewServeMux()
	invSvc(t).Register(mux)
	return func(p *authz.Principal, method, path string) (int, map[string]any) {
		req := httptest.NewRequest(method, path, nil).WithContext(auth.WithPrincipal(t.Context(), p))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
}

// TestM9LoopRiskRescore: loop 4 — new vulnerability intelligence (a CISA
// KEV import) re-scores the affected findings and the feed shows it.
func TestM9LoopRiskRescore(t *testing.T) {
	ctx := t.Context()
	h := newM9Harness(t)
	m9Flags(t, monitoring.Flag)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	_, repo := m9App(t, "intel")
	cve := fmt.Sprintf("CVE-2099-%d", 40000+int(uuid.New().ID()%9999))
	f := seedFinding(t, repo, "high", "sca", cve, "go.sum", []string{"trivy-fs"}, nil)
	if _, err := appPool.Exec(ctx, `UPDATE findings SET cve = $2, package_name = 'example.org/lib', package_version = '1.0.0', risk_dirty = true WHERE id = $1`, f, cve); err != nil {
		t.Fatal(err)
	}
	for {
		n, err := risk.Recompute(ctx, appPool, orgID, 500)
		if err != nil {
			t.Fatal(err)
		}
		if n < 500 {
			break
		}
	}
	// A new finding's first score is not "re-scoring": nothing yet.
	if got := h.feed(admin, "repository_id="+repo.String()+"&type=risk.rescored"); len(got) != 0 {
		t.Fatalf("first score recorded as re-score: %v", got)
	}
	var before float64
	_ = appPool.QueryRow(ctx, `SELECT risk_score FROM findings WHERE id = $1`, f).Scan(&before)

	// The intelligence sync adds the CVE to KEV (file import, same code
	// as the online sync).
	kev := `{"catalogVersion":"m9","vulnerabilities":[{"cveID":"` + cve + `","vendorProject":"Example","product":"lib","dueDate":"2099-01-01"}]}`
	if _, err := intel.Load(ctx, appPool, intel.KEV, "file", nil, []byte(kev)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = appPool.Exec(context.Background(), `DELETE FROM intel_kev WHERE cve_id = $1`, cve) })
	for {
		n, err := risk.Recompute(ctx, appPool, orgID, 500)
		if err != nil {
			t.Fatal(err)
		}
		if n < 500 {
			break
		}
	}
	var after float64
	var isKEV bool
	_ = appPool.QueryRow(ctx, `SELECT risk_score, kev FROM findings WHERE id = $1`, f).Scan(&after, &isKEV)
	if !isKEV || after <= before {
		t.Fatalf("finding not re-scored: kev=%v %v → %v", isKEV, before, after)
	}
	ev := h.feed(admin, "repository_id="+repo.String()+"&type=risk.rescored")
	if len(ev) != 1 {
		t.Fatalf("loop 4 feed: %v", ev)
	}
	det := ev[0]["details"].(map[string]any)
	if det["kev_added"].(float64) != 1 || !strings.Contains(fmt.Sprint(det["finding_ids"]), f.String()) || ev[0]["severity"] != "high" || ev[0]["loop"].(float64) != 4 {
		t.Errorf("loop 4 event: %v", ev[0])
	}
}

// TestM9LoopFixVerification: loop 5 — an item marked fix submitted queues
// the targeted rescan (an open fix pull request waits for its merge), the
// finished verification is in the feed; and the remediation ↔ threat link.
func TestM9LoopFixVerification(t *testing.T) {
	ctx := t.Context()
	h := newM9Harness(t)
	m9Flags(t, "remediation_workspace", monitoring.Flag)
	admin := realPrincipal(t, authz.RoleSuperAdmin)
	app, repo := m9App(t, "fix")
	commit := strings.Repeat("d1", 20)
	scan1 := seedScan(t, repo, commit, "opengrep")
	f1 := seedFinding(t, repo, "critical", "sast", "go.sqli", "app/db.go", []string{"opengrep"}, &scan1)
	f2 := seedFinding(t, repo, "high", "sast", "go.xss", "app/web.go", []string{"opengrep"}, &scan1)
	code, out := h.user(admin, "POST", "/api/v1/remediation/items", map[string]any{"finding_ids": []uuid.UUID{f1, f2}, "mode": "per_finding"})
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	it1 := out["items"].([]any)[0].(map[string]any)["id"].(string)
	it2 := out["items"].([]any)[1].(map[string]any)["id"].(string)

	// Item 2 has an open fix pull request: marking it fix submitted waits
	// for the merge (no verification yet).
	fp := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO fix_pull_requests (id, organization_id, repository_id, kind, package_name, target_version, grouping, status, pr_url)
		VALUES ($1, $2, $3, 'dependency', 'example.org/lib', '1.2.0', 'finding', 'open', 'https://github.com/acme/x/pull/9')`, fp, orgID, repo); err != nil {
		t.Fatal(err)
	} else if code, b := h.user(admin, "PATCH", "/api/v1/remediation/items/"+it2, map[string]any{"fix_pull_request_id": fp}); code != 200 {
		t.Fatalf("link fix pr: %d %v", code, b)
	}

	for _, id := range []string{it1, it2} {
		if code, b := h.user(admin, "PATCH", "/api/v1/remediation/items/"+id, map[string]any{"status": "fix_submitted"}); code != 200 {
			t.Fatalf("fix submitted: %d %v", code, b)
		}
	}
	var trig, vstatus, itemStatus string
	if err := appPool.QueryRow(ctx, `SELECT v.trigger, v.status, i.status FROM remediation_verifications v JOIN remediation_items i ON i.id = v.item_id
		WHERE v.item_id = $1`, it1).Scan(&trig, &vstatus, &itemStatus); err != nil {
		t.Fatal("loop 5: no verification queued:", err)
	}
	if trig != "fix_submitted" || vstatus != "queued" || itemStatus != "verifying" {
		t.Errorf("verification %s %s, item %s", trig, vstatus, itemStatus)
	}
	var n2 int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM remediation_verifications WHERE item_id = $1`, it2).Scan(&n2)
	if n2 != 0 {
		t.Errorf("an item with an open fix pull request was verified before the merge: %d", n2)
	}
	q := h.feed(admin, "repository_id="+repo.String()+"&type=fix.verification_queued")
	if len(q) != 1 || q[0]["subject_id"] != it1 || q[0]["details"].(map[string]any)["trigger"] != "fix_submitted" {
		t.Fatalf("loop 5 queued feed: %v", q)
	}

	// The fix merged path (M8 loop) also reaches the feed: the fix pull
	// request is merged and the background loop queues the rescan.
	if _, err := appPool.Exec(ctx, `UPDATE fix_pull_requests SET status = 'merged', finished_at = now() WHERE id = $1`, fp); err == nil {
		if _, err := h.rem.QueueMergedFixPRs(ctx); err != nil {
			t.Fatal(err)
		}
		if got := h.feed(admin, "repository_id="+repo.String()+"&type=fix.verification_queued"); len(got) != 2 || got[0]["details"].(map[string]any)["trigger"] != "fix_pr_merged" {
			t.Errorf("merged fix feed: %v", got)
		}
	}

	// A finished scan without the finding proves the fix: fix.verified.
	if _, err := appPool.Exec(ctx, `UPDATE remediation_verifications SET status = 'failed', failure_reason = 'superseded by test', finished_at = now() WHERE item_id = $1 AND status = 'queued'`, it1); err != nil {
		t.Fatal(err)
	}
	_, _ = appPool.Exec(ctx, `UPDATE remediation_items SET status = 'in_progress' WHERE id = $1`, it1)
	scan2 := seedScan(t, repo, strings.Repeat("e2", 20), "opengrep")
	if _, err := appPool.Exec(ctx, `UPDATE findings SET status = 'fixed', resolved_at = now(), last_scan_job_id = $2 WHERE id = $1`, f1, scan2); err != nil {
		t.Fatal(err)
	}
	if code, b := h.user(admin, "POST", "/api/v1/remediation/items/"+it1+"/verify", map[string]any{"scan_job_id": scan2}); code != 200 && code != 201 && code != 202 {
		t.Fatalf("verify with scan: %d %v", code, b)
	}
	if v := h.feed(admin, "repository_id="+repo.String()+"&type=fix.verified"); len(v) != 1 || v[0]["subject_id"] != it1 {
		t.Errorf("loop 5 verified feed: %v", v)
	}

	// Remediation ↔ threat link (both sides).
	m9Flags(t, "codegraph", "threat_models")
	tmodel, threat := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO threat_models (id, organization_id, lineage_id, application_id, method, title) VALUES ($1, $2, $1, $3, 'manual', 'M9 manual model')`,
		tmodel, orgID, app); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO threats (id, organization_id, threat_model_id, title, category, method, evidence_type, severity, confidence)
		VALUES ($1, $2, $3, 'Tampering with prices', 'tampering', 'manual', 'unverified', 'high', 0.5)`, threat, orgID, tmodel); err != nil {
		t.Fatal(err)
	}
	code, out = h.user(admin, "POST", "/api/v1/remediation/items", map[string]any{"threat_id": threat, "finding_ids": []uuid.UUID{}})
	if code != 201 {
		t.Fatalf("item for threat: %d %v", code, out)
	}
	ti := out["items"].([]any)[0].(map[string]any)
	if ti["kind"] != "threat_mitigation" || ti["threat"].(map[string]any)["id"] != threat.String() || ti["application_id"] != app.String() {
		t.Errorf("threat item: %v", ti)
	}
	// Code fix items cannot reference a threat; other applications' threats are refused.
	if code, b := h.user(admin, "PATCH", "/api/v1/remediation/items/"+it2, map[string]any{"threat_id": threat}); code != 422 || errCode(b) != "PTH-REM-1107" {
		t.Errorf("code fix linked: %d %v", code, b)
	}
	code, b := h.user(admin, "GET", "/api/v1/remediation/items?threat_id="+threat.String(), nil)
	if code != 200 || len(b["items"].([]any)) != 1 {
		t.Errorf("filter by threat: %d %v", code, b)
	}
	code, th := h.user(admin, "GET", "/api/v1/threats/"+threat.String(), nil)
	if code != 200 || len(th["remediation_items"].([]any)) != 1 {
		t.Errorf("threat side: %d %v", code, th)
	}
	if code, b := h.user(admin, "PATCH", "/api/v1/remediation/items/"+ti["id"].(string), map[string]any{"threat_id": nil}); code != 200 || b["threat"] != nil {
		t.Errorf("unlink: %d %v", code, b)
	}
}

// TestM9LoopGateFeedback: loop 6 — a failed gate under a policy notifies
// developers (in-app, webhook) and appears in the feed; without a policy
// nothing blocks and nothing is sent.
func TestM9LoopGateFeedback(t *testing.T) {
	ctx := t.Context()
	h := newM9Harness(t)
	m9Flags(t, "remediation_workspace", monitoring.Flag)
	if err := notify.EnsureDefaults(ctx, appPool, h.store, orgID); err != nil {
		t.Fatal(err)
	}
	admin := realPrincipal(t, authz.RoleSuperAdmin)
	dev := realPrincipal(t, "developer")
	_, repo := m9App(t, "gate")
	_, freeRepo := m9App(t, "nogate")
	seedFinding(t, repo, "critical", "sast", "go.rce", "app/run.go", []string{"opengrep"}, nil)
	seedFinding(t, freeRepo, "critical", "sast", "go.rce", "app/run.go", []string{"opengrep"}, nil)
	pol := seedPolicy(t, "m9-critical", policy.Conditions{MinSeverity: "critical", RepositoryIDs: []string{repo.String()}}, policy.Actions{Notify: true})
	if code, g := h.user(admin, "POST", "/api/v1/gates", map[string]any{"name": "m9 deploy " + uuid.NewString()[:4], "stage": "deploy", "mode": "block",
		"policy_id": pol, "repository_id": repo}); code != 201 {
		t.Fatalf("gate: %d %v", code, g)
	}
	code, wh := h.user(admin, "POST", "/api/v1/notifications/webhooks", map[string]any{"name": "M9 CI " + uuid.NewString()[:4], "format": "json",
		"url": "https://ci.example/hook", "events": []string{"gate.failed"}})
	if code != 201 {
		t.Fatalf("webhook: %d %v", code, wh)
	}
	whID := wh["webhook"].(map[string]any)["id"].(string)
	t.Cleanup(func() { h.user(admin, "DELETE", "/api/v1/notifications/webhooks/"+whID, nil) })

	// No policy: pass, no feedback.
	code, d := h.user(dev, "POST", "/api/v1/gates/evaluate", map[string]any{"stage": "deploy", "repository_id": freeRepo})
	if code != 200 || d["outcome"] != "pass" {
		t.Fatalf("no policy: %d %v", code, d)
	}
	var n int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE event_key = 'gate.failed' AND repository_id = $1`, freeRepo).Scan(&n)
	if n != 0 || len(h.feed(admin, "repository_id="+freeRepo.String()+"&type=gate.failed")) != 0 {
		t.Error("feedback without a policy")
	}

	// Policy matched: block → feedback.
	code, d = h.user(dev, "POST", "/api/v1/gates/evaluate", map[string]any{"stage": "deploy", "repository_id": repo})
	if code != 200 || d["outcome"] != "block" {
		t.Fatalf("block: %d %v", code, d)
	}
	decision := d["id"].(string)
	ev := h.feed(admin, "repository_id="+repo.String()+"&type=gate.failed")
	if len(ev) != 1 || ev[0]["subject_id"] != decision || ev[0]["severity"] != "critical" || ev[0]["loop"].(float64) != 6 {
		t.Fatalf("loop 6 feed: %v", ev)
	}
	disp := &notify.Dispatcher{Pool: appPool, Secrets: h.store, BaseURL: "https://pathos.test", Log: log}
	for range 10 {
		if k, err := disp.DispatchEvents(ctx); err != nil || k == 0 {
			break
		}
	}
	var inApp, hooks int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM notifications n JOIN notification_events e ON e.id = n.event_id
		WHERE e.subject_id = $1 AND n.channel = 'in_app' AND n.user_id = $2`, decision, dev.UserID).Scan(&inApp)
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM outbound_webhook_deliveries w JOIN notification_events e ON e.id = w.event_id
		WHERE e.subject_id = $1 AND w.endpoint_id = $2`, decision, whID).Scan(&hooks)
	if inApp != 1 || hooks != 1 {
		t.Errorf("developer feedback: in-app %d, webhook %d", inApp, hooks)
	}
}

// TestM9LoopAITriage: loop 7 — new findings of a scan are queued for AI
// triage when AI is configured; the triage writes an M7 AI evidence record
// that the feed points at; with continuous monitoring the AI never approves
// on its own (even with approval policy "never"): a false-positive verdict
// waits for a person.
func TestM9LoopAITriage(t *testing.T) {
	ctx := t.Context()
	h := newM9Harness(t)
	m9Flags(t, monitoring.Flag, "ai_intelligence") // the AI evidence log API (M7)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	fake := &fakeProvider{response: `{"verdict":"false_positive","confidence":0.9,"suggested_severity":"low","rationale":"Constant input.","remediation":"","evidence_cited":["line 10"]}`}
	aiSvc := &ai.Service{DB: appPool, Authz: h.svc.Authz, Secrets: &secrets.Store{Keys: kr}, Log: log, Principal: auth.PrincipalFrom,
		NewProvider: func(ai.Config) (ai.Provider, error) { return fake, nil }}
	aiSvc.Register(h.api)
	_, repo := m9App(t, "ai")

	// AI configured, auto review on, approval policy "never".
	var cfgID string
	_ = appPool.QueryRow(ctx, `SELECT id::text FROM ai_configurations WHERE organization_id = $1 AND is_default AND archived_at IS NULL`, orgID).Scan(&cfgID)
	var provID any
	if cfgID == "" {
		code, prov := h.user(admin, "POST", "/api/v1/ai/providers", map[string]any{"name": "M9 model", "kind": "anthropic", "api_key": "sk-ant-m9"})
		if code != 201 {
			t.Fatalf("provider: %d %v", code, prov)
		}
		provID = prov["id"]
		code, cfg := h.user(admin, "POST", "/api/v1/ai/configurations", map[string]any{"name": "M9", "provider_id": provID, "effort": "medium",
			"auto_review": true, "approval_policy": "never", "categories": []string{"sast"}, "min_severity": "medium"})
		if code != 201 {
			t.Fatalf("configuration: %d %v", code, cfg)
		}
		cfgID = cfg["id"].(string)
	} else {
		var cur map[string]any
		_, cfgs := h.user(admin, "GET", "/api/v1/ai/configurations", nil)
		for _, x := range cfgs["items"].([]any) {
			if m := x.(map[string]any); m["id"] == cfgID {
				cur = m["current"].(map[string]any)
			}
		}
		provID = cur["provider_id"]
		if code, b := h.user(admin, "PUT", "/api/v1/ai/configurations/"+cfgID, map[string]any{"provider_id": provID, "auto_review": true,
			"approval_policy": "never", "categories": []string{"sast"}, "min_severity": "medium"}); code != 200 {
			t.Fatalf("configuration: %d %v", code, b)
		}
		t.Cleanup(func() {
			h.user(admin, "PUT", "/api/v1/ai/configurations/"+cfgID, map[string]any{"provider_id": provID, "auto_review": cur["auto_review"],
				"approval_policy": cur["approval_policy"], "categories": cur["categories"], "min_severity": cur["min_severity"]})
		})
	}

	// A scan reports a new finding; the scan-finished hooks run.
	job := uuid.Must(uuid.NewV7())
	var pv uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT current_version_id FROM scan_profiles WHERE organization_id = $1 AND is_default`, orgID).Scan(&pv)
	if _, err := appPool.Exec(ctx, `INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, ref, status, findings_new, finished_at)
		VALUES ($1, $2, $3, $4, 'push', 'main', 'succeeded', 1, now())`, job, orgID, repo, pv); err != nil {
		t.Fatal(err)
	}
	f := insertFinding(t, repo, "high", "eval(user_input)\n")
	_, _ = appPool.Exec(ctx, `UPDATE findings SET first_scan_job_id = $1, last_scan_job_id = $1 WHERE id = $2`, job, f)
	h.loops.OnScanFinished(ctx, orgID, job)
	aiSvc.OnScanFinished(ctx, orgID, job)

	if ev := h.feed(admin, "repository_id="+repo.String()+"&type=findings.new"); len(ev) != 1 || ev[0]["severity"] != "high" {
		t.Errorf("findings.new: %v", ev)
	}
	ev := h.feed(admin, "repository_id="+repo.String()+"&type=ai.triage_queued")
	if len(ev) != 1 || ev[0]["details"].(map[string]any)["queued"].(float64) != 1 || ev[0]["loop"].(float64) != 7 {
		t.Fatalf("loop 7 feed: %v", ev)
	}
	// The AI worker answers "false positive": it waits for a person.
	var reviewStatus string
	for range 30 {
		if n, err := aiSvc.ProcessOne(ctx); err != nil || n == 0 {
			break
		}
		if appPool.QueryRow(ctx, `SELECT status FROM ai_reviews WHERE finding_id = $1 ORDER BY created_at DESC LIMIT 1`, f).Scan(&reviewStatus) == nil {
			break
		}
	}
	var fstatus string
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, f).Scan(&fstatus)
	if reviewStatus != "pending_approval" || fstatus != "open" {
		t.Errorf("AI decided on its own: review %q, finding %q", reviewStatus, fstatus)
	}
	// The triage is an M7 AI evidence record linked from the review,
	// AI-inferred and pending a person's decision.
	var reviewID, recordID, task, decision, conclusion string
	if err := appPool.QueryRow(ctx, `SELECT ar.id::text, e.id::text, e.task, e.review_decision, e.conclusion FROM ai_reviews ar
		JOIN ai_evidence_records e ON e.id = ar.evidence_record_id
		WHERE ar.finding_id = $1 AND ar.source = 'automated' AND e.finding_id = $1 ORDER BY ar.created_at DESC LIMIT 1`, f).
		Scan(&reviewID, &recordID, &task, &decision, &conclusion); err != nil {
		t.Fatalf("no AI evidence record for the triage: %v", err)
	}
	if task != "finding_validation" || decision != "pending" || !strings.HasPrefix(conclusion, "false_positive") {
		t.Errorf("evidence record: task %q, decision %q, conclusion %q", task, decision, conclusion)
	}
	code, rec := h.user(admin, "GET", "/api/v1/ai/evidence/"+recordID, nil)
	if code != 200 || rec["record"].(map[string]any)["label"] != "ai_inferred" {
		t.Errorf("evidence record API: %d %v", code, rec)
	}
	ev = h.feed(admin, "repository_id="+repo.String()+"&type=ai.triage_concluded")
	if len(ev) != 1 || ev[0]["loop"].(float64) != 7 || ev[0]["evidence_label"] != "ai_inferred" ||
		ev[0]["evidence"].(map[string]any)["evidence_record_id"] != recordID || ev[0]["evidence"].(map[string]any)["ai_review_id"] != reviewID ||
		ev[0]["details"].(map[string]any)["review_status"] != "pending_approval" || ev[0]["link"] != "/findings?finding="+f.String() {
		t.Fatalf("loop 7 conclusion feed: %v", ev)
	}
	// Only a person applies the false-positive verdict; the record carries
	// that decision.
	var analystID uuid.UUID
	email := "m9-analyst-" + uuid.NewString()[:6] + "@m9.test"
	if err := appPool.QueryRow(ctx, `INSERT INTO users (id, organization_id, email, status) VALUES ($1, $2, $3, 'active') RETURNING id`,
		uuid.Must(uuid.NewV7()), orgID, email).Scan(&analystID); err != nil {
		t.Fatal(err)
	}
	analyst := principalWithRole(t, "security_analyst")
	analyst.UserID, analyst.Email = analystID, email
	if code, b := h.user(analyst, "POST", "/api/v1/ai/reviews/"+reviewID+"/approve", map[string]any{"note": "checked"}); code != 204 {
		t.Fatalf("approve: %d %v", code, b)
	}
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, f).Scan(&fstatus)
	_ = appPool.QueryRow(ctx, `SELECT review_decision FROM ai_evidence_records WHERE id = $1`, recordID).Scan(&decision)
	if fstatus != "false_positive" || decision != "accepted" {
		t.Errorf("after a person approved: finding %q, evidence record %q", fstatus, decision)
	}
	for _, p := range fake.prompts {
		if strings.Contains(p.User, "sk-ant") {
			t.Error("a secret reached the model")
		}
	}
}

// TestM9ExportsStamped walks every export endpoint and checks the version
// stamp (X-PATHOS-Generated-By with the version and build; JSON documents
// also carry it in the body).
func TestM9ExportsStamped(t *testing.T) {
	ctx := t.Context()
	h := newM9Harness(t)
	m9Flags(t, "codegraph", "threat_models", monitoring.Flag)
	admin := realPrincipal(t, authz.RoleSuperAdmin)
	app, repo := m9App(t, "export")
	_, _ = appPool.Exec(ctx, `INSERT INTO sbom_components (organization_id, repository_id, scan_job_id, name, version, purl)
		VALUES ($1, $2, $3, 'left-pad', '1.3.0', 'pkg:npm/left-pad@1.3.0')`, orgID, repo, seedScan(t, repo, strings.Repeat("f", 40)))
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "graph-exp-" + uuid.NewString()[:6], "family": "graph",
		"scanners": map[string]string{"pathos-graph": "test"}})
	sid := h.runGraphBuild(admin, app, repo, reg["token"].(string), strings.Repeat("a", 40), graphFixture(t, "fixture-graph.json"))
	code, b := h.user(admin, "POST", "/api/v1/threat-models", map[string]any{"application_id": app, "title": "Export model", "generate": true})
	if code != 201 {
		t.Fatalf("model: %d %v", code, b)
	}
	model := b["model"].(map[string]any)["id"].(string)

	// The other services with exports.
	mux := exportMux(t)
	call := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil).WithContext(auth.WithPrincipal(ctx, admin))
		rec := httptest.NewRecorder()
		if strings.HasPrefix(path, "/api/v1/codegraph/") || strings.HasPrefix(path, "/api/v1/threat-models/") || strings.HasPrefix(path, "/api/v1/monitoring/") {
			h.api.ServeHTTP(rec, req)
		} else {
			mux.ServeHTTP(rec, req)
		}
		return rec
	}
	exports := []struct{ path, bodyMarker string }{
		{"/api/v1/codegraph/applications/" + app.String() + "/snapshots/" + sid + "/export", `"generated_by"`},
		{"/api/v1/threat-models/" + model + "/export?format=pathos", "PATHOS v"},
		{"/api/v1/repositories/" + repo.String() + "/sbom?format=cyclonedx", "PATHOS v"},
		{"/api/v1/repositories/" + repo.String() + "/sbom?format=spdx", "PATHOS v"},
		{"/api/v1/repositories/" + repo.String() + "/vex", "PATHOS v"},
		{"/api/v1/compliance/frameworks/owasp_top10_2021/export?format=json", `"generated_by"`},
		{"/api/v1/compliance/frameworks/owasp_top10_2021/export?format=csv", "control,title"},
		{"/api/v1/monitoring/events?format=csv", "created_at,type"},
		{"/api/v1/human-review/reports/export", "review_id"},
	}
	for _, e := range exports {
		rec := call(e.path)
		if rec.Code != 200 {
			t.Errorf("%s: %d %s", e.path, rec.Code, truncateBody(rec.Body.Bytes()))
			continue
		}
		stamp := rec.Header().Get("X-PATHOS-Generated-By")
		if !strings.HasPrefix(stamp, "Quditmind PATHOS v") || !strings.Contains(stamp, " · build ") || rec.Header().Get("X-PATHOS-Version") == "" {
			t.Errorf("%s: stamp %q", e.path, stamp)
		}
		if !strings.Contains(rec.Body.String(), e.bodyMarker) {
			t.Errorf("%s: body without %q: %s", e.path, e.bodyMarker, truncateBody(rec.Body.Bytes()))
		}
	}
	// The compliance report and technical facts state their lifecycle evidence.
	rec := call("/api/v1/compliance/frameworks/owasp_top10_2021")
	var cf map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &cf)
	secs, _ := cf["lifecycle_evidence"].([]any)
	if len(secs) != 4 {
		t.Fatalf("compliance lifecycle evidence: %v", cf["lifecycle_evidence"])
	}
	for _, s := range secs {
		m := s.(map[string]any)
		if m["evidence"] == "" || m["evidence_label"] != "verified" {
			t.Errorf("section without evidence: %v", m)
		}
		if m["key"] == "codegraph" && (m["available"] != true || m["metrics"].(map[string]any)["repositories_with_graph"].(float64) < 1) {
			t.Errorf("codegraph section: %v", m)
		}
		if m["key"] == "remediation" && m["available"] != false {
			t.Errorf("remediation section without the flag: %v", m)
		}
	}
}

func invSvc(t *testing.T) *inventory.Service {
	t.Helper()
	return &inventory.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log, Principal: auth.PrincipalFrom}
}

// exportMux serves the export endpoints outside the M9 harness: SBOM,
// VEX, compliance and Human Eye reports.
func exportMux(t *testing.T) *http.ServeMux {
	t.Helper()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	mux := http.NewServeMux()
	(&vuln.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}).Register(mux)
	(&releases.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}).Register(mux)
	(&compliance.Service{DB: appPool, Log: log, Principal: auth.PrincipalFrom}).Register(mux)
	(&review.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}).Register(mux)
	return mux
}

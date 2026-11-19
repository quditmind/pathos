//go:build integration

package integration

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/codegraph"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/tenant"
	"pathos/internal/secrets"
)

// graphHarness is the scan service (worker API) and the CodeGraph service
// wired as in the server.
type graphHarness struct {
	*scanHarness
	graph *codegraph.Service
}

func newGraphHarness(t *testing.T) *graphHarness {
	h := newScanHarness(t)
	g := codegraph.NewService(appPool, h.svc.Authz, log, auth.PrincipalFrom, nil)
	h.svc.OnGraphResult = g.OnGraphResult
	h.svc.OnScanFinished = g.OnScanFinished
	g.Register(h.api)
	return &graphHarness{scanHarness: h, graph: g}
}

// raw calls the user API and returns the raw body.
func (h *graphHarness) raw(p *authz.Principal, method, path string) (int, []byte) {
	h.t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	rec := httptest.NewRecorder()
	h.api.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// graphFixture reads a discovery document produced by the real
// worker-graph image on the fixture repository (test data).
func graphFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../internal/codegraph/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func setFlag(t *testing.T, name string, on bool) {
	t.Helper()
	if _, err := appPool.Exec(context.Background(), `INSERT INTO feature_flags (id, organization_id, name, enabled) VALUES ($1, $2, $3, $4)
		ON CONFLICT (organization_id, name) DO UPDATE SET enabled = EXCLUDED.enabled`, uuid.Must(uuid.NewV7()), orgID, name, on); err != nil {
		t.Fatal(err)
	}
}

// runGraphBuild queues a build through the API, leases it as the graph
// worker, uploads the document and completes the execution.
func (h *graphHarness) runGraphBuild(admin *authz.Principal, appID, repoID uuid.UUID, token, commit string, doc []byte) string {
	t := h.t
	t.Helper()
	code, b := h.user(admin, "POST", "/api/v1/codegraph/applications/"+appID.String()+"/build", map[string]any{"repository_id": repoID})
	if code != 202 {
		t.Fatalf("build: %d %v", code, b)
	}
	snap := b["snapshots"].([]any)[0].(map[string]any)
	job := leaseJob(t, h.scanHarness, token, snap["scan_job_id"].(string))
	if job["kind"] != "codegraph" {
		t.Fatalf("lease kind: %v", job["kind"])
	}
	if sc := job["scanners"].([]any); len(sc) != 1 || sc[0].(map[string]any)["key"] != "pathos-graph" {
		t.Fatalf("a CodeGraph execution runs only pathos-graph: %v", sc)
	}
	if job["previous_commit_sha"] != nil || job["secret_validation"] != nil {
		t.Errorf("scan-only lease fields on a CodeGraph execution: %v", job)
	}
	jobID := job["job_id"].(string)
	if code, r := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/results", map[string]any{"scanner": "pathos-graph",
		"version": "test", "status": "succeeded", "duration_ms": 1000, "output_gzip": gzB64(doc)}); code != 200 {
		t.Fatalf("upload graph: %d %v", code, r)
	}
	if code, r := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/complete", map[string]any{"status": "succeeded",
		"commit_sha": commit}); code != 200 {
		t.Fatalf("complete: %d %v", code, r)
	}
	return snap["snapshot_id"].(string)
}

func TestCodeGraph(t *testing.T) {
	quietNotifications(t)
	h := newGraphHarness(t)
	ctx := t.Context()
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	repo := createRepo(t, "graph-"+uuid.NewString()[:6])
	appID := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO applications (id, organization_id, name, criticality) VALUES ($1, $2, $3, 'high')`,
		appID, orgID, "CodeGraph app "+uuid.NewString()[:6]); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE repositories SET application_id = $2 WHERE id = $1`, repo, appID); err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/codegraph/applications/" + appID.String()

	// Behind the flag: 404 PTH-PLAT-1007 while off.
	setFlag(t, "codegraph", false)
	if code, b := h.user(admin, "GET", base+"/snapshots", nil); code != 404 || !strings.Contains(fmt.Sprint(b), "PTH-PLAT-1007") {
		t.Fatalf("flag off: %d %v", code, b)
	}
	setFlag(t, "codegraph", true)
	t.Cleanup(func() { setFlag(t, "codegraph", false) })

	// No graph worker online: refused with PTH-DISC-1001.
	if _, err := appPool.Exec(ctx, `UPDATE workers SET last_seen_at = now() - interval '1 hour' WHERE scanners ? 'pathos-graph'`); err != nil {
		t.Fatal(err)
	}
	if code, b := h.user(admin, "POST", base+"/build", map[string]any{}); code != 409 || !strings.Contains(fmt.Sprint(b), "PTH-DISC-1001") {
		t.Fatalf("no worker: %d %v", code, b)
	}
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "graph-" + uuid.NewString()[:6], "family": "graph",
		"scanners": map[string]string{"gitleaks": "8.30.1", "pathos-graph": "test"}})
	token := reg["token"].(string)

	// Other application's repository: PTH-DISC-1005.
	if code, b := h.user(admin, "POST", base+"/build", map[string]any{"repository_id": uuid.New()}); code != 422 || !strings.Contains(fmt.Sprint(b), "PTH-DISC-1005") {
		t.Errorf("foreign repository: %d %v", code, b)
	}

	// An open finding located in a file of the fixture graph is attached.
	doc := graphFixture(t, "fixture-graph.json")
	var parsed codegraph.Doc
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatal(err)
	}
	findingFile, findingLine := "", 0
	for _, n := range parsed.Nodes {
		if f, _ := n.Attrs["file"].(string); n.Type == "function" && f != "" {
			l, _ := n.Attrs["line"].(float64)
			findingFile, findingLine = f, int(l)+1
			break
		}
	}
	if findingFile == "" {
		t.Fatal("fixture graph has no function with a file")
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, scanner_keys, category, rule_id, title,
		severity, file_path, start_line, status) VALUES ($1, $2, $3, $4, '{opengrep}', 'sast', 'test.rule', 'Test finding (fixture)', 'high', $5, $6, 'open')`,
		uuid.Must(uuid.NewV7()), orgID, repo, "fp-graph-"+uuid.NewString(), findingFile, findingLine); err != nil {
		t.Fatal(err)
	}
	// Observed runtime link: a workload running an image linked to the repository.
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	sec, _ := (&secrets.Store{Keys: kr}).Create(ctx, appPool, orgID, secrets.KindSCM, "k8s", []byte("t"), nil)
	cluster, wl, img := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO runtime_clusters (id, organization_id, name, api_server, auth_type, secret_id) VALUES ($1, $2, $3, 'https://k8s.example.test', 'token', $4)`,
			[]any{cluster, orgID, "cg-" + uuid.NewString()[:6], sec}},
		{`INSERT INTO runtime_workloads (id, organization_id, cluster_id, namespace, kind, name, internet_exposed) VALUES ($1, $2, $3, 'shop', 'Deployment', 'api', true)`,
			[]any{wl, orgID, cluster}},
		{`INSERT INTO runtime_workload_images (id, organization_id, workload_id, container, image) VALUES ($1, $2, $3, 'api', 'registry.example.test/shop/api:1')`,
			[]any{img, orgID, wl}},
		{`INSERT INTO runtime_deployments (organization_id, workload_id, image_id, repository_id, basis, detail) VALUES ($1, $2, $3, $4, 'oci_source', 'test fixture')`,
			[]any{orgID, wl, img, repo}},
	} {
		if _, err := appPool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}

	sid1 := h.runGraphBuild(admin, appID, repo, token, strings.Repeat("a", 40), doc)
	snapURL := base + "/snapshots/" + sid1
	code, sum := h.user(admin, "GET", snapURL, nil)
	if code != 200 {
		t.Fatalf("snapshot: %d %v", code, sum)
	}
	sn := sum["snapshot"].(map[string]any)
	if sn["status"] != "ready" || sn["commit_sha"] != strings.Repeat("a", 40) || sn["node_count"].(float64) < 10 {
		t.Fatalf("snapshot not ready: %v", sn)
	}
	if ev := sum["evidence_types"].(map[string]any); ev["verified"] == nil || ev["observed"] == nil {
		t.Errorf("evidence types: %v", ev)
	}
	if code, list := h.user(admin, "GET", base+"/snapshots", nil); code != 200 || len(list["snapshots"].([]any)) != 1 {
		t.Errorf("list: %d %v", code, list)
	}

	// Store invariants: every edge has evidence of its own type; the
	// database refuses an edge without evidence.
	var bad int
	if err := ownerPool.QueryRow(ctx, `SELECT count(*) FROM codegraph_edges e WHERE e.snapshot_id = $1 AND NOT EXISTS
		(SELECT 1 FROM codegraph_evidence v WHERE v.edge_id = e.id AND v.evidence = e.evidence)`, sid1).Scan(&bad); err != nil || bad != 0 {
		t.Fatalf("edges without evidence: %d %v", bad, err)
	}
	tx, err := appPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var a, b2 uuid.UUID
	_ = tx.QueryRow(ctx, `SELECT id FROM codegraph_nodes WHERE snapshot_id = $1 ORDER BY id LIMIT 1`, sid1).Scan(&a)
	_ = tx.QueryRow(ctx, `SELECT id FROM codegraph_nodes WHERE snapshot_id = $1 ORDER BY id DESC LIMIT 1`, sid1).Scan(&b2)
	if _, err := tx.Exec(ctx, `INSERT INTO codegraph_edges (id, organization_id, snapshot_id, edge_key, source_id, target_id, type, evidence)
		VALUES ($1, $2, $3, 'x|calls|y', $4, $5, 'calls', 'verified')`, uuid.New(), orgID, sid1, a, b2); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("edge without evidence committed: %v", err)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO codegraph_evidence (id, organization_id, snapshot_id, edge_id, evidence, kind, ref)
		SELECT $1, organization_id, snapshot_id, id, 'guess', 'file_line', 'a:1' FROM codegraph_edges WHERE snapshot_id = $2 LIMIT 1`, uuid.New(), sid1); err == nil {
		t.Fatal("an evidence type outside the three was accepted")
	}

	// All 15 views answer, with evidence on every edge.
	code, vb := h.user(admin, "GET", "/api/v1/codegraph/views", nil)
	if code != 200 || len(vb["views"].([]any)) != 15 {
		t.Fatalf("views: %d", code)
	}
	nonEmpty := 0
	var routeID, datastoreID, functionID string
	for _, v := range vb["views"].([]any) {
		name := v.(map[string]any)["name"].(string)
		code, g := h.user(admin, "GET", snapURL+"/graph?view="+name, nil)
		if code != 200 {
			t.Fatalf("view %s: %d %v", name, code, g)
		}
		for _, e := range g["edges"].([]any) {
			em := e.(map[string]any)
			refs, _ := em["evidence_refs"].([]any)
			if len(refs) == 0 || !slices.Contains([]string{"verified", "observed", "ai_inferred"}, em["evidence"].(string)) {
				t.Fatalf("view %s: edge without evidence %v", name, em)
			}
		}
		if len(g["nodes"].([]any)) > 0 {
			nonEmpty++
		}
		for _, n := range g["nodes"].([]any) {
			nm := n.(map[string]any)
			switch nm["type"] {
			case "route":
				if routeID == "" {
					routeID = nm["id"].(string)
				}
			case "datastore":
				datastoreID = nm["id"].(string)
			case "function":
				if functionID == "" {
					functionID = nm["id"].(string)
				}
			}
		}
	}
	if nonEmpty < 10 {
		t.Errorf("only %d of 15 views have nodes on the fixture repository", nonEmpty)
	}

	// Ownership: the application owns the repository (registry evidence);
	// observed runtime edges from the runtime context.
	_, own := h.user(admin, "GET", snapURL+"/graph?view=ownership", nil)
	if len(own["edges"].([]any)) != 1 || own["edges"].([]any)[0].(map[string]any)["evidence_refs"].([]any)[0].(map[string]any)["kind"] != "registry" {
		t.Errorf("ownership: %v", own)
	}
	_, dep := h.user(admin, "GET", snapURL+"/graph?view=deployment&filters=evidence:observed", nil)
	if len(dep["edges"].([]any)) == 0 {
		t.Errorf("no observed runtime edges in the deployment view: %v", dep)
	}
	_, exp := h.user(admin, "GET", snapURL+"/graph?view=internet_exposure", nil)
	if len(exp["nodes"].([]any)) == 0 {
		t.Error("internet exposure view is empty")
	}

	// Findings attach by file and line.
	_, fo := h.user(admin, "GET", snapURL+"/graph?view=findings_overlay&filters=severity:high", nil)
	hasFinding := false
	for _, n := range fo["nodes"].([]any) {
		if c := n.(map[string]any)["finding_counts"].(map[string]any); c["high"] != nil {
			hasFinding = true
		}
	}
	if !hasFinding {
		t.Errorf("finding not attached: %v", fo["nodes"])
	}

	// Aggregation over the limit, then lazy expansion of an aggregate.
	code, agg := h.user(admin, "GET", snapURL+"/graph?view=call_graph&limit=3", nil)
	if code != 200 || len(agg["nodes"].([]any))+len(agg["aggregated"].([]any)) > 3 || len(agg["aggregated"].([]any)) == 0 {
		t.Fatalf("aggregation: %d nodes=%d aggregated=%v", code, len(agg["nodes"].([]any)), agg["aggregated"])
	}
	aggID := agg["aggregated"].([]any)[0].(map[string]any)["id"].(string)
	code, ex := h.user(admin, "GET", snapURL+"/graph?view=call_graph&limit=2000&focus="+url.QueryEscape(aggID), nil)
	if code != 200 || len(ex["nodes"].([]any))+len(ex["aggregated"].([]any)) == 0 {
		t.Errorf("expand %s: %d %v", aggID, code, ex)
	}
	// Bad parameters: PTH-GRAPH-1003.
	for _, q := range []string{"view=nope", "limit=2001", "depth=9", "filters=color:red"} {
		if code, b := h.user(admin, "GET", snapURL+"/graph?"+q, nil); code != 400 || !strings.Contains(fmt.Sprint(b), "PTH-GRAPH-1003") {
			t.Errorf("%s: %d %v", q, code, b)
		}
	}

	// Inspector.
	if functionID == "" || routeID == "" || datastoreID == "" {
		t.Fatalf("fixture lacks a function, route or datastore: %q %q %q", functionID, routeID, datastoreID)
	}
	code, insp := h.user(admin, "GET", snapURL+"/nodes/"+functionID, nil)
	if code != 200 || insp["node"] == nil || len(insp["ancestors"].([]any)) == 0 || insp["source_links"] == nil {
		t.Fatalf("inspector: %d %v", code, insp)
	}
	links := insp["source_links"].([]any)
	if len(links) == 0 || !strings.HasPrefix(links[0].(map[string]any)["url"].(string), "https://github.com/acme/") {
		t.Errorf("source links: %v", links)
	}

	// Path tracing: from a route out to the datastore, and into the
	// datastore with a hop limit.
	code, pth := h.user(admin, "GET", snapURL+"/paths?from="+routeID+"&to="+datastoreID+"&direction=out&max=8", nil)
	if code != 200 {
		t.Fatalf("paths: %d %v", code, pth)
	}
	t.Logf("route → datastore paths: %d", len(pth["paths"].([]any)))
	code, pin := h.user(admin, "GET", snapURL+"/paths?from="+datastoreID+"&direction=in&max=3", nil)
	if code != 200 || len(pin["paths"].([]any)) == 0 {
		t.Errorf("inbound paths: %d %v", code, pin)
	}
	for _, e := range pin["edges"].([]any) {
		if len(e.(map[string]any)["evidence_refs"].([]any)) == 0 {
			t.Fatal("path edge without evidence")
		}
	}
	if code, _ := h.user(admin, "GET", snapURL+"/paths?from="+routeID+"&max=9", nil); code != 400 {
		t.Errorf("max 9 hops: %d", code)
	}

	// Export: every node and edge, every edge with evidence.
	code, raw := h.raw(admin, "GET", snapURL+"/export?format=json")
	if code != 200 {
		t.Fatalf("export: %d %s", code, raw)
	}
	var exp1 struct {
		Schema string            `json:"schema"`
		Nodes  []json.RawMessage `json:"nodes"`
		Edges  []struct {
			EvidenceRefs []any `json:"evidence_refs"`
		} `json:"edges"`
	}
	if err := json.Unmarshal(raw, &exp1); err != nil || exp1.Schema != codegraph.ExportSchema {
		t.Fatalf("export JSON: %v %s", err, raw[:min(len(raw), 200)])
	}
	if float64(len(exp1.Nodes)) != sn["node_count"].(float64) || float64(len(exp1.Edges)) != sn["edge_count"].(float64) {
		t.Errorf("export counts %d/%d vs %v/%v", len(exp1.Nodes), len(exp1.Edges), sn["node_count"], sn["edge_count"])
	}
	for _, e := range exp1.Edges {
		if len(e.EvidenceRefs) == 0 {
			t.Fatal("exported edge without evidence")
		}
	}

	// A second commit: diff and change impact.
	sid2 := h.runGraphBuild(admin, appID, repo, token, strings.Repeat("b", 40), graphFixture(t, "fixture-graph-v2.json"))
	code, df := h.user(admin, "GET", base+"/diff?from="+sid1+"&to="+sid2, nil)
	if code != 200 {
		t.Fatalf("diff: %d %v", code, df)
	}
	s := df["summary"].(map[string]any)
	if s["added_nodes"].(float64) == 0 || s["removed_edges"].(float64) == 0 {
		t.Errorf("diff summary: %v", s)
	}
	code, ci := h.user(admin, "GET", base+"/snapshots/"+sid2+"/graph?view=change_impact", nil)
	if code != 200 || ci["base_snapshot_id"] != sid1 || len(ci["nodes"].([]any)) == 0 {
		t.Errorf("change impact: %d base=%v nodes=%d", code, ci["base_snapshot_id"], len(ci["nodes"].([]any)))
	}

	// Feedback loop: a successful scan of a new commit triggers
	// rediscovery, rate-limited by min_interval_minutes.
	scanJob := func(commit string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		var pv uuid.UUID
		if err := appPool.QueryRow(ctx, `SELECT current_version_id FROM scan_profiles WHERE organization_id = $1 AND is_default AND archived_at IS NULL`, orgID).Scan(&pv); err != nil {
			t.Fatal(err)
		}
		if _, err := appPool.Exec(ctx, `INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, ref, commit_sha, status, finished_at)
			VALUES ($1, $2, $3, $4, 'push', 'main', $5, 'succeeded', now())`, id, orgID, repo, pv, commit); err != nil {
			t.Fatal(err)
		}
		return id
	}
	countSnaps := func() int {
		var n int
		_ = appPool.QueryRow(ctx, `SELECT count(*) FROM codegraph_snapshots WHERE repository_id = $1`, repo).Scan(&n)
		return n
	}
	before := countSnaps()
	h.graph.OnScanFinished(ctx, orgID, scanJob(strings.Repeat("c", 40)))
	if countSnaps() != before {
		t.Error("rediscovery ignored the minimum interval")
	}
	if code, b := h.user(admin, "PUT", "/api/v1/codegraph/settings", map[string]any{"auto_rebuild": true, "min_interval_minutes": 0, "keep_snapshots": 1}); code != 200 {
		t.Fatalf("settings: %d %v", code, b)
	}
	viewer := scoped("viewer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID})
	if code, _ := h.user(viewer, "PUT", "/api/v1/codegraph/settings", map[string]any{"auto_rebuild": false, "min_interval_minutes": 0, "keep_snapshots": 1}); code != 403 {
		t.Errorf("viewer changed settings: %d", code)
	}
	h.graph.OnScanFinished(ctx, orgID, scanJob(strings.Repeat("d", 40)))
	if countSnaps() != before+1 {
		t.Fatal("a new commit did not trigger rediscovery")
	}
	h.graph.OnScanFinished(ctx, orgID, scanJob(strings.Repeat("e", 40)))
	if countSnaps() != before+1 {
		t.Error("rediscovery queued twice while a build is queued")
	}
	// The queued rediscovery fails without a graph when its execution is
	// cancelled (PTH-DISC-1003).
	if _, err := appPool.Exec(ctx, `UPDATE scan_jobs SET status = 'cancelled', finished_at = now() WHERE repository_id = $1 AND trigger = 'codegraph' AND status = 'queued'`, repo); err != nil {
		t.Fatal(err)
	}
	_, list := h.user(admin, "GET", base+"/snapshots?status=failed", nil)
	if l := list["snapshots"].([]any); len(l) != 1 || l[0].(map[string]any)["error_code"] != "PTH-DISC-1003" {
		t.Errorf("reconcile: %v", list)
	}

	// Retention: keep_snapshots 1 archives the older ready snapshot.
	n, err := codegraph.Retain(tenant.WithSystem(ctx), appPool, nil)
	if err != nil || n < 1 {
		t.Fatalf("retain: %d %v", n, err)
	}
	if code, b := h.user(admin, "GET", snapURL+"/graph?view=architecture", nil); code != 409 || !strings.Contains(fmt.Sprint(b), "PTH-GRAPH-1005") {
		t.Errorf("archived snapshot: %d %v", code, b)
	}
	if code, b := h.user(admin, "GET", base+"/snapshots/"+sid2+"/graph?view=architecture", nil); code != 200 {
		t.Errorf("newest snapshot kept: %d %v", code, b)
	}

	// Access: a user scoped to another business unit sees nothing.
	other := scoped("viewer", authz.Scope{Type: authz.ScopeBusinessUnit, ID: uuid.New()})
	if code, _ := h.user(other, "GET", base+"/snapshots/"+sid2, nil); code != 404 && code != 403 {
		t.Errorf("out-of-scope user: %d", code)
	}
}

// TestCodeGraphViewLatency measures the API latency of a 2,000-node view
// on a synthetic graph (test data: 20,000 functions in 200 directories,
// 40,000 calls), cold (skeleton load) and warm.
func TestCodeGraphViewLatency(t *testing.T) {
	quietNotifications(t)
	h := newGraphHarness(t)
	ctx := t.Context()
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	setFlag(t, "codegraph", true)
	t.Cleanup(func() { setFlag(t, "codegraph", false) })
	repo := createRepo(t, "graph-perf-"+uuid.NewString()[:6])
	appID := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO applications (id, organization_id, name) VALUES ($1, $2, $3)`, appID, orgID, "perf "+uuid.NewString()[:6]); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE repositories SET application_id = $2 WHERE id = $1`, repo, appID); err != nil {
		t.Fatal(err)
	}
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "graph-perf-" + uuid.NewString()[:6], "family": "graph",
		"scanners": map[string]string{"gitleaks": "8.30.1", "pathos-graph": "test"}})
	doc := syntheticGraph(20000, 2)
	start := time.Now()
	sid := h.runGraphBuild(admin, appID, repo, reg["token"].(string), strings.Repeat("f", 40), doc)
	t.Logf("ingest of %d bytes (20,000 functions): %s", len(doc), time.Since(start).Round(time.Millisecond))
	u := "/api/v1/codegraph/applications/" + appID.String() + "/snapshots/" + sid + "/graph?view=call_graph&limit=2000"
	var times []time.Duration
	for i := range 11 {
		t0 := time.Now()
		code, b := h.raw(admin, "GET", u)
		d := time.Since(t0)
		if code != 200 {
			t.Fatalf("view: %d %s", code, b)
		}
		var g struct {
			Nodes, Aggregated, Edges []any
		}
		_ = json.Unmarshal(b, &g)
		if i == 0 {
			t.Logf("cold 2,000-node view: %s (%d nodes, %d aggregates, %d edges, %d bytes)", d.Round(time.Millisecond), len(g.Nodes), len(g.Aggregated), len(g.Edges), len(b))
			if len(g.Nodes)+len(g.Aggregated) > 2000 {
				t.Fatal("over the limit")
			}
			continue
		}
		times = append(times, d)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	t.Logf("warm 2,000-node view: median %s, p95 %s (10 runs)", times[len(times)/2].Round(time.Millisecond), times[len(times)*95/100].Round(time.Millisecond))
	if times[len(times)/2] > 2*time.Second {
		t.Errorf("median latency %s over 2 s", times[len(times)/2])
	}
}

// TestCodeGraphRealGraphLatency measures views and paths on a real
// discovery document (the worker-graph run on the PATHOS repository), when
// PATHOS_CODEGRAPH_REAL_GRAPH names its gzip file. Skipped otherwise.
func TestCodeGraphRealGraphLatency(t *testing.T) {
	path := os.Getenv("PATHOS_CODEGRAPH_REAL_GRAPH")
	if path == "" {
		t.Skip("PATHOS_CODEGRAPH_REAL_GRAPH not set")
	}
	f, err := os.Open(path) // #nosec G304 -- test input named by the operator
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	quietNotifications(t)
	h := newGraphHarness(t)
	ctx := t.Context()
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	setFlag(t, "codegraph", true)
	t.Cleanup(func() { setFlag(t, "codegraph", false) })
	repo := createRepo(t, "graph-real-"+uuid.NewString()[:6])
	appID := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO applications (id, organization_id, name) VALUES ($1, $2, $3)`, appID, orgID, "real "+uuid.NewString()[:6]); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `UPDATE repositories SET application_id = $2 WHERE id = $1`, repo, appID); err != nil {
		t.Fatal(err)
	}
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "graph-real-" + uuid.NewString()[:6], "family": "graph",
		"scanners": map[string]string{"gitleaks": "8.30.1", "pathos-graph": "test"}})
	start := time.Now()
	sid := h.runGraphBuild(admin, appID, repo, reg["token"].(string), strings.Repeat("9", 40), doc)
	t.Logf("real graph: ingest of %d bytes in %s", len(doc), time.Since(start).Round(time.Millisecond))
	var bad int
	if err := ownerPool.QueryRow(ctx, `SELECT count(*) FROM codegraph_edges e WHERE e.snapshot_id = $1 AND NOT EXISTS
		(SELECT 1 FROM codegraph_evidence v WHERE v.edge_id = e.id AND v.evidence = e.evidence)`, sid).Scan(&bad); err != nil || bad != 0 {
		t.Fatalf("edges without evidence: %d %v", bad, err)
	}
	base := "/api/v1/codegraph/applications/" + appID.String() + "/snapshots/" + sid
	measure := func(name, u string) {
		var times []time.Duration
		var size, units int
		for range 6 {
			t0 := time.Now()
			code, b := h.raw(admin, "GET", u)
			times = append(times, time.Since(t0))
			if code != 200 {
				t.Fatalf("%s: %d %s", name, code, b)
			}
			var g struct{ Nodes, Aggregated, Paths []any }
			_ = json.Unmarshal(b, &g)
			size, units = len(b), len(g.Nodes)+len(g.Aggregated)+len(g.Paths)
		}
		warm := slices.Clone(times[1:])
		slices.Sort(warm)
		t.Logf("real graph %s: first %s, warm median %s, max %s (%d units, %d bytes)", name, times[0].Round(time.Millisecond),
			warm[len(warm)/2].Round(time.Millisecond), warm[len(warm)-1].Round(time.Millisecond), units, size)
	}
	for _, v := range []string{"architecture", "call_graph", "api", "dependencies", "internet_exposure"} {
		measure("view "+v+" (limit 2000)", base+"/graph?view="+v+"&limit=2000")
	}
	var route string
	_ = appPool.QueryRow(ctx, `SELECT id FROM codegraph_nodes WHERE snapshot_id = $1 AND type = 'route' ORDER BY node_key LIMIT 1`, sid).Scan(&route)
	measure("paths out of a route (8 hops)", base+"/paths?from="+route+"&direction=out&max=8&limit=50")
}

// syntheticGraph builds a discovery document (test data) of n functions.
func syntheticGraph(n, callsPer int) []byte {
	type m = map[string]any
	nodes := []m{{"key": "repository", "type": "repository", "label": "perf"}}
	var edges []m
	for d := 0; d < 200; d++ {
		dir := fmt.Sprintf("pkg%d/sub%d", d%20, d)
		nodes = append(nodes, m{"key": "mod:" + dir, "type": "module", "label": dir, "parent": "repository", "attrs": m{"path": dir}},
			m{"key": "file:" + dir + "/f.go", "type": "file", "label": "f.go", "parent": "mod:" + dir, "attrs": m{"file": dir + "/f.go", "language": "Go"}})
	}
	for i := 0; i < n; i++ {
		dir := fmt.Sprintf("pkg%d/sub%d", (i%200)%20, i%200)
		nodes = append(nodes, m{"key": fmt.Sprintf("fn:%d", i), "type": "function", "label": fmt.Sprintf("F%d", i), "parent": "file:" + dir + "/f.go",
			"attrs": m{"file": dir + "/f.go", "line": i, "end_line": i + 1}})
		for c := 1; c <= callsPer && i > c; c++ {
			edges = append(edges, m{"source": fmt.Sprintf("fn:%d", i), "target": fmt.Sprintf("fn:%d", (i*31+c*17)%i), "type": "calls",
				"evidence": "verified", "evidence_refs": []m{{"kind": "file_line", "ref": fmt.Sprintf("%s/f.go:%d", dir, i), "detail": "call"}}})
		}
	}
	b, _ := json.Marshal(m{"schema": codegraph.Schema, "engines": m{"pathos-graph": "synthetic"}, "stats": m{}, "nodes": nodes, "edges": edges})
	return b
}

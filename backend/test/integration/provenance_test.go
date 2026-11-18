//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/eol"
	"pathos/internal/intel"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/scans"
	"pathos/internal/secrets"
)

// leaseFor leases jobs until it gets the one for repo (others are
// drained) and returns it.
func (h *scanHarness) leaseFor(token string, repo uuid.UUID) map[string]any {
	h.t.Helper()
	for i := 0; i < 20; i++ {
		code, j := h.worker(token, "POST", "/internal/worker/v1/lease", map[string]any{})
		if code != 200 {
			continue
		}
		if j["repository_id"] == repo.String() {
			return j
		}
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+j["job_id"].(string)+"/complete", map[string]any{"status": "failed", "error": "test drain"})
	}
	h.t.Fatalf("no job leased for %s", repo)
	return nil
}

func provenanceHarness(t *testing.T, offline bool) (*scanHarness, string) {
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	svc := &scans.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log,
		Principal: auth.PrincipalFrom, BootstrapToken: bootstrap, OrgID: orgID, Secrets: &secrets.Store{Keys: kr}, Offline: offline}
	mux := newMux(svc.Register)
	(&eol.Service{DB: appPool, Authz: svc.Authz, Log: log, Principal: auth.PrincipalFrom}).Register(mux)
	h := &scanHarness{t: t, api: mux, internal: svc.InternalHandler(), svc: svc}
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "prov-" + uuid.NewString()[:6], "family": "core"})
	return h, reg["token"].(string)
}

func TestDeclaredEndpointVerification(t *testing.T) {
	ctx := t.Context()
	h, token := provenanceHarness(t, false)
	admin := reviewUser(t, "platform_admin")
	viewer := reviewUser(t, "viewer")
	repo := createRepo(t, "ep-"+uuid.NewString()[:6])
	base := "/api/v1/repositories/" + repo.String() + "/endpoint-verification"

	code, st := h.user(admin, "GET", base, nil)
	if code != 200 || st["configured"] != false || len(st["endpoints"].([]any)) != 0 {
		t.Fatalf("initial state: %d %v", code, st)
	}
	if code, out := h.user(admin, "PUT", base, map[string]any{"authorized": true}); code != 400 || !strings.Contains(errMsg(out), "declare public") {
		t.Errorf("no declared endpoints: %d %v", code, out)
	}
	for i, e := range [][2]string{{"url", "https://shop.acme.test"}, {"domain", "api.acme.test"}} {
		if _, err := appPool.Exec(ctx, `INSERT INTO repository_public_endpoints (id, organization_id, repository_id, kind, value, position)
			VALUES ($1, $2, $3, $4, $5, $6)`, uuid.New(), orgID, repo, e[0], e[1], i); err != nil {
			t.Fatal(err)
		}
	}
	if code, out := h.user(admin, "PUT", base, map[string]any{"enabled": true}); code != 400 || !strings.Contains(errMsg(out), "authorized") {
		t.Errorf("enabling without an authorization statement: %d %v", code, out)
	}
	if code, _ := h.user(viewer, "PUT", base, map[string]any{"enabled": true, "authorized": true}); code != 403 && code != 404 {
		t.Errorf("viewer enables verification: %d", code)
	}
	code, st = h.user(admin, "PUT", base, map[string]any{"enabled": true, "authorized": true, "authorization_note": "Owner approval CHG-77", "rate_limit": 3})
	if code != 200 || st["configured"] != true || st["enabled"] != true || st["authorized_at"] == nil || st["rate_limit"].(float64) != 3 || st["nuclei"] != false {
		t.Fatalf("enable: %d %v", code, st)
	}
	for _, e := range st["endpoints"].([]any) {
		if e.(map[string]any)["authorized"] != true || e.(map[string]any)["status"] != "not_checked" {
			t.Errorf("endpoint state: %v", e)
		}
	}
	// Turning on Nuclei needs a new statement; an endpoint declared later
	// is not covered until then.
	if code, _ := h.user(admin, "PUT", base, map[string]any{"nuclei": true}); code != 400 {
		t.Errorf("nuclei without re-authorization: %d", code)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO repository_public_endpoints (id, organization_id, repository_id, kind, value, position)
		VALUES ($1, $2, $3, 'ip', '203.0.113.10', 0)`, uuid.New(), orgID, repo); err != nil {
		t.Fatal(err)
	}
	_, st = h.user(viewer, "GET", base, nil)
	if st["unauthorized"].(float64) != 1 {
		t.Errorf("unauthorized endpoint count: %v", st)
	}
	// The generic target API refuses to manage it.
	targetID := st["scan_target_id"].(string)
	if code, _ := h.user(admin, "PUT", "/api/v1/scan-targets/"+targetID, map[string]any{"name": "x"}); code != 400 {
		t.Errorf("generic update of an endpoints target: %d", code)
	}
	if code, _ := h.user(admin, "POST", "/api/v1/scan-targets", map[string]any{"repository_id": repo, "kind": "endpoints", "name": "x",
		"reference": "x", "authorized": true}); code != 400 {
		t.Errorf("generic create of an endpoints target: %d", code)
	}

	code, q := h.user(admin, "POST", base+"/run", nil)
	if code != 202 || q["job_id"] == nil {
		t.Fatalf("run: %d %v", code, q)
	}
	job := h.leaseFor(token, repo)
	tg := job["target"].(map[string]any)
	eps := tg["endpoints"].([]any)
	if tg["kind"] != "endpoints" || len(eps) != 3 || tg["rate_limit"].(float64) != 3 {
		t.Fatalf("leased endpoints target: %v", tg)
	}
	authorized := 0
	for _, e := range eps {
		if e.(map[string]any)["authorized"] == true {
			authorized++
		}
	}
	if authorized != 2 {
		t.Errorf("authorized endpoints in the lease: %d", authorized)
	}
	if sc := job["scanners"].([]any); len(sc) != 1 || sc[0].(map[string]any)["key"] != "pathos-endpoints" {
		t.Errorf("scanners: %v", sc)
	}
	report := map[string]any{"version": 1, "endpoints": []map[string]any{
		{"kind": "url", "value": "https://shop.acme.test", "status": "verified", "checks": map[string]any{"tls": map[string]any{"protocol": "TLS 1.3"}},
			"issues": []map[string]any{
				{"id": "hsts-missing", "title": "HTTP Strict Transport Security (HSTS) not set", "severity": "low", "location": "https://shop.acme.test", "cwe": []string{"CWE-319"}},
				{"id": "tls-weak-protocol", "title": "Legacy TLS protocol versions accepted", "severity": "medium", "location": "https://shop.acme.test"}}},
		{"kind": "domain", "value": "api.acme.test", "status": "dns_failed", "detail": "egress proxy answered 503 (ERR_DNS_FAIL 0)", "checks": map[string]any{}},
		{"kind": "ip", "value": "203.0.113.10", "status": "skipped", "detail": "not covered by the authorization statement", "checks": map[string]any{}},
	}}
	raw, _ := json.Marshal(report)
	jid := job["job_id"].(string)
	if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{"scanner": "pathos-endpoints",
		"status": "succeeded", "output_gzip": gzB64(raw)}); code != 200 || out["findings"].(float64) != 2 {
		t.Fatalf("upload: %d %v", code, out)
	}
	if code, _ := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/complete", map[string]any{"status": "succeeded"}); code != 200 {
		t.Fatalf("complete: %d", code)
	}
	_, st = h.user(viewer, "GET", base, nil)
	statuses := map[string]string{}
	for _, e := range st["endpoints"].([]any) {
		m := e.(map[string]any)
		statuses[m["value"].(string)] = m["status"].(string)
	}
	if statuses["https://shop.acme.test"] != "verified" || statuses["api.acme.test"] != "dns_failed" || statuses["203.0.113.10"] != "skipped" {
		t.Errorf("statuses: %v", statuses)
	}
	if st["open_findings"].(float64) != 2 {
		t.Errorf("open findings: %v", st["open_findings"])
	}
	var cat string
	_ = appPool.QueryRow(ctx, `SELECT category FROM findings WHERE scan_target_id = $1 AND rule_id = 'endpoint/hsts-missing'`, targetID).Scan(&cat)
	if cat != "dast" {
		t.Errorf("finding category %q", cat)
	}
	var audits int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action LIKE 'endpoint_verification.%' AND target_id = $1`, repo.String()).Scan(&audits)
	if audits < 1 {
		t.Error("endpoint verification changes are audited")
	}

	// Offline: verification cannot be run or enabled.
	off, _ := provenanceHarness(t, true)
	if code, _ := off.user(admin, "POST", base+"/run", nil); code != 409 {
		t.Errorf("offline run: %d", code)
	}
	if code, out := off.user(admin, "GET", base, nil); code != 200 || out["offline"] != true {
		t.Errorf("offline state: %d %v", code, out)
	}
	if code, _ := off.user(admin, "POST", "/api/v1/scan-targets/"+targetID+"/scan", nil); code != 409 {
		t.Errorf("offline target scan: %d", code)
	}
	// Disabling is always possible.
	if code, out := h.user(admin, "PUT", base, map[string]any{"enabled": false}); code != 200 || out["enabled"] != false {
		t.Errorf("disable: %d %v", code, out)
	}
	if code, _ := h.user(admin, "POST", base+"/run", nil); code != 409 {
		t.Errorf("disabled verification runs: %d", code)
	}
}

func TestIntroducingCommitsRuntimesAndEOL(t *testing.T) {
	ctx := t.Context()
	h, token := provenanceHarness(t, false)
	admin := reviewUser(t, "platform_admin")
	repo := createRepo(t, "blame-"+uuid.NewString()[:6])

	// End-of-life data imported from a file (offline style).
	raw, err := os.ReadFile("../../internal/eol/testdata/products-full.json")
	if err != nil {
		t.Fatal(err)
	}
	run, err := intel.Load(ctx, appPool, "endoflife", "file", nil, raw)
	if err != nil || run.Status != "succeeded" || run.Records != 16 {
		t.Fatalf("feed import: %v %+v", err, run)
	}

	scan := func(trigger, commit string, results []map[string]any, runtimes []map[string]any, blame map[string]any) string {
		t.Helper()
		res, err := scans.Enqueue(ctx, appPool, orgID, repo, trigger, "main", commit, nil)
		if err != nil {
			t.Fatal(err)
		}
		job := h.leaseFor(token, repo)
		jid := job["job_id"].(string)
		if jid != res.JobID.String() {
			t.Fatalf("leased %s, queued %s", jid, res.JobID)
		}
		for _, r := range results {
			if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/results", r); code != 200 {
				t.Fatalf("upload: %d %v", code, out)
			}
		}
		if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/runtimes", map[string]any{"version": 1, "runtimes": runtimes}); code != 200 {
			t.Fatalf("runtimes: %d %v", code, out)
		}
		if blame != nil {
			if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/blame", blame); code != 200 {
				t.Fatalf("blame: %d %v", code, out)
			}
		}
		if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/complete", map[string]any{"status": "succeeded", "commit_sha": commit}); code != 200 {
			t.Fatalf("complete: %d %v", code, out)
		}
		return jid
	}
	opengrep := map[string]any{"scanner": "opengrep", "status": "succeeded", "output_gzip": fixture(t, "opengrep.sarif")}
	sha1 := strings.Repeat("a", 40)
	introducing := strings.Repeat("c", 40)
	first := scan("manual", sha1, []map[string]any{opengrep},
		[]map[string]any{{"kind": "runtime", "name": "node", "version": "16.20.0", "path": ".nvmrc"},
			{"kind": "image", "name": "python:3.12-slim", "path": "Dockerfile"},
			{"kind": "runtime", "name": "bad name!", "version": "1"}},
		map[string]any{"version": 1, "mode": "full",
			"entries": []map[string]any{{"file": "app.py", "line": 3, "commit": introducing, "author": "Dana Developer\x07", "time": "2026-01-02T03:04:05+01:00"}},
			"missing": []map[string]any{{"file": "app.py", "line": 5}}})

	// Introducing commits.
	rows, _ := appPool.Query(ctx, `SELECT start_line, introduced_status, introduced_commit_sha, introduced_author, introduced_at IS NOT NULL
		FROM findings WHERE repository_id = $1 AND category = 'sast' ORDER BY start_line`, repo)
	got := map[int]string{}
	for rows.Next() {
		var line int
		var status, sha, author string
		var hasAt bool
		_ = rows.Scan(&line, &status, &sha, &author, &hasAt)
		got[line] = status + "|" + sha + "|" + author
		if line == 3 && !hasAt {
			t.Error("introduced_at missing")
		}
	}
	rows.Close()
	if got[3] != "known|"+introducing+"|Dana Developer" || got[5] != "not_found||" || got[7] != "||" {
		t.Errorf("introducing commits: %v", got)
	}
	var fid string
	_ = appPool.QueryRow(ctx, `SELECT id FROM findings WHERE repository_id = $1 AND start_line = 3 AND category = 'sast'`, repo).Scan(&fid)
	if code, f := h.user(admin, "GET", "/api/v1/findings/"+fid, nil); code != 200 || f["introduced_status"] != "known" ||
		f["introduced_commit_sha"] != introducing || f["introduced_author"] != "Dana Developer" {
		t.Errorf("finding API: %d %v", code, f)
	}

	// Runtimes stored (invalid names dropped) and end-of-life findings.
	var nRuntimes int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM repository_runtimes WHERE repository_id = $1`, repo).Scan(&nRuntimes)
	if nRuntimes != 2 {
		t.Errorf("runtimes stored: %d", nRuntimes)
	}
	var eolID, sev, eolStatus, firstJob string
	var due *time.Time
	if err := appPool.QueryRow(ctx, `SELECT id, severity, status, first_scan_job_id::text, sla_due_at FROM findings
		WHERE repository_id = $1 AND category = 'eol' AND rule_id = 'eol/nodejs/16'`, repo).Scan(&eolID, &sev, &eolStatus, &firstJob, &due); err != nil {
		t.Fatalf("end-of-life finding: %v", err)
	}
	if sev != "high" || eolStatus != "open" || firstJob != first || due == nil {
		t.Errorf("eol finding: %s %s %s %v", sev, eolStatus, firstJob, due)
	}
	code, view := h.user(admin, "GET", "/api/v1/repositories/"+repo.String()+"/eol", nil)
	if code != 200 || view["feed_loaded"] != true || view["eol"].(float64) < 1 || view["supported"].(float64) < 1 {
		t.Errorf("eol view: %d %v", code, view)
	}
	_, job := h.user(admin, "GET", "/api/v1/scans/"+first, nil)
	if job["change_summary"] != nil {
		t.Errorf("manual scans have no change summary: %v", job["change_summary"])
	}

	// A push scan: Node.js upgraded, one code finding fixed; shallow clone.
	sha2 := strings.Repeat("b", 40)
	fewer := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"opengrep","rules":[]}},"results":[]}]}`
	second := scan("push", sha2, []map[string]any{{"scanner": "opengrep", "status": "succeeded", "output_gzip": gzB64([]byte(fewer))},
		{"scanner": "gitleaks", "status": "succeeded", "output_gzip": fixture(t, "gitleaks.sarif")}},
		[]map[string]any{{"kind": "runtime", "name": "node", "version": "22.1.0", "path": ".nvmrc"}},
		map[string]any{"version": 1, "mode": "shallow", "entries": []any{}})
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, eolID).Scan(&eolStatus)
	if eolStatus != "fixed" {
		t.Errorf("end-of-life finding after the upgrade: %s", eolStatus)
	}
	var shallow int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND category = 'secrets' AND introduced_status = 'shallow_clone'`, repo).Scan(&shallow)
	if shallow == 0 {
		t.Error("shallow clones record the introducing commit as unknown")
	}
	_, job = h.user(admin, "GET", "/api/v1/scans/"+second, nil)
	cs, _ := job["change_summary"].(map[string]any)
	if cs == nil || cs["base_commit"] != sha1 || cs["head_commit"] != sha2 || cs["fixed_total"].(float64) < 3 || cs["new_total"].(float64) < 1 {
		t.Errorf("change summary: %v", job["change_summary"])
	}
	var payload []byte
	_ = appPool.QueryRow(ctx, `SELECT payload FROM notification_events WHERE subject_id = $1 AND event_key = 'findings.new'`, second).Scan(&payload)
	if len(payload) == 0 {
		t.Error("push scan with new findings raises findings.new")
	}
}

func TestSignatureVerificationEvidence(t *testing.T) {
	ctx := t.Context()
	h, token := provenanceHarness(t, false)
	admin := reviewUser(t, "platform_admin")
	repo := createRepo(t, "sig-"+uuid.NewString()[:6])
	base := map[string]any{"repository_id": repo, "kind": "image", "name": "API image", "reference": "ghcr.io/acme/api:1.0"}
	bad := map[string]any{}
	for k, v := range base {
		bad[k] = v
	}
	bad["config"] = map[string]any{"signature": map[string]any{"mode": "keyless", "identity": "x"}}
	if code, _ := h.user(admin, "POST", "/api/v1/scan-targets", bad); code != 400 {
		t.Errorf("keyless without issuer: %d", code)
	}
	base["config"] = map[string]any{"signature": map[string]any{"mode": "keyless", "identity_regexp": "^https://github.com/acme/",
		"issuer": "https://token.actions.githubusercontent.com", "require": true, "attestation": "slsaprovenance"}}
	code, tg := h.user(admin, "POST", "/api/v1/scan-targets", base)
	if code != 201 {
		t.Fatalf("create: %d %v", code, tg)
	}
	if sc := tg["scanners"].([]any); len(sc) != 2 || sc[1] != "cosign" {
		t.Errorf("scanners: %v", sc)
	}
	id := tg["id"].(string)
	if code, _ := h.user(admin, "POST", "/api/v1/scan-targets/"+id+"/scan", nil); code != 202 {
		t.Fatalf("scan: %d", code)
	}
	job := h.leaseFor(token, repo)
	lt := job["target"].(map[string]any)
	sig, _ := lt["signature"].(map[string]any)
	if sig == nil || sig["mode"] != "keyless" || sig["require"] != true {
		t.Fatalf("leased signature policy: %v", lt)
	}
	report, _ := json.Marshal(map[string]any{"version": 1, "subject": "ghcr.io/acme/api:1.0", "mode": "keyless", "status": "unsigned",
		"detail": "no signatures found", "required": true})
	jid := job["job_id"].(string)
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{"scanner": "trivy-image", "status": "succeeded",
		"output_gzip": gzB64([]byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"trivy"}},"results":[]}]}`))})
	if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{"scanner": "cosign", "status": "succeeded",
		"output_gzip": gzB64(report)}); code != 200 || out["findings"].(float64) != 1 {
		t.Fatalf("cosign upload: %d %v", code, out)
	}
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/complete", map[string]any{"status": "succeeded"})
	_, j := h.user(admin, "GET", "/api/v1/scans/"+jid, nil)
	if j["gate_failed"] != true {
		t.Errorf("a required signature that is missing fails the gate: %v", j["gate_failed"])
	}
	var cat, sev string
	_ = appPool.QueryRow(ctx, `SELECT category, severity FROM findings WHERE scan_target_id = $1 AND 'cosign' = ANY(scanner_keys)`, id).Scan(&cat, &sev)
	if cat != "supply-chain" || sev != "high" {
		t.Errorf("signature finding: %q %q", cat, sev)
	}
	_, tg = h.user(admin, "GET", "/api/v1/scan-targets/"+id, nil)
	lv, _ := tg["last_verification"].(map[string]any)
	if lv == nil || lv["status"] != "unsigned" || lv["required"] != true {
		t.Errorf("verification evidence on the target: %v", tg["last_verification"])
	}
	// Turning the policy off removes cosign from the scan.
	if code, out := h.user(admin, "PUT", "/api/v1/scan-targets/"+id, map[string]any{"config": map[string]any{}}); code != 200 ||
		len(out["scanners"].([]any)) != 1 {
		t.Errorf("policy off: %d %v", code, out)
	}
	if code, _ := h.user(admin, "PUT", "/api/v1/scan-targets/"+id, map[string]any{"signature_material": "abc"}); code != http.StatusBadRequest {
		t.Errorf("signature material on an image target: %d", code)
	}
}

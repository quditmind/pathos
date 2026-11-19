//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/scans"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

const bootstrap = "bootstrap-token-0123456789abcdef0123456789abcdef"

type scanHarness struct {
	t        *testing.T
	api      *http.ServeMux
	internal http.Handler
	svc      *scans.Service
}

func newScanHarness(t *testing.T) *scanHarness {
	svc := &scans.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log,
		Principal: auth.PrincipalFrom, BootstrapToken: bootstrap, OrgID: orgID,
		CloneCredential: func(context.Context, uuid.UUID, uuid.UUID) (scm.Credential, error) {
			return scm.Credential{Username: "x-access-token", Token: "ghs_short_lived"}, nil
		}}
	h := &scanHarness{t: t, api: http.NewServeMux(), internal: svc.InternalHandler(), svc: svc}
	svc.Register(h.api)
	return h
}

func (h *scanHarness) user(p *authz.Principal, method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	raw, _ := json.Marshal(body)
	if body == nil {
		raw = nil
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	rec := httptest.NewRecorder()
	h.api.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (h *scanHarness) worker(token, method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.internal.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func createRepo(t *testing.T, name string) uuid.UUID {
	t.Helper()
	ctx := t.Context()
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	st := &secrets.Store{Keys: kr}
	sec, _ := st.Create(ctx, appPool, orgID, secrets.KindSCM, "x", []byte("t"), nil)
	wh, _ := st.Create(ctx, appPool, orgID, secrets.KindWebhook, "w", []byte("w"), nil)
	conn, repo := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO scm_connections (id, organization_id, name, provider, base_url, auth_type, secret_id, webhook_secret_id)
		VALUES ($1, $2, $3, 'github', 'https://api.github.com', 'pat', $4, $5)`, conn, orgID, "conn-"+name, sec, wh); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO repositories (id, organization_id, scm_connection_id, external_id, full_name, name, url, clone_url, default_branch)
		VALUES ($1, $2, $3, $4, $5, $4, 'https://github.com/'||$5, 'https://github.com/'||$5||'.git', 'main')`, repo, orgID, conn, name, "acme/"+name); err != nil {
		t.Fatal(err)
	}
	return repo
}

func fixture(t *testing.T, name string) string {
	raw, err := os.ReadFile("../../internal/scanners/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

var fixtureFiles = map[string]string{"gitleaks": "gitleaks.sarif", "opengrep": "opengrep.sarif", "trivy-fs": "trivy-fs.sarif",
	"grype": "grype.json", "osv-scanner": "osv-scanner.sarif", "checkov": "checkov.sarif"}

func TestScanPipeline(t *testing.T) {
	h := newScanHarness(t)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	repo := createRepo(t, "pipeline-"+uuid.NewString()[:6])

	// Profiles: mandatory Gitleaks is locked on, unavailable scanners rejected.
	code, prof := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "SCA only " + uuid.NewString()[:4],
		"sbom": true, "scanners": []map[string]any{{"key": "osv-scanner"}}})
	if code != 201 {
		t.Fatalf("create profile: %d %v", code, prof)
	}
	keys := []string{}
	for _, s := range prof["current"].(map[string]any)["scanners"].([]any) {
		keys = append(keys, s.(map[string]any)["key"].(string))
	}
	if !strings.Contains(strings.Join(keys, ","), "gitleaks") {
		t.Errorf("gitleaks must be added automatically: %v", keys)
	}
	// CodeQL is catalogued but never bundled (its licence forbids it).
	if code, _ := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "x", "scanners": []map[string]any{{"key": "codeql"}}}); code != 400 {
		t.Errorf("unavailable scanner: want 400, got %d", code)
	}
	if code, p2 := h.user(admin, "PUT", "/api/v1/scan-profiles/"+prof["id"].(string), map[string]any{"change_note": "add trivy", "sbom": true,
		"scanners": []map[string]any{{"key": "osv-scanner"}, {"key": "trivy-fs"}}}); code != 200 || p2["current"].(map[string]any)["version"].(float64) != 2 {
		t.Errorf("update creates version 2: %d %v", code, p2)
	}
	if _, err := appPool.Exec(t.Context(), `INSERT INTO profile_scanners (profile_version_id, scanner_key) VALUES ($1, 'gitleaks')`, uuid.New()); err == nil {
		t.Error("orphan profile scanner insert should fail")
	}

	// Enqueue and coalesce.
	code, q1 := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	if code != 202 || q1["coalesced"] == true {
		t.Fatalf("enqueue: %d %v", code, q1)
	}
	if _, q2 := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil); q2["coalesced"] != true || q2["job_id"] != q1["job_id"] {
		t.Errorf("second trigger must coalesce: %v", q2)
	}
	viewer := scoped("viewer", authz.Scope{Type: authz.ScopeOrganization, ID: orgID})
	if code, _ := h.user(viewer, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil); code != 403 {
		t.Errorf("viewer lacks scans.run: want 403, got %d", code)
	}

	// Worker registration.
	if code, _ := h.worker("wrong-bootstrap-token-0123456789abcdef", "POST", "/internal/worker/v1/register", map[string]any{"name": "w1", "family": "core"}); code != 401 {
		t.Errorf("bad bootstrap token: want 401, got %d", code)
	}
	wname := "core-" + uuid.NewString()[:6]
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": wname, "family": "core", "scanners": map[string]string{"gitleaks": "8.30.1"}})
	token := reg["token"].(string)
	if code, _ := h.worker(bootstrap, "POST", "/internal/worker/v1/lease", map[string]any{}); code != 401 {
		t.Errorf("bootstrap token must not authorize job calls, got %d", code)
	}

	// Lease: drain any queue left by other tests until we get our job.
	var job map[string]any
	for i := 0; i < 20; i++ {
		code, j := h.worker(token, "POST", "/internal/worker/v1/lease", map[string]any{})
		if code != 200 {
			t.Fatalf("lease: %d", code)
		}
		if j["job_id"] == q1["job_id"] {
			job = j
			break
		}
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+j["job_id"].(string)+"/complete", map[string]any{"status": "failed", "error": "test drain"})
	}
	if job == nil {
		t.Fatal("job not leased")
	}
	cred := job["credential"].(map[string]any)
	if cred["token"] != "ghs_short_lived" || job["ref"] != "main" || len(job["scanners"].([]any)) < 7 {
		t.Fatalf("lease payload: %v", job)
	}
	jobID := job["job_id"].(string)

	// Another worker cannot upload to this job.
	_, reg2 := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": wname + "-b", "family": "core"})
	if code, _ := h.worker(reg2["token"].(string), "POST", "/internal/worker/v1/jobs/"+jobID+"/results", map[string]any{"scanner": "gitleaks", "status": "succeeded"}); code != 409 {
		t.Errorf("foreign worker upload: want 409, got %d", code)
	}

	for key, file := range fixtureFiles {
		code, r := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/results", map[string]any{
			"scanner": key, "version": "test", "status": "succeeded", "duration_ms": 1200, "output_gzip": fixture(t, file)})
		if code != 200 {
			t.Fatalf("upload %s: %d %v", key, code, r)
		}
	}
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/results", map[string]any{"scanner": "syft", "status": "succeeded", "output_gzip": fixture(t, "grype.json")})
	if code, _ := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/results", map[string]any{"scanner": "gitleaks", "status": "succeeded"}); code != 409 {
		t.Errorf("duplicate upload: want 409, got %d", code)
	}
	if code, done := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/complete", map[string]any{"status": "succeeded"}); code != 200 || done["status"] != "succeeded" {
		t.Fatalf("complete: %d %v", code, done)
	}

	code, detail := h.user(admin, "GET", "/api/v1/scans/"+jobID, nil)
	if code != 200 || detail["status"] != "succeeded" || detail["findings_new"].(float64) < 15 || len(detail["results"].([]any)) != 7 {
		t.Fatalf("job detail: %d %v", code, detail)
	}
	code, fl := h.user(admin, "GET", "/api/v1/findings?status=all&repository_id="+repo.String()+"&q=CVE-2021-23337", nil)
	items := fl["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("CVE-2021-23337 must be one deduplicated finding, got %d: %v", len(items), fl)
	}
	scannersFound := items[0].(map[string]any)["scanner_keys"].([]any)
	if len(scannersFound) != 3 {
		t.Errorf("finding should list trivy, grype and osv: %v", scannersFound)
	}
	_, sum := h.user(admin, "GET", "/api/v1/findings/summary?repository_id="+repo.String(), nil)
	if sum["critical"].(float64) < 1 || sum["high"].(float64) < 1 {
		t.Errorf("summary: %v", sum)
	}
	code, fd := h.user(admin, "GET", "/api/v1/findings/"+items[0].(map[string]any)["id"].(string), nil)
	if code != 200 || len(fd["occurrences"].([]any)) != 3 {
		t.Errorf("finding detail should have 3 occurrences: %d %v", code, fd)
	}
	if code, _ := h.user(admin, "GET", "/api/v1/scans/"+jobID+"/results/grype/artifact", nil); code != 200 {
		t.Errorf("raw artifact download: %d", code)
	}
	if code, _ := h.user(scoped("viewer", authz.Scope{Type: authz.ScopeRegion, ID: uuid.New()}), "GET", "/api/v1/findings/"+items[0].(map[string]any)["id"].(string), nil); code != 404 {
		t.Errorf("out-of-scope finding must 404, got %d", code)
	}

	// Rescan: Trivy fails, everything else reports nothing. Findings only
	// Trivy could vouch for stay open; the rest are auto-fixed.
	_, q3 := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	_, job2 := h.worker(token, "POST", "/internal/worker/v1/lease", map[string]any{})
	if job2["job_id"] != q3["job_id"] {
		t.Fatalf("expected second job, got %v", job2)
	}
	j2 := job2["job_id"].(string)
	empty := map[string]string{"grype": `{"matches":[]}`}
	for key := range fixtureFiles {
		body := map[string]any{"scanner": key, "status": "succeeded"}
		if key == "trivy-fs" {
			body["status"], body["error"] = "failed", "db download failed"
		} else {
			content := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}`
			if c, ok := empty[key]; ok {
				content = c
			}
			var b bytes.Buffer
			zw := gzip.NewWriter(&b)
			_, _ = zw.Write([]byte(content))
			_ = zw.Close()
			body["output_gzip"] = base64.StdEncoding.EncodeToString(b.Bytes())
		}
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+j2+"/results", body)
	}
	_, done2 := h.worker(token, "POST", "/internal/worker/v1/jobs/"+j2+"/complete", map[string]any{"status": "succeeded"})
	if done2["status"] != "partial" {
		t.Errorf("one failed scanner gives a partial result, got %v", done2)
	}
	var open, fixed, trivyOpen int
	_ = appPool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE status = 'open'), count(*) FILTER (WHERE status = 'fixed'),
		count(*) FILTER (WHERE status = 'open' AND 'trivy-fs' = ANY(scanner_keys)) FROM findings WHERE repository_id = $1`, repo).Scan(&open, &fixed, &trivyOpen)
	if fixed == 0 || open != trivyOpen {
		t.Errorf("auto-resolution: open=%d fixed=%d trivyOpen=%d", open, fixed, trivyOpen)
	}

	// Cancel a queued job; a heartbeat on a cancelled running job says stop.
	_, q4 := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	if code, _ := h.user(admin, "POST", "/api/v1/scans/"+q4["job_id"].(string)+"/cancel", nil); code != 204 {
		t.Errorf("cancel queued: %d", code)
	}
	_, q5 := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	h.worker(token, "POST", "/internal/worker/v1/lease", map[string]any{})
	h.user(admin, "POST", "/api/v1/scans/"+q5["job_id"].(string)+"/cancel", nil)
	if _, hb := h.worker(token, "POST", "/internal/worker/v1/jobs/"+q5["job_id"].(string)+"/heartbeat", map[string]any{}); hb["cancel"] != true {
		t.Errorf("heartbeat should request cancellation: %v", hb)
	}

	// Lease expiry requeues the job.
	_, q6 := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	h.worker(token, "POST", "/internal/worker/v1/lease", map[string]any{})
	_, _ = appPool.Exec(t.Context(), `UPDATE scan_jobs SET lease_expires_at = now() - interval '1 minute' WHERE id = $1`, q6["job_id"])
	if _, again := h.worker(reg2["token"].(string), "POST", "/internal/worker/v1/lease", map[string]any{}); again["job_id"] != q6["job_id"] {
		t.Errorf("expired lease should be re-leased: %v", again)
	}
	// The worker dies while the same scan is queued again: the expired job
	// gives way to the queued one instead of blocking the repository.
	_, q7 := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	if q7["job_id"] == q6["job_id"] {
		t.Fatal("a running scan must not absorb a new request")
	}
	_, _ = appPool.Exec(t.Context(), `UPDATE scan_jobs SET lease_expires_at = now() - interval '1 minute' WHERE id = $1`, q6["job_id"])
	if _, next := h.worker(reg2["token"].(string), "POST", "/internal/worker/v1/lease", map[string]any{}); next["job_id"] != q7["job_id"] {
		t.Errorf("the queued scan should be leased after the expired one: %v", next)
	}
	var st6, err6 string
	_ = appPool.QueryRow(t.Context(), `SELECT status, error FROM scan_jobs WHERE id = $1`, q6["job_id"]).Scan(&st6, &err6)
	if st6 != "failed" || !strings.Contains(err6, "lease expired") {
		t.Errorf("expired job with a queued successor: %s %q", st6, err6)
	}

	// Revocation is sticky.
	_, workers := h.user(admin, "GET", "/api/v1/workers", nil)
	var wid string
	for _, w := range workers["items"].([]any) {
		if w.(map[string]any)["name"] == wname {
			wid = w.(map[string]any)["id"].(string)
		}
	}
	if code, _ := h.user(admin, "POST", "/api/v1/workers/"+wid+"/revoke", nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := h.worker(token, "POST", "/internal/worker/v1/lease", map[string]any{}); code != 401 {
		t.Errorf("revoked token: want 401, got %d", code)
	}
	if code, _ := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": wname, "family": "core"}); code != 403 {
		t.Errorf("revoked name cannot re-register: want 403, got %d", code)
	}

	// Archived default profile is refused.
	_, profs := h.user(admin, "GET", "/api/v1/scan-profiles", nil)
	for _, p := range profs["items"].([]any) {
		if p.(map[string]any)["is_default"] == true {
			if code, _ := h.user(admin, "DELETE", "/api/v1/scan-profiles/"+p.(map[string]any)["id"].(string), nil); code != 409 {
				t.Errorf("archiving the default profile: want 409, got %d", code)
			}
		}
	}
}

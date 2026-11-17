//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
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
	"pathos/internal/secrets"
)

func TestScanTargets(t *testing.T) {
	ctx := t.Context()
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	svc := &scans.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log,
		Principal: auth.PrincipalFrom, BootstrapToken: bootstrap, OrgID: orgID, Secrets: &secrets.Store{Keys: kr}}
	h := &scanHarness{t: t, api: newMux(svc.Register), internal: svc.InternalHandler()}
	admin := reviewUser(t, "platform_admin")
	viewer := reviewUser(t, "viewer")
	repo := createRepo(t, "tgt-"+uuid.NewString()[:6])

	// --- validation and authorization --------------------------------------
	url := map[string]any{"repository_id": repo, "kind": "url", "name": "Staging web", "reference": "https://staging.example.test",
		"auth_type": "header", "auth_header_name": "Authorization", "auth_secret": "Bearer tgt-secret-123"}
	if code, _ := h.user(viewer, "POST", "/api/v1/scan-targets", url); code != 403 {
		t.Errorf("viewer cannot add targets: %d", code)
	}
	if code, out := h.user(admin, "POST", "/api/v1/scan-targets", url); code != 400 || !strings.Contains(errMsg(out), "authorized") {
		t.Errorf("DAST target without authorization: %d %v", code, out)
	}
	inj := map[string]any{}
	for k, v := range url {
		inj[k] = v
	}
	inj["authorized"], inj["auth_secret"] = true, "Bearer x\r\nX-Injected: 1"
	if code, _ := h.user(admin, "POST", "/api/v1/scan-targets", inj); code != 400 {
		t.Errorf("header values with line breaks must be rejected: %d", code)
	}
		url["authorized"] = true
	url["authorization_note"] = "Change CHG-1234, owner approved"
	code, ut := h.user(admin, "POST", "/api/v1/scan-targets", url)
	if code != 201 || ut["authorized_at"] == nil || ut["has_secret"] != true || ut["egress_host"] != "staging.example.test" {
		t.Fatalf("create url target: %d %v", code, ut)
	}
	raw, _ := json.Marshal(ut)
	if strings.Contains(string(raw), "tgt-secret-123") {
		t.Fatal("target credential returned by the API")
	}
	urlID := ut["id"].(string)
	if code, _ := h.user(admin, "POST", "/api/v1/scan-targets", url); code != 409 {
		t.Errorf("duplicate target: %d", code)
	}
	spec := "openapi: 3.0.0\ninfo: {title: t, version: '1'}\nservers: [{url: 'https://other.example.test'}]\npaths: {/a: {get: {}}}\n"
	if code, _ := h.user(admin, "POST", "/api/v1/scan-targets", map[string]any{"repository_id": repo, "kind": "api", "name": "API",
		"reference": "https://api.example.test", "api_spec": spec, "authorized": true}); code != 400 {
		t.Errorf("API spec pointing at another host: %d", code)
	}
	if code, _ := h.user(admin, "PUT", "/api/v1/scan-targets/"+urlID, map[string]any{"reference": "https://prod.example.test"}); code != 400 {
		t.Errorf("changing the address needs a new authorization: %d", code)
	}
	if code, _ := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "dast " + uuid.NewString()[:4],
		"scanners": []map[string]any{{"key": "nuclei"}}}); code != 400 {
		t.Errorf("target scanners cannot be put in repository profiles: %d", code)
	}

	// --- SBOM target -------------------------------------------------------
	sbom, _ := os.ReadFile("../../internal/scanners/testdata/syft.cdx.json")
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("repository_id", repo.String())
	_ = mw.WriteField("name", "Vendor appliance SBOM")
	fw, _ := mw.CreateFormFile("file", "vendor.cdx.json")
	_, _ = fw.Write(sbom)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/v1/scan-targets/sbom", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.api.ServeHTTP(rec, req.WithContext(auth.WithPrincipal(req.Context(), admin)))
	var st map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if rec.Code != 201 || st["sbom_format"] != "cyclonedx" || st["sbom_components"].(float64) == 0 {
		t.Fatalf("SBOM target: %d %v", rec.Code, st)
	}
	sbomID := st["id"].(string)

	// --- queueing ----------------------------------------------------------
	_, q1 := h.user(admin, "POST", "/api/v1/scan-targets/"+urlID+"/scan", nil)
	_, q2 := h.user(admin, "POST", "/api/v1/scan-targets/"+urlID+"/scan", nil)
	if q1["job_id"] == nil || q2["coalesced"] != true || q2["job_id"] != q1["job_id"] {
		t.Fatalf("target scans coalesce: %v %v", q1, q2)
	}
	// Jobs of one repository run one at a time, in queue order.
	_, qs := h.user(admin, "POST", "/api/v1/scan-targets/"+sbomID+"/scan", nil)
	_, rq := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
	if rq["job_id"] == nil || rq["job_id"] == q1["job_id"] || rq["job_id"] == qs["job_id"] {
		t.Fatalf("a repository scan is separate from queued target scans: %v", rq)
	}

	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "tgt-" + uuid.NewString()[:6], "family": "core"})
	token := reg["token"].(string)
	leased := map[string]map[string]any{}
	// Only one job per repository runs at a time: run them one by one.
	run := func(id string, results ...map[string]any) map[string]any {
		t.Helper()
		var job map[string]any
		for i := 0; i < 10 && job == nil; i++ {
			if j, ok := leased[id]; ok {
				job = j
				break
			}
			code, j := h.worker(token, "POST", "/internal/worker/v1/lease", map[string]any{})
			if code != 200 {
				continue
			}
			jid := j["job_id"].(string)
			if j["repository_id"] != repo.String() {
				// Left over by another test.
				h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/complete", map[string]any{"status": "failed", "error": "test drain"})
				continue
			}
			leased[jid] = j
			if jid == id {
				job = j
			}
		}
		if job == nil {
			t.Fatalf("job %s not leased", id)
		}
		for _, r := range results {
			if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+id+"/results", r); code != 200 && code != 201 {
				t.Fatalf("upload: %d %v", code, out)
			}
		}
		if code, out := h.worker(token, "POST", "/internal/worker/v1/jobs/"+id+"/complete", map[string]any{"status": "succeeded"}); code != 200 {
			t.Fatalf("complete: %d %v", code, out)
		}
		delete(leased, id)
		return job
	}

	nuclei := fixture(t, "nuclei.jsonl")
	urlJob := run(q1["job_id"].(string), map[string]any{"scanner": "nuclei", "status": "succeeded", "output_gzip": nuclei})
	tg, _ := urlJob["target"].(map[string]any)
	if tg == nil || tg["kind"] != "url" || tg["header_value"] != "Bearer tgt-secret-123" || urlJob["clone_url"] != "" || urlJob["credential"] != nil {
		t.Fatalf("leased target job: %v", urlJob)
	}
	if sc := urlJob["scanners"].([]any); len(sc) != 1 || sc[0].(map[string]any)["key"] != "nuclei" {
		t.Errorf("url target scanners: %v", sc)
	}
	var dast int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE scan_target_id = $1 AND category = 'dast' AND status = 'open'`, urlID).Scan(&dast)
	if dast != 2 {
		t.Errorf("DAST findings on the target: %d", dast)
	}
	_, lst := h.user(admin, "GET", "/api/v1/findings?scan_target_id="+urlID, nil)
	if items, _ := lst["items"].([]any); len(items) != 2 || items[0].(map[string]any)["scan_target_kind"] != "url" {
		t.Errorf("findings filtered by target: %v", lst["items"])
	}

	sbomJob := run(qs["job_id"].(string), map[string]any{"scanner": "grype", "status": "succeeded", "output_gzip": fixture(t, "grype.json")})
	stg := sbomJob["target"].(map[string]any)
	sum := sha256.Sum256(sbom)
	if stg["kind"] != "sbom" || stg["sha256"] != hex.EncodeToString(sum[:]) {
		t.Errorf("SBOM lease: %v", stg)
	}
	var sbomFindings int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE scan_target_id = $1 AND status = 'open'`, sbomID).Scan(&sbomFindings)
	if sbomFindings == 0 {
		t.Error("SBOM target produced no findings")
	}

	// The repository scan's Grype run finds nothing; target findings are
	// not the repository's and stay open.
	repoJob := run(rq["job_id"].(string), map[string]any{"scanner": "grype", "status": "succeeded",
		"output_gzip": gzB64([]byte(`{"matches":[]}`))})
	if repoJob["target"] != nil {
		t.Errorf("repository job has a target: %v", repoJob["target"])
	}
	for _, sc := range repoJob["scanners"].([]any) {
		if k := sc.(map[string]any)["key"]; k == "nuclei" || k == "trivy-image" {
			t.Errorf("target scanner %s in a repository scan", k)
		}
	}
	var stillOpen int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE scan_target_id = $1 AND status = 'open'`, sbomID).Scan(&stillOpen)
	if stillOpen != sbomFindings {
		t.Errorf("a repository scan resolved SBOM target findings: %d -> %d", sbomFindings, stillOpen)
	}

	// A second target scan that no longer finds anything resolves the
	// target's findings.
	_, q3 := h.user(admin, "POST", "/api/v1/scan-targets/"+urlID+"/scan", nil)
	run(q3["job_id"].(string), map[string]any{"scanner": "nuclei", "status": "succeeded", "output_gzip": gzB64([]byte(""))})
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE scan_target_id = $1 AND status = 'fixed'`, urlID).Scan(&dast)
	if dast != 2 {
		t.Errorf("target findings resolved by a clean target scan: %d", dast)
	}

	// --- lifecycle ---------------------------------------------------------
	if code, _ := h.user(admin, "DELETE", "/api/v1/scan-targets/"+urlID, nil); code != 409 {
		t.Errorf("targets with findings are disabled, not deleted: %d", code)
	}
	if code, out := h.user(admin, "PUT", "/api/v1/scan-targets/"+urlID, map[string]any{"enabled": false}); code != 200 || out["enabled"] != false {
		t.Errorf("disable: %d %v", code, out)
	}
	if code, _ := h.user(admin, "POST", "/api/v1/scan-targets/"+urlID+"/scan", nil); code != 409 {
		t.Errorf("disabled targets are not scanned: %d", code)
	}
	code, img := h.user(admin, "POST", "/api/v1/scan-targets", map[string]any{"repository_id": repo, "kind": "image", "name": "API image",
		"reference": "ghcr.io/acme/api:1.0", "auth_type": "basic", "auth_username": "bot", "auth_secret": "ghp_registry_token"})
	if code != 201 || img["egress_host"] != "ghcr.io" {
		t.Fatalf("image target: %d %v", code, img)
	}
	var secretID *uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT secret_id FROM scan_targets WHERE id = $1`, img["id"]).Scan(&secretID)
	if code, _ := h.user(admin, "DELETE", "/api/v1/scan-targets/"+img["id"].(string), nil); code != 204 {
		t.Errorf("delete unused target: %d", code)
	}
	var left int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM secrets WHERE id = $1`, secretID).Scan(&left)
	if secretID == nil || left != 0 {
		t.Error("the deleted target's credential must be removed")
	}
	_, all := h.user(viewer, "GET", "/api/v1/scan-targets?repository_id="+repo.String(), nil)
	if items, _ := all["items"].([]any); len(items) != 2 {
		t.Errorf("viewer lists targets: %v", all)
	}
	var audits int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE target_type = 'scan_target' AND target_id = $1`, urlID).Scan(&audits)
	if audits < 3 {
		t.Errorf("target changes are audited: %d", audits)
	}
}

func gzB64(b []byte) string {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func errMsg(out map[string]any) string {
	if e, ok := out["error"].(map[string]any); ok {
		s, _ := e["message"].(string)
		return s
	}
	return ""
}

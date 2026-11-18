//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"os"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/vuln"
)

func gzJSON(t *testing.T, v any) string {
	t.Helper()
	raw, ok := v.([]byte)
	if !ok {
		var err error
		if raw, err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

// TestContentScanning covers the 1.1 content scanners end to end through
// the worker API: malware (ClamAV report), binary hardening, framework
// configuration rules (Opengrep), and licence policy violations from the
// SBOM and from file-level licences, including their lifecycle when the
// component disappears or the policy changes.
func TestContentScanning(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	vsvc := &vuln.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log, Principal: auth.PrincipalFrom}
	vmux := http.NewServeMux()
	vsvc.Register(vmux)
	vcall := func(method, path string, body any) int {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(auth.WithPrincipal(req.Context(), admin))
		rec := httptest.NewRecorder()
		vmux.ServeHTTP(rec, req)
		return rec.Code
	}
	policy := func(entries map[string]string) {
		t.Helper()
		items := []map[string]string{}
		for id, d := range entries {
			items = append(items, map[string]string{"spdx_id": id, "decision": d})
		}
		if code := vcall("PUT", "/api/v1/license-policies", map[string]any{"items": items}); code != 204 {
			t.Fatalf("license policy update: %d", code)
		}
	}
	t.Cleanup(func() { policy(vuln.DefaultLicensePolicy) })
	policy(map[string]string{"AGPL-3.0-only": "deny", "GPL-3.0-only": "review", "GPL-2.0-or-later": "deny"})

	// The catalog lists the new scanners.
	code, cat := h.user(admin, "GET", "/api/v1/scanners", nil)
	if code != 200 {
		t.Fatalf("catalog: %d", code)
	}
	cats := map[string]string{}
	for _, it := range cat["items"].([]any) {
		m := it.(map[string]any)
		cats[m["key"].(string)] = m["category"].(string)
	}
	if cats["clamav"] != "malware" || cats["binary-hardening"] != "binary" || cats["licensecheck"] != "license" {
		t.Fatalf("catalog entries: %v", cats)
	}

	repo := createRepo(t, "content-"+uuid.NewString()[:6])
	wname := "core-" + uuid.NewString()[:6]
	_, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": wname, "family": "core",
		"scanners": map[string]string{"gitleaks": "8.30.1", "clamav": "1.5.0", "binary-hardening": "1.1.0", "licensecheck": "1.1.0"}})
	token := reg["token"].(string)

	runScan := func(results map[string]any) string {
		t.Helper()
		_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", nil)
		var job map[string]any
		for i := 0; i < 20; i++ {
			code, j := h.worker(token, "POST", "/internal/worker/v1/lease", map[string]any{})
			if code != 200 {
				t.Fatalf("lease: %d", code)
			}
			if j["job_id"] == q["job_id"] {
				job = j
				break
			}
			h.worker(token, "POST", "/internal/worker/v1/jobs/"+j["job_id"].(string)+"/complete", map[string]any{"status": "failed", "error": "test drain"})
		}
		if job == nil {
			t.Fatal("job not leased")
		}
		id := job["job_id"].(string)
		for key, out := range results {
			body := map[string]any{"scanner": key, "version": "test", "status": "succeeded"}
			if s, ok := out.(string); ok && (s == "skipped" || s == "failed") {
				body["status"], body["error"] = s, "test"
			} else {
				body["output_gzip"] = gzJSON(t, out)
			}
			if code, r := h.worker(token, "POST", "/internal/worker/v1/jobs/"+id+"/results", body); code != 200 {
				t.Fatalf("upload %s: %d %v", key, code, r)
			}
		}
		if code, done := h.worker(token, "POST", "/internal/worker/v1/jobs/"+id+"/complete", map[string]any{"status": "succeeded"}); code != 200 {
			t.Fatalf("complete: %d %v", code, done)
		}
		return id
	}

	sbom := func(comps ...map[string]any) map[string]any {
		return map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": comps}
	}
	comp := func(name, version, lic string) map[string]any {
		return map[string]any{"type": "library", "name": name, "version": version, "purl": "pkg:npm/" + name + "@" + version,
			"bom-ref": name, "licenses": []any{map[string]any{"license": map[string]any{"id": lic}}}}
	}
	misconfig, err := os.ReadFile("../../internal/scanners/testdata/opengrep-misconfig.sarif")
	if err != nil {
		t.Fatal(err)
	}
	first := map[string]any{
		"syft": sbom(comp("badlib", "1.0.0", "AGPL-3.0-only"), comp("goodlib", "2.0.0", "MIT"), comp("gpllib", "3.0.0", "GPL-3.0-only")),
		"licensecheck": map[string]any{"tool": "licensecheck", "version": "1.1.0", "licenses": []any{
			map[string]any{"path": "src/copied.c", "spdx": "GPL-3.0", "method": "license-text", "line": 3},
			map[string]any{"path": "lib/dual.js", "spdx": "GPL-2.0-or-later", "method": "spdx-tag", "line": 1, "alternatives": []string{"MIT"}},
			map[string]any{"path": "LICENSE", "spdx": "MIT", "method": "license-text"},
		}},
		"clamav": map[string]any{"tool": "clamav", "version": "1.1.0", "engine": "ClamAV 1.5.0/27800", "findings": []any{map[string]any{
			"rule_id": "malware/Win.Test.EICAR_HDB-1", "title": "Malware detected: Win.Test.EICAR_HDB-1", "severity": "critical",
			"confidence": "high", "cwe": []string{"CWE-506"}, "file_path": "tests/eicar.com", "key": "Win.Test.EICAR_HDB-1",
			"description": "ClamAV matched Win.Test.EICAR_HDB-1. Engine: ClamAV 1.5.0/27800.", "evidence": "signature: Win.Test.EICAR_HDB-1\nengine: ClamAV 1.5.0/27800"}}},
		"binary-hardening": map[string]any{"tool": "binary-hardening", "version": "1.1.0", "findings": []any{map[string]any{
			"rule_id": "binary/elf-no-pie", "title": "Executable is not position independent (no PIE)", "severity": "medium",
			"confidence": "high", "cwe": []string{"CWE-693"}, "file_path": "bin/tool", "key": "binary/elf-no-pie",
			"description": "bin/tool: ET_EXEC.\n\nRemediation: -fPIE -pie"}}},
		"opengrep": misconfig,
	}
	runScan(first)

	findings := func(q string) []map[string]any {
		t.Helper()
		code, fl := h.user(admin, "GET", "/api/v1/findings?repository_id="+repo.String()+"&"+q, nil)
		if code != 200 {
			t.Fatalf("findings %s: %d %v", q, code, fl)
		}
		var out []map[string]any
		for _, it := range fl["items"].([]any) {
			out = append(out, it.(map[string]any))
		}
		return out
	}
	if fs := findings("status=all&category=malware"); len(fs) != 1 || fs[0]["severity"] != "critical" || fs[0]["file_path"] != "tests/eicar.com" {
		t.Errorf("malware finding: %v", fs)
	}
	if fs := findings("status=all&category=binary"); len(fs) != 1 || fs[0]["rule_id"] != "binary/elf-no-pie" {
		t.Errorf("binary hardening finding: %v", fs)
	}
	if fs := findings("status=all&category=misconfiguration"); len(fs) < 8 {
		t.Errorf("framework configuration findings: %d", len(fs))
	}
	lic := map[string]map[string]any{}
	for _, f := range findings("status=all&category=license") {
		lic[f["rule_id"].(string)+"|"+f["package_name"].(string)+"|"+f["file_path"].(string)] = f
	}
	bad := lic["license/AGPL-3.0-only|badlib|"]
	if bad == nil || bad["severity"] != "high" || bad["status"] != "open" || bad["sla_due_at"] == nil ||
		bad["scanner_keys"].([]any)[0] != "license-policy" {
		t.Fatalf("denied component licence finding with SLA: %v", lic)
	}
	if f := lic["license/GPL-3.0-only|gpllib|"]; f == nil || f["severity"] != "medium" {
		t.Errorf("review licence finding: %v", f)
	}
	if f := lic["license/GPL-3.0|"+"|src/copied.c"]; f == nil || f["severity"] != "medium" || f["confidence"] != "medium" ||
		f["scanner_keys"].([]any)[0] != "licensecheck" {
		t.Errorf("file licence text GPL-3.0 matches the GPL-3.0-only policy entry: %v", lic)
	}
	if len(lic) != 3 {
		t.Errorf("MIT and an OR choice with an allowed alternative are not violations: %v", lic)
	}
	badID := bad["id"].(string)
	_, fd := h.user(admin, "GET", "/api/v1/findings/"+badID, nil)
	if occ, _ := fd["occurrences"].([]any); len(occ) != 1 {
		t.Errorf("licence finding occurrence: %v", fd["occurrences"])
	}

	// The policy no longer denies AGPL: fixed at once, never deleted.
	policy(map[string]string{"GPL-3.0-only": "review", "GPL-2.0-or-later": "deny"})
	var status string
	if err := appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, badID).Scan(&status); err != nil || status != "fixed" {
		t.Fatalf("policy change resolves the finding: %q %v", status, err)
	}
	// Denied again: re-opened (recurrence), severity follows the decision.
	policy(map[string]string{"AGPL-3.0-only": "review", "GPL-3.0-only": "review", "GPL-2.0-or-later": "deny"})
	var sev string
	var rec int
	_ = appPool.QueryRow(ctx, `SELECT status, severity, recurrence_count FROM findings WHERE id = $1`, badID).Scan(&status, &sev, &rec)
	if status != "open" || sev != "medium" || rec != 1 {
		t.Errorf("re-opened with the new decision: %s %s %d", status, sev, rec)
	}
	var hist int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM finding_status_history WHERE finding_id = $1 AND reason LIKE '%licence policy%'`, badID).Scan(&hist)
	if hist < 1 {
		t.Error("status changes are recorded with the licence policy reason")
	}
	var audited bool
	_ = appPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_logs WHERE action = 'license_policy.update' AND metadata ? 'findings_resolved' AND created_at > now() - interval '1 minute')`).Scan(&audited)
	if !audited {
		t.Error("policy update audited with the finding counts")
	}

	// Rescan: badlib removed from the SBOM, the copied file gone; ClamAV
	// skipped (not configured) keeps the malware finding open.
	second := map[string]any{
		"syft":             sbom(comp("goodlib", "2.0.0", "MIT"), comp("gpllib", "3.0.0", "GPL-3.0-only")),
		"licensecheck":     map[string]any{"tool": "licensecheck", "licenses": []any{}},
		"clamav":           "skipped",
		"binary-hardening": map[string]any{"tool": "binary-hardening", "findings": []any{}},
		"opengrep":         misconfig,
	}
	runScan(second)
	_ = appPool.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1`, badID).Scan(&status)
	if status != "fixed" {
		t.Errorf("component removed: %s", status)
	}
	if fs := findings("category=license&status=open"); len(fs) != 1 || fs[0]["package_name"] != "gpllib" {
		t.Errorf("only gpllib stays open: %v", fs)
	}
	if fs := findings("category=malware&status=open"); len(fs) != 1 {
		t.Errorf("a skipped ClamAV run is no evidence that malware was removed: %v", fs)
	}
	if fs := findings("category=binary&status=open"); len(fs) != 0 {
		t.Errorf("binary hardening finding fixed: %v", fs)
	}
	var total int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND category = 'license'`, repo).Scan(&total)
	if total != 3 {
		t.Errorf("licence findings are never deleted: %d", total)
	}
	var files int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM repository_file_licenses WHERE repository_id = $1`, repo).Scan(&files)
	if files != 0 {
		t.Errorf("file licence inventory replaced by the latest run: %d", files)
	}

	// Category filters elsewhere accept the new categories.
	if code, _ := h.user(admin, "GET", "/api/v1/findings?category=bogus", nil); code != 400 {
		t.Errorf("unknown category: %d", code)
	}
}

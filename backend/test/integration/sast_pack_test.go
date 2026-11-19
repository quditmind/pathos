//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"io"
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

// A secrets scanner of the worker-sast pack (TruffleHog, parser
// import:trufflehog) uploads its real output: the findings are recorded and
// the stored report holds no secret value, like an imported report. The
// fixture is TruffleHog 3.99.9 output on fake credentials
// (internal/worker/testdata/manifests).
func TestSASTPackSecretsReportIsSanitized(t *testing.T) {
	ctx := t.Context()
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	svc := &scans.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log,
		Principal: auth.PrincipalFrom, BootstrapToken: bootstrap, OrgID: orgID, Secrets: &secrets.Store{Keys: kr}}
	h := &scanHarness{t: t, api: newMux(svc.Register), internal: svc.InternalHandler()}
	admin := reviewUser(t, "platform_admin")
	tag := uuid.NewString()[:6]

	tools := map[string]any{"trufflehog": map[string]any{"name": "TruffleHog", "category": "secrets", "scan_types": []string{"secrets"},
		"license_spdx": "AGPL-3.0-only", "family": "sast", "targets": []string{"repository"}, "network": "none",
		"parser": "import:trufflehog", "first_party": true}}
	code, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "sast-pack-" + tag, "family": "sast",
		"scanners": map[string]string{"gitleaks": "8.30.1", "trufflehog": "3.99.9"}, "tools": tools})
	if code != 200 {
		t.Fatalf("register: %d %v", code, reg)
	}
	token := reg["token"].(string)
	repo := createRepo(t, "sast-pack-"+tag)
	code, prof := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "TruffleHog " + tag,
		"scanners": []map[string]any{{"key": "trufflehog"}}})
	if code != 201 {
		t.Fatalf("profile: %d %v", code, prof)
	}
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", map[string]any{"profile_id": prof["id"]})
	jid := h.leaseJob(token, q["job_id"].(string))["job_id"].(string)

	raw, err := os.ReadFile("../../internal/worker/testdata/manifests/trufflehog.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if code, r := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{"scanner": "trufflehog", "version": "3.99.9",
		"status": "succeeded", "output_gzip": gzB64(raw), "parser": map[string]any{"kind": "import", "format": "trufflehog"}}); code != 200 ||
		r["findings"].(float64) != 3 {
		t.Fatalf("trufflehog results: %d %v", code, r)
	}
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/complete", map[string]any{"status": "succeeded"})

	var n int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND 'trufflehog' = ANY(scanner_keys) AND category = 'secrets'
		AND file_path = 'config/settings.env'`, repo).Scan(&n)
	if n != 3 {
		t.Errorf("findings: %d", n)
	}
	var gz []byte
	if err := appPool.QueryRow(ctx, `SELECT a.data_gzip FROM scan_artifacts a JOIN scan_results r ON r.id = a.scan_result_id
		WHERE r.scan_job_id = $1 AND r.scanner_key = 'trufflehog'`, jid).Scan(&gz); err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := io.ReadAll(zr)
	if len(stored) == 0 || strings.Contains(string(stored), "Fixture-") || !strings.Contains(string(stored), "[REDACTED]") {
		t.Errorf("the stored report keeps no secret: %s", stored)
	}
}

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/scans"
	"pathos/internal/secrets"
)

// PATHOS 2.0 tool framework: manifests advertised by workers, routing of
// jobs to the workers that advertise their tools, manifest parsers,
// GET /api/v1/scan-types and the intrusive testing authorization.
func TestToolFramework(t *testing.T) {
	ctx := t.Context()
	// The jobs this test fails (its own and drained ones) raise scan.failed
	// notification events; they are marked processed at the end so that
	// later notification tests only see their own.
	var start time.Time
	_ = appPool.QueryRow(ctx, `SELECT now()`).Scan(&start)
	t.Cleanup(func() {
		_, _ = appPool.Exec(context.Background(), `UPDATE notification_events SET processed_at = now() WHERE processed_at IS NULL AND created_at >= $1`, start)
	})
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	svc := &scans.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log,
		Principal: auth.PrincipalFrom, BootstrapToken: bootstrap, OrgID: orgID, Secrets: &secrets.Store{Keys: kr}}
	h := &scanHarness{t: t, api: newMux(svc.Register), internal: svc.InternalHandler()}
	admin := reviewUser(t, "platform_admin")
	tag := uuid.NewString()[:6]
	lint := "plugin-code-quality-lint" + tag
	fuzzer := "plugin-dast-fuzz" + tag

	// --- registration: manifests are advertised with their metadata ---------
	tools := map[string]any{
		"bandit": map[string]any{"name": "Bandit", "category": "sast", "scan_types": []string{"sast"}, "license_spdx": "Apache-2.0",
			"family": "sast", "targets": []string{"repository"}, "network": "none", "parser": "import:bandit", "first_party": true},
		lint: map[string]any{"name": "Lint " + tag, "category": "code-quality", "scan_types": []string{"code-quality"}, "license_spdx": "MIT",
			"homepage": "https://example.com/lint", "targets": []string{"repository"}, "parser": "jsonmap"},
		fuzzer: map[string]any{"name": "Fuzz " + tag, "category": "dast", "scan_types": []string{"dast", "fuzzing"}, "license_spdx": "Apache-2.0",
			"targets": []string{"url"}, "network": "target", "intrusive": true, "parser": "sarif"},
		// Refused: a first-party manifest cannot claim a core tool, nor a
		// plugin key, nor an unknown scan type.
		"gitleaks":                           map[string]any{"name": "fake", "category": "secrets", "first_party": true},
		"plugin-sast-claims" + tag:           map[string]any{"name": "x", "category": "sast", "first_party": true},
		"plugin-sast-badtype" + tag:          map[string]any{"name": "x", "category": "sast", "scan_types": []string{"nope"}},
		"plugin-code-quality-mismatch" + tag: map[string]any{"name": "x", "category": "sast"},
	}
	scannersAdv := map[string]string{"gitleaks": "8.30.1", "bandit": "1.9.4", lint: "1.0", fuzzer: "2.0", "plugin-sast-claims" + tag: "1",
		"plugin-sast-badtype" + tag: "1", "plugin-code-quality-mismatch" + tag: "1"}
	code, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "sast-" + tag, "family": "sast",
		"scanners": scannersAdv, "tools": tools})
	if code != 200 {
		t.Fatalf("register: %d %v", code, reg)
	}
	sastToken := reg["token"].(string)
	var advertised []byte
	var sc map[string]string
	_ = appPool.QueryRow(ctx, `SELECT tools FROM workers WHERE name = $1`, "sast-"+tag).Scan(&advertised)
	var adv map[string]map[string]any
	_ = json.Unmarshal(advertised, &adv)
	if adv["bandit"] == nil || adv[lint] == nil || adv[fuzzer] == nil || adv["gitleaks"] != nil || adv["plugin-sast-claims"+tag] != nil ||
		adv["plugin-sast-badtype"+tag] != nil || adv["plugin-code-quality-mismatch"+tag] != nil {
		t.Errorf("advertised manifests: %s", advertised)
	}
	var scRaw []byte
	_ = appPool.QueryRow(ctx, `SELECT scanners FROM workers WHERE name = $1`, "sast-"+tag).Scan(&scRaw)
	_ = json.Unmarshal(scRaw, &sc)
	if sc["gitleaks"] == "" || sc["bandit"] == "" || sc["plugin-sast-claims"+tag] != "" {
		t.Errorf("worker scanners: %v", sc)
	}
	var cat, network, lic string
	var types, targets []string
	var intrusive bool
	if err := appPool.QueryRow(ctx, `SELECT category, network, license_spdx, scan_types, targets, intrusive FROM scanner_catalog WHERE key = $1`, fuzzer).
		Scan(&cat, &network, &lic, &types, &targets, &intrusive); err != nil || cat != "dast" || network != "target" || !intrusive ||
		lic != "Apache-2.0" || strings.Join(types, ",") != "dast,fuzzing" || strings.Join(targets, ",") != "url" {
		t.Errorf("plugin catalog row: %v %s %s %s %v %v %v", err, cat, network, lic, types, targets, intrusive)
	}
	if err := appPool.QueryRow(ctx, `SELECT category FROM scanner_catalog WHERE key = $1`, lint).Scan(&cat); err != nil || cat != "code-quality" {
		t.Errorf("code-quality plugin (category with a dash): %v %s", err, cat)
	}
	// A later registration cannot make an intrusive tool look harmless.
	if _, err := appPool.Exec(ctx, `SELECT pathos_register_tool_manifest($1, 'x', 'dast', '', 'MIT', '{dast,fuzzing}', '{url}', 'none', false, 'sarif')`, fuzzer); err != nil {
		t.Fatal(err)
	}
	_ = appPool.QueryRow(ctx, `SELECT network, intrusive FROM scanner_catalog WHERE key = $1`, fuzzer).Scan(&network, &intrusive)
	if network != "target" || !intrusive {
		t.Errorf("authorization requirements only grow: %s %v", network, intrusive)
	}
	if _, err := appPool.Exec(ctx, `SELECT pathos_register_tool_manifest('bandit', 'x', 'sast', '', 'MIT', '{}', '{}', 'none', false, 'sarif')`); err == nil {
		t.Error("the application role registers plugin keys only")
	}

	// --- catalog and scan types ---------------------------------------------
	_, list := h.user(admin, "GET", "/api/v1/scanners", nil)
	byKey := map[string]map[string]any{}
	for _, it := range list["items"].([]any) {
		m := it.(map[string]any)
		byKey[m["key"].(string)] = m
	}
	if byKey["bandit"]["runnable"] != true || byKey[fuzzer]["intrusive"] != true || byKey[fuzzer]["target_only"] != true ||
		byKey[lint]["category"] != "code-quality" || byKey["shellcheck"]["category"] != "code-quality" {
		t.Errorf("catalog: bandit %v fuzzer %v lint %v", byKey["bandit"], byKey[fuzzer], byKey[lint])
	}
	viewer := reviewUser(t, "viewer")
	if code, _ := h.user(&authz.Principal{UserID: uuid.New(), OrganizationID: orgID}, "GET", "/api/v1/scan-types", nil); code != 403 {
		t.Errorf("scan types without scanners.read: %d", code)
	}
	code, st := h.user(viewer, "GET", "/api/v1/scan-types", nil)
	if code != 200 || len(st["items"].([]any)) != 25 || st["workers_online"].(float64) < 1 || len(st["generic_import_formats"].([]any)) == 0 {
		t.Fatalf("scan types: %d %v", code, st["workers_online"])
	}
	types25 := map[string]map[string]any{}
	for _, it := range st["items"].([]any) {
		m := it.(map[string]any)
		types25[m["id"].(string)] = m
	}
	toolOf := func(typ, key string) map[string]any {
		for _, x := range types25[typ]["tools"].([]any) {
			if x.(map[string]any)["key"] == key {
				return x.(map[string]any)
			}
		}
		return nil
	}
	if b := toolOf("sast", "bandit"); b == nil || b["runnable"] != true || b["workers"].(float64) < 1 || types25["sast"]["runnable"] != true {
		t.Errorf("sast: bandit %v", b)
	}
	if l := toolOf("code-quality", lint); l == nil || l["source"] != "plugin" || l["runnable"] != true {
		t.Errorf("code-quality plugin: %v", l)
	}
	if f := toolOf("fuzzing", fuzzer); f == nil || f["intrusive"] != true {
		t.Errorf("fuzzing plugin: %v", f)
	}
	if lp := toolOf("license-policy", "license-policy"); lp == nil || lp["source"] != "server" || lp["runnable"] != true {
		t.Errorf("licence policy: %v", lp)
	}
	if fmts := types25["sast"]["import_formats"].([]any); len(fmts) == 0 || types25["sast"]["importable"] != true {
		t.Errorf("sast import formats: %v", fmts)
	}
	// Every scan type with import formats lists them (licence, SBOM,
	// malware, binary, licence policy and database have none).
	for id, typ := range types25 {
		fmts, _ := typ["import_formats"].([]any)
		switch id {
		case "license", "sbom", "malware", "binary", "license-policy", "database":
		default:
			if len(fmts) == 0 {
				t.Errorf("%s: no import formats", id)
			}
		}
	}

	// --- routing: a job with bandit goes to the worker that has it ----------
	_, core := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "core-" + tag, "family": "core",
		"scanners": map[string]string{"gitleaks": "8.30.1"}})
	coreToken := core["token"].(string)
	repo := createRepo(t, "tf-"+tag)
	code, prof := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "Bandit " + tag,
		"scanners": []map[string]any{{"key": "bandit"}, {"key": lint}}})
	if code != 201 {
		t.Fatalf("profile: %d %v", code, prof)
	}
	if code, out := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "Fuzz " + tag,
		"scanners": []map[string]any{{"key": fuzzer}}}); code != 400 {
		t.Errorf("an intrusive tool in a repository profile: %d %v", code, out)
	}
	h.user(admin, "PUT", "/api/v1/repositories/"+repo.String()+"/scan-profile", map[string]any{"profile_id": prof["id"]})
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", map[string]any{"profile_id": prof["id"]})
	jobID := q["job_id"].(string)
	for i := 0; i < 30; i++ {
		code, j := h.worker(coreToken, "POST", "/internal/worker/v1/lease", map[string]any{})
		if code != 200 || j["job_id"] == nil {
			break
		}
		if j["job_id"] == jobID {
			t.Fatal("the core worker leased a job that needs bandit while a worker with bandit is online")
		}
		h.worker(coreToken, "POST", "/internal/worker/v1/jobs/"+j["job_id"].(string)+"/complete", map[string]any{"status": "failed", "error": "test drain"})
	}
	job := h.leaseJob(sastToken, jobID)
	jid := job["job_id"].(string)

	// --- manifest parsers: the tool's own output with the parser ------------
	bandit, err := os.ReadFile("../../internal/worker/testdata/manifests/bandit.json")
	if err != nil {
		t.Fatal(err)
	}
	if code, r := h.worker(sastToken, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{"scanner": "gitleaks", "status": "succeeded",
		"output_gzip": gzB64([]byte(`{"results":[]}`)), "parser": map[string]any{"kind": "import", "format": "bandit"}}); code != 400 {
		t.Errorf("a parser for a built-in tool: %d %v", code, r)
	}
	if code, r := h.worker(sastToken, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{"scanner": "bandit", "status": "succeeded",
		"output_gzip": gzB64(bandit), "parser": map[string]any{"kind": "import", "format": "no-such"}}); code != 400 {
		t.Errorf("an unknown import format: %d %v", code, r)
	}
	if code, r := h.worker(sastToken, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{"scanner": "bandit", "version": "1.9.4",
		"status": "succeeded", "output_gzip": gzB64(bandit), "parser": map[string]any{"kind": "import", "format": "bandit"}}); code != 200 ||
		r["findings"].(float64) < 4 {
		t.Fatalf("bandit results: %d %v", code, r)
	}
	lintOut := `{"items":[{"rule":"L1","msg":"unsafe call","path":"/work/x/src/run.sh","line":3,"lvl":"error"},` +
		`{"rule":"L1","msg":"unsafe call","path":"/work/x/src/run.sh","line":9,"lvl":"error"}]}`
	if code, r := h.worker(sastToken, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{"scanner": lint, "version": "1.0",
		"status": "succeeded", "output_gzip": gzB64([]byte(lintOut)), "parser": map[string]any{"kind": "jsonmap", "jsonmap": map[string]any{
			"records": "items", "rule_id": "rule", "title": "msg", "file": "path", "line": "line", "severity": "lvl"}}}); code != 200 ||
		r["findings"].(float64) != 2 {
		t.Fatalf("jsonmap results: %d %v", code, r)
	}
	h.worker(sastToken, "POST", "/internal/worker/v1/jobs/"+jid+"/complete", map[string]any{"status": "succeeded"})
	var nBandit, nLint int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND 'bandit' = ANY(scanner_keys) AND category = 'sast'`, repo).Scan(&nBandit)
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND $2 = ANY(scanner_keys) AND category = 'code-quality'
		AND file_path = 'run.sh' AND severity = 'high'`, repo, lint).Scan(&nLint)
	if nBandit < 4 || nLint != 2 {
		t.Errorf("findings: bandit %d, code-quality %d", nBandit, nLint)
	}
	var ct string
	var parser []byte
	if err := appPool.QueryRow(ctx, `SELECT a.content_type, a.parser FROM scan_artifacts a JOIN scan_results r ON r.id = a.scan_result_id
		WHERE r.scan_job_id = $1 AND r.scanner_key = $2`, jid, lint).Scan(&ct, &parser); err != nil || !strings.Contains(string(parser), `"jsonmap"`) {
		t.Errorf("the parser is stored with the original report: %v %s %s", err, ct, parser)
	}

	// --- fallback: no online worker has bandit -> any worker runs the job ---
	_, q2 := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", map[string]any{"profile_id": prof["id"]})
	if _, err := appPool.Exec(ctx, `UPDATE workers SET last_seen_at = now() - interval '1 hour' WHERE name = $1`, "sast-"+tag); err != nil {
		t.Fatal(err)
	}
	if j := h.leaseJob(coreToken, q2["job_id"].(string)); j == nil {
		t.Fatal("job not leased by the remaining worker")
	}
	h.worker(coreToken, "POST", "/internal/worker/v1/jobs/"+q2["job_id"].(string)+"/complete", map[string]any{"status": "failed", "error": "test"})

	// --- intrusive testing authorization -----------------------------------
	target := map[string]any{"repository_id": repo, "kind": "url", "name": "Fuzz target", "reference": "https://fuzz-" + tag + ".example.test",
		"authorized": true, "config": map[string]any{"tools": []string{fuzzer}}}
	if code, out := h.user(admin, "POST", "/api/v1/scan-targets", map[string]any{"repository_id": repo, "kind": "image", "name": "img",
		"reference": "registry.example.test/app:1", "config": map[string]any{"tools": []string{fuzzer}}}); code != 400 {
		t.Errorf("a url tool on an image target: %d %v", code, out)
	}
	if code, out := h.user(admin, "POST", "/api/v1/scan-targets", map[string]any{"repository_id": repo, "kind": "url", "name": "x",
		"reference": "https://x-" + tag + ".example.test", "authorized": true, "config": map[string]any{"tools": []string{"gitleaks"}}}); code != 400 {
		t.Errorf("a built-in tool in config.tools: %d %v", code, out)
	}
	code, tg := h.user(admin, "POST", "/api/v1/scan-targets", target)
	if code != 201 || tg["intrusive_authorized_at"] != nil {
		t.Fatalf("create target: %d %v", code, tg)
	}
	tid := tg["id"].(string)
	if !strings.Contains(strings.Join(anyStrings(tg["scanners"]), ","), fuzzer) {
		t.Errorf("the target runs its tools: %v", tg["scanners"])
	}
	if code, out := h.user(admin, "POST", "/api/v1/scan-targets/"+tid+"/scan", nil); code != 409 || !strings.Contains(errMsg(out), "intrusive") {
		t.Errorf("intrusive tool without the flag: %d %v", code, out)
	}
	if code, out := h.user(viewer, "PUT", "/api/v1/scan-targets/"+tid, map[string]any{"intrusive_authorized": true}); code != 403 && code != 404 {
		t.Errorf("viewer sets the intrusive flag: %d %v", code, out)
	}
	code, tg = h.user(admin, "PUT", "/api/v1/scan-targets/"+tid, map[string]any{"intrusive_authorized": true,
		"intrusive_authorization_note": "Pen-test window PT-77"})
	if code != 200 || tg["intrusive_authorized_at"] == nil || tg["intrusive_authorization_note"] != "Pen-test window PT-77" {
		t.Fatalf("authorize intrusive testing: %d %v", code, tg)
	}
	if _, err := appPool.Exec(ctx, `UPDATE workers SET last_seen_at = now() WHERE name = $1`, "sast-"+tag); err != nil {
		t.Fatal(err)
	}
	code, sq := h.user(admin, "POST", "/api/v1/scan-targets/"+tid+"/scan", nil)
	if code != 202 {
		t.Fatalf("scan with the flag: %d %v", code, sq)
	}
	tj := h.leaseJob(sastToken, sq["job_id"].(string))
	tgt := tj["target"].(map[string]any)
	if tgt["intrusive_authorized"] != true || !strings.Contains(strings.Join(scannerKeys(tj), ","), fuzzer) {
		t.Errorf("leased target job: %v %v", tgt, tj["scanners"])
	}
	h.worker(sastToken, "POST", "/internal/worker/v1/jobs/"+sq["job_id"].(string)+"/complete", map[string]any{"status": "succeeded"})
	// A new address withdraws the flag; withdrawing is audited.
	code, tg = h.user(admin, "PUT", "/api/v1/scan-targets/"+tid, map[string]any{"reference": "https://fuzz2-" + tag + ".example.test", "authorized": true})
	if code != 200 || tg["intrusive_authorized_at"] != nil {
		t.Errorf("address change keeps the intrusive flag: %d %v", code, tg["intrusive_authorized_at"])
	}
	var audits int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE target_id = $1 AND action IN ('scan_target.intrusive_authorize', 'scan_target.intrusive_revoke')`,
		tid).Scan(&audits)
	if audits != 2 {
		t.Errorf("intrusive authorization audit entries: %d", audits)
	}
	if code, _ := h.user(admin, "PUT", "/api/v1/scan-targets/"+tid, map[string]any{"intrusive_authorized": true}); code != 200 {
		t.Errorf("re-authorize: %d", code)
	}
	if code, _ := h.user(admin, "POST", "/api/v1/scan-targets", map[string]any{"repository_id": repo, "kind": "image", "name": "img2",
		"reference": "registry.example.test/app:2", "intrusive_authorized": true}); code != 400 {
		t.Errorf("intrusive flag on an image target: %d", code)
	}

	// --- the new categories are accepted everywhere categories are listed --
	if _, err := appPool.Exec(ctx, `UPDATE human_review_settings SET auto_categories = '{crypto,code-quality,api}' WHERE organization_id = $1`, orgID); err != nil {
		t.Errorf("human review categories: %v", err)
	}
	_, _ = appPool.Exec(ctx, `UPDATE human_review_settings SET auto_categories = '{sast,sca,secrets,iac,container}' WHERE organization_id = $1`, orgID)
	if _, err := appPool.Exec(ctx, `SELECT pathos_register_import_tool('import-mobile-mobsf', 'MobSF', 'mobile')`); err != nil {
		t.Errorf("import key with a new category: %v", err)
	}
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func scannerKeys(job map[string]any) []string {
	var out []string
	for _, s := range job["scanners"].([]any) {
		out = append(out, s.(map[string]any)["key"].(string))
	}
	return out
}

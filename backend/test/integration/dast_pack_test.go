//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/scans"
	"pathos/internal/secrets"
)

// The worker-dast pack: a worker that advertises the real manifests of
// workers/dast/tools.d. Tools that contact the target need the target's
// authorization statement; every intrusive tool is refused for a target
// whose intrusive testing is not authorized, and allowed once it is.
func TestDASTPackAuthorization(t *testing.T) {
	ctx := t.Context()
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	svc := &scans.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log,
		Principal: auth.PrincipalFrom, BootstrapToken: bootstrap, OrgID: orgID, Secrets: &secrets.Store{Keys: kr}}
	h := &scanHarness{t: t, api: newMux(svc.Register), internal: svc.InternalHandler()}
	admin := reviewUser(t, "platform_admin")
	tag := uuid.NewString()[:6]

	// Advertise the manifests as the worker-dast image does.
	files, err := filepath.Glob("../../../workers/dast/tools.d/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("manifests: %v", err)
	}
	type manifest struct {
		Name        string   `yaml:"name"`
		DisplayName string   `yaml:"display_name"`
		Category    string   `yaml:"category"`
		ScanTypes   []string `yaml:"scan_types"`
		License     string   `yaml:"license_spdx"`
		Homepage    string   `yaml:"homepage"`
		Family      string   `yaml:"family"`
		Targets     []string `yaml:"targets"`
		Network     string   `yaml:"network"`
		Intrusive   bool     `yaml:"intrusive"`
		Parser      string   `yaml:"parser"`
	}
	tools := map[string]any{}
	versions := map[string]string{"gitleaks": "8.30.1"}
	byKey := map[string]manifest{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var m manifest
		if err := yaml.Unmarshal(raw, &m); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		byKey[m.Name] = m
		tools[m.Name] = map[string]any{"name": m.DisplayName, "category": m.Category, "scan_types": m.ScanTypes, "license_spdx": m.License,
			"homepage": m.Homepage, "family": m.Family, "targets": m.Targets, "network": m.Network, "intrusive": m.Intrusive,
			"parser": m.Parser, "first_party": true}
		versions[m.Name] = "1.0"
	}
	code, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "dast-" + tag, "family": "dast",
		"scanners": versions, "tools": tools})
	if code != 200 {
		t.Fatalf("register: %d %v", code, reg)
	}
	token := reg["token"].(string)

	// The catalog rows carry the authorization requirements.
	for key, m := range byKey {
		var network, family string
		var intrusive bool
		if err := appPool.QueryRow(ctx, `SELECT network, intrusive, worker_family FROM scanner_catalog WHERE key = $1`, key).
			Scan(&network, &intrusive, &family); err != nil || network != "target" || intrusive != m.Intrusive || family != "dast" {
			t.Errorf("catalog row %s: %v %s %v %s", key, err, network, intrusive, family)
		}
	}
	// Never in a repository scan profile.
	if code, out := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "DAST " + tag,
		"scanners": []map[string]any{{"key": "zap-baseline"}}}); code != 400 {
		t.Errorf("a DAST tool in a repository profile: %d %v", code, out)
	}

	repo := createRepo(t, "dast-"+tag)
	host := "app-" + tag + ".example.test"
	spec := "openapi: 3.0.3\ninfo: {title: t, version: '1'}\nservers: [{url: 'https://" + host + "/'}]\n" +
		"paths:\n  /items:\n    get:\n      responses: {'200': {description: ok}}\n"
	targets := map[string]string{}
	for _, kind := range []string{"url", "api"} {
		body := map[string]any{"repository_id": repo, "kind": kind, "name": kind + " " + tag, "reference": "https://" + host,
			"authorized": true, "authorization_note": "Test system " + tag}
		if kind == "api" {
			body["api_spec"] = spec
		}
		code, tg := h.user(admin, "POST", "/api/v1/scan-targets", body)
		if code != 201 {
			t.Fatalf("create %s target: %d %v", kind, code, tg)
		}
		targets[kind] = tg["id"].(string)
	}
	setTools := func(kind string, keys ...string) {
		t.Helper()
		if code, out := h.user(admin, "PUT", "/api/v1/scan-targets/"+targets[kind], map[string]any{"config": map[string]any{"tools": keys}}); code != 200 {
			t.Fatalf("set tools %v on %s: %d %v", keys, kind, code, out)
		}
	}
	scan := func(kind string) (int, map[string]any) {
		return h.user(admin, "POST", "/api/v1/scan-targets/"+targets[kind]+"/scan", nil)
	}
	drain := func(jobID string) {
		if j := h.leaseJob(token, jobID); j != nil {
			h.worker(token, "POST", "/internal/worker/v1/jobs/"+jobID+"/complete", map[string]any{"status": "succeeded"})
		}
	}
	kindOf := func(m manifest) string {
		for _, x := range m.Targets {
			if x == "url" {
				return "url"
			}
		}
		return "api"
	}

	// API-only tools cannot be put on a URL target.
	if code, out := h.user(admin, "PUT", "/api/v1/scan-targets/"+targets["url"], map[string]any{"config": map[string]any{"tools": []string{"schemathesis"}}}); code != 400 {
		t.Errorf("an API tool on a URL target: %d %v", code, out)
	}

	// Without the intrusive flag: every intrusive tool is refused (409), the
	// others are queued.
	for key, m := range byKey {
		kind := kindOf(m)
		setTools(kind, key)
		code, out := scan(kind)
		if m.Intrusive {
			if code != 409 || !strings.Contains(errMsg(out), "intrusive") {
				t.Errorf("%s without intrusive authorization: %d %v", key, code, out)
			}
			continue
		}
		if code != 202 {
			t.Errorf("%s (not intrusive): %d %v", key, code, out)
			continue
		}
		drain(out["job_id"].(string))
	}

	// With the flag: allowed, and the leased job carries the flag the worker
	// checks again before running an intrusive tool.
	for _, kind := range []string{"url", "api"} {
		if code, out := h.user(admin, "PUT", "/api/v1/scan-targets/"+targets[kind], map[string]any{"intrusive_authorized": true,
			"intrusive_authorization_note": "Pen-test window " + tag}); code != 200 {
			t.Fatalf("authorize intrusive testing (%s): %d %v", kind, code, out)
		}
	}
	for key, m := range byKey {
		if !m.Intrusive {
			continue
		}
		kind := kindOf(m)
		setTools(kind, key)
		code, out := scan(kind)
		if code != 202 {
			t.Errorf("%s with intrusive authorization: %d %v", key, code, out)
			continue
		}
		j := h.leaseJob(token, out["job_id"].(string))
		if j == nil {
			t.Errorf("%s: job not leased by the dast worker", key)
			continue
		}
		if tg := j["target"].(map[string]any); tg["intrusive_authorized"] != true || !strings.Contains(strings.Join(scannerKeys(j), ","), key) {
			t.Errorf("%s: leased job %v %v", key, tg, j["scanners"])
		}
		h.worker(token, "POST", "/internal/worker/v1/jobs/"+out["job_id"].(string)+"/complete", map[string]any{"status": "succeeded"})
	}

	// Withdrawing the flag refuses them again.
	if code, _ := h.user(admin, "PUT", "/api/v1/scan-targets/"+targets["url"], map[string]any{"intrusive_authorized": false}); code != 200 {
		t.Fatal("withdraw intrusive authorization")
	}
	setTools("url", "zap", "zap-baseline")
	if code, out := scan("url"); code != 409 || !strings.Contains(errMsg(out), "intrusive") {
		t.Errorf("after withdrawing the flag: %d %v", code, out)
	}
	// Retire this test's worker so later tests do not route to it.
	_, _ = appPool.Exec(ctx, `UPDATE workers SET last_seen_at = now() - interval '1 hour' WHERE name = $1`, "dast-"+tag)
}

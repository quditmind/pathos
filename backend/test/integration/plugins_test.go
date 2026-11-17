//go:build integration

package integration

import (
	"testing"

	"github.com/google/uuid"

	"pathos/internal/authz"
)

func TestScannerPlugins(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	tag := uuid.NewString()[:6]
	key := "plugin-sast-p" + tag

	// A worker registers a declarative adapter (and a bogus one).
	code, reg := h.worker(bootstrap, "POST", "/internal/worker/v1/register", map[string]any{"name": "plug-" + tag, "family": "core",
		"scanners": map[string]string{"gitleaks": "8.30.1", key: "1.0", "plugin-sast-ghost" + tag: "1.0", "rm-rf": "1"},
		"plugins":  map[string]any{key: map[string]string{"name": "Plugin " + tag, "homepage": "https://example.com/p"}}})
	if code != 200 {
		t.Fatalf("register: %d %v", code, reg)
	}
	var name, family, cat string
	if err := appPool.QueryRow(ctx, `SELECT name, worker_family, category FROM scanner_catalog WHERE key = $1`, key).Scan(&name, &family, &cat); err != nil ||
		name != "Plugin "+tag || family != "plugin" || cat != "sast" {
		t.Fatalf("catalog row: %v %s %s %s", err, name, family, cat)
	}
	var ghost int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM scanner_catalog WHERE key = $1`, "plugin-sast-ghost"+tag).Scan(&ghost)
	if ghost != 0 {
		t.Error("a plugin key without its definition is not registered")
	}
	// The app role cannot register non-plugin keys through the function.
	if _, err := appPool.Exec(ctx, `SELECT pathos_register_plugin_scanner('gitleaks', 'x', 'secrets', '')`); err == nil {
		t.Error("only plugin keys can be registered")
	}
	if _, err := appPool.Exec(ctx, `SELECT pathos_register_plugin_scanner('plugin-sast-x`+tag+`', 'x', 'sca', '')`); err == nil {
		t.Error("the category must match the key")
	}

	// It is listed, selectable in profiles; unregistered plugin keys are not.
	_, cat2 := h.user(admin, "GET", "/api/v1/scanners", nil)
	found := false
	for _, it := range cat2["items"].([]any) {
		if it.(map[string]any)["key"] == key {
			found = it.(map[string]any)["adapter_available"] == true
		}
	}
	if !found {
		t.Error("plugin listed as available")
	}
	code, prof := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "Plugin profile " + tag, "scanners": []map[string]any{{"key": key}}})
	if code != 201 {
		t.Fatalf("profile with plugin: %d %v", code, prof)
	}
	if code, _ := h.user(admin, "POST", "/api/v1/scan-profiles", map[string]any{"name": "Ghost " + tag, "scanners": []map[string]any{{"key": "plugin-sast-ghost" + tag}}}); code != 400 {
		t.Errorf("unregistered plugin in a profile: %d", code)
	}

	// Its SARIF results become findings of its category.
	repo := createRepo(t, "plug-"+tag)
	h.user(admin, "PUT", "/api/v1/repositories/"+repo.String()+"/scan-profile", map[string]any{"profile_id": prof["id"]})
	_, q := h.user(admin, "POST", "/api/v1/repositories/"+repo.String()+"/scan", map[string]any{"profile_id": prof["id"]})
	token := reg["token"].(string)
	job := h.leaseJob(token, q["job_id"].(string))
	jid := job["job_id"].(string)
	hasPlugin := false
	for _, sc := range job["scanners"].([]any) {
		if sc.(map[string]any)["key"] == key {
			hasPlugin = true
		}
	}
	if !hasPlugin {
		t.Fatalf("the job asks for the plugin: %v", job["scanners"])
	}
	if code, r := h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/results", map[string]any{
		"scanner": key, "version": "1.0", "status": "succeeded", "output_gzip": fixture(t, "opengrep.sarif")}); code != 200 {
		t.Fatalf("upload plugin results: %d %v", code, r)
	}
	h.worker(token, "POST", "/internal/worker/v1/jobs/"+jid+"/complete", map[string]any{"status": "succeeded"})
	var n int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE repository_id = $1 AND $2 = ANY(scanner_keys) AND category = 'sast'`, repo, key).Scan(&n)
	if n == 0 {
		t.Error("plugin findings recorded as SAST")
	}
}

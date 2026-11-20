//go:build integration

package integration

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/scanners"
	"pathos/internal/scans"
)

// PATHOS 3.0 M6: scan profile tiers, kinds of check and "confirmed by N
// engines".

func tierCount(t *testing.T, org uuid.UUID) map[string]int {
	t.Helper()
	rows, err := ownerPool.Query(t.Context(), `SELECT template, count(*) FROM scan_profiles WHERE organization_id = $1 AND template IS NOT NULL GROUP BY template`, org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			t.Fatal(err)
		}
		out[k] = n
	}
	return out
}

func TestScanProfileTiersSeedingIsIdempotent(t *testing.T) {
	ctx := t.Context()
	// A fresh organization, seeded the way pathosctl migrate and the
	// installation administration seed one.
	o, _, err := org.EnsureOrganization(ctx, ownerPool, "Tiers "+uuid.NewString()[:6], "tiers-"+uuid.NewString()[:6])
	if err != nil {
		t.Fatal(err)
	}
	if err := scans.EnsureDefaultProfile(ctx, ownerPool, o); err != nil {
		t.Fatal(err)
	}
	// A custom profile already called "Quick" keeps its name.
	if _, err := ownerPool.Exec(ctx, `UPDATE scan_profiles SET name = 'Quick' WHERE organization_id = $1 AND is_default`, o); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := scans.EnsureTierProfiles(ctx, ownerPool, o); err != nil {
			t.Fatal(err)
		}
	}
	if got := tierCount(t, o); got["quick"] != 1 || got["standard"] != 1 || got["comprehensive"] != 1 {
		t.Fatalf("tiers after three seeds: %v", got)
	}
	var names []string
	rows, _ := ownerPool.Query(ctx, `SELECT name FROM scan_profiles WHERE organization_id = $1 ORDER BY name`, o)
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		names = append(names, n)
	}
	rows.Close()
	if fmt.Sprint(names) != "[Comprehensive Quick Quick (PATHOS) Standard]" {
		t.Fatalf("names %v", names)
	}
	// Every seeded version holds exactly its tier's tools.
	for _, tier := range scans.Tiers {
		var n int
		if err := ownerPool.QueryRow(ctx, `SELECT count(*) FROM profile_scanners ps JOIN scan_profiles p ON p.current_version_id = ps.profile_version_id
			WHERE p.organization_id = $1 AND p.template = $2`, o, tier.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if want := len(scans.TierSettings(tier).Scanners); n != want {
			t.Errorf("%s: %d tools, want %d", tier.ID, n, want)
		}
	}
	// An administrator's rename and archive are never undone.
	if _, err := ownerPool.Exec(ctx, `UPDATE scan_profiles SET name = 'Fast', archived_at = CASE WHEN template = 'standard' THEN now() END
		WHERE organization_id = $1 AND template IN ('quick', 'standard')`, o); err != nil {
		t.Fatal(err)
	}
	// The runtime role seeds too (new organizations from the installation
	// administration), under row-level security.
	if err := scans.EnsureTierProfiles(ctx, appPool, orgID); err != nil {
		t.Fatal(err)
	}
	if err := scans.EnsureTierProfiles(ctx, ownerPool, o); err != nil {
		t.Fatal(err)
	}
	if got := tierCount(t, o); got["quick"] != 1 || got["standard"] != 1 || got["comprehensive"] != 1 {
		t.Fatalf("re-seed recreated a renamed or archived tier: %v", got)
	}
	if got := tierCount(t, orgID); len(got) != 3 {
		t.Fatalf("app-role seeding: %v", got)
	}
}

// setFlag is defined in onboarding_m3_test.go.

func TestScanProfileTiersAndKindsAPI(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	if err := scans.EnsureTierProfiles(ctx, appPool, orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setFlag(t, scans.TiersFlag, false) })

	listTemplates := func() map[string]string {
		_, out := h.user(admin, "GET", "/api/v1/scan-profiles", nil)
		m := map[string]string{}
		for _, it := range out["items"].([]any) {
			p := it.(map[string]any)
			if tpl, ok := p["template"].(string); ok {
				m[tpl] = p["id"].(string)
			}
		}
		return m
	}
	// Behind the flag: hidden and not found while it is off.
	setFlag(t, scans.TiersFlag, false)
	if got := listTemplates(); len(got) != 0 {
		t.Fatalf("tiers listed with the flag off: %v", got)
	}
	var quickID string
	_ = appPool.QueryRow(ctx, `SELECT id FROM scan_profiles WHERE organization_id = $1 AND template = 'quick'`, orgID).Scan(&quickID)
	if code, _ := h.user(admin, "GET", "/api/v1/scan-profiles/"+quickID, nil); code != 404 {
		t.Fatalf("tier readable with the flag off: %d", code)
	}
	setFlag(t, scans.TiersFlag, true)
	got := listTemplates()
	if len(got) != 3 {
		t.Fatalf("tiers with the flag on: %v", got)
	}

	// Kinds of check of the Standard profile: N of 10 per kind, and with
	// no online worker every repository kind lacks a runnable tool.
	code, out := h.user(admin, "GET", "/api/v1/scan-profiles/"+got["standard"]+"/kinds", nil)
	if code != 200 {
		t.Fatalf("kinds: %d %v", code, out)
	}
	kinds := map[string]map[string]any{}
	for _, k := range out["kinds"].([]any) {
		m := k.(map[string]any)
		kinds[m["id"].(string)] = m
	}
	if len(kinds) != len(scanners.CheckKinds)+len(scanners.OutsideKinds) {
		t.Fatalf("%d kinds", len(kinds))
	}
	iac := kinds["iac"]
	if iac["tools_target"].(float64) != 10 || iac["listed"].(float64) < 4 || iac["listed"].(float64) > 6 || iac["repository_scope"] != true {
		t.Fatalf("iac %v", iac)
	}
	if kinds["threat-modelling"]["repository_scope"] != false || kinds["threat-modelling"]["lacks_runnable"] != false {
		t.Fatalf("threat modelling %v", kinds["threat-modelling"])
	}
	workers := int(out["workers_online"].(float64))
	if workers == 0 && iac["lacks_runnable"] != true {
		t.Fatalf("no worker online but iac has a runnable tool: %v", iac)
	}

	// A worker that advertises Checkov makes iac runnable.
	if _, err := appPool.Exec(ctx, `INSERT INTO workers (id, organization_id, name, family, version, token_sha256, scanners, tools, last_seen_at)
		VALUES ($1, $2, $3, 'core', 'test', $4, '{"checkov": "3.0"}', '{}', now())`, uuid.Must(uuid.NewV7()), orgID, "m6-"+uuid.NewString()[:6], uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	_, out = h.user(admin, "GET", "/api/v1/scan-profiles/"+got["standard"]+"/kinds", nil)
	for _, k := range out["kinds"].([]any) {
		m := k.(map[string]any)
		if m["id"] == "iac" && (m["lacks_runnable"] != false || m["runnable"].(float64) < 1) {
			t.Fatalf("iac with a Checkov worker: %v", m)
		}
	}

	// The coverage API groups scan types by kind of check.
	_, cov := h.user(admin, "GET", "/api/v1/scan-types", nil)
	if n := len(cov["kinds"].([]any)); n != len(scanners.CheckKinds)+len(scanners.OutsideKinds) {
		t.Fatalf("coverage kinds %d", n)
	}
	for _, it := range cov["items"].([]any) {
		if it.(map[string]any)["kind_of_check"] == "" {
			t.Fatalf("scan type without kind: %v", it)
		}
	}
}

func TestFindingKindsAndEngines(t *testing.T) {
	ctx := t.Context()
	h := newScanHarness(t)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	repo := createRepo(t, "kinds-"+uuid.NewString()[:6])
	insert := func(cat string, keys []string) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := appPool.Exec(ctx, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, severity)
			VALUES ($1, $2, $3, $4, $5, $6, 'R1', 'kinds test', 'high')`, id, orgID, repo, uuid.NewString(), cat, keys); err != nil {
			t.Fatal(err)
		}
		return id
	}
	iac := insert("iac", []string{"checkov", "kics", "trivy-config", "import-iac-checkov"})
	lang := insert("sast", []string{"bandit", "import-sast-gosec"})
	deep := insert("sast", []string{"opengrep", "bandit"})

	code, out := h.user(admin, "GET", "/api/v1/findings/"+iac.String(), nil)
	if code != 200 || out["kind_of_check"] != "iac" || out["kind_of_check_name"] != "Infrastructure as code" || out["engines_count"].(float64) != 3 {
		t.Fatalf("finding %d %v %v %v", code, out["kind_of_check"], out["kind_of_check_name"], out["engines_count"])
	}
	if len(out["scanner_keys"].([]any)) != 4 {
		t.Fatal("the API keeps the tool fields for audit")
	}
	ids := func(q string) map[string]bool {
		_, out := h.user(admin, "GET", "/api/v1/findings?repository_id="+repo.String()+"&"+q, nil)
		m := map[string]bool{}
		for _, it := range out["items"].([]any) {
			m[it.(map[string]any)["id"].(string)] = true
		}
		return m
	}
	if got := ids("kind=sast-language"); !got[lang.String()] || got[deep.String()] || got[iac.String()] {
		t.Fatalf("kind=sast-language: %v", got)
	}
	if got := ids("kind=sast-deep"); !got[deep.String()] || got[lang.String()] {
		t.Fatalf("kind=sast-deep: %v", got)
	}
	if code, _ := h.user(admin, "GET", "/api/v1/findings?kind=nope", nil); code != 400 {
		t.Fatalf("invalid kind: %d", code)
	}

	// KindSQL and EnginesSQL agree with the Go functions for every
	// category and representative engine sets.
	keySets := [][]string{{}, {"opengrep"}, {"bandit"}, {"bandit", "opengrep"}, {"import-sast-gosec"}, {"pmd"}, {"testssl"}, {"testssl", "opengrep"},
		{"trivy-fs", "import-sca-trivy", "sarif-trivy", "grype"}, {"zap", "zap-baseline"}, {"import-code-quality-ruff"}, {"import-supply-chain-scorecard", "scorecard"}, {"retirejs", "import-sca-retire-js", "npm-audit"}}
	for _, cat := range scanners.FindingCategories {
		for _, keys := range keySets {
			var kind string
			var engines int
			if err := ownerPool.QueryRow(ctx, `SELECT `+scanners.KindSQL("f")+`, `+scanners.EnginesSQL("f")+`
				FROM (VALUES ($1::text, $2::text[])) f(category, scanner_keys)`, cat, keys).Scan(&kind, &engines); err != nil {
				t.Fatal(err)
			}
			if want := scanners.KindOfFinding(cat, keys); kind != want {
				t.Errorf("KindSQL(%s, %v) = %s, Go %s", cat, keys, kind, want)
			}
			if want := scanners.EnginesCount(keys); engines != want {
				t.Errorf("EnginesSQL(%v) = %d, Go %d", keys, engines, want)
			}
		}
	}

	// Scan list filter by kind of check.
	if code, _ := h.user(admin, "GET", "/api/v1/scans?kind=iac", nil); code != 200 {
		t.Fatalf("scans?kind: %d", code)
	}
	if code, _ := h.user(admin, "GET", "/api/v1/scans?kind="+url.QueryEscape("x y"), nil); code != 400 {
		t.Fatalf("scans?kind invalid: %d", code)
	}
}

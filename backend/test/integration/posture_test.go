//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
	"pathos/internal/posture"
	"pathos/internal/repos"
	"pathos/internal/scm"
	"pathos/internal/secrets"
	"pathos/internal/vuln"
)

func TestPosture(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	svc := &posture.Service{DB: appPool, Authz: az, Log: log, Principal: auth.PrincipalFrom}
	h := &scanHarness{t: t, api: newMux(svc.Register)}
	admin := reviewUser(t, "platform_admin")
	suffix := uuid.NewString()[:6]

	// An application with one repository; a second repository without
	// application or owner.
	app := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO applications (id, organization_id, name, criticality) VALUES ($1, $2, $3, 'critical')`,
		app, orgID, "Payments "+suffix); err != nil {
		t.Fatal(err)
	}
	r1, r2 := createRepo(t, "pay-"+suffix), createRepo(t, "orphan-"+suffix)
	if _, err := appPool.Exec(ctx, `UPDATE repositories SET application_id = $2, technical_owner_id = $3, public_exposure = 'yes' WHERE id = $1`,
		r1, app, admin.UserID); err != nil {
		t.Fatal(err)
	}

	// A successful SAST scan of r1.
	var pv uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT current_version_id FROM scan_profiles WHERE organization_id = $1 AND is_default`, orgID).Scan(&pv)
	job := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, ref, status, finished_at)
		VALUES ($1, $2, $3, $4, 'manual', 'main', 'succeeded', now())`, job, orgID, r1, pv); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO scan_results (id, organization_id, scan_job_id, scanner_key, status) VALUES ($1, $2, $3, 'opengrep', 'succeeded')`,
		uuid.Must(uuid.NewV7()), orgID, job); err != nil {
		t.Fatal(err)
	}

	// SBOM with dependency edges (demo -> lodash, minimist).
	raw, _ := os.ReadFile("../../internal/scanners/testdata/syft.cdx.json")
	if err := db.InTx(ctx, appPool, func(tx pgx.Tx) error {
		_, err := vuln.StoreSBOM(ctx, tx, orgID, r1, job, raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var depth int
	_ = appPool.QueryRow(ctx, `SELECT depth FROM sbom_components WHERE repository_id = $1 AND name = 'lodash'`, r1).Scan(&depth)
	if depth != 1 {
		t.Fatalf("lodash is a direct dependency: depth %d", depth)
	}

	// Findings: a KEV dependency finding (risk 90) and three more high-risk ones.
	cve := fmt.Sprintf("CVE-2099-%d", 10000+time.Now().UnixNano()%90000000)
	lodash := insertRiskFinding(t, r1, "sca", "high", 90, true, "lodash", "4.17.20", cve)
	for _, rs := range []float64{60, 55, 52} {
		insertRiskFinding(t, r1, "sast", "medium", rs, false, "", "", "")
	}
	insertRiskFinding(t, r2, "sast", "low", 12, false, "", "", "")

	// --- application posture and rollup -------------------------------------
	_, apps := h.user(admin, "GET", "/api/v1/posture/applications", nil)
	var ap map[string]any
	for _, it := range apps["items"].([]any) {
		if m := it.(map[string]any); m["id"] == app.String() {
			ap = m
		}
	}
	if ap == nil {
		t.Fatalf("application missing: %v", apps)
	}
	// 90 + 3 other findings with risk >= 50.
	if ap["risk_score"].(float64) != 93 || ap["risk_band"] != "critical" || ap["kev_open"].(float64) != 1 || ap["open_total"].(float64) != 4 ||
		ap["criticality"] != "critical" || ap["repositories"].(float64) != 1 {
		t.Errorf("application posture: %v", ap)
	}
	if code, _ := h.user(admin, "GET", "/api/v1/posture/aggregate?by=nope", nil); code != 400 {
		t.Errorf("invalid dimension: %d", code)
	}
	for _, by := range []string{"business_unit", "team", "owner", "region"} {
		if code, out := h.user(admin, "GET", "/api/v1/posture/aggregate?by="+by, nil); code != 200 || len(out["items"].([]any)) == 0 {
			t.Errorf("aggregate by %s: %d %v", by, code, out)
		}
	}
	_, bm := h.user(admin, "GET", "/api/v1/posture/benchmark?by=application", nil)
	if len(bm["metrics"].([]any)) != 7 || len(bm["items"].([]any)) == 0 {
		t.Errorf("benchmark: %v", bm)
	}

	// --- coverage -----------------------------------------------------------
	_, cov := h.user(admin, "GET", "/api/v1/posture/coverage?q=pay-"+suffix, nil)
	items := cov["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("coverage: %v", cov)
	}
	cells := items[0].(map[string]any)["cells"].(map[string]any)
	if cells["sast"].(map[string]any)["status"] != "covered" || cells["sca"].(map[string]any)["status"] != "never" ||
		cells["dast"].(map[string]any)["status"] != "not_configured" {
		t.Errorf("coverage cells: %v", cells)
	}

	// --- unmanaged and shadow repositories ------------------------------------
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	fake := &fakeSCM{repos: []scm.RemoteRepo{{ExternalID: "shadow-" + suffix, FullName: "acme/shadow-" + suffix, Visibility: "private"},
		{ExternalID: "pay-" + suffix, FullName: "acme/pay-" + suffix}}}
	reposSvc := &repos.Service{DB: appPool, Authz: az, Secrets: &secrets.Store{Keys: kr}, Log: log, Principal: auth.PrincipalFrom,
		NewClient: func(scm.Config) (scm.FullClient, error) { return fake, nil }}
	var conn uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT scm_connection_id FROM repositories WHERE id = $1`, r1).Scan(&conn)
	run, err := reposSvc.Inventory(context.Background(), orgID, conn)
	if err != nil || run.Status != "succeeded" || run.Repositories != 2 {
		t.Fatalf("inventory: %v %+v", err, run)
	}
	_, um := h.user(admin, "GET", "/api/v1/posture/unmanaged", nil)
	var shadowNames []string
	for _, s := range um["shadow"].([]any) {
		shadowNames = append(shadowNames, s.(map[string]any)["full_name"].(string))
	}
	if !contains(shadowNames, "acme/shadow-"+suffix) || contains(shadowNames, "acme/pay-"+suffix) {
		t.Errorf("shadow repositories (imported ones excluded): %v", shadowNames)
	}
	var orphanIssues []any
	for _, it := range um["repositories"].([]any) {
		if m := it.(map[string]any); m["id"] == r2.String() {
			orphanIssues = m["issues"].([]any)
		}
	}
	if !containsAny(orphanIssues, "no_application") || !containsAny(orphanIssues, "no_owner") || !containsAny(orphanIssues, "never_scanned") {
		t.Errorf("governance gaps: %v", orphanIssues)
	}
	// A repository-scoped user sees only that repository and no shadow list.
	only2 := scoped("security_analyst", authz.Scope{Type: authz.ScopeRepository, ID: r2})
	_, um2 := h.user(only2, "GET", "/api/v1/posture/unmanaged", nil)
	if um2["shadow_visible"] != false || len(um2["repositories"].([]any)) != 1 {
		t.Errorf("scoped unmanaged view: %v", um2)
	}

	// --- dependency graph and paths -------------------------------------------
	_, dg := h.user(admin, "GET", "/api/v1/repositories/"+r1.String()+"/dependencies", nil)
	st := dg["stats"].(map[string]any)
	if st["edges"].(float64) != 2 || st["direct"].(float64) != 2 || st["roots"].(float64) != 1 || st["vulnerable"].(float64) != 1 {
		t.Errorf("dependency graph stats: %v", st)
	}
	_, fp := h.user(admin, "GET", "/api/v1/findings/"+lodash.String()+"/dependency-paths", nil)
	comps := fp["components"].([]any)
	if len(comps) != 1 || comps[0].(map[string]any)["relation"] != "direct" {
		t.Fatalf("finding dependency paths: %v", fp)
	}
	path := comps[0].(map[string]any)["paths"].([]any)[0].([]any)
	if len(path) != 2 || path[0].(map[string]any)["name"] != "demo" || path[1].(map[string]any)["name"] != "lodash" {
		t.Errorf("path demo -> lodash: %v", path)
	}
	if code, _ := h.user(only2, "GET", "/api/v1/repositories/"+r1.String()+"/dependencies", nil); code != 404 {
		t.Errorf("dependency graph outside scope: %d", code)
	}

	// --- blast radius ----------------------------------------------------------
	code, br := h.user(admin, "GET", "/api/v1/posture/blast-radius?cve="+cve, nil)
	if code != 200 {
		t.Fatalf("blast radius: %d %v", code, br)
	}
	if sum := br["summary"].(map[string]any); sum["repositories"].(float64) != 1 || sum["internet_exposed"].(float64) != 1 {
		t.Errorf("blast radius by CVE: %v", br)
	}
	hit := br["items"].([]any)[0].(map[string]any)
	if hit["relation"] != "direct" || hit["kev"] != true || hit["application_name"] != "Payments "+suffix {
		t.Errorf("affected repository: %v", hit)
	}
	_, bp := h.user(admin, "GET", "/api/v1/posture/blast-radius?package=minimist&version=1.2.5", nil)
	found := false
	for _, it := range bp["items"].([]any) {
		if m := it.(map[string]any); m["repository_id"] == r1.String() {
			found = m["relation"] == "direct" && m["open_findings"].(float64) == 0
		}
	}
	if !found {
		t.Errorf("blast radius by package from the inventory: %v", bp["items"])
	}
	if code, _ := h.user(admin, "GET", "/api/v1/posture/blast-radius?cve=1%27%20OR%201=1", nil); code != 400 {
		t.Errorf("invalid CVE: %d", code)
	}
	_, br2 := h.user(only2, "GET", "/api/v1/posture/blast-radius?cve="+cve, nil)
	if br2["summary"].(map[string]any)["repositories"].(float64) != 0 {
		t.Errorf("blast radius outside scope: %v", br2)
	}

	// --- context graph ----------------------------------------------------------
	_, cg := h.user(admin, "GET", "/api/v1/posture/context-graph?node=application:"+app.String(), nil)
	types := map[string]int{}
	for _, n := range cg["nodes"].([]any) {
		types[n.(map[string]any)["type"].(string)]++
	}
	if types["application"] != 1 || types["repository"] != 1 || types["owner"] != 1 || types["finding"] != 4 || types["component"] != 1 {
		t.Errorf("context graph nodes: %v", types)
	}
	if code, _ := h.user(only2, "GET", "/api/v1/posture/context-graph?node=application:"+app.String(), nil); code != 404 {
		t.Errorf("context graph outside scope: %d", code)
	}
}

func insertRiskFinding(t *testing.T, repo uuid.UUID, category, severity string, risk float64, kev bool, pkg, version, cve string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(t.Context(), `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id,
		title, description, severity, file_path, package_name, package_version, cve, kev, risk_score, risk_dirty)
		VALUES ($1, $2, $3, $4, $5, '{opengrep}', 'r', 'finding '||$4, '', $6, 'package-lock.json', $7, $8, $9, $10, $11, false)`,
		id, orgID, repo, uuid.NewString(), category, severity, pkg, version, cve, kev, risk); err != nil {
		t.Fatal(err)
	}
	return id
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func containsAny(list []any, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

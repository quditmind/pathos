//go:build integration

package integration

// PATHOS 3.0 M3: application onboarding, classification, tag framework and
// lifecycle (docs/user-guide/application-onboarding.md). The central
// guarantee: onboarding the same repository twice, sequentially or
// concurrently, never creates a duplicate application, onboarding or
// repository; and incomplete applications are saved as drafts with an
// onboarding status.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/inventory"
	"pathos/internal/org"
	"pathos/internal/repos"
)

func setFlag(t *testing.T, name string, on bool) {
	t.Helper()
	if _, err := ownerPool.Exec(context.Background(), `INSERT INTO feature_flags (id, organization_id, name, enabled) VALUES ($1, $2, $3, $4)
		ON CONFLICT (organization_id, name) DO UPDATE SET enabled = EXCLUDED.enabled`, uuid.Must(uuid.NewV7()), orgID, name, on); err != nil {
		t.Fatal(err)
	}
}

func errCode(m map[string]any) string {
	if e, ok := m["error"].(map[string]any); ok {
		s, _ := e["error_code"].(string)
		return s
	}
	return ""
}

func TestOnboardingNoDuplicatesAndDrafts(t *testing.T) {
	ctx := t.Context()
	h := newHarness(t)
	(&inventory.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log, Principal: auth.PrincipalFrom}).Register(h.mux)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	sfx := uuid.NewString()[:6]
	if err := repos.EnsureAssetDefaults(ctx, appPool, orgID); err != nil {
		t.Fatal(err)
	}

	// Flag off: the module looks absent.
	setFlag(t, "onboarding", false)
	if code, m := h.do(admin, "POST", "/api/v1/onboarding/match", map[string]any{}); code != 404 || errCode(m) != "PTH-PLAT-1007" {
		t.Fatalf("flag off: %d %v", code, m)
	}
	setFlag(t, "onboarding", true)
	setFlag(t, "lifecycle_overview", true)
	t.Cleanup(func() {
		setFlag(t, "onboarding", false)
		setFlag(t, "lifecycle_overview", false)
	})

	code, conn := h.do(admin, "POST", "/api/v1/scm-connections", map[string]any{
		"name": "Onboard GH " + sfx, "provider": "github", "auth_type": "pat", "token": "ghp_x", "owner": "acme"})
	if code != 201 {
		t.Fatalf("connection: %d %v", code, conn)
	}
	connID := id(conn, "id")
	src := func(ext, full string, url string) map[string]any {
		return map[string]any{"scm_connection_id": connID, "external_id": ext, "full_name": full, "url": url, "language": "Go"}
	}

	// 1. Find existing asset: nothing registered yet.
	code, m := h.do(admin, "POST", "/api/v1/onboarding/match", map[string]any{"repositories": []any{src("101", "acme/payments-api", "https://github.com/acme/payments-api")}})
	if code != 200 || m["suggested_name"] != "Payments API" {
		t.Fatalf("match: %d %v", code, m)
	}
	s0 := m["sources"].([]any)[0].(map[string]any)
	if s0["existing_repository"] != nil || s0["onboarding"] != nil || s0["source_key"] != "github.com/acme/payments-api" {
		t.Fatalf("match source: %v", s0)
	}

	// 2. Register as new: a draft with detected languages.
	appName := "Payments Platform " + sfx
	code, reg := h.do(admin, "POST", "/api/v1/onboarding", map[string]any{"mode": "new", "application": map[string]any{"name": appName},
		"repositories": []any{src("101", "acme/payments-api", "https://github.com/acme/payments-api")}})
	if code != 201 {
		t.Fatalf("register: %d %v", code, reg)
	}
	app := reg["application"].(map[string]any)
	appID := app["id"].(string)
	if app["onboarding_status"] != "draft" || !strings.HasPrefix(app["progress"].(map[string]any)["label"].(string), "Onboarding: ") {
		t.Fatalf("draft: %v", app)
	}
	if det := app["detected"].(map[string]any)["languages"]; det == nil || fmt.Sprint(app["languages"]) != "[Go]" {
		t.Errorf("languages should be detected from the provider hint: %v %v", app["languages"], app["detected"])
	}

	// 3. The same repository again, through another URL spelling: 409, nothing created.
	for _, u := range []string{"https://github.com/acme/payments-api", "git@github.com:ACME/payments-api.git"} {
		other := "Other " + sfx + uuid.NewString()[:4]
		code, m := h.do(admin, "POST", "/api/v1/onboarding", map[string]any{"mode": "new", "application": map[string]any{"name": other},
			"repositories": []any{src("999-"+uuid.NewString()[:4], "acme/payments-api", u)}})
		if code != 409 || errCode(m) != "PTH-ONB-1008" {
			t.Fatalf("second onboarding (%s): %d %v", u, code, m)
		}
		if d, _ := m["error"].(map[string]any)["details"].(map[string]any); d == nil || d["application_id"] != appID {
			t.Errorf("conflict should name the existing application: %v", m)
		}
		var n int
		_ = appPool.QueryRow(ctx, `SELECT count(*) FROM applications WHERE organization_id = $1 AND name = $2`, orgID, other).Scan(&n)
		if n != 0 {
			t.Fatalf("a rejected onboarding created application %q", other)
		}
	}
	// Linking the same repository to another existing application is refused too.
	code, other := h.do(admin, "POST", "/api/v1/applications", map[string]any{"name": "Existing " + sfx})
	if code != 201 {
		t.Fatal(code, other)
	}
	if code, m := h.do(admin, "POST", "/api/v1/onboarding", map[string]any{"mode": "link", "application_id": id(other, "id"),
		"repositories": []any{src("101", "acme/payments-api", "https://github.com/acme/payments-api")}}); code != 409 || errCode(m) != "PTH-ONB-1008" {
		t.Fatalf("link of an onboarded repository: %d %v", code, m)
	}
	// The match step now reports the onboarding in progress and proposes the application.
	_, m = h.do(admin, "POST", "/api/v1/onboarding/match", map[string]any{"repositories": []any{src("101", "acme/payments-api", "https://github.com/acme/payments-api")}})
	if s0 := m["sources"].([]any)[0].(map[string]any); s0["onboarding"] == nil {
		t.Errorf("match should report the onboarding: %v", m)
	}
	if c := m["candidates"].([]any); len(c) == 0 || c[0].(map[string]any)["id"] != appID {
		t.Errorf("first candidate should be the onboarding application: %v", m["candidates"])
	}
	// An existing application with a similar name is proposed for a new repository.
	_, m = h.do(admin, "POST", "/api/v1/onboarding/match", map[string]any{"repositories": []any{src("150", "acme/payments-platform-"+sfx+"-web", "https://github.com/acme/payments-platform-"+sfx+"-web")}})
	found := false
	for _, c := range m["candidates"].([]any) {
		if c.(map[string]any)["id"] == appID {
			found = true
			if rs := fmt.Sprint(c.(map[string]any)["reasons"]); !strings.Contains(rs, "owner or team acme") {
				t.Errorf("reasons should include the shared owner: %s", rs)
			}
		}
	}
	if !found {
		t.Errorf("similar application not proposed: %v", m["candidates"])
	}

	// 4. Concurrent onboardings of one repository: exactly one wins.
	const workers = 8
	var wg sync.WaitGroup
	codes := make([]int, workers)
	errs := make([]string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("HR %s %d", sfx, i)
			if i%2 == 0 {
				name = "HR Portal " + sfx // half of them also race on the name
			}
			c, m := h.do(admin, "POST", "/api/v1/onboarding", map[string]any{"mode": "new", "application": map[string]any{"name": name},
				"repositories": []any{src("102", "acme/hr-portal", "https://github.com/acme/hr-portal")}})
			codes[i], errs[i] = c, errCode(m)
		}(i)
	}
	wg.Wait()
	wins := 0
	for i, c := range codes {
		switch {
		case c == 201:
			wins++
		case c == 409 && (errs[i] == "PTH-ONB-1008" || errs[i] == "PTH-ONB-1011"):
		default:
			t.Errorf("concurrent onboarding %d: %d %s", i, c, errs[i])
		}
	}
	var apps, rows int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM applications WHERE organization_id = $1 AND name LIKE $2`, orgID, "HR %"+sfx+"%").Scan(&apps)
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM asset_onboardings WHERE organization_id = $1 AND source_key = 'github.com/acme/hr-portal'`, orgID).Scan(&rows)
	if wins != 1 || apps != 1 || rows != 1 {
		t.Fatalf("concurrent onboarding: wins=%d applications=%d onboardings=%d (codes %v %v)", wins, apps, rows, codes, errs)
	}

	// 5. The database refuses a second onboarding row even without the API checks.
	if _, err := appPool.Exec(ctx, `INSERT INTO asset_onboardings (id, organization_id, application_id, source_key, full_name, decision)
		VALUES ($1, $2, $3, 'github.com/acme/hr-portal', 'acme/hr-portal', 'registered_new')`, uuid.Must(uuid.NewV7()), orgID, appID); err == nil {
		t.Fatal("unique constraint missing on asset_onboardings")
	}

	// 6. A repository already in PATHOS is linked, never imported again.
	repoID := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO repositories (id, organization_id, scm_connection_id, external_id, full_name, name, url, clone_url,
		default_branch, languages, hosting_region) VALUES ($1, $2, $3, '103', 'acme/website', 'website', 'https://github.com/acme/website',
		'https://github.com/acme/website.git', 'master', '{"TypeScript": 9000, "CSS": 1000}', 'europe')`, repoID, orgID, connID); err != nil {
		t.Fatal(err)
	}
	var pv uuid.UUID
	_ = appPool.QueryRow(ctx, `SELECT current_version_id FROM scan_profiles WHERE organization_id = $1 AND is_default`, orgID).Scan(&pv)
	job := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, ref, status, finished_at)
		VALUES ($1, $2, $3, $4, 'manual', 'master', 'succeeded', now())`, job, orgID, repoID, pv); err != nil {
		t.Fatal(err)
	}
	if _, err := appPool.Exec(ctx, `INSERT INTO sbom_components (organization_id, repository_id, scan_job_id, name, version, purl, type)
		VALUES ($1, $2, $3, 'react', '18.3.1', 'pkg:npm/react@18.3.1', 'library')`, orgID, repoID, job); err != nil {
		t.Fatal(err)
	}
	_, m = h.do(admin, "POST", "/api/v1/onboarding/match", map[string]any{"repositories": []any{src("", "ACME/Website", "https://github.com/acme/website.git")}})
	if s0 := m["sources"].([]any)[0].(map[string]any); s0["existing_repository"] == nil || id(s0, "existing_repository", "id") != repoID.String() {
		t.Fatalf("existing repository not found: %v", m)
	}
	webName := "Website " + sfx
	code, reg = h.do(admin, "POST", "/api/v1/onboarding", map[string]any{"mode": "new", "application": map[string]any{"name": webName},
		"repositories": []any{src("", "acme/website", "https://github.com/acme/website")}})
	if code != 201 {
		t.Fatalf("register website: %d %v", code, reg)
	}
	web := reg["application"].(map[string]any)
	webID := web["id"].(string)
	srcs := reg["sources"].([]any)
	if len(srcs) != 1 || srcs[0].(map[string]any)["decision"] != "linked_existing" || srcs[0].(map[string]any)["repository_id"] != repoID.String() {
		t.Fatalf("existing repository must be linked: %v", srcs)
	}
	if fmt.Sprint(web["languages"]) != "[TypeScript CSS]" || fmt.Sprint(web["frameworks"]) != "[React]" || fmt.Sprint(web["runtimes"]) != "[Node.js]" ||
		web["hosting_region"] != "europe" {
		t.Errorf("detection from repository metadata and SBOM: %v %v %v %v", web["languages"], web["frameworks"], web["runtimes"], web["hosting_region"])
	}
	det := web["detected"].(map[string]any)
	if det["frameworks"].(map[string]any)["source"] != "sbom" || det["languages"].(map[string]any)["source"] != "repository" {
		t.Errorf("detected sources: %v", det)
	}

	// 7. Drafts: incomplete applications save with status and are listed.
	code, m = h.do(admin, "POST", "/api/v1/applications/"+webID+"/onboarding/complete", nil)
	if code != 422 || errCode(m) != "PTH-ONB-1009" || m["error"].(map[string]any)["fields"].(map[string]any)["owner"] == nil {
		t.Fatalf("incomplete save must be refused with the missing fields: %d %v", code, m)
	}
	code, m = h.do(admin, "GET", "/api/v1/onboarding", nil)
	listed := ""
	for _, it := range m["items"].([]any) {
		if it.(map[string]any)["id"] == webID {
			listed = it.(map[string]any)["progress"].(map[string]any)["label"].(string)
		}
	}
	if code != 200 || !strings.HasPrefix(listed, "Onboarding: ") || !strings.HasSuffix(listed, " of 9 fields") {
		t.Fatalf("draft not listed with status: %d %q", code, listed)
	}
	// A person's edit removes the detected mark of that field only.
	code, m = h.do(admin, "PATCH", "/api/v1/applications/"+webID+"/classification", map[string]any{"frameworks": []string{"React", "Next.js"}, "data_classification": "nope"})
	if code != 400 || m["error"].(map[string]any)["fields"].(map[string]any)["data_classification"] == nil {
		t.Fatalf("unknown catalogue value must be rejected: %d %v", code, m)
	}
	owner, err := identity.CreateUser(ctx, appPool, identity.User{OrganizationID: orgID, Email: "owner-" + sfx + "@acme.test", Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	bu := uuid.Must(uuid.NewV7())
	if _, err := appPool.Exec(ctx, `INSERT INTO business_units (id, organization_id, name) VALUES ($1, $2, $3)`, bu, orgID, "Web BU "+sfx); err != nil {
		t.Fatal(err)
	}
	code, m = h.do(admin, "PATCH", "/api/v1/applications/"+webID+"/classification", map[string]any{"frameworks": []string{"React", "Next.js"},
		"owner_user_id": owner.ID, "business_unit_id": bu, "criticality": "high", "data_classification": "confidential",
		"internet_exposure": "public", "compliance_scopes": []string{"pci_dss"}, "application_type": "web_application"})
	if code != 200 {
		t.Fatalf("classify: %d %v", code, m)
	}
	if _, still := m["detected"].(map[string]any)["frameworks"]; still {
		t.Error("frameworks edited by a person must lose the detected mark")
	}
	if _, still := m["detected"].(map[string]any)["languages"]; !still {
		t.Error("untouched detected fields keep the mark")
	}

	// 8. Mandatory tag category for the application type, and an automatic rule.
	_, cat := h.do(admin, "POST", "/api/v1/tag-categories", map[string]any{"name": "Compliance " + sfx})
	catID := id(cat, "id")
	_, pci := h.do(admin, "POST", "/api/v1/tag-categories/"+catID+"/tags", map[string]any{"name": "pci-dss", "color": "red"})
	_, gdpr := h.do(admin, "POST", "/api/v1/tag-categories/"+catID+"/tags", map[string]any{"name": "gdpr"})
	if code, m := h.do(admin, "PATCH", "/api/v1/tag-categories/"+catID+"/framework", map[string]any{"color": "#cf222e", "mandatory_asset_types": []string{"web_application"}}); code != 204 {
		t.Fatalf("category framework: %d %v", code, m)
	}
	t.Cleanup(func() {
		_, _ = h.do(admin, "PATCH", "/api/v1/tag-categories/"+catID+"/framework", map[string]any{"mandatory_asset_types": []string{}})
	})
	if code, m := h.do(admin, "PATCH", "/api/v1/tag-categories/"+catID+"/framework", map[string]any{"mandatory_asset_types": []string{"spaceship"}}); code != 400 {
		t.Errorf("unknown application type must be rejected: %d %v", code, m)
	}
	code, m = h.do(admin, "POST", "/api/v1/applications/"+webID+"/onboarding/complete", nil)
	if code != 422 || errCode(m) != "PTH-ONB-1010" {
		t.Fatalf("missing mandatory tag category: %d %v", code, m)
	}
	code, rule := h.do(admin, "POST", "/api/v1/tag-rules", map[string]any{"name": "PCI scope " + sfx, "tag_id": id(pci, "id"),
		"target_type": "application", "condition": "classification", "field": "compliance_scopes", "value": "pci_dss", "apply": true})
	if code != 201 || rule["applied"].(float64) < 1 {
		t.Fatalf("rule: %d %v", code, rule)
	}
	code, m = h.do(admin, "GET", "/api/v1/applications/"+webID, nil)
	tags := m["tags"].([]any)
	if code != 200 || len(tags) != 1 || tags[0].(map[string]any)["name"] != "pci-dss" || tags[0].(map[string]any)["source"] != "rule" ||
		tags[0].(map[string]any)["category_color"] != "#cf222e" {
		t.Fatalf("rule tag: %d %v", code, tags)
	}

	// 9. Save to inventory: the existing repository moves into the application, once.
	code, m = h.do(admin, "POST", "/api/v1/applications/"+webID+"/onboarding/complete", nil)
	if code != 200 || m["application"].(map[string]any)["onboarding_status"] != "complete" ||
		m["application"].(map[string]any)["progress"].(map[string]any)["label"] != "Registered" {
		t.Fatalf("complete: %d %v", code, m)
	}
	var linkedApp uuid.UUID
	var copies int
	_ = appPool.QueryRow(ctx, `SELECT application_id FROM repositories WHERE id = $1`, repoID).Scan(&linkedApp)
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM repositories WHERE organization_id = $1 AND lower(full_name) = 'acme/website'`, orgID).Scan(&copies)
	if linkedApp.String() != webID || copies != 1 {
		t.Fatalf("repository link: app=%s copies=%d", linkedApp, copies)
	}
	if code, m := h.do(admin, "POST", "/api/v1/applications/"+webID+"/onboarding/discovery", map[string]any{}); code != 200 ||
		m["sources"].([]any)[0].(map[string]any)["status"] != "discovery_started" {
		t.Fatalf("discovery: %d %v", code, m)
	}

	// 10. Bulk tagging and history (who, when, old, new).
	code, m = h.do(admin, "POST", "/api/v1/tag-assignments/bulk", map[string]any{"target_type": "application", "ids": []string{webID, appID, uuid.NewString()},
		"add_tag_ids": []string{id(gdpr, "id")}})
	if code != 200 || m["updated"].(float64) != 2 {
		t.Fatalf("bulk: %d %v", code, m)
	}
	code, m = h.do(admin, "GET", "/api/v1/tag-history?target_type=application&target_id="+webID, nil)
	hist := m["items"].([]any)
	if code != 200 || len(hist) < 2 {
		t.Fatalf("history: %d %v", code, m)
	}
	latest := hist[0].(map[string]any)
	if latest["source"] != "bulk" || fmt.Sprint(latest["old_tags"]) != "[pci-dss]" || fmt.Sprint(latest["new_tags"]) != "[gdpr pci-dss]" || latest["actor_email"] != admin.Email {
		t.Errorf("history entry: %v", latest)
	}
	// Bulk tagging of repositories, and a path-pattern rule.
	_, team := h.do(admin, "POST", "/api/v1/tag-categories", map[string]any{"name": "Area " + sfx})
	_, front := h.do(admin, "POST", "/api/v1/tag-categories/"+id(team, "id")+"/tags", map[string]any{"name": "frontend"})
	code, rule = h.do(admin, "POST", "/api/v1/tag-rules", map[string]any{"name": "Web repos " + sfx, "tag_id": id(front, "id"),
		"target_type": "repository", "condition": "path_pattern", "value": "acme/web*"})
	if code != 201 {
		t.Fatalf("path rule: %d %v", code, rule)
	}
	if code, m := h.do(admin, "POST", "/api/v1/tag-rules/"+id(rule, "rule", "id")+"/apply", nil); code != 200 || m["tagged"].(float64) < 1 {
		t.Fatalf("apply path rule: %d %v", code, m)
	}
	var tagged bool
	_ = appPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM repository_tags WHERE repository_id = $1 AND tag_id = $2)`, repoID, id(front, "id")).Scan(&tagged)
	if !tagged {
		t.Error("path rule did not tag the repository")
	}

	// 11. Lifecycle: nine phases, real data only.
	code, m = h.do(admin, "GET", "/api/v1/applications/"+webID+"/lifecycle", nil)
	phases := m["phases"].([]any)
	if code != 200 || len(phases) != 9 {
		t.Fatalf("lifecycle: %d %v", code, m)
	}
	byKey := map[string]map[string]any{}
	for _, p := range phases {
		byKey[p.(map[string]any)["key"].(string)] = p.(map[string]any)
	}
	if byKey["connect"]["has_data"] != true || byKey["discover"]["has_data"] != true || byKey["assess"]["has_data"] != true ||
		byKey["threat_model"]["available"] != true || byKey["threat_model"]["has_data"] != false {
		t.Errorf("phases: %v", byKey)
	}
	// Built modules never say "arrives in" (M9); phases without data say so.
	for _, k := range []string{"discover", "threat_model", "remediate", "report"} {
		if sum, _ := byKey[k]["summary"].(string); strings.Contains(sum, "arrives in") || sum == "" {
			t.Errorf("phase %s summary: %q", k, sum)
		}
	}
	code, m = h.do(admin, "GET", "/api/v1/lifecycle/overview", nil)
	if code != 200 || len(m["items"].([]any)) < 3 || len(m["phase_totals"].([]any)) != 9 {
		t.Fatalf("overview: %d %v", code, m)
	}

	// 12. Authorization: a viewer can read the profile but not change it.
	viewer := principalWithRole(t, "auditor")
	if code, m := h.do(viewer, "GET", "/api/v1/applications/"+webID, nil); code != 200 || m["can_manage"] != false {
		t.Errorf("viewer read: %d %v", code, m)
	}
	if code, _ := h.do(viewer, "PATCH", "/api/v1/applications/"+webID+"/classification", map[string]any{"criticality": "low"}); code != 403 {
		t.Errorf("viewer write: %d", code)
	}
	if code, _ := h.do(viewer, "POST", "/api/v1/onboarding", map[string]any{"mode": "new", "application": map[string]any{"name": "nope " + sfx},
		"repositories": []any{src("160", "acme/other-"+sfx, "https://github.com/acme/other-"+sfx)}}); code != 403 {
		t.Errorf("viewer register: %d", code)
	}
	if code, _ := h.do(admin, "GET", "/api/v1/applications/"+uuid.NewString(), nil); code != 404 {
		t.Errorf("unknown application: %d", code)
	}

	// 13. Application mandatory fields are configurable.
	code, m = h.do(admin, "PATCH", "/api/v1/application-settings", map[string]any{"required_fields": []string{"owner", "criticality"}})
	if code != 200 || len(m["required_fields"].([]any)) != 2 {
		t.Fatalf("settings: %d %v", code, m)
	}
	t.Cleanup(func() {
		_, _ = h.do(admin, "PATCH", "/api/v1/application-settings", map[string]any{"required_fields": []string{"owner", "business_unit",
			"criticality", "languages", "frameworks", "data_classification", "internet_exposure", "hosting_region", "environment"}})
	})
	_, m = h.do(admin, "GET", "/api/v1/applications/"+appID, nil)
	if l := m["progress"].(map[string]any)["label"]; !strings.HasSuffix(l.(string), " of 2 fields") {
		t.Errorf("progress after settings change: %v", l)
	}
	if code, _ := h.do(admin, "PATCH", "/api/v1/application-settings", map[string]any{"required_fields": []string{"favourite_colour"}}); code != 400 {
		t.Errorf("unknown field must be rejected: %d", code)
	}
}

// Draft completion never moves a repository out of another application
// silently: refused by default (PTH-ONB-1012), kept or moved only when the
// request lists it, and every move is audited.
func TestOnboardingDoesNotMoveRepositoriesSilently(t *testing.T) {
	ctx := t.Context()
	h := newHarness(t)
	(&inventory.Service{DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}, Log: log, Principal: auth.PrincipalFrom}).Register(h.mux)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	sfx := uuid.NewString()[:6]
	if err := repos.EnsureAssetDefaults(ctx, appPool, orgID); err != nil {
		t.Fatal(err)
	}
	setFlag(t, "onboarding", true)
	t.Cleanup(func() { setFlag(t, "onboarding", false) })
	// Only criticality is mandatory here, so completion reaches the repository check.
	if code, m := h.do(admin, "PATCH", "/api/v1/application-settings", map[string]any{"required_fields": []string{"criticality"}}); code != 200 {
		t.Fatalf("settings: %d %v", code, m)
	}
	t.Cleanup(func() {
		_, _ = h.do(admin, "PATCH", "/api/v1/application-settings", map[string]any{"required_fields": []string{"owner", "business_unit",
			"criticality", "languages", "frameworks", "data_classification", "internet_exposure", "hosting_region", "environment"}})
	})

	_, conn := h.do(admin, "POST", "/api/v1/scm-connections", map[string]any{
		"name": "Move GH " + sfx, "provider": "github", "auth_type": "pat", "token": "ghp_x", "owner": "acme"})
	connID := id(conn, "id")
	code, appX := h.do(admin, "POST", "/api/v1/applications", map[string]any{"name": "App X " + sfx})
	if code != 201 {
		t.Fatal(code, appX)
	}
	xID := id(appX, "id")
	repo := func(name string) uuid.UUID {
		rid := uuid.Must(uuid.NewV7())
		if _, err := appPool.Exec(ctx, `INSERT INTO repositories (id, organization_id, scm_connection_id, external_id, full_name, name, url, clone_url,
			default_branch, application_id) VALUES ($1, $2, $3, $4, $5, $4, 'https://github.com/'||$5, 'https://github.com/'||$5||'.git', 'main', $6)`,
			rid, orgID, connID, name+"-"+sfx, "acme/"+name+"-"+sfx, xID); err != nil {
			t.Fatal(err)
		}
		return rid
	}
	appOf := func(rid uuid.UUID) string {
		var a uuid.UUID
		_ = appPool.QueryRow(ctx, `SELECT application_id FROM repositories WHERE id = $1`, rid).Scan(&a)
		return a.String()
	}
	onboard := func(name string, rid uuid.UUID, move bool) string {
		body := map[string]any{"mode": "new", "application": map[string]any{"name": name}, "repositories": []any{map[string]any{"repository_id": rid}}}
		if move {
			body["move_repositories"] = []string{rid.String()}
		}
		code, m := h.do(admin, "POST", "/api/v1/onboarding", body)
		if code != 201 {
			t.Fatalf("register %s: %d %v", name, code, m)
		}
		src := m["sources"].([]any)[0].(map[string]any)
		if src["current_application"] == nil || id(src, "current_application", "id") != xID || src["move_requested"] != move {
			t.Errorf("source should report the current application and the move request: %v", src)
		}
		return id(m, "application", "id")
	}

	// 1. Refused by default: nothing moves, the draft stays a draft.
	r1 := repo("kept")
	yID := onboard("App Y "+sfx, r1, false)
	code, m := h.do(admin, "POST", "/api/v1/applications/"+yID+"/onboarding/complete", nil)
	if code != 409 || errCode(m) != "PTH-ONB-1012" {
		t.Fatalf("silent move must be refused: %d %v", code, m)
	}
	conflicts := m["error"].(map[string]any)["details"].(map[string]any)["conflicts"].([]any)
	if len(conflicts) != 1 || id(conflicts[0].(map[string]any), "application_id") != xID || id(conflicts[0].(map[string]any), "repository_id") != r1.String() {
		t.Errorf("conflict details: %v", conflicts)
	}
	if appOf(r1) != xID {
		t.Fatal("repository moved without an explicit request")
	}
	if _, m := h.do(admin, "GET", "/api/v1/applications/"+yID, nil); m["onboarding_status"] != "draft" {
		t.Errorf("refused completion must leave a draft: %v", m["onboarding_status"])
	}
	if code, _ := h.do(admin, "POST", "/api/v1/applications/"+yID+"/onboarding/complete",
		map[string]any{"move_repositories": []string{r1.String()}, "keep_repositories": []string{r1.String()}}); code != 400 {
		t.Errorf("moved and kept at once must be rejected: %d", code)
	}

	// 2. Kept explicitly: completes, the repository stays in App X.
	code, m = h.do(admin, "POST", "/api/v1/applications/"+yID+"/onboarding/complete", map[string]any{"keep_repositories": []string{r1.String()}})
	if code != 200 || appOf(r1) != xID || m["sources"].([]any)[0].(map[string]any)["status"] != "kept" {
		t.Fatalf("keep: %d app=%s %v", code, appOf(r1), m)
	}

	// 3. Moved explicitly: completes, moves and audits who, which repository, old and new application.
	r2 := repo("moved")
	zID := onboard("App Z "+sfx, r2, true)
	code, m = h.do(admin, "POST", "/api/v1/applications/"+zID+"/onboarding/complete", map[string]any{"move_repositories": []string{r2.String()}})
	if code != 200 || appOf(r2) != zID {
		t.Fatalf("move: %d app=%s %v", code, appOf(r2), m)
	}
	var actor, oldApp, newApp string
	if err := appPool.QueryRow(ctx, `SELECT actor_email, metadata->>'old_application_id', metadata->>'new_application_id' FROM audit_logs
		WHERE organization_id = $1 AND action = 'repository.application_move' AND target_type = 'repository' AND target_id = $2`,
		orgID, r2.String()).Scan(&actor, &oldApp, &newApp); err != nil {
		t.Fatalf("move not audited: %v", err)
	}
	if actor != admin.Email || oldApp != xID || newApp != zID {
		t.Errorf("audit entry: actor=%s old=%s new=%s", actor, oldApp, newApp)
	}
	var n int
	_ = appPool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE organization_id = $1 AND action = 'repository.application_move' AND target_id = $2`,
		orgID, r1.String()).Scan(&n)
	if n != 0 {
		t.Error("a kept repository must not have a move entry")
	}
}

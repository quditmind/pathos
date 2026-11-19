//go:build integration

package integration

// Cross-tenant isolation suite (docs/MULTI_TENANCY.md).
//
// The file name starts with zz_ so it runs after every other test of the
// package: organization B (the victim) is the suite's main organization,
// which by then holds data of every resource type the other tests create
// (repositories, scans, findings, human reviews, applications, releases,
// policies, schedules, notifications, integrations, AI, runtime, ...).
// Organization A (the attacker) is created here with users of every system
// role and similar data of its own.
//
// As each of A's users, every API route found in the source (every
// HandleFunc/Handle registration under internal/) is called through the
// real server (authentication middleware included) with B's resource ids,
// plus list/search/export routes with B's ids as filters. The suite
// asserts that:
//   - no response contains any id of a B row or a B user's email;
//   - routes addressing a B resource answer 403 or 404 (writes may also
//     answer 400 when the body is validated before the lookup);
//   - B's rows (every tenant table, including its audit log) are byte for
//     byte unchanged afterwards.
// It also covers the worker API, MCP, inbound webhooks and row-level
// security directly.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/mcp"
	"pathos/internal/notify"
	"pathos/internal/platform/config"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
	"pathos/internal/platform/sourcestore"
	"pathos/internal/platform/tenant"
	"pathos/internal/repos"
	"pathos/internal/review"
	"pathos/internal/scans"
	"pathos/internal/secrets"
	"pathos/internal/server"
	"pathos/internal/tenancy"
	"pathos/internal/vuln"
)

// route is one registered API route.
type route struct {
	Method, Path, File string
}

// scanRoutes finds every route registration in the backend source:
// calls X.HandleFunc("<METHOD> /path", ...) and X.Handle(...) with a
// string literal pattern. The router registers routes only this way (the
// gap test in internal/server checks that), so new routes are covered
// automatically.
func scanRoutes(t *testing.T) []route {
	t.Helper()
	root := filepath.Join("..", "..", "internal")
	var out []route
	seen := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			pat, _ := strconv.Unquote(lit.Value)
			method, p, ok := strings.Cut(pat, " ")
			if !ok {
				method, p = "", pat
			}
			if !strings.HasPrefix(p, "/api/") && p != "/mcp" {
				return true
			}
			if strings.HasSuffix(p, "/") { // catch-all
				return true
			}
			key := method + " " + p
			if !seen[key] {
				seen[key] = true
				out = append(out, route{Method: method, Path: p, File: path})
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path+out[i].Method < out[j].Path+out[j].Method })
	return out
}

// paramTables maps the path segment before an id parameter to the table
// holding that resource.
var paramTables = map[string]string{
	"repositories": "repositories", "human-reviews": "human_reviews", "findings": "findings",
	"scm-connections": "scm_connections", "scans": "scan_jobs", "users": "users", "applications": "applications",
	"schedules": "scan_schedules", "registries": "registry_connections", "webhooks": "outbound_webhooks",
	"versions": "application_versions", "source-uploads": "source_uploads", "security-policies": "security_policies",
	"scan-targets": "scan_targets", "scan-profiles": "scan_profiles", "custom-rules": "custom_rules",
	"clusters": "runtime_clusters", "ticket-connections": "ticket_connections", "tag-categories": "tag_categories",
	"repository-imports": "repository_import_jobs", "mcp-servers": "mcp_servers", "conversations": "ai_conversations",
	"ai-fixes": "ai_fix_proposals", "workers": "workers", "tags": "tags", "scm-oauth-apps": "scm_oauth_apps",
	"pr-checks": "pr_checks", "component-policies": "component_policies", "workloads": "runtime_workloads",
	"vex-suggestions": "vex_suggestions", "tokens": "api_tokens", "suppression-rules": "suppression_rules",
	"role-assignments": "role_assignments", "risk-acceptances": "risk_acceptances", "mappings": "runtime_app_mappings",
	"identities": "developer_identities", "fix-prs": "fix_pull_requests", "configurations": "ai_configurations",
	"asset-classifications": "asset_classifications", "github": "scm_connections", "gitlab": "scm_connections",
	"bitbucket": "scm_connections", "bitbucket-data-center": "scm_connections", "azure-devops": "scm_connections", "evidence": "human_review_evidence",
	"organizations": "organizations", "providers": "ai_providers", "reviews": "ai_reviews",
	"ai": "human_review_recommendations", "rules": "notification_rules", "deliveries": "notifications",
	"reports": "saved_reports", "connectors": "connectors",
	// PATHOS 3.0 M8: remediation workspace and security gates.
	"items": "remediation_items", "views": "remediation_views", "gates": "security_gates", "decisions": "gate_decisions",
	"gate-exceptions": "gate_exceptions",
}

// specialTables resolves segments whose table depends on the full path.
func tableFor(path, seg string) string {
	switch {
	case strings.HasPrefix(path, "/api/v1/ai/reports/"):
		return "ai_reports"
	case strings.Contains(path, "/notifications/webhooks/{id}/deliveries"):
		return "outbound_webhooks"
	}
	return paramTables[seg]
}

// literalParams are the values used for parameters that are not ids.
var literalParams = map[string]string{
	// Global vulnerability intelligence (not tenant data).
	"cve":  "CVE-2021-44228",
	"feed": "epss", "event": "findings.new", "key": "owasp_top10_2021", "scanner": "semgrep", "which": "before",
	"n": "1", "action": "approve",
}

type isoUser struct {
	role  string
	token string
	mcp   string
	p     *authz.Principal
}

func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	orgB := orgID

	// A pool exactly like a multi-tenant production install: no default
	// organization, so unscoped queries see nothing.
	iso, err := db.Connect(ctx, appURL, log)
	if err != nil {
		t.Fatal(err)
	}
	defer iso.Close()

	keys, err := crypto.NewKeyring(map[int][]byte{1: testKey})
	if err != nil {
		t.Fatal(err)
	}
	store := &secrets.Store{Keys: keys}
	seed := func(ctx context.Context, id uuid.UUID) error {
		if err := scans.EnsureDefaultProfile(ctx, iso, id); err != nil {
			return err
		}
		if err := vuln.EnsureDefaults(ctx, iso, id); err != nil {
			return err
		}
		if err := notify.EnsureDefaults(ctx, iso, store, id); err != nil {
			return err
		}
		if err := mcp.EnsureBuiltIn(ctx, iso, id, "https://pathos.example"); err != nil {
			return err
		}
		if err := review.EnsureSettings(ctx, iso, id); err != nil {
			return err
		}
		return repos.EnsureAssetDefaults(ctx, iso, id)
	}
	slugA := "iso-a-" + uuid.NewString()[:6]
	orgA, _, err := tenancy.CreateOrganization(ctx, iso, "Isolation A", slugA, "", seed)
	if err != nil {
		t.Fatal("create organization A:", err)
	}
	// Flagged modules are on in A too, so their routes are probed.
	for _, flag := range []string{"connectors", "remediation_workspace"} {
		if _, err := ownerPool.Exec(ctx, `INSERT INTO feature_flags (id, organization_id, name, enabled) VALUES ($1, $2, $3, true)`,
			uuid.Must(uuid.NewV7()), orgA.ID, flag); err != nil {
			t.Fatal(err)
		}
	}
	// B must be seeded the same way (it is the suite's main organization).
	if err := mcp.EnsureBuiltIn(tenant.WithOrg(ctx, orgB), iso, orgB, "https://pathos.example"); err != nil {
		t.Fatal(err)
	}

	pub, _ := url.Parse("https://pathos.example")
	cfg := &config.Config{PublicURL: pub, OrgClaim: "groups", OrgGroupPrefix: "/pathos/"}
	as := &auth.Service{Cfg: cfg, DB: iso, Log: log, OrgID: orgB, MultiTenant: true}
	sources, err := sourcestore.NewFS(t.TempDir(), keys)
	if err != nil {
		t.Fatal(err)
	}
	handlers := server.Build(server.Deps{DB: iso, Auth: as, OrgID: orgB, MultiTenant: true, Log: log, Secrets: store,
		PublicURL: "https://pathos.example", WorkerBootstrapToken: strings.Repeat("b", 40), Offline: true, Sources: sources})
	api := handlers.Public

	// Users of every system role in A, each with a REST token (read and
	// write) and an MCP token.
	actx := tenant.WithOrg(ctx, orgA.ID)
	var users []isoUser
	for _, r := range authz.SystemRoles {
		u, err := identity.CreateUser(actx, iso, identity.User{OrganizationID: orgA.ID, Email: r.Key + "-" + uuid.NewString()[:6] + "@iso-a.test", Status: identity.StatusActive})
		if err != nil {
			t.Fatal(err)
		}
		sub := "sub-" + uuid.NewString()
		if err := identity.SetKeycloakSubject(actx, iso, orgA.ID, u.ID, sub); err != nil {
			t.Fatal(err)
		}
		role, err := identity.GetRoleByKey(actx, iso, orgA.ID, r.Key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := identity.CreateAssignment(actx, iso, orgA.ID, u.ID, role.ID, authz.Scope{Type: authz.ScopeOrganization, ID: orgA.ID}, nil); err != nil {
			t.Fatal(err)
		}
		grants, _ := identity.LoadGrants(actx, iso, u.ID)
		iu := isoUser{role: r.Key, p: &authz.Principal{UserID: u.ID, OrganizationID: orgA.ID, Email: u.Email, Subject: sub, Grants: grants}}
		iu.token = mintToken(t, actx, iso, orgA.ID, u.ID, "api:read", "api:write")
		iu.mcp = mintToken(t, actx, iso, orgA.ID, u.ID, "mcp")
		users = append(users, iu)
	}
	admin := users[0]
	if admin.role != authz.RoleSuperAdmin {
		t.Fatal("first system role must be super_admin")
	}
	do := func(tok, method, path string, body []byte) (int, []byte) {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req := httptest.NewRequest(method, path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		return rec.Code, rec.Body.Bytes()
	}

	// Similar data in A: an SCM connection with repositories, plus
	// organization structure created through the API as A's
	// administrator.
	{
		sec, err := store.Create(actx, iso, orgA.ID, secrets.KindSCM, "a-scm", []byte("t"), nil)
		if err != nil {
			t.Fatal(err)
		}
		wh, err := store.Create(actx, iso, orgA.ID, secrets.KindWebhook, "a-wh", []byte("w"), nil)
		if err != nil {
			t.Fatal(err)
		}
		conn := uuid.Must(uuid.NewV7())
		if _, err := iso.Exec(actx, `INSERT INTO scm_connections (id, organization_id, name, provider, base_url, auth_type, secret_id, webhook_secret_id)
			VALUES ($1, $2, 'a-conn', 'github', 'https://api.github.com', 'pat', $3, $4)`, conn, orgA.ID, sec, wh); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"app", "api", "web"} {
			if _, err := iso.Exec(actx, `INSERT INTO repositories (id, organization_id, scm_connection_id, external_id, full_name, name, url, clone_url, default_branch)
				VALUES ($1, $2, $3, $4, $5, $4, 'https://github.com/'||$5, 'https://github.com/'||$5||'.git', 'main')`,
				uuid.Must(uuid.NewV7()), orgA.ID, conn, name, "iso-a/"+name); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, c := range []struct{ path, body string }{
		{"/api/v1/business-units", `{"name":"Isolation BU A"}`},
		{"/api/v1/applications", `{"name":"Isolation app A"}`},
		{"/api/v1/tag-categories", `{"name":"Isolation tags A"}`},
		{"/api/v1/custom-rules", `{"name":"iso-rule-a","content":"rules:\n  - id: iso-a\n    pattern: eval(...)\n    message: m\n    languages: [python]\n    severity: ERROR\n"}`},
	} {
		if code, out := do(admin.token, "POST", c.path, []byte(c.body)); code != 201 && code != 200 {
			t.Logf("seed A %s: %d %s", c.path, code, truncateBody(out))
		}
	}

	// Resource types the earlier tests leave empty in B.
	seedVictim(t, ctx, orgB)
	// B's identity: every id of a B row and every B user's email.
	bIDs, bEmails := victimMarkers(t, ctx, orgB)
	if len(bIDs) < 200 {
		t.Fatalf("organization B should hold data of many resource types, found %d ids", len(bIDs))
	}
	before := snapshot(t, ctx, orgB)
	bByTable := victimIDsByTable(t, ctx, orgB)

	// Ids the attacker sends may come back in A's own data (for example
	// A's audit log records the target of A's denied request): those are
	// echoes of A's input, not B's data. Every other B id is a leak; a
	// route that returns the addressed B resource is caught by its status
	// and by the other ids of that resource.
	sent := map[string]bool{}
	leak := func(body []byte) string {
		for _, m := range uuidRe.FindAll(body, -1) {
			if id := strings.ToLower(string(m)); bIDs[id] && !sent[id] {
				return string(m)
			}
		}
		lb := bytes.ToLower(body)
		for _, e := range bEmails {
			if bytes.Contains(lb, []byte(e)) {
				return e
			}
		}
		return ""
	}

	routes := scanRoutes(t)
	if len(routes) < 380 {
		t.Fatalf("route scan found only %d routes", len(routes))
	}
	paramRe := regexp.MustCompile(`\{([a-zA-Z_.]+)\}`)
	type probe struct {
		method, path string
		addressesB   bool
		key          string // route pattern ("METHOD /path")
	}
	var probes []probe
	unmapped := map[string]bool{}
	for _, r := range routes {
		methods := []string{r.Method}
		if r.Method == "" {
			methods = []string{"GET", "POST"}
		}
		for _, m := range methods {
			if r.Path == "/mcp" {
				continue // covered by the MCP section below
			}
			if !strings.Contains(r.Path, "{") {
				probes = append(probes, probe{m, r.Path, false, r.Method + " " + r.Path})
				if m == "GET" {
					// Lists, searches and exports filtered by B's ids.
					q := url.Values{}
					q.Set("q", "iso")
					for param, table := range map[string]string{"repository_id": "repositories", "application_id": "applications",
						"finding_id": "findings", "scan_id": "scan_jobs", "business_unit_id": "business_units", "user_id": "users",
						"team_id": "teams", "target_id": "scan_targets", "version_id": "application_versions", "cluster_id": "runtime_clusters"} {
						if ids := bByTable[table]; len(ids) > 0 {
							q.Set(param, ids[0])
							sent[ids[0]] = true
						}
					}
					probes = append(probes, probe{m, r.Path + "?" + q.Encode(), false, r.Method + " " + r.Path})
				}
				continue
			}
			// Substitute every parameter; ids come from B.
			segs := strings.Split(r.Path, "/")
			path := make([]string, len(segs))
			addresses := false
			ok := true
			for i, s := range segs {
				pm := paramRe.FindStringSubmatch(s)
				if pm == nil {
					path[i] = s
					continue
				}
				name := pm[1]
				if i > 0 && segs[i-1] == "cves" {
					name = "cve"
				}
				if v, lit := literalParams[name]; lit {
					path[i] = v
					continue
				}
				prev := ""
				if i > 0 {
					prev = segs[i-1]
				}
				table := tableFor(r.Path, prev)
				ids := bByTable[table]
				if table == "organizations" {
					ids = []string{orgB.String()}
				}
				if len(ids) == 0 && addresses {
					// A child of a B resource that B has none of: the
					// parent already addresses B.
					ids = []string{uuid.NewString()}
				}
				if len(ids) == 0 {
					unmapped[r.Path+" ("+table+")"] = true
					ok = false
					break
				}
				path[i] = ids[0]
				sent[ids[0]] = true
				addresses = true
			}
			if ok {
				probes = append(probes, probe{m, strings.Join(path, "/"), addresses, r.Method + " " + r.Path})
			}
		}
	}
	for k := range unmapped {
		t.Logf("not probed (B has no row to address): %s", k)
	}
	if len(unmapped) > 0 {
		t.Errorf("%d parameterised routes have no B resource to address; add data or a mapping", len(unmapped))
	}

	// The probes run twice: with row-level security enforced (the
	// production configuration), and with it switched off, which shows
	// that the application layer alone (organization filters in every
	// query, authorization of every resource) also isolates B.
	runProbes := func(t *testing.T, layer string) {
		statuses := map[int]int{}
		failRoles := map[string][]string{}
		fail := func(kind, method, path, role string, code int, detail string) {
			k := fmt.Sprintf("%s %s %s: %d %s", kind, method, uuidRe.ReplaceAllString(path, "{B}"), code, detail)
			failRoles[k] = append(failRoles[k], role)
		}
		requests := 0
		for _, u := range users {
			for _, pr := range probes {
				var body []byte
				if pr.method == "POST" || pr.method == "PUT" || pr.method == "PATCH" {
					body = []byte(`{}`)
				}
				code, out := do(u.token, pr.method, pr.path, body)
				requests++
				statuses[code]++
				if l := leak(out); l != "" {
					fail("LEAK", pr.method, pr.path, u.role, code, "contains "+l)
					continue
				}
				if pr.addressesB {
					allowed := code == 403 || code == 404 || code == 401 ||
						// Bodies are validated before the lookup on some writes
						// (an empty body never reaches B's row).
						((code == 400 || code == 422) && pr.method != "GET") ||
						// A precondition of the caller's own organization,
						// checked before the lookup.
						(code == 409 && bytes.Contains(out, []byte(`"attribution_disabled"`)))
					if !allowed {
						fail("STATUS", pr.method, pr.path, u.role, code, uuidRe.ReplaceAllString(truncateBody(out), "{id}"))
					}
				}
				if code >= 500 && code != 501 && code != 502 && code != 503 {
					fail("ERROR", pr.method, pr.path, u.role, code, uuidRe.ReplaceAllString(truncateBody(out), "{id}"))
				}
			}
		}
		// Unauthenticated: inbound SCM webhooks addressed to B's connections
		// (the signature check uses B's secret; a forged delivery is rejected).
		for _, prov := range []string{"github", "gitlab", "bitbucket", "bitbucket-data-center", "azure-devops"} {
			for _, c := range bByTable["scm_connections"] {
				code, out := do("", "POST", "/api/webhooks/"+prov+"/"+c, []byte(`{"zen":"x"}`))
				requests++
				sent[c] = true
				if l := leak(out); l != "" || (code != 401 && code != 403 && code != 404 && code != 400) {
					fail("WEBHOOK", "POST", "/api/webhooks/"+prov+"/"+c, "anonymous", code, truncateBody(out))
				}
			}
		}
		keysSorted := make([]string, 0, len(failRoles))
		for k := range failRoles {
			keysSorted = append(keysSorted, k)
		}
		slices.Sort(keysSorted)
		for _, k := range keysSorted {
			t.Errorf("%s [as %s]", k, strings.Join(failRoles[k], ","))
		}
		t.Logf("isolation (%s): %d routes, %d probes, %d users (one per system role), %d requests; statuses %v",
			layer, len(routes), len(probes), len(users), requests, statuses)
	}
	// Valid-body write probes: every write route that addresses a B
	// resource gets a body that passes validation (generated from the
	// handler's request struct, completed by fixtures), so the request
	// reaches the organization check. Body references point at A's
	// resources, so only the addressed resource is foreign.
	bodies := buildBodyIndex(t)
	{
		var cat uuid.UUID
		if err := iso.QueryRow(actx, `SELECT id FROM tag_categories WHERE organization_id = $1 LIMIT 1`, orgA.ID).Scan(&cat); err == nil {
			if code, out := do(admin.token, "POST", "/api/v1/tag-categories/"+cat.String()+"/tags", []byte(`{"name":"iso-a-tag","color":"blue"}`)); code != 201 {
				t.Logf("seed A tag: %d %s", code, truncateBody(out))
			}
		}
	}
	// An AI provider in A (its configurations reference one).
	if sec, err := store.Create(actx, iso, orgA.ID, secrets.KindAI, "a-ai", []byte("k"), nil); err == nil {
		if _, err := iso.Exec(actx, `INSERT INTO ai_providers (id, organization_id, name, kind, secret_id) VALUES ($1, $2, 'a-provider', 'anthropic', $3)`,
			uuid.Must(uuid.NewV7()), orgA.ID, sec); err != nil {
			t.Logf("seed A AI provider: %v", err)
		}
	}
	// A finding with a human review in A, and developer attribution on,
	// so that the creates that take them have a valid control.
	{
		var aRepo uuid.UUID
		_ = iso.QueryRow(actx, `SELECT id FROM repositories WHERE organization_id = $1 LIMIT 1`, orgA.ID).Scan(&aRepo)
		f1, f2 := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
		for _, f := range []uuid.UUID{f1, f2} {
			if _, err := iso.Exec(actx, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id,
				title, description, severity, file_path, start_line) VALUES ($1, $2, $3, $4, 'sast', '{opengrep}', 'iso.rule', 'iso finding A', 'x', 'high', 'a.py', 1)`,
				f, orgA.ID, aRepo, uuid.NewString()); err != nil {
				t.Logf("seed A finding: %v", err)
			}
		}
		if _, err := iso.Exec(actx, `INSERT INTO human_reviews (id, organization_id, review_key, finding_id, repository_id, original_severity, source, due_at)
			VALUES ($1, $2, $3, $4, $5, 'high', 'manual', now() + interval '30 days')`, uuid.Must(uuid.NewV7()), orgA.ID, "ISO-A-"+uuid.NewString()[:8], f2, aRepo); err != nil {
			t.Logf("seed A human review: %v", err)
		}
		// A security policy in A (security gates reference one).
		if _, err := iso.Exec(actx, `INSERT INTO security_policies (id, organization_id, name, conditions, actions) VALUES ($1, $2, 'iso-a-policy', '{"min_severity":"critical"}', '{"notify":true}')`,
			uuid.Must(uuid.NewV7()), orgA.ID); err != nil {
			t.Logf("seed A security policy: %v", err)
		}
		if _, err := iso.Exec(actx, `INSERT INTO developer_insight_settings (organization_id, attribution_enabled) VALUES ($1, true)
			ON CONFLICT (organization_id) DO UPDATE SET attribution_enabled = true`, orgA.ID); err != nil {
			t.Logf("seed A attribution: %v", err)
		}
	}
	aByTable := victimIDsByTable(t, ctx, orgA.ID)
	idsOf := func(byTable map[string][]string) idFunc {
		return func(field string) string {
			if tbl, ok := strings.CutPrefix(field, "@"); ok {
				if v := byTable[tbl]; len(v) > 0 {
					return v[0]
				}
				return ""
			}
			if tbl, ok := refTables[field]; ok {
				if v := byTable[tbl]; len(v) > 0 {
					return v[0]
				}
			}
			return ""
		}
	}
	runWriteProbes := func(t *testing.T, layer string) {
		type outcome struct {
			reached bool
			detail  string
		}
		results := map[string]outcome{}
		statuses := map[int]int{}
		requests := 0
		for _, u := range users {
			for _, pr := range probes {
				if !pr.addressesB || pr.method == "GET" || pr.method == "" {
					continue
				}
				body := bodies.bodyFor(pr.key, idsOf(aByTable))
				var raw []byte
				if body != nil {
					raw, _ = json.Marshal(body)
				} else if pr.method != "DELETE" {
					raw = []byte(`{}`)
				}
				path := pr.path
				if q := writeQueries[pr.key]; q != "" {
					path += "?" + q
				}
				code, out := do(u.token, pr.method, path, raw)
				requests++
				statuses[code]++
				if l := leak(out); l != "" {
					t.Errorf("LEAK (valid body) %s %s as %s: %d contains %s", pr.method, pr.key, u.role, code, l)
					continue
				}
				// Reached the organization check: not stopped by body
				// validation, by the webhook signature (unauthenticated
				// routes) or by the session-only rule for API tokens.
				reached := code != 400 && code != 422 && code != 401 && !bytes.Contains(out, []byte(`"token_not_allowed"`))
				ok := code == 403 || code == 404 || !reached ||
					// Inbound webhooks: the forged delivery fails B's signature.
					(code == 401 && strings.HasPrefix(pr.path, "/api/webhooks/")) ||
					(code == 409 && bytes.Contains(out, []byte(`"attribution_disabled"`)))
				if !ok {
					t.Errorf("STATUS (valid body) %s %s as %s: %d %s", pr.method, pr.key, u.role, code, truncateBody(out))
				}
				if u.role == authz.RoleSuperAdmin {
					results[pr.key] = outcome{reached, uuidRe.ReplaceAllString(truncateBody(out), "{id}")}
				}
			}
		}
		// Session-only routes (API tokens may not manage tokens): called
		// with A's principal directly, as the session would.
		{
			ms := &mcp.Service{DB: iso, Log: log, Principal: auth.PrincipalFrom, PublicURL: "https://pathos.example"}
			mux := http.NewServeMux()
			ms.Register(mux)
			for _, tok := range bByTable["api_tokens"] {
				req := httptest.NewRequest("DELETE", "/api/v1/me/tokens/"+tok, nil).WithContext(auth.WithPrincipal(ctx, admin.p))
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				requests++
				if rec.Code != 404 || leak(rec.Body.Bytes()) != "" {
					t.Errorf("DELETE /api/v1/me/tokens/{B} with A's session principal: %d %s", rec.Code, truncateBody(rec.Body.Bytes()))
				} else {
					results["DELETE /api/v1/me/tokens/{id}"] = outcome{true, "session principal: 404"}
				}
			}
		}

		reached := 0
		var notReached []string
		for k, o := range results {
			if o.reached {
				reached++
			} else {
				notReached = append(notReached, k+": "+o.detail)
			}
		}
		slices.Sort(notReached)
		for _, n := range notReached {
			t.Logf("write probe stopped at validation: %s", n)
		}
		t.Logf("valid-body write probes (%s): %d write routes addressing B, %d reached the organization check (not 400/422, not a webhook signature 401, not the session-only token rule), %d requests; statuses %v",
			layer, len(results), reached, requests, statuses)
		if reached < minWriteRoutesReached {
			t.Errorf("only %d write routes reached past validation (minimum %d): a fixture or request struct changed", reached, minWriteRoutesReached)
		}
		for _, k := range requiredWriteRoutes {
			if o, ok := results[k]; !ok || !o.reached {
				t.Errorf("required write route %s did not reach the organization check: %v", k, o.detail)
			}
		}

		// Creates whose parent is in the body: B's parent must be
		// rejected; the same body with A's parent is the control that
		// shows the body is valid.
		parentRoutes, controls := 0, 0
		for _, r := range routes {
			if r.Method != "POST" || strings.Contains(r.Path, "{") || strings.HasPrefix(r.Path, "/api/v1/installation/") ||
				strings.HasPrefix(r.Path, "/api/webhooks/") || strings.HasPrefix(r.Path, "/api/auth/") || r.Path == "/api/v1/me/organization" {
				continue
			}
			key := r.Method + " " + r.Path
			probeB := bodies.bodyFor(key, idsOf(bByTable))
			hasParent := false
			for f := range probeB {
				if tbl, ok := refTables[f]; ok && len(bByTable[tbl]) > 0 && len(aByTable[tbl]) > 0 {
					hasParent = true
				}
			}
			if !hasParent {
				continue
			}
			parentRoutes++
			raw, _ := json.Marshal(probeB)
			code, out := do(admin.token, "POST", r.Path, raw)
			requests++
			if l := leak(out); l != "" {
				t.Errorf("LEAK (parent in body) POST %s: %d contains %s", r.Path, code, l)
			}
			if code < 400 || code >= 500 {
				t.Errorf("POST %s accepted organization B's parent in the body: %d %s", r.Path, code, truncateBody(out))
			}
			if controlSkip[key] {
				t.Logf("parent in body: POST %s: with B's parents %d (no control: it would contact an external system)", r.Path, code)
				continue
			}
			ctrl, _ := json.Marshal(bodies.bodyFor(key, idsOf(aByTable)))
			ccode, cout := do(admin.token, "POST", r.Path, ctrl)
			if ccode >= 200 && ccode < 300 {
				controls++
			}
			t.Logf("parent in body: POST %s: with B's parents %d %s; with A's parents %d %s", r.Path, code,
				uuidRe.ReplaceAllString(truncateBody(out), "{id}"), ccode, uuidRe.ReplaceAllString(truncateBody(cout), "{id}"))
		}
		t.Logf("parent-in-body creates (%s): %d routes probed with B's parents (all rejected), %d of them accept the same body with A's parents (valid control)",
			layer, parentRoutes, controls)
		if controls < minParentControls {
			t.Errorf("only %d parent-in-body creates have a valid control (minimum %d)", controls, minParentControls)
		}
	}

	t.Run("routes with row-level security", func(t *testing.T) {
		runProbes(t, "row-level security and application")
		runWriteProbes(t, "row-level security and application")
	})
	t.Run("routes, application layer only", func(t *testing.T) {
		setRLS(t, ctx, false)
		defer setRLS(t, ctx, true)
		runProbes(t, "application only")
		runWriteProbes(t, "application only")
	})

	t.Run("mcp", func(t *testing.T) { isoMCP(t, api, users, bByTable, leak) })
	t.Run("worker api", func(t *testing.T) { isoWorker(t, ctx, iso, handlers.Worker, orgA, orgB, bByTable, leak) })
	t.Run("row level security", func(t *testing.T) { isoRLS(t, ctx, iso, orgA.ID, orgB) })
	t.Run("organization switch", func(t *testing.T) { isoSwitch(t, ctx, iso, as, orgA.ID, orgB, users[0]) })
	t.Run("installation api", func(t *testing.T) { isoInstallation(t, ctx, iso, api, users, do) })

	after := snapshot(t, ctx, orgB)
	for table, h := range before {
		if after[table] != h {
			t.Errorf("organization B's %s changed during the isolation run", table)
		}
	}
}

// Coverage floors of the valid-body probes (measured; raise them when
// fixtures are added, never lower them without a reason).
//
// Measured 2026-11-19: 130 of the 131 write routes that address a B
// resource reach the organization check with a valid body (the remaining
// one is the GitHub webhook, which is unauthenticated and stops at B's
// signature); 11 of the 15 creates with a parent in the body have a valid
// control (4 would contact an SCM or need an uploaded archive).
const (
	minWriteRoutesReached = 130
	minParentControls     = 11
)

// requiredWriteRoutes must reach the organization check with a valid body.
var requiredWriteRoutes = []string{
	// findings: status, assignment, triage, risk acceptance, suppression,
	// tickets, AI fixes and secret validation
	"POST /api/v1/findings/{id}/status", "POST /api/v1/findings/{id}/assign", "POST /api/v1/findings/{id}/risk-acceptance",
	"POST /api/v1/risk-acceptances/{id}/{action}", "POST /api/v1/suppression-rules/{id}/{action}", "POST /api/v1/findings/{id}/tickets",
	"POST /api/v1/findings/{id}/ai-fixes", "POST /api/v1/ai-fixes/{id}/pull-request", "POST /api/v1/findings/{id}/fix-pr",
	"POST /api/v1/findings/{id}/secret-validation/recheck", "POST /api/v1/findings/{id}/ai-review",
	"POST /api/v1/ai/reviews/{id}/approve", "POST /api/v1/ai/reviews/{id}/reject",
	// repositories
	"PATCH /api/v1/repositories/{id}", "POST /api/v1/repositories/{id}/sync", "DELETE /api/v1/repositories/{id}",
	"POST /api/v1/repositories/{id}/archive", "POST /api/v1/repositories/{id}/scan", "PUT /api/v1/repositories/{id}/scan-profile",
	// scan targets (update also carries authorization and intrusive authorization)
	"PUT /api/v1/scan-targets/{id}", "DELETE /api/v1/scan-targets/{id}", "POST /api/v1/scan-targets/{id}/scan",
	// scan profiles, schedules, policies
	"PUT /api/v1/scan-profiles/{id}", "DELETE /api/v1/scan-profiles/{id}", "POST /api/v1/scan-profiles/{id}/default",
	"PUT /api/v1/schedules/{id}", "DELETE /api/v1/schedules/{id}", "POST /api/v1/schedules/{id}/run",
	"PUT /api/v1/security-policies/{id}", "DELETE /api/v1/security-policies/{id}",
	"PUT /api/v1/component-policies/{id}", "DELETE /api/v1/component-policies/{id}",
	// users, roles and tokens
	"POST /api/v1/users/{id}/deactivate", "POST /api/v1/users/{id}/reactivate", "POST /api/v1/users/{id}/role-assignments",
	"DELETE /api/v1/role-assignments/{id}", "POST /api/v1/users/{id}/require-mfa", "DELETE /api/v1/me/tokens/{id}",
	// integrations, tickets, webhooks
	"PATCH /api/v1/scm-connections/{id}", "DELETE /api/v1/scm-connections/{id}", "POST /api/v1/scm-connections/{id}/resync",
	"PUT /api/v1/ticket-connections/{id}", "DELETE /api/v1/ticket-connections/{id}", "POST /api/v1/ticket-connections/{id}/test",
	"PUT /api/v1/notifications/webhooks/{id}", "DELETE /api/v1/notifications/webhooks/{id}", "POST /api/v1/notifications/webhooks/{id}/test",
	// runtime clusters and registries
	"PUT /api/v1/runtime/clusters/{id}", "DELETE /api/v1/runtime/clusters/{id}", "POST /api/v1/runtime/clusters/{id}/sync",
	"PUT /api/v1/runtime/registries/{id}", "DELETE /api/v1/runtime/registries/{id}", "POST /api/v1/runtime/registries/{id}/sync",
	// human reviews: comments, decisions, assessment
	"POST /api/v1/human-reviews/{id}/comments", "POST /api/v1/human-reviews/{id}/decision", "PUT /api/v1/human-reviews/{id}/assessment",
	"POST /api/v1/human-reviews/{id}/assign", "PATCH /api/v1/human-reviews/{id}", "POST /api/v1/human-reviews/{id}/independent-review",
}

var uuidRe = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

func truncateBody(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	return string(b)
}

func mintToken(t *testing.T, ctx context.Context, q db.Querier, org, user uuid.UUID, scopes ...string) string {
	t.Helper()
	tok := mcp.TokenPrefix + strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
	sum := sha256.Sum256([]byte(tok))
	if _, err := q.Exec(ctx, `INSERT INTO api_tokens (id, organization_id, user_id, name, prefix, token_sha256, scopes, expires_at)
		VALUES ($1, $2, $3, 'isolation', $4, $5, $6, now() + interval '1 day')`,
		uuid.Must(uuid.NewV7()), org, user, tok[:16], hex.EncodeToString(sum[:]), scopes); err != nil {
		t.Fatal(err)
	}
	return tok
}

// tenantTables lists tables with an organization_id column.
func tenantTables(t *testing.T, ctx context.Context) []string {
	t.Helper()
	rows, err := ownerPool.Query(ctx, `SELECT c.relname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'organization_id' AND NOT a.attisdropped
		WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func victimMarkers(t *testing.T, ctx context.Context, org uuid.UUID) (map[string]bool, []string) {
	t.Helper()
	ids := map[string]bool{org.String(): true}
	for _, tbl := range tenantTables(t, ctx) {
		var hasID bool
		_ = ownerPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = $1 AND column_name = 'id' AND data_type = 'uuid')`, tbl).Scan(&hasID)
		if !hasID {
			continue
		}
		rows, err := ownerPool.Query(ctx, `SELECT id::text FROM `+pgx.Identifier{tbl}.Sanitize()+` WHERE organization_id = $1`, org)
		if err != nil {
			t.Fatal(err)
		}
		vals, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			ids[v] = true
		}
	}
	rows, err := ownerPool.Query(ctx, `SELECT email FROM users WHERE organization_id = $1`, org)
	if err != nil {
		t.Fatal(err)
	}
	emails, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	return ids, emails
}

func victimIDsByTable(t *testing.T, ctx context.Context, org uuid.UUID) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, tbl := range tenantTables(t, ctx) {
		var hasID bool
		_ = ownerPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = $1 AND column_name = 'id' AND data_type = 'uuid')`, tbl).Scan(&hasID)
		if !hasID {
			continue
		}
		rows, err := ownerPool.Query(ctx, `SELECT id::text FROM `+pgx.Identifier{tbl}.Sanitize()+` WHERE organization_id = $1 ORDER BY id DESC LIMIT 3`, org)
		if err != nil {
			t.Fatal(err)
		}
		out[tbl], _ = pgx.CollectRows(rows, pgx.RowTo[string])
	}
	return out
}

// snapshot hashes every row of org in every tenant table (and the child
// tables without an organization column, through their parents).
func snapshot(t *testing.T, ctx context.Context, org uuid.UUID) map[string]string {
	t.Helper()
	out := map[string]string{}
	q := func(name, sql string) {
		var h *string
		if err := ownerPool.QueryRow(ctx, sql, org).Scan(&h); err != nil {
			t.Fatalf("snapshot %s: %v", name, err)
		}
		if h != nil {
			out[name] = *h
		} else {
			out[name] = ""
		}
	}
	for _, tbl := range tenantTables(t, ctx) {
		where := ``
		if tbl == "audit_logs" {
			// Forged webhook deliveries to B's endpoints are recorded in
			// B's own audit log, by design (checked separately).
			where = ` AND x.action <> 'webhook.rejected'`
		}
		q(tbl, `SELECT md5(string_agg(x::text, '|' ORDER BY x::text)) FROM `+pgx.Identifier{tbl}.Sanitize()+` x WHERE x.organization_id = $1`+where)
	}
	q("organizations", `SELECT md5(x::text) FROM organizations x WHERE x.id = $1`)
	q("profile_scanners", `SELECT md5(string_agg(x::text, '|' ORDER BY x::text)) FROM profile_scanners x JOIN scan_profile_versions v ON v.id = x.profile_version_id WHERE v.organization_id = $1`)
	q("custom_rule_versions", `SELECT md5(string_agg(x::text, '|' ORDER BY x::text)) FROM custom_rule_versions x JOIN custom_rules r ON r.id = x.rule_id WHERE r.organization_id = $1`)
	q("pr_findings", `SELECT md5(string_agg(x::text, '|' ORDER BY x::text)) FROM pr_findings x JOIN pr_checks c ON c.id = x.pr_check_id WHERE c.organization_id = $1`)
	q("fix_pull_request_findings", `SELECT md5(string_agg(x::text, '|' ORDER BY x::text)) FROM fix_pull_request_findings x JOIN fix_pull_requests p ON p.id = x.fix_pull_request_id WHERE p.organization_id = $1`)
	q("source_upload_parts", `SELECT md5(string_agg(x::text, '|' ORDER BY x::text)) FROM source_upload_parts x JOIN source_uploads u ON u.id = x.upload_id WHERE u.organization_id = $1`)
	q("application_version_repositories", `SELECT md5(string_agg(x::text, '|' ORDER BY x::text)) FROM application_version_repositories x JOIN application_versions v ON v.id = x.version_id WHERE v.organization_id = $1`)
	return out
}

// isoMCP calls every MCP tool as each of A's users with B's ids.
func isoMCP(t *testing.T, api http.Handler, users []isoUser, bByTable map[string][]string, leak func([]byte) string) {
	call := func(tok string, body map[string]any) (int, []byte) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		return rec.Code, rec.Body.Bytes()
	}
	bFinding := ""
	if ids := bByTable["findings"]; len(ids) > 0 {
		bFinding = ids[0]
	}
	calls := 0
	for _, u := range users {
		code, out := call(u.mcp, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
		if code != 200 {
			t.Fatalf("tools/list as %s: %d %s", u.role, code, out)
		}
		if l := leak(out); l != "" {
			t.Errorf("tools/list leaks %s", l)
		}
		var list struct {
			Result struct {
				Tools []struct {
					Name        string `json:"name"`
					InputSchema struct {
						Properties map[string]struct {
							Type string   `json:"type"`
							Enum []string `json:"enum"`
						} `json:"properties"`
					} `json:"inputSchema"`
				} `json:"tools"`
			} `json:"result"`
		}
		_ = json.Unmarshal(out, &list)
		for _, tool := range list.Result.Tools {
			args := map[string]any{}
			for name, prop := range tool.InputSchema.Properties {
				switch {
				case strings.HasSuffix(name, "_id"):
					args[name] = bFinding
				case len(prop.Enum) > 0:
					args[name] = prop.Enum[0]
				case prop.Type == "number" || prop.Type == "integer":
					args[name] = 1
				case prop.Type == "boolean":
					args[name] = true
				case prop.Type == "array":
					args[name] = []any{}
				default:
					args[name] = "isolation"
				}
			}
			code, out := call(u.mcp, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
				"params": map[string]any{"name": tool.Name, "arguments": args}})
			calls++
			if l := leak(out); l != "" {
				t.Errorf("MCP %s as %s leaks %s: %s", tool.Name, u.role, l, truncateBody(out))
			}
			if code != 200 {
				t.Errorf("MCP %s as %s: %d", tool.Name, u.role, code)
			}
		}
		// A token never works for another organization's MCP endpoint
		// configuration: the registry lookup is the token's organization.
	}
	t.Logf("MCP: %d tool calls with B's finding id", calls)
}

// isoWorker registers a worker for A and checks it can neither lease nor
// touch B's jobs.
func isoWorker(t *testing.T, ctx context.Context, iso *pgxpool.Pool, wapi http.Handler, orgA tenancy.Organization, orgB uuid.UUID,
	bByTable map[string][]string, leak func([]byte) string) {
	call := func(tok, method, path string, body any) (int, []byte) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		wapi.ServeHTTP(rec, req)
		return rec.Code, rec.Body.Bytes()
	}
	// A queued job in B.
	bctx := tenant.WithOrg(ctx, orgB)
	var bRepo uuid.UUID
	if err := iso.QueryRow(bctx, `SELECT id FROM repositories WHERE organization_id = $1 AND archived_at IS NULL ORDER BY created_at LIMIT 1`, orgB).Scan(&bRepo); err != nil {
		t.Fatal("B needs a repository:", err)
	}
	res, err := scans.Enqueue(bctx, iso, orgB, bRepo, "manual", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	bJob := res.JobID.String()
	code, out := call(strings.Repeat("b", 40), "POST", "/internal/worker/v1/register",
		map[string]any{"name": "iso-worker-a", "family": "core", "version": "test", "scanners": map[string]string{"semgrep": "1"}, "organization": orgA.Slug})
	if code != 200 {
		t.Fatalf("register worker for A: %d %s", code, out)
	}
	var reg struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(out, &reg)
	for range 3 {
		code, out = call(reg.Token, "POST", "/internal/worker/v1/lease", map[string]any{})
		if l := leak(out); l != "" {
			t.Fatalf("worker of A leased B's data: %s %s", l, truncateBody(out))
		}
		if code == 200 && bytes.Contains(out, []byte(bJob)) {
			t.Fatalf("worker of A leased B's job")
		}
	}
	for _, p := range []struct{ method, path string }{
		{"POST", "/internal/worker/v1/jobs/" + bJob + "/heartbeat"},
		{"POST", "/internal/worker/v1/jobs/" + bJob + "/results"},
		{"POST", "/internal/worker/v1/jobs/" + bJob + "/complete"},
		{"GET", "/internal/worker/v1/jobs/" + bJob + "/source"},
		{"GET", "/internal/worker/v1/jobs/" + bJob + "/target-file"},
		{"POST", "/internal/worker/v1/jobs/" + bJob + "/imports"},
		{"POST", "/internal/worker/v1/jobs/" + bJob + "/changes"},
		{"POST", "/internal/worker/v1/jobs/" + bJob + "/events"},
	} {
		code, out := call(reg.Token, p.method, p.path, map[string]any{})
		if l := leak(out); l != "" {
			t.Errorf("worker API %s %s leaks %s", p.method, p.path, l)
		}
		if code != 404 && code != 403 && code != 409 && code != 400 {
			t.Errorf("worker API %s %s on B's job: %d %s", p.method, p.path, code, truncateBody(out))
		}
	}
	// Fix verification (M8): a queued targeted rescan of B is neither leased
	// nor answerable by A's worker.
	{
		var bItem uuid.UUID
		if err := ownerPool.QueryRow(ctx, `SELECT id FROM remediation_items WHERE organization_id = $1 LIMIT 1`, orgB).Scan(&bItem); err != nil {
			t.Fatal("B needs a remediation item:", err)
		}
		bVer := uuid.Must(uuid.NewV7())
		if _, err := ownerPool.Exec(ctx, `INSERT INTO remediation_verifications (id, organization_id, item_id, repository_id, trigger, status, scanner_keys, files, after_ref)
			VALUES ($1, $2, $3, $4, 'manual', 'queued', '{semgrep}', '{a.py}', 'main')`, bVer, orgB, bItem, bRepo); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			code, out := call(reg.Token, "POST", "/internal/worker/v1/remediation-lease", map[string]any{})
			if l := leak(out); l != "" || (code == 200 && bytes.Contains(out, []byte(bVer.String()))) {
				t.Fatalf("worker of A leased B's fix verification: %d %s", code, truncateBody(out))
			}
		}
		code, out := call(reg.Token, "POST", "/internal/worker/v1/remediation-jobs/"+bVer.String()+"/result", map[string]any{"status": "completed"})
		if code != 404 || leak(out) != "" {
			t.Errorf("worker of A answered B's fix verification: %d %s", code, truncateBody(out))
		}
		var st string
		_ = ownerPool.QueryRow(ctx, `SELECT status FROM remediation_verifications WHERE id = $1`, bVer).Scan(&st)
		if st != "queued" {
			t.Errorf("B's fix verification changed to %q through A's worker", st)
		}
		if _, err := ownerPool.Exec(ctx, `DELETE FROM remediation_verifications WHERE id = $1`, bVer); err != nil {
			t.Fatal(err)
		}
	}
	var status string
	_ = ownerPool.QueryRow(ctx, `SELECT status FROM scan_jobs WHERE id = $1`, res.JobID).Scan(&status)
	if status != "queued" {
		t.Errorf("B's job changed to %q through A's worker", status)
	}
	// Leave B's queue as it was.
	if _, err := ownerPool.Exec(ctx, `DELETE FROM scan_jobs WHERE id = $1`, res.JobID); err != nil {
		t.Fatal(err)
	}
	// Suspended organizations' workers are refused.
	if _, err := tenancy.SetStatus(ctx, iso, orgA.ID, tenancy.StatusSuspended, "test"); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(reg.Token, "POST", "/internal/worker/v1/lease", map[string]any{}); code != 403 {
		t.Errorf("worker of a suspended organization leased: %d", code)
	}
	if _, err := tenancy.SetStatus(ctx, iso, orgA.ID, tenancy.StatusActive, ""); err != nil {
		t.Fatal(err)
	}
}

// isoRLS checks row-level security directly with the runtime role.
func isoRLS(t *testing.T, ctx context.Context, iso *pgxpool.Pool, orgA, orgB uuid.UUID) {
	gaps, err := tenancy.RLSGaps(ctx, iso)
	if err != nil || len(gaps) > 0 {
		t.Fatalf("tenant tables without enforced row-level security: %v %v", gaps, err)
	}
	// Every table without organization_id is either global reference
	// data or has its own policy; a new table must be classified here.
	global := []string{"eol_cycles", "eol_products", "goose_db_version", "intel_epss", "intel_feed_runs", "intel_feeds", "intel_kev",
		"intel_vulns", "package_health", "permissions", "installation_settings", "scanner_catalog", "scheduler_state"}
	rows, err := ownerPool.Query(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
		WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
		  AND NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'organization_id' AND NOT a.attisdropped)
		  AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid) ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	unscoped, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	for _, u := range unscoped {
		if !slices.Contains(global, u) {
			t.Errorf("table %s has no organization_id and no row-level security policy: classify it (docs/MULTI_TENANCY.md)", u)
		}
	}

	tables := tenantTables(t, ctx)
	tables = append(tables, "organizations", "profile_scanners", "custom_rule_versions", "pr_findings", "fix_pull_request_findings",
		"source_upload_parts", "application_version_repositories", "role_permissions", "installation_admins", "installation_audit_logs")
	nonEmpty := 0
	for _, tbl := range tables {
		var n int
		// No session variable: nothing.
		if err := iso.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{tbl}.Sanitize()).Scan(&n); err != nil {
			t.Fatalf("%s: %v", tbl, err)
		}
		if tbl == "roles" || tbl == "role_permissions" {
			// System roles (organization_id NULL) and their permissions
			// are global; organization roles must stay hidden.
			_ = iso.QueryRow(ctx, `SELECT count(*) FROM roles WHERE organization_id IS NOT NULL`).Scan(&n)
		}
		if n != 0 {
			t.Errorf("%s: %d rows visible without an organization", tbl, n)
		}
		var all int
		_ = ownerPool.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{tbl}.Sanitize()).Scan(&all)
		if all > 0 {
			nonEmpty++
		}
	}
	if nonEmpty < 60 {
		t.Errorf("only %d tenant tables hold rows; the RLS check needs data", nonEmpty)
	}
	actx := tenant.WithOrg(ctx, orgA)
	for _, tbl := range tenantTables(t, ctx) {
		var n int
		if err := iso.QueryRow(actx, `SELECT count(*) FROM `+pgx.Identifier{tbl}.Sanitize()+` WHERE organization_id = $1`, orgB).Scan(&n); err != nil {
			t.Fatalf("%s: %v", tbl, err)
		}
		if n != 0 {
			t.Errorf("%s: %d rows of B visible in A's scope", tbl, n)
		}
	}
	var n int
	_ = iso.QueryRow(actx, `SELECT count(*) FROM organizations`).Scan(&n)
	if n != 1 {
		t.Errorf("A's scope sees %d organizations", n)
	}
	_ = iso.QueryRow(actx, `SELECT count(*) FROM installation_admins`).Scan(&n)
	if n != 0 {
		t.Error("installation administrators visible in an organization's scope")
	}
	// Writes into B from A's scope.
	if _, err := iso.Exec(actx, `INSERT INTO teams (id, organization_id, name) VALUES ($1, $2, 'evil')`, uuid.Must(uuid.NewV7()), orgB); err == nil ||
		!strings.Contains(err.Error(), "row-level security") {
		t.Errorf("insert into B from A's scope: %v", err)
	}
	for _, stmt := range []string{
		`UPDATE teams SET name = name || 'x' WHERE organization_id = $1`,
		`DELETE FROM teams WHERE organization_id = $1`,
		`UPDATE findings SET status = 'resolved' WHERE organization_id = $1`,
		`DELETE FROM repositories WHERE organization_id = $1`,
		`UPDATE organizations SET name = 'pwned' WHERE id = $1`,
	} {
		tag, err := iso.Exec(actx, stmt, orgB)
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("%s from A's scope: %v rows=%d", stmt, err, tag.RowsAffected())
		}
	}
	// Moving an A row into B is rejected by the policy's WITH CHECK.
	var aTeam uuid.UUID
	if err := iso.QueryRow(actx, `INSERT INTO teams (id, organization_id, name) VALUES ($1, $2, $3) RETURNING id`,
		uuid.Must(uuid.NewV7()), orgA, "move-"+uuid.NewString()[:6]).Scan(&aTeam); err != nil {
		t.Fatal(err)
	}
	if _, err := iso.Exec(actx, `UPDATE teams SET organization_id = $2 WHERE id = $1`, aTeam, orgB); err == nil {
		t.Error("moving a row to another organization must fail")
	}
	// Audit log partitions are not directly accessible.
	part := "audit_logs_" + time.Now().UTC().Format("2006_01")
	if _, err := iso.Exec(actx, `SELECT count(*) FROM `+part); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("direct partition access: %v", err)
	}
	// System scope sees both organizations; the owner always does.
	_ = iso.QueryRow(tenant.WithSystem(ctx), `SELECT count(*) FROM organizations WHERE id = ANY($1)`, []uuid.UUID{orgA, orgB}).Scan(&n)
	if n != 2 {
		t.Errorf("system scope sees %d of 2 organizations", n)
	}
	// Same-organization references: the database rejects a row of A that
	// points at B's row, even for the owner (foreign keys ignore RLS).
	var bUser uuid.UUID
	_ = ownerPool.QueryRow(ctx, `SELECT id FROM users WHERE organization_id = $1 LIMIT 1`, orgB).Scan(&bUser)
	_, err = ownerPool.Exec(ctx, `INSERT INTO notifications (id, organization_id, event_key, channel, user_id, email, subject, body, link)
		VALUES ($1, $2, 'findings.new', 'in_app', $3, '', 's', 'b', '')`, uuid.Must(uuid.NewV7()), orgA, bUser)
	if !db.IsForeignKeyViolation(err) {
		t.Errorf("cross-organization reference must violate a foreign key: %v", err)
	}
	var bRole uuid.UUID
	if err := ownerPool.QueryRow(ctx, `INSERT INTO roles (id, organization_id, key, name) VALUES ($1, $2, $3, 'B custom') RETURNING id`,
		uuid.Must(uuid.NewV7()), orgB, "iso_"+strings.ReplaceAll(uuid.NewString()[:8], "-", "")).Scan(&bRole); err != nil {
		t.Fatal(err)
	}
	var aUser uuid.UUID
	_ = ownerPool.QueryRow(ctx, `SELECT id FROM users WHERE organization_id = $1 LIMIT 1`, orgA).Scan(&aUser)
	_, err = ownerPool.Exec(ctx, `INSERT INTO role_assignments (id, organization_id, user_id, role_id, scope_type, scope_id)
		VALUES ($1, $2, $3, $4, 'organization', $2)`, uuid.Must(uuid.NewV7()), orgA, aUser, bRole)
	if !db.IsForeignKeyViolation(err) {
		t.Errorf("assigning another organization's custom role must fail: %v", err)
	}
	_, _ = ownerPool.Exec(ctx, `DELETE FROM roles WHERE id = $1`, bRole)
}

// isoSwitch checks the organization switcher: a person can switch only
// to organizations they are an active member of.
func isoSwitch(t *testing.T, ctx context.Context, iso *pgxpool.Pool, as *auth.Service, orgA, orgB uuid.UUID, u isoUser) {
	_ = ctx
	_ = iso
	_ = as
	ms, err := tenancy.Memberships(ctx, iso, u.p.Subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.OrganizationID == orgB {
			t.Fatal("A's user must not be a member of B")
		}
	}
	if len(ms) != 1 || ms[0].OrganizationID != orgA {
		t.Fatalf("memberships: %+v", ms)
	}
}

// isoInstallation checks that organization administrators (including the
// organization role platform_admin) are not installation
// administrators.
func isoInstallation(t *testing.T, ctx context.Context, iso *pgxpool.Pool, api http.Handler, users []isoUser,
	do func(tok, method, path string, body []byte) (int, []byte)) {
	_ = ctx
	_ = iso
	_ = api
	for _, u := range users {
		for _, p := range []struct{ method, path string }{
			{"GET", "/api/v1/installation/organizations"}, {"POST", "/api/v1/installation/organizations"},
			{"GET", "/api/v1/installation/admins"}, {"GET", "/api/v1/installation/audit-logs"},
		} {
			var body []byte
			if p.method == "POST" {
				body = []byte(`{"name":"x","slug":"x-iso"}`)
			}
			if code, out := do(u.token, p.method, p.path, body); code != 403 && code != 404 {
				t.Errorf("%s %s as %s (organization role only): %d %s", p.method, p.path, u.role, code, truncateBody(out))
			}
		}
	}
}

// seedVictim adds B rows for resource types the earlier tests do not leave
// behind, so that every parameterised route addresses a real B resource.
func seedVictim(t *testing.T, ctx context.Context, org uuid.UUID) {
	t.Helper()
	one := func(sql string) uuid.UUID {
		var id uuid.UUID
		_ = ownerPool.QueryRow(ctx, sql, org).Scan(&id)
		return id
	}
	repo := one(`SELECT id FROM repositories WHERE organization_id = $1 ORDER BY created_at LIMIT 1`)
	finding := one(`SELECT id FROM findings WHERE organization_id = $1 ORDER BY first_seen_at LIMIT 1`)
	user := one(`SELECT id FROM users WHERE organization_id = $1 ORDER BY created_at LIMIT 1`)
	user2 := one(`SELECT id FROM users WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 1`)
	secret := one(`SELECT id FROM secrets WHERE organization_id = $1 LIMIT 1`)
	app := one(`SELECT id FROM applications WHERE organization_id = $1 LIMIT 1`)
	job := one(`SELECT id FROM scan_jobs WHERE organization_id = $1 LIMIT 1`)
	n := func() string { return uuid.NewString()[:8] }
	cluster := uuid.Must(uuid.NewV7())
	vexImport := uuid.Must(uuid.NewV7())
	connector := uuid.Must(uuid.NewV7())
	// The Connectors hub is behind its flag: on for B so its routes reach
	// the organization checks.
	for _, flag := range []string{"connectors", "remediation_workspace"} {
		if _, err := ownerPool.Exec(ctx, `INSERT INTO feature_flags (id, organization_id, name, enabled) VALUES ($1, $2, $3, true)
			ON CONFLICT (organization_id, name) DO UPDATE SET enabled = true`, uuid.Must(uuid.NewV7()), org, flag); err != nil {
			t.Fatal(err)
		}
	}
	// Remediation and gates (M8) rows of B.
	remItem, gatePolicy, gate, decision := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	stmts := []struct {
		table, sql string
		args       []any
	}{
		{"component_policies", `INSERT INTO component_policies (id, organization_id, name, condition_kind) VALUES ($1, $2, $3, 'outdated')`, []any{uuid.Must(uuid.NewV7()), org, "iso-b-" + n()}},
		{"human_reviews", `INSERT INTO human_reviews (id, organization_id, review_key, finding_id, repository_id, original_severity, source, due_at) VALUES ($1, $2, $3, $4, $5, 'high', 'manual', now() + interval '30 days')`, []any{uuid.Must(uuid.NewV7()), org, "ISO-B-" + n(), finding, repo}},
		{"custom_rules", `INSERT INTO custom_rules (id, organization_id, name, content) VALUES ($1, $2, $3, 'rules: []')`, []any{uuid.Must(uuid.NewV7()), org, "iso-b-" + n()}},
		{"pr_checks", `INSERT INTO pr_checks (id, organization_id, repository_id, scan_job_id, pull_request, gate_severity) VALUES ($1, $2, $3, $4, 7, 'high')`, []any{uuid.Must(uuid.NewV7()), org, repo, job}},
		{"runtime_clusters", `INSERT INTO runtime_clusters (id, organization_id, name, api_server, auth_type, secret_id) VALUES ($1, $2, $3, 'https://k8s.b.example', 'token', $4)`, []any{cluster, org, "iso-b-" + n(), secret}},
		{"runtime_workloads", `INSERT INTO runtime_workloads (id, organization_id, cluster_id, namespace, kind, name) VALUES ($1, $2, $3, 'b', 'Deployment', 'b-app')`, []any{uuid.Must(uuid.NewV7()), org, cluster}},
		{"ai_reports", `INSERT INTO ai_reports (id, organization_id, kind, scope_type, title, facts, created_by) VALUES ($1, $2, 'technical', 'organization', 'B report', '{}', $3)`, []any{uuid.Must(uuid.NewV7()), org, user}},
		{"security_policies", `INSERT INTO security_policies (id, organization_id, name, conditions, actions) VALUES ($1, $2, $3, '{}', '{}')`, []any{uuid.Must(uuid.NewV7()), org, "iso-b-" + n()}},
		{"saved_reports", `INSERT INTO saved_reports (id, organization_id, owner_id, name, definition) VALUES ($1, $2, $3, $4, '{}')`, []any{uuid.Must(uuid.NewV7()), org, user, "iso-b-" + n()}},
		{"ai_conversations", `INSERT INTO ai_conversations (id, organization_id, user_id, title) VALUES ($1, $2, $3, 'B conversation')`, []any{uuid.Must(uuid.NewV7()), org, user}},
		{"suppression_rules", `INSERT INTO suppression_rules (id, organization_id, name, scope_type, decision, justification, expires_at, requested_by, match_rule_id) VALUES ($1, $2, $3, 'organization', 'false_positive', 'organization B suppression for isolation', now() + interval '30 days', $4, 'b-rule')`, []any{uuid.Must(uuid.NewV7()), org, "iso-b-" + n(), user}},
		{"developer_identities", `INSERT INTO developer_identities (id, organization_id, author_name, user_id) VALUES ($1, $2, $3, $4)`, []any{uuid.Must(uuid.NewV7()), org, "b-dev-" + n(), user2}},
		{"runtime_app_mappings", `INSERT INTO runtime_app_mappings (id, organization_id, application_id, namespace) VALUES ($1, $2, $3, 'b')`, []any{uuid.Must(uuid.NewV7()), org, app}},
		{"scm_oauth_apps", `INSERT INTO scm_oauth_apps (id, organization_id, provider, name, client_id, secret_id) VALUES ($1, $2, 'github', $3, 'b-client', $4)`, []any{uuid.Must(uuid.NewV7()), org, "iso-b-" + n(), secret}},
		{"vex_imports", `INSERT INTO vex_imports (id, organization_id, format, document_sha256, imported_by, repository_id) VALUES ($1, $2, 'openvex', $3, $4, $5)`, []any{vexImport, org, strings.Repeat("b", 64), user, repo}},
		{"vex_suggestions", `INSERT INTO vex_suggestions (id, organization_id, import_id, finding_id, repository_id, vulnerability, vex_status, requested_by) VALUES ($1, $2, $3, $4, $5, 'CVE-2099-0001', 'not_affected', $6)`, []any{uuid.Must(uuid.NewV7()), org, vexImport, finding, repo, user}},
		{"connectors", `INSERT INTO connectors (id, organization_id, kind, name, config, status, last_check_at, last_error_code) VALUES ($1, $2, 'vault', $3, '{"address":"https://vault.b.example"}', 'failing', now(), 'PTH-CONN-1007')`, []any{connector, org, "iso-b-" + n()}},
		{"connector_health_checks", `INSERT INTO connector_health_checks (id, organization_id, connector_id, status, trigger, error_code, message) VALUES ($1, $2, $3, 'failing', 'user', 'PTH-CONN-1007', 'B check')`, []any{uuid.Must(uuid.NewV7()), org, connector}},
		{"application_versions", `INSERT INTO application_versions (id, organization_id, application_id, version) VALUES ($1, $2, $3, $4)`, []any{uuid.Must(uuid.NewV7()), org, app, "b-" + n()}},
		{"remediation_items", `INSERT INTO remediation_items (id, organization_id, repository_id, title, kind, owner_id) VALUES ($1, $2, $3, 'B item', 'code_fix', $4)`, []any{remItem, org, repo, user}},
		{"remediation_item_findings", `INSERT INTO remediation_item_findings (organization_id, item_id, finding_id) VALUES ($1, $2, $3)`, []any{org, remItem, finding}},
		{"remediation_verifications", `INSERT INTO remediation_verifications (id, organization_id, item_id, repository_id, trigger, status, failure_reason, finished_at) VALUES ($1, $2, $3, $4, 'manual', 'failed', 'B verification', now())`, []any{uuid.Must(uuid.NewV7()), org, remItem, repo}},
		{"remediation_views", `INSERT INTO remediation_views (id, organization_id, owner_id, name, filters, shared) VALUES ($1, $2, $3, $4, '{"status":"open"}', true)`, []any{uuid.Must(uuid.NewV7()), org, user, "iso-b-" + n()}},
		{"security_gates", `WITH p AS (INSERT INTO security_policies (id, organization_id, name, conditions, actions) VALUES ($5, $2, $6, '{"min_severity":"critical"}', '{"block":true}') RETURNING id)
			INSERT INTO security_gates (id, organization_id, name, stage, policy_id, mode, repository_id) SELECT $1, $2, $3, 'deploy', p.id, 'block', $4 FROM p`, []any{gate, org, "iso-b-gate-" + n(), repo, gatePolicy, "iso-b-gate-policy-" + n()}},
		{"gate_decisions", `INSERT INTO gate_decisions (id, organization_id, stage, repository_id, outcome, gate_ids, policy_ids, reasons) VALUES ($1, $2, 'deploy', $3, 'block', ARRAY[$4::uuid], ARRAY[$5::uuid], '[{"code":"policy_matched","message":"B"}]')`, []any{decision, org, repo, gate, gatePolicy}},
		{"gate_exceptions", `INSERT INTO gate_exceptions (id, organization_id, gate_id, decision_id, kind, repository_id, reason, requested_by, expires_at) VALUES ($1, $2, $3, $4, 'exception', $5, 'B exception', $6, now() + interval '30 days')`, []any{uuid.Must(uuid.NewV7()), org, gate, decision, repo, user}},
	}
	for _, st := range stmts {
		var exists bool
		_ = ownerPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+pgx.Identifier{st.table}.Sanitize()+` WHERE organization_id = $1)`, org).Scan(&exists)
		if exists {
			continue
		}
		if _, err := ownerPool.Exec(ctx, st.sql, st.args...); err != nil {
			t.Logf("seed B %s: %v", st.table, err)
		}
	}
}

// setRLS switches row-level security on every table with a tenant policy
// (as the owner, bypassing pathos_set_multi_tenant's organization check).
func setRLS(t *testing.T, ctx context.Context, on bool) {
	t.Helper()
	verb := "DISABLE"
	if on {
		verb = "ENABLE"
	}
	if _, err := ownerPool.Exec(ctx, `DO $$ DECLARE r record; BEGIN
		FOR r IN SELECT DISTINCT c.relname FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
		         JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public' LOOP
			EXECUTE format('ALTER TABLE %I `+verb+` ROW LEVEL SECURITY', r.relname);
		END LOOP; END $$`); err != nil {
		t.Fatal(err)
	}
}

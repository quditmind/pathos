//go:build integration

package integration

// Organization lifecycle, installation administrators and login mapping
// with multi-tenancy enabled (docs/MULTI_TENANCY.md).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/platform/config"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
	"pathos/internal/platform/tenant"
	"pathos/internal/scans"
	"pathos/internal/secrets"
	"pathos/internal/tenancy"
)

func TestTenantLifecycle(t *testing.T) {
	ctx := context.Background()
	iso, err := db.Connect(ctx, appURL, log)
	if err != nil {
		t.Fatal(err)
	}
	defer iso.Close()
	keys, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	store := &secrets.Store{Keys: keys}

	adminSub := "inst-" + uuid.NewString()
	caller := &tenancy.Caller{Subject: adminSub, Email: "inst@platform.test"}
	var deleted []string
	h := &tenancy.Handlers{DB: iso, Log: log, DefaultOrgID: orgID,
		Caller: func(context.Context) *tenancy.Caller { return caller },
		Seed:   func(ctx context.Context, id uuid.UUID) error { return scans.EnsureDefaultProfile(ctx, iso, id) },
		DeleteSources: func(_ context.Context, keys []string) error {
			deleted = append(deleted, keys...)
			return nil
		}}
	mux := http.NewServeMux()
	h.Register(mux)
	call := func(method, path string, body any) (int, map[string]any) {
		var rd *bytes.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rd)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	// Not an installation administrator yet.
	if code, _ := call("GET", "/api/v1/installation/organizations", nil); code != 403 {
		t.Fatalf("non-administrator listed organizations: %d", code)
	}
	if _, err := tenancy.GrantInstallationAdmin(ctx, iso, adminSub, caller.Email, "test"); err != nil {
		t.Fatal(err)
	}

	slug := "life-" + uuid.NewString()[:8]
	code, out := call("POST", "/api/v1/installation/organizations", map[string]any{"name": "Lifecycle Inc", "slug": slug, "admin_email": "Owner@Life.test"})
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	newOrg := uuid.MustParse(out["organization"].(map[string]any)["id"].(string))
	if code, _ := call("POST", "/api/v1/installation/organizations", map[string]any{"name": "Dup", "slug": slug}); code != 409 {
		t.Errorf("duplicate slug: %d", code)
	}
	if code, _ := call("POST", "/api/v1/installation/organizations", map[string]any{"name": "Bad", "slug": "Bad Slug"}); code != 400 {
		t.Errorf("invalid slug: %d", code)
	}
	octx := tenant.WithOrg(ctx, newOrg)
	var regions, profiles, admins int
	_ = iso.QueryRow(octx, `SELECT count(*) FROM regions`).Scan(&regions)
	_ = iso.QueryRow(octx, `SELECT count(*) FROM scan_profiles`).Scan(&profiles)
	_ = iso.QueryRow(octx, `SELECT count(*) FROM users u JOIN role_assignments ra ON ra.user_id = u.id JOIN roles r ON r.id = ra.role_id
		WHERE u.email = 'owner@life.test' AND u.status = 'invited' AND r.key = $1 AND ra.scope_type = 'organization'`, authz.RoleSuperAdmin).Scan(&admins)
	if regions != 3 || profiles == 0 || admins != 1 {
		t.Fatalf("seeded organization: regions=%d profiles=%d invited admins=%d", regions, profiles, admins)
	}

	// Login mapping: the invited administrator signs in with a verified
	// email; a person whose token names the organization in the group
	// claim gets a membership without roles; a person with neither is
	// refused.
	pub, _ := url.Parse("https://pathos.example")
	as := &auth.Service{Cfg: &config.Config{PublicURL: pub, OrgClaim: "groups", OrgGroupPrefix: "/pathos/", InstallationAdminEmail: "inst@platform.test"},
		DB: iso, Log: log, OrgID: orgID, MultiTenant: true}
	// The installation administrator email joins the default organization
	// (without roles) at its first verified sign-in.
	if _, active, err := as.ProvisionMemberships(ctx, identity.LoginIdentity{Subject: adminSub, Email: "Inst@Platform.test", EmailVerified: true}, nil); err != nil || active != orgID {
		t.Fatalf("installation administrator sign-in: active=%v err=%v", active, err)
	}
	ownerSub := "owner-" + uuid.NewString()
	res, active, err := as.ProvisionMemberships(ctx, identity.LoginIdentity{Subject: ownerSub, Email: "owner@life.test", EmailVerified: true, Name: "Owner"}, nil)
	if err != nil || active != newOrg || !res.Linked {
		t.Fatalf("invited administrator login: active=%v linked=%v err=%v", active, res.Linked, err)
	}
	memberSub := "member-" + uuid.NewString()
	_, active, err = as.ProvisionMemberships(ctx, identity.LoginIdentity{Subject: memberSub, Email: "m@life.test", EmailVerified: true},
		[]any{"/pathos/" + slug, "/pathos/does-not-exist", "/other/" + slug})
	if err != nil || active != newOrg {
		t.Fatalf("claim membership: active=%v err=%v", active, err)
	}
	var grants int
	_ = iso.QueryRow(octx, `SELECT count(*) FROM role_assignments ra JOIN users u ON u.id = ra.user_id WHERE u.keycloak_subject = $1`, memberSub).Scan(&grants)
	if grants != 0 {
		t.Errorf("claim membership must not grant roles, got %d", grants)
	}
	if _, _, err := as.ProvisionMemberships(ctx, identity.LoginIdentity{Subject: "nobody-" + uuid.NewString(), Email: "x@life.test", EmailVerified: true}, nil); err == nil {
		t.Error("a login without membership, invitation or claim must be refused")
	}
	// Unverified email does not link an invitation.
	_, _ = call("POST", "/api/v1/installation/organizations", map[string]any{"name": "Other", "slug": slug + "-b", "admin_email": "lurker@life.test"})
	if _, _, err := as.ProvisionMemberships(ctx, identity.LoginIdentity{Subject: "lurker-" + uuid.NewString(), Email: "lurker@life.test", EmailVerified: false}, nil); err == nil {
		t.Error("an unverified email must not link an invitation")
	}
	// The same person in two organizations: memberships list both.
	_, _, err = as.ProvisionMemberships(ctx, identity.LoginIdentity{Subject: memberSub, Email: "m@life.test", EmailVerified: true},
		[]any{"/pathos/" + slug, "/pathos/" + slug + "-b"})
	if err != nil {
		t.Fatal(err)
	}
	ms, _ := tenancy.MyMemberships(ctx, iso, memberSub, newOrg)
	if len(ms.Items) != 2 || !ms.MultiTenant || ms.InstallationAdmin {
		t.Fatalf("memberships: %+v", ms)
	}

	// Data and stored objects of the organization.
	if _, err := iso.Exec(octx, `INSERT INTO teams (id, organization_id, name) VALUES ($1, $2, 'life team')`, uuid.Must(uuid.NewV7()), newOrg); err != nil {
		t.Fatal(err)
	}
	snapshotKey := "snapshots/" + newOrg.String() + "/x.tar.gz"
	err = db.InTx(octx, iso, func(tx pgx.Tx) error {
		sec, err := store.Create(octx, tx, newOrg, secrets.KindSCM, "s", []byte("t"), nil)
		if err != nil {
			return err
		}
		conn, repo := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(octx, `INSERT INTO scm_connections (id, organization_id, name, provider, base_url, auth_type, secret_id, webhook_secret_id)
			VALUES ($1, $2, 'c', 'github', 'https://api.github.com', 'pat', $3, $3)`, conn, newOrg, sec); err != nil {
			return err
		}
		if _, err := tx.Exec(octx, `INSERT INTO repositories (id, organization_id, scm_connection_id, external_id, full_name, name, url, clone_url, default_branch)
			VALUES ($1, $2, $3, 'r', 'life/r', 'r', 'https://github.com/life/r', 'https://github.com/life/r.git', 'main')`, repo, newOrg, conn); err != nil {
			return err
		}
		_, err = tx.Exec(octx, `INSERT INTO source_snapshots (id, organization_id, repository_id, object_key, archive_sha256, archive_size, snapshot_sha256, snapshot_size, uncompressed_bytes, file_count, malware_scan)
			VALUES ($1, $2, $3, $4, $5, 1, $5, 1, 1, 1, 'not_configured')`, uuid.Must(uuid.NewV7()), newOrg, repo, snapshotKey, strings.Repeat("a", 64))
		return err
	})
	if err != nil {
		t.Logf("source snapshot fixture: %v (object deletion is then checked without it)", err)
		snapshotKey = ""
	}

	// The default organization can be neither suspended nor deleted.
	if code, _ := call("POST", "/api/v1/installation/organizations/"+orgID.String()+"/suspend", map[string]any{}); code != 409 {
		t.Errorf("default organization suspended: %d", code)
	}
	// Delete needs suspension first, then the slug.
	if code, _ := call("DELETE", "/api/v1/installation/organizations/"+newOrg.String(), map[string]any{"confirm_slug": slug}); code != 409 {
		t.Errorf("delete of an active organization: %d", code)
	}
	if code, out := call("POST", "/api/v1/installation/organizations/"+newOrg.String()+"/suspend", map[string]any{"reason": "contract ended"}); code != 200 || out["status"] != "suspended" {
		t.Fatalf("suspend: %d %v", code, out)
	}
	// A suspended organization's members cannot sign in.
	if _, active, err := as.ProvisionMemberships(ctx, identity.LoginIdentity{Subject: ownerSub, Email: "owner@life.test", EmailVerified: true}, nil); err == nil {
		t.Errorf("login into a suspended organization: %v", active)
	}
	// Nor use API tokens.
	ownerUser := uuid.Nil
	_ = ownerPool.QueryRow(ctx, `SELECT id FROM users WHERE organization_id = $1 AND keycloak_subject = $2`, newOrg, ownerSub).Scan(&ownerUser)
	tok := mintToken(t, octx, iso, newOrg, ownerUser, "api:read")
	protected := http.NewServeMux()
	protected.HandleFunc("GET /api/v1/ping", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	api := as.Authenticate(as.RequireAuth(protected))
	req := httptest.NewRequest("GET", "/api/v1/ping", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "organization_suspended") {
		t.Errorf("API token of a suspended organization: %d %s", rec.Code, rec.Body.String())
	}
	if code, _ := call("DELETE", "/api/v1/installation/organizations/"+newOrg.String(), map[string]any{"confirm_slug": "wrong"}); code != 400 {
		t.Errorf("delete with a wrong slug: %d", code)
	}
	code, out = call("DELETE", "/api/v1/installation/organizations/"+newOrg.String(), map[string]any{"confirm_slug": slug})
	if code != 200 {
		t.Fatalf("delete: %d %v", code, out)
	}
	if snapshotKey != "" && !slices.Contains(deleted, snapshotKey) {
		t.Errorf("stored objects of the organization were not deleted: %v", deleted)
	}
	for _, tbl := range tenantTables(t, ctx) {
		if tbl == "installation_audit_logs" {
			continue // the installation's own record of the organization's lifecycle
		}
		var n int
		if err := ownerPool.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{tbl}.Sanitize()+` WHERE organization_id = $1`, newOrg).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s still has %d rows of the deleted organization", tbl, n)
		}
	}
	var n int
	_ = ownerPool.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE id = $1`, newOrg).Scan(&n)
	if n != 0 {
		t.Error("organization row not deleted")
	}
	// Every step is in the installation audit log.
	entries, _ := tenancy.ListInstallationAudit(ctx, iso, 50)
	var actions []string
	for _, e := range entries {
		if e.OrganizationID != nil && *e.OrganizationID == newOrg {
			actions = append(actions, e.Action)
		}
	}
	for _, want := range []string{"organization.create", "organization.suspend", "organization.delete"} {
		if !slices.Contains(actions, want) {
			t.Errorf("installation audit log lacks %s: %v", want, actions)
		}
	}
	// The other organizations are untouched.
	_ = ownerPool.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE id = $1`, orgID).Scan(&n)
	if n != 1 {
		t.Fatal("deleting one organization touched another")
	}
}

// TestTenantScopeNeverCarriesOver: with a single pooled connection, every
// checkout gets the scope of its own context. A connection used for one
// organization (or for system work, or in a rolled-back transaction) never
// keeps that scope for the next query.
func TestTenantScopeNeverCarriesOver(t *testing.T) {
	ctx := context.Background()
	u, err := url.Parse(appURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("pool_max_conns", "1")
	u.RawQuery = q.Encode()
	one, err := db.Connect(ctx, u.String(), log)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	var pid0 int
	_ = one.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid0)
	count := func(c context.Context) int {
		var n, pid int
		if err := one.QueryRow(c, `SELECT count(*), pg_backend_pid() FROM organizations`).Scan(&n, &pid); err != nil {
			t.Fatal(err)
		}
		if pid != pid0 {
			t.Fatalf("expected the same pooled connection (pid %d), got %d", pid0, pid)
		}
		return n
	}
	org := tenant.WithOrg(ctx, orgID)
	steps := []struct {
		name string
		ctx  context.Context
		want func(int) bool
	}{
		{"organization", org, func(n int) bool { return n == 1 }},
		{"unscoped after organization", ctx, func(n int) bool { return n == 0 }},
		{"system", tenant.WithSystem(ctx), func(n int) bool { return n >= 1 }},
		{"unscoped after system", ctx, func(n int) bool { return n == 0 }},
	}
	for _, s := range steps {
		if n := count(s.ctx); !s.want(n) {
			t.Fatalf("%s: %d organizations visible", s.name, n)
		}
	}
	// A transaction in an organization's scope that is rolled back, and
	// one that changes the variables itself, leave nothing behind.
	tx, err := one.Begin(org)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(org, `SELECT set_config('app.rls_bypass', 'on', false), set_config('app.organization_id', '', false)`); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback(org)
	if n := count(ctx); n != 0 {
		t.Fatalf("unscoped after a rolled-back transaction: %d organizations visible", n)
	}
	tx, _ = one.Begin(org)
	_, _ = tx.Exec(org, `SELECT set_config('app.rls_bypass', 'on', false), set_config('app.organization_id', '', false)`)
	_ = tx.Commit(org)
	if n := count(ctx); n != 0 {
		t.Fatalf("unscoped after a transaction that widened its own scope: %d organizations visible", n)
	}
}

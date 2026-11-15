//go:build integration

// Package integration runs tests against a real PostgreSQL server.
//
// Run with scripts/test-integration.sh, which starts a throwaway PostgreSQL
// container and sets PATHOS_TEST_DATABASE_URL (a superuser URL). Each test
// run creates and drops its own database.
package integration

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
	"pathos/internal/scanners"
	"pathos/internal/scans"
	"pathos/internal/secrets"
	"pathos/internal/vuln"
)

var (
	// testKey is the one master key all tests use, so global operations
	// (key rotation) see consistent ciphertexts.
	testKey   = func() []byte { k := make([]byte, 32); _, _ = rand.Read(k); return k }()
	ownerPool *pgxpool.Pool // migration owner
	appPool   *pgxpool.Pool // least-privilege runtime role
	orgID     uuid.UUID
	log       = slog.New(slog.NewTextHandler(io.Discard, nil))
)

func TestMain(m *testing.M) {
	base := os.Getenv("PATHOS_TEST_DATABASE_URL")
	if base == "" {
		fmt.Println("PATHOS_TEST_DATABASE_URL not set; skipping integration tests")
		os.Exit(0)
	}
	ctx := context.Background()
	dbName := "pathos_it_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

	admin, err := pgx.Connect(ctx, base)
	must(err)
	for _, stmt := range []string{
		`DO $$ BEGIN
		   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pathos_owner') THEN CREATE ROLE pathos_owner LOGIN PASSWORD 'owner'; END IF;
		   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pathos_app') THEN CREATE ROLE pathos_app LOGIN PASSWORD 'app'; END IF;
		 END $$`,
		`CREATE DATABASE ` + dbName + ` OWNER pathos_owner`,
		`GRANT CONNECT ON DATABASE ` + dbName + ` TO pathos_app`,
	} {
		_, err = admin.Exec(ctx, stmt)
		must(err)
	}
	// Match production: only the owner may create objects in public.
	adminDB := withDB(base, dbName, "", "")
	c2, err := pgx.Connect(ctx, adminDB)
	must(err)
	_, err = c2.Exec(ctx, `REVOKE CREATE ON SCHEMA public FROM PUBLIC; ALTER SCHEMA public OWNER TO pathos_owner`)
	must(err)
	c2.Close(ctx)

	ownerPool, err = db.Connect(ctx, withDB(base, dbName, "pathos_owner", "owner"), log)
	must(err)
	must(db.Migrate(ctx, ownerPool, log))
	must(org.SyncCatalog(ctx, ownerPool))
	must(scanners.Sync(ctx, ownerPool))
	orgID, _, err = org.EnsureOrganization(ctx, ownerPool, "Acme", "acme")
	must(err)
	must(scans.EnsureDefaultProfile(ctx, ownerPool, orgID))
	must(vuln.EnsureDefaults(ctx, ownerPool, orgID))
	must(notify.EnsureDefaults(ctx, ownerPool, nil, orgID))
	_, err = ownerPool.Exec(ctx, `SELECT pathos_apply_app_grants()`)
	must(err)
	appPool, err = db.Connect(ctx, withDB(base, dbName, "pathos_app", "app"), log)
	must(err)

	code := m.Run()

	appPool.Close()
	ownerPool.Close()
	_, _ = admin.Exec(ctx, `DROP DATABASE `+dbName+` WITH (FORCE)`)
	admin.Close(ctx)
	os.Exit(code)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func withDB(base, name, user, pass string) string {
	u, err := url.Parse(base)
	must(err)
	u.Path = "/" + name
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	return u.String()
}

func TestMigrationsAndSeedingAreIdempotent(t *testing.T) {
	ctx := context.Background()
	if err := db.Migrate(ctx, ownerPool, log); err != nil {
		t.Fatal(err)
	}
	if err := org.SyncCatalog(ctx, ownerPool); err != nil {
		t.Fatal(err)
	}
	id, created, err := org.EnsureOrganization(ctx, ownerPool, "Acme", "acme")
	if err != nil || created || id != orgID {
		t.Fatalf("second EnsureOrganization should return existing org: id=%v created=%v err=%v", id, created, err)
	}
	var roles, perms, regions int
	_ = ownerPool.QueryRow(ctx, `SELECT count(*) FROM roles WHERE is_system`).Scan(&roles)
	_ = ownerPool.QueryRow(ctx, `SELECT count(*) FROM permissions`).Scan(&perms)
	_ = ownerPool.QueryRow(ctx, `SELECT count(*) FROM regions WHERE organization_id = $1`, orgID).Scan(&regions)
	if roles != len(authz.SystemRoles) || perms != len(authz.Permissions) || regions != 3 {
		t.Fatalf("unexpected seed counts roles=%d perms=%d regions=%d", roles, perms, regions)
	}
	cur, latest, err := db.MigrationStatus(ctx, appPool)
	if err != nil || cur != latest {
		t.Fatalf("app role should read migration status: cur=%d latest=%d err=%v", cur, latest, err)
	}
}

func TestAppRoleLeastPrivilege(t *testing.T) {
	ctx := context.Background()
	if err := audit.Write(ctx, appPool, audit.Entry{OrganizationID: orgID, Action: "test.write"}); err != nil {
		t.Fatalf("app role must be able to insert audit entries: %v", err)
	}
	partition := "audit_logs_" + time.Now().UTC().Format("2006_01")
	denied := map[string]string{
		"update audit log":          `UPDATE audit_logs SET action = 'tampered'`,
		"delete audit log":          `DELETE FROM audit_logs`,
		"truncate audit log":        `TRUNCATE audit_logs`,
		"update audit partition":    `UPDATE ` + partition + ` SET action = 'tampered'`,
		"delete default partition":  `DELETE FROM audit_logs_default`,
		"modify permission catalog": `INSERT INTO permissions (key, category, description) VALUES ('x.y', 'x', 'x')`,
		"create table":              `CREATE TABLE evil (id int)`,
		"write migration history":   `DELETE FROM goose_db_version`,
	}
	for name, stmt := range denied {
		t.Run(name, func(t *testing.T) {
			_, err := appPool.Exec(ctx, stmt)
			if err == nil || !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("expected permission denied, got %v", err)
			}
		})
	}
	if err := org.EnsureAuditPartitions(ctx, appPool); err != nil {
		t.Fatalf("app role must be able to run partition maintenance: %v", err)
	}
}

func provision(t *testing.T, li identity.LoginIdentity, bootstrap string) (identity.ProvisionResult, error) {
	t.Helper()
	var res identity.ProvisionResult
	err := db.InTx(context.Background(), appPool, func(tx pgx.Tx) error {
		var err error
		res, err = identity.ProvisionOnLogin(context.Background(), tx, orgID, li, bootstrap)
		return err
	})
	return res, err
}

func TestJITProvisioning(t *testing.T) {
	ctx := context.Background()
	admin := "root-" + uuid.NewString()[:6] + "@acme.test"

	// Unverified bootstrap email must not receive super_admin.
	r, err := provision(t, identity.LoginIdentity{Subject: uuid.NewString(), Email: admin, EmailVerified: false}, admin)
	if err != nil || r.GrantedSuperAdmin {
		t.Fatalf("unverified bootstrap login must not get super_admin: %+v %v", r, err)
	}
	_, _ = ownerPool.Exec(ctx, `DELETE FROM users WHERE email = $1`, admin)

	sub := uuid.NewString()
	r, err = provision(t, identity.LoginIdentity{Subject: sub, Email: strings.ToUpper(admin), EmailVerified: true, Name: "Root"}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Created || !r.GrantedSuperAdmin || r.User.Email != admin || r.User.Status != identity.StatusActive {
		t.Fatalf("bootstrap login should create active super admin: %+v", r)
	}
	r2, err := provision(t, identity.LoginIdentity{Subject: sub, Email: admin, EmailVerified: true}, admin)
	if err != nil || r2.Created || r2.GrantedSuperAdmin || r2.User.ID != r.User.ID {
		t.Fatalf("repeat login should reuse user without re-granting: %+v %v", r2, err)
	}
	if r2.User.DisplayName != "Root" {
		t.Errorf("missing name claim must not wipe the display name, got %q", r2.User.DisplayName)
	}

	// A second "bootstrap" identity cannot claim super_admin once one exists.
	other := identity.LoginIdentity{Subject: uuid.NewString(), Email: "x-" + admin, EmailVerified: true}
	if r3, err := provision(t, other, other.Email); err != nil || r3.GrantedSuperAdmin {
		t.Fatalf("super_admin must only be granted while none exists: %+v %v", r3, err)
	}

	// Invited user is linked on first verified login.
	invited, err := identity.CreateUser(ctx, appPool, identity.User{OrganizationID: orgID, Email: "invitee-" + admin})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision(t, identity.LoginIdentity{Subject: uuid.NewString(), Email: invited.Email, EmailVerified: false}, ""); err == nil {
		t.Fatal("unverified email must not link to an invited account")
	}
	r4, err := provision(t, identity.LoginIdentity{Subject: uuid.NewString(), Email: invited.Email, EmailVerified: true}, "")
	if err != nil || !r4.Linked || r4.User.ID != invited.ID || r4.User.Status != identity.StatusActive {
		t.Fatalf("verified login should link invited user: %+v %v", r4, err)
	}

	// Deactivated users cannot log in.
	if _, err := identity.SetStatus(ctx, appPool, orgID, invited.ID, identity.StatusDeactivated); err != nil {
		t.Fatal(err)
	}
	if _, err := provision(t, identity.LoginIdentity{Subject: *r4.User.KeycloakSubject, Email: invited.Email, EmailVerified: true}, ""); !errors.Is(err, identity.ErrDeactivated) {
		t.Fatalf("want ErrDeactivated, got %v", err)
	}

	n, err := identity.CountActiveOrgSuperAdmins(ctx, appPool, orgID, nil, nil)
	if err != nil || n != 1 {
		t.Fatalf("want exactly 1 super admin, got %d (%v)", n, err)
	}
	if n, _ := identity.CountActiveOrgSuperAdmins(ctx, appPool, orgID, &r.User.ID, nil); n != 0 {
		t.Fatalf("excluding the only super admin should count 0, got %d", n)
	}
}

func TestBusinessUnitHierarchyScoping(t *testing.T) {
	ctx := context.Background()
	mkBU := func(name string, parent *uuid.UUID) uuid.UUID {
		id := uuid.Must(uuid.NewV7())
		if _, err := appPool.Exec(ctx, `INSERT INTO business_units (id, organization_id, parent_id, name) VALUES ($1, $2, $3, $4)`,
			id, orgID, parent, name+uuid.NewString()[:4]); err != nil {
			t.Fatal(err)
		}
		return id
	}
	finance := mkBU("Finance", nil)
	payments := mkBU("Payments", &finance)
	cards := mkBU("Cards", &payments)
	hr := mkBU("HR", nil)

	u, err := identity.CreateUser(ctx, appPool, identity.User{OrganizationID: orgID, Email: "scoped-" + uuid.NewString()[:6] + "@acme.test", Status: identity.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	role, err := identity.GetRoleByKey(ctx, appPool, orgID, "security_analyst")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.CreateAssignment(ctx, appPool, orgID, u.ID, role.ID, authz.Scope{Type: authz.ScopeBusinessUnit, ID: finance}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.CreateAssignment(ctx, appPool, orgID, u.ID, role.ID, authz.Scope{Type: authz.ScopeBusinessUnit, ID: finance}, nil); !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("duplicate assignment should conflict, got %v", err)
	}
	grants, err := identity.LoadGrants(ctx, appPool, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	p := &authz.Principal{UserID: u.ID, OrganizationID: orgID, Grants: grants}
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}

	for name, tc := range map[string]struct {
		bu   uuid.UUID
		want bool
	}{"assigned BU": {finance, true}, "child BU": {payments, true}, "grandchild BU": {cards, true}, "sibling BU": {hr, false}} {
		ok, err := az.Can(ctx, p, authz.PermFindingsTriage, authz.Scope{Type: authz.ScopeBusinessUnit, ID: tc.bu})
		if err != nil || ok != tc.want {
			t.Errorf("%s: got %v (%v), want %v", name, ok, err, tc.want)
		}
	}
	if ok, _ := az.Can(ctx, p, authz.PermUsersRead, authz.Scope{Type: authz.ScopeOrganization, ID: orgID}); ok {
		t.Error("BU-scoped analyst must not read users")
	}
	if _, err := az.Can(ctx, p, authz.PermFindingsTriage, authz.Scope{Type: authz.ScopeBusinessUnit, ID: uuid.New()}); !errors.Is(err, org.ErrScopeNotFound) {
		t.Errorf("unknown BU should return ErrScopeNotFound, got %v", err)
	}
}

func TestSecretsStoreAndRotation(t *testing.T) {
	ctx := context.Background()
	k2 := make([]byte, 32)
	_, _ = rand.Read(k2)
	kr1, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	s1 := &secrets.Store{Keys: kr1}

	id, err := s1.Create(ctx, appPool, orgID, secrets.KindSCM, "github", []byte("ghp_example"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	_ = appPool.QueryRow(ctx, `SELECT ciphertext FROM secrets WHERE id = $1`, id).Scan(&raw)
	if strings.Contains(string(raw), "ghp_example") {
		t.Fatal("plaintext stored in database")
	}
	if _, err := s1.Reveal(ctx, appPool, orgID, id, secrets.KindAI); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("revealing with the wrong kind must fail, got %v", err)
	}
	// Rotation runs in a transaction that is rolled back, so other tests
	// keep using the shared key.
	tx, err := ownerPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Moving the ciphertext to a different kind is detected by AAD.
	if _, err := tx.Exec(ctx, `UPDATE secrets SET kind = 'ai' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Reveal(ctx, tx, orgID, id, secrets.KindAI); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("kind swap must fail decryption, got %v", err)
	}
	_, _ = tx.Exec(ctx, `UPDATE secrets SET kind = 'scm' WHERE id = $1`, id)
	kr2, _ := crypto.NewKeyring(map[int][]byte{1: testKey, 2: k2})
	n, err := (&secrets.Store{Keys: kr2}).RewrapAll(ctx, tx)
	if err != nil || n < 1 {
		t.Fatalf("rewrap failed: n=%d err=%v", n, err)
	}
	only2, _ := crypto.NewKeyring(map[int][]byte{2: k2})
	pt, err := (&secrets.Store{Keys: only2}).Reveal(ctx, tx, orgID, id, secrets.KindSCM)
	if err != nil || string(pt) != "ghp_example" {
		t.Fatalf("secret should open with the new key only after rotation: %q %v", pt, err)
	}
}

func TestAuditListPagination(t *testing.T) {
	ctx := context.Background()
	action := "test.page." + uuid.NewString()[:6]
	for i := 0; i < 5; i++ {
		if err := audit.Write(ctx, appPool, audit.Entry{OrganizationID: orgID, Action: action, IP: "10.0.0.1", Metadata: map[string]any{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
	page1, err := audit.List(ctx, appPool, audit.ListParams{OrganizationID: orgID, Action: action, Limit: 3})
	if err != nil || len(page1) != 3 {
		t.Fatalf("page1: %d %v", len(page1), err)
	}
	last := page1[len(page1)-1]
	page2, err := audit.List(ctx, appPool, audit.ListParams{OrganizationID: orgID, Action: action, Limit: 3, Before: &last.CreatedAt, BeforeID: &last.ID})
	if err != nil || len(page2) != 2 {
		t.Fatalf("page2: %d %v", len(page2), err)
	}
	seen := map[uuid.UUID]bool{}
	for _, r := range append(page1, page2...) {
		if seen[r.ID] {
			t.Fatal("duplicate row across pages")
		}
		seen[r.ID] = true
	}
	if page1[0].IP == nil || *page1[0].IP != "10.0.0.1" {
		t.Errorf("ip not stored: %v", page1[0].IP)
	}
}

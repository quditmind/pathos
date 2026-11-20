//go:build integration

package integration

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"pathos/internal/platform/db"
	"pathos/migrations"
)

// scratchDB creates an empty database owned by pathos_owner (dropped at
// the end of the test) and returns an owner pool.
func scratchDB(t *testing.T, prefix string) *pgxpool.Pool {
	t.Helper()
	ctx := t.Context()
	base := os.Getenv("PATHOS_TEST_DATABASE_URL")
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	name := prefix + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name+` OWNER pathos_owner`); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, withDB(base, name, "pathos_owner", "owner"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), `DROP DATABASE `+name+` WITH (FORCE)`)
		admin.Close(context.Background())
	})
	return pool
}

// migrations223 is the migration set of PATHOS 2.2.3: 00001–00042 (the same
// files in both lines) plus the released 2.2.x 00043 and 00044, verbatim
// from release/2.2 (testdata/migrations-2.2.3).
func migrations223(t *testing.T) fs.FS {
	t.Helper()
	out := fstest.MapFS{}
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		v, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil || v > 42 {
			continue
		}
		b, err := fs.ReadFile(migrations.FS, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = &fstest.MapFile{Data: b}
	}
	for _, name := range []string{"00043_scan_concurrency.sql", "00044_hardening.sql"} {
		b, err := os.ReadFile(filepath.Join("testdata", "migrations-2.2.3", name))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = &fstest.MapFile{Data: b}
	}
	// 2.2.3 has 40 migration files (00030, 00036, 00037 and 00039 do not exist).
	if len(out) != 40 {
		t.Fatalf("the 2.2.3 migration set has %d files, want 40", len(out))
	}
	return out
}

// schemaOf describes what migrations create: columns, indexes and
// constraints of the public schema, and the applied goose versions.
func schemaOf(t *testing.T, pool *pgxpool.Pool) map[string][]string {
	t.Helper()
	ctx := t.Context()
	queries := map[string]string{
		"columns": `SELECT table_name || '.' || column_name || ' ' || data_type || ' null=' || is_nullable || ' default=' || COALESCE(column_default, '')
			FROM information_schema.columns WHERE table_schema = 'public' AND table_name <> 'goose_db_version'`,
		"indexes":     `SELECT indexname || ': ' || indexdef FROM pg_indexes WHERE schemaname = 'public' AND tablename <> 'goose_db_version'`,
		"constraints": `SELECT conrelid::regclass::text || '.' || conname || ': ' || pg_get_constraintdef(oid) FROM pg_constraint WHERE connamespace = 'public'::regnamespace`,
		"versions":    `SELECT version_id::text FROM goose_db_version WHERE is_applied AND version_id > 0`,
	}
	out := map[string][]string{}
	for k, q := range queries {
		rows, err := pool.Query(ctx, q)
		if err != nil {
			t.Fatal(k, err)
		}
		vals, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(k, err)
		}
		slices.Sort(vals)
		out[k] = vals
	}
	return out
}

func diffSets(a, b []string) (onlyA, onlyB []string) {
	for _, x := range a {
		if !slices.Contains(b, x) {
			onlyA = append(onlyA, x)
		}
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			onlyB = append(onlyB, x)
		}
	}
	return
}

// An installation upgraded from 2.2.3 (whose goose table records versions
// 43 and 44 for the 2.2.x migrations) reaches exactly the schema of a fresh
// 3.0 install, keeps its 2.2.x data, and migrating again changes nothing.
func TestUpgradeFrom223(t *testing.T) {
	ctx := t.Context()

	// Fresh 3.0 install.
	fresh := scratchDB(t, "pathos_fresh_")
	if err := db.Migrate(ctx, fresh, log); err != nil {
		t.Fatal("fresh install:", err)
	}
	want := schemaOf(t, fresh)
	for _, v := range []string{"43", "44", "65", "66", "67"} {
		if !slices.Contains(want["versions"], v) {
			t.Fatalf("fresh install: version %s not applied", v)
		}
	}

	// A 2.2.3 install, migrated by goose exactly as 2.2.3 does.
	old := scratchDB(t, "pathos_up223_")
	sqlDB := stdlib.OpenDBFromPool(old)
	defer func(c *sql.DB) { _ = c.Close() }(sqlDB)
	prov, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations223(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prov.Up(ctx); err != nil {
		t.Fatal("2.2.3 migrations:", err)
	}
	var cur int64
	if err := old.QueryRow(ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&cur); err != nil || cur != 44 {
		t.Fatalf("2.2.3 schema version %d %v", cur, err)
	}
	var ff bool
	_ = old.QueryRow(ctx, `SELECT to_regclass('feature_flags') IS NOT NULL`).Scan(&ff)
	if ff {
		t.Fatal("a 2.2.3 schema has no feature_flags table")
	}

	// 2.2.x data: an anonymous public repository.
	org := uuid.Must(uuid.NewV7())
	repo := uuid.Must(uuid.NewV7())
	if _, err := old.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'Upgraded', 'upgraded')`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(ctx, `INSERT INTO repositories (id, organization_id, source_type, source_provider, external_id, full_name, name, url, clone_url)
		VALUES ($1, $2, 'git', 'github', $3, 'octo/hello', 'hello', 'https://github.com/octo/hello', 'https://github.com/octo/hello.git')`,
		repo, org, uuid.NewString()); err != nil {
		t.Fatal(err)
	}

	// Upgrade to 3.0 with the production code path.
	if err := db.Migrate(ctx, old, log); err != nil {
		t.Fatal("upgrade from 2.2.3:", err)
	}
	got := schemaOf(t, old)
	for _, k := range []string{"columns", "indexes", "constraints", "versions"} {
		if a, b := diffSets(want[k], got[k]); len(a)+len(b) > 0 {
			t.Errorf("%s differ between a fresh install and an upgrade from 2.2.3:\n only fresh:    %v\n only upgraded: %v", k, a, b)
		}
	}
	var st, prov2 string
	if err := old.QueryRow(ctx, `SELECT source_type, source_provider FROM repositories WHERE id = $1`, repo).Scan(&st, &prov2); err != nil || st != "git" || prov2 != "github" {
		t.Fatalf("the anonymous repository was not kept: %s %s %v", st, prov2, err)
	}
	// The 3.0 migrations of 43 and 44 ran (their tables exist).
	for _, tbl := range []string{"feature_flags", "connectors", "rea_analyses", "monitoring_events"} {
		var ok bool
		if err := old.QueryRow(ctx, `SELECT to_regclass($1::text) IS NOT NULL`, tbl).Scan(&ok); err != nil || !ok {
			t.Errorf("table %s missing after the upgrade (%v)", tbl, err)
		}
	}

	// Again: nothing to do, and the reconciliation leaves a 3.0 database alone.
	if err := db.Migrate(ctx, old, log); err != nil {
		t.Fatal("second migrate:", err)
	}
	if err := db.Migrate(ctx, fresh, log); err != nil {
		t.Fatal("second migrate of the fresh install:", err)
	}
	if a, b := diffSets(want["versions"], schemaOf(t, fresh)["versions"]); len(a)+len(b) > 0 {
		t.Errorf("a second migrate changed the versions of a 3.0 install: %v %v", a, b)
	}
	c, latest, err := db.MigrationStatus(ctx, old)
	if err != nil || c != latest || latest != 67 {
		t.Fatalf("upgraded install at %d of %d (%v)", c, latest, err)
	}
}

// Migration 00066 combines the 2.2.x concurrency indexes with the
// reverse-engineering lane of 00061: one running repository scan per
// repository, pull request and lane (imports and target scans excluded),
// one running scan per target and lane. concurrency_test.go and the
// reverse-engineering tests exercise the behaviour through the API.
func TestScanConcurrencyLanes(t *testing.T) {
	ctx := t.Context()
	pool := scratchDB(t, "pathos_lanes_")
	if err := db.Migrate(ctx, pool, log); err != nil {
		t.Fatal(err)
	}
	var def string
	if err := pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE indexname = 'scan_jobs_running_uq'`).Scan(&def); err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"COALESCE(pull_request, 0)", "(trigger = 'rea'::text)", "target_id IS NULL", "<> 'import'::text"} {
		if !strings.Contains(def, part) {
			t.Errorf("scan_jobs_running_uq %q lacks %q", def, part)
		}
	}
	if err := pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE indexname = 'scan_jobs_running_target_uq'`).Scan(&def); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(def, "target_id, ((trigger = 'rea'::text))") && !strings.Contains(def, "target_id, (trigger = 'rea'::text)") {
		t.Errorf("scan_jobs_running_target_uq %q", def)
	}
}

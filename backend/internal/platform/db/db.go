// Package db wraps the pgx connection pool, transactions and migrations.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"pathos/internal/platform/tenant"
	"pathos/migrations"
)

// Querier is satisfied by *pgxpool.Pool and pgx.Tx.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Connect opens a pool and waits (with retries) until the database answers.
func Connect(ctx context.Context, url string, log *slog.Logger) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute
	// PostgreSQL's JIT compiler costs 0.5-1 s on the large aggregate
	// queries (dashboard, posture) and saves less than that
	// (docs/PERFORMANCE.md). A jit parameter in the database URL wins.
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	if _, set := cfg.ConnConfig.RuntimeParams["jit"]; !set {
		cfg.ConnConfig.RuntimeParams["jit"] = "off"
	}
	st := &poolState{}
	cfg.PrepareConn = st.prepare
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pools.Store(pool, st)
	deadline := time.Now().Add(60 * time.Second)
	for {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = pool.Ping(pctx)
		cancel()
		if err == nil {
			return pool, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			pool.Close()
			return nil, fmt.Errorf("database not reachable: %w", err)
		}
		log.Warn("waiting for database", "err", err)
		time.Sleep(2 * time.Second)
	}
}

// poolState holds the per-pool tenancy default.
type poolState struct {
	mu         sync.RWMutex
	defaultOrg uuid.UUID
}

var pools sync.Map // *pgxpool.Pool -> *poolState

// prepare runs on every connection checkout. It always overwrites both
// row-level security variables, so a connection never keeps the scope of
// its previous user: the scope comes from the context of the query that
// checks the connection out (tenant.WithOrg / tenant.WithSystem), else the
// pool default (single-organization installs), else none, which makes
// every tenant table look empty.
func (st *poolState) prepare(ctx context.Context, c *pgx.Conn) (bool, error) {
	st.mu.RLock()
	def := st.defaultOrg
	st.mu.RUnlock()
	org, bypass := tenant.Settings(ctx, def)
	if _, err := c.Exec(ctx, `SELECT set_config('app.organization_id', $1, false), set_config('app.rls_bypass', $2, false)`, org, bypass); err != nil {
		// Never hand out a connection whose scope could not be set.
		return false, fmt.Errorf("set tenant scope: %w", err)
	}
	return true, nil
}

// SetDefaultOrganization makes orgID the scope of queries whose context
// carries none. Only single-organization installs set it (there it is the
// only organization, so nothing changes for existing code paths); with
// multi-tenancy enabled the default stays empty and unscoped queries see
// no tenant rows.
func SetDefaultOrganization(pool *pgxpool.Pool, orgID uuid.UUID) {
	if v, ok := pools.Load(pool); ok {
		st := v.(*poolState)
		st.mu.Lock()
		st.defaultOrg = orgID
		st.mu.Unlock()
	}
}

// InTx runs fn in a transaction, committing on success.
func InTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Migrate applies all pending migrations.
func Migrate(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	// An upgrade from 2.2.x first releases the migration versions both
	// lines used (reconcile22.go).
	if err := reconcile22(ctx, sqlDB, log); err != nil {
		return err
	}
	provider, err := newProvider(sqlDB)
	if err != nil {
		return err
	}
	results, err := provider.Up(ctx)
	for _, r := range results {
		log.Info("migration applied", "version", r.Source.Version, "file", r.Source.Path, "duration_ms", r.Duration.Milliseconds())
	}
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// MigrateDownTo rolls back migrations above version (rollback of a
// release). Down migrations may delete data that the older schema cannot
// represent; each migration documents what.
func MigrateDownTo(ctx context.Context, pool *pgxpool.Pool, version int64, log *slog.Logger) error {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	provider, err := newProvider(sqlDB)
	if err != nil {
		return err
	}
	results, err := provider.DownTo(ctx, version)
	for _, r := range results {
		log.Info("migration rolled back", "version", r.Source.Version, "file", r.Source.Path, "duration_ms", r.Duration.Milliseconds())
	}
	if err != nil {
		return fmt.Errorf("migrate down: %w", err)
	}
	return nil
}

// MigrationStatus returns (current, latest) versions.
func MigrationStatus(ctx context.Context, pool *pgxpool.Pool) (int64, int64, error) {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	provider, err := newProvider(sqlDB)
	if err != nil {
		return 0, 0, err
	}
	cur, err := provider.GetDBVersion(ctx)
	if err != nil {
		return 0, 0, err
	}
	srcs := provider.ListSources()
	var latest int64
	if len(srcs) > 0 {
		latest = srcs[len(srcs)-1].Version
	}
	return cur, latest, nil
}

func newProvider(sqlDB *sql.DB) (*goose.Provider, error) {
	return goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS)
}

// IsUniqueViolation reports whether err is a unique constraint violation.
func IsUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// IsForeignKeyViolation reports whether err is a foreign key violation.
func IsForeignKeyViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23503"
}

// IsCheckViolation reports whether err is a check constraint violation.
func IsCheckViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23514"
}

// SetChangeContext attributes finding status changes made later in tx (read
// by the pathos_finding_lifecycle trigger). source is one of user, scanner,
// ai, expiry or system.
func SetChangeContext(ctx context.Context, tx pgx.Tx, actor *[16]byte, source, reason string) error {
	a := ""
	if actor != nil {
		a = fmt.Sprintf("%x-%x-%x-%x-%x", actor[0:4], actor[4:6], actor[6:8], actor[8:10], actor[10:16])
	}
	if len(reason) > 2000 {
		reason = reason[:2000]
	}
	_, err := tx.Exec(ctx, `SELECT set_config('pathos.actor', $1, true), set_config('pathos.source', $2, true), set_config('pathos.reason', $3, true)`,
		a, source, reason)
	return err
}

// rowSecurity is set when multi-tenancy (row-level security) is enabled:
// PostgreSQL rejects COPY FROM into tables with row-level security.
var rowSecurity atomic.Bool

// SetRowLevelSecurity tells CopyFrom whether tenant tables enforce
// row-level security (multi-tenancy enabled).
func SetRowLevelSecurity(on bool) { rowSecurity.Store(on) }

// Copier is satisfied by pgx.Tx and *pgxpool.Pool.
type Copier interface {
	CopyFrom(ctx context.Context, table pgx.Identifier, cols []string, src pgx.CopyFromSource) (int64, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// CopyFrom bulk-inserts rows. Without row-level security it uses COPY (as
// before); with row-level security (which COPY FROM does not support) it
// sends multi-row INSERT statements, whose rows the tenant policies check.
func CopyFrom(ctx context.Context, q Copier, table pgx.Identifier, cols []string, src pgx.CopyFromSource) (int64, error) {
	if !rowSecurity.Load() {
		return q.CopyFrom(ctx, table, cols, src)
	}
	if len(cols) == 0 {
		return 0, errors.New("copy: no columns")
	}
	head := "INSERT INTO " + table.Sanitize() + " ("
	for i, c := range cols {
		if i > 0 {
			head += ", "
		}
		head += pgx.Identifier{c}.Sanitize()
	}
	head += ") VALUES "
	// At most 65535 bind parameters per statement.
	per := max(1, 60000/len(cols))
	var total int64
	var args []any
	n := 0
	flush := func() error {
		if n == 0 {
			return nil
		}
		var b strings.Builder
		b.WriteString(head)
		for r := range n {
			if r > 0 {
				b.WriteString(", ")
			}
			b.WriteByte('(')
			for c := range cols {
				if c > 0 {
					b.WriteString(", ")
				}
				b.WriteString("$" + strconv.Itoa(r*len(cols)+c+1))
			}
			b.WriteByte(')')
		}
		tag, err := q.Exec(ctx, b.String(), args...)
		if err != nil {
			return err
		}
		total += tag.RowsAffected()
		args, n = args[:0], 0
		return nil
	}
	for src.Next() {
		vals, err := src.Values()
		if err != nil {
			return total, err
		}
		if len(vals) != len(cols) {
			return total, fmt.Errorf("copy: %d values for %d columns", len(vals), len(cols))
		}
		args = append(args, vals...)
		n++
		if n == per {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	if err := src.Err(); err != nil {
		return total, err
	}
	return total, flush()
}

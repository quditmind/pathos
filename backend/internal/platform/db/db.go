// Package db wraps the pgx connection pool, transactions and migrations.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

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
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
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

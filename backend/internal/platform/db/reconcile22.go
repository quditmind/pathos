package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
)

// Upgrades from 2.2.x (PATHOS 2.2.2 and later).
//
// goose records applied migrations by version number only, in
// goose_db_version. The 2.2.x maintenance line added migrations 00043
// (scan concurrency) and 00044 (hardening) after the 3.0 line had used
// those numbers for other changes (00043 feature flags, 00044 connectors).
// In 3.0 the 2.2.x migrations are 00066 and 00067, rewritten to be
// idempotent. On a database upgraded from 2.2.x, versions 43 and 44 are
// recorded as applied although the 3.0 migrations of those numbers never
// ran: goose would skip them and later migrations would fail.
//
// reconcile22 detects that state before goose runs: a version recorded as
// applied whose 3.0 schema object does not exist was applied by 2.2.x. Its
// rows are removed from goose_db_version, so goose applies the 3.0
// migration of that number, then 00045 to 00065, then 00066 and 00067 (which
// find the 2.2.x objects in place and leave them, with their data,
// unchanged). Nothing else is touched. A 3.0 database (the object exists)
// and a fresh database (no version table) are left alone.

// collided22 maps a migration version used by both lines to a table the
// 3.0 migration of that number creates.
var collided22 = []struct {
	Version int64
	Table   string
}{
	{43, "feature_flags"},
	{44, "connectors"},
}

// reconcile22 runs in one transaction before the goose provider is built.
func reconcile22(ctx context.Context, sqlDB *sql.DB, log *slog.Logger) error {
	var hasTable bool
	if err := sqlDB.QueryRowContext(ctx, `SELECT to_regclass('goose_db_version') IS NOT NULL`).Scan(&hasTable); err != nil {
		return fmt.Errorf("migrate: reading the migration table: %w", err)
	}
	if !hasTable {
		return nil
	}
	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	// Serialize with another instance starting at the same moment.
	if _, err := tx.ExecContext(ctx, `LOCK TABLE goose_db_version IN EXCLUSIVE MODE`); err != nil {
		return fmt.Errorf("migrate: locking the migration table: %w", err)
	}
	for _, c := range collided22 {
		var applied, exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM goose_db_version WHERE version_id = $1 AND is_applied),
			to_regclass($2::text) IS NOT NULL`, c.Version, c.Table).Scan(&applied, &exists); err != nil {
			return fmt.Errorf("migrate: checking version %d: %w", c.Version, err)
		}
		if !applied || exists {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM goose_db_version WHERE version_id = $1`, c.Version); err != nil {
			return fmt.Errorf("migrate: reconciling version %d: %w", c.Version, err)
		}
		if log != nil {
			log.Info("migration version recorded by PATHOS 2.2.x released for the 3.0 migration of the same number",
				"version", c.Version, "missing_table", c.Table)
		}
	}
	return tx.Commit()
}

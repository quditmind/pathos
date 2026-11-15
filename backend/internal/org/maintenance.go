package org

import (
	"context"

	"pathos/internal/platform/db"
)

// EnsureAuditPartitions creates audit log partitions for the coming months.
func EnsureAuditPartitions(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, `SELECT pathos_ensure_audit_partitions(3)`)
	return err
}

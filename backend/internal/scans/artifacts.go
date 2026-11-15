package scans

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
	"pathos/internal/platform/objstore"
)

// artifactKey is the object key of an artifact, prefixed by organization so
// a bucket can be browsed and lifecycle-managed per tenant. IDs are UUIDv7,
// so keys sort by creation time.
func artifactKey(orgID, id uuid.UUID) string {
	return fmt.Sprintf("artifacts/%s/%s.gz", orgID, id)
}

// putArtifact stores gzip data in the object store (returning its key) or,
// without one, returns the bytes to store inline.
func putArtifact(ctx context.Context, store objstore.Store, orgID, id uuid.UUID, gz []byte) (key *string, inline []byte, err error) {
	if store == nil {
		return nil, gz, nil
	}
	k := artifactKey(orgID, id)
	if err := store.Put(ctx, k, gz, "application/gzip"); err != nil {
		return nil, nil, fmt.Errorf("object store: %w", err)
	}
	return &k, nil, nil
}

// MigrateArtifacts moves inline artifacts into the object store in batches
// and returns how many moved. Each row is updated only after its object is
// written, so an interrupted run can be resumed.
func MigrateArtifacts(ctx context.Context, pool db.Querier, store objstore.Store, batch int) (int, error) {
	moved := 0
	for {
		rows, err := pool.Query(ctx, `SELECT id, organization_id, data_gzip FROM scan_artifacts WHERE object_key IS NULL ORDER BY id LIMIT $1`, batch)
		if err != nil {
			return moved, err
		}
		type item struct {
			id, org uuid.UUID
			gz      []byte
		}
		items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (item, error) {
			var it item
			return it, r.Scan(&it.id, &it.org, &it.gz)
		})
		if err != nil || len(items) == 0 {
			return moved, err
		}
		for _, it := range items {
			key := artifactKey(it.org, it.id)
			if err := store.Put(ctx, key, it.gz, "application/gzip"); err != nil {
				return moved, err
			}
			if _, err := pool.Exec(ctx, `UPDATE scan_artifacts SET object_key = $2, data_gzip = NULL WHERE id = $1 AND object_key IS NULL`, it.id, key); err != nil {
				return moved, err
			}
			moved++
		}
	}
}

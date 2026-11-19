package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/risk"
)

// recompute marks n findings dirty and times risk.Recompute (the function
// the jobs role runs) draining them, once per batch size. Stop the jobs
// service first, or it competes for the same rows.
func recompute(ctx context.Context, dsn, limits string, n int) error {
	if dsn == "" {
		return errors.New("-db is required")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	var org uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		return err
	}
	fmt.Printf("%10s %10s %10s %12s %14s\n", "batch", "findings", "seconds", "findings/s", "slowest batch")
	for _, s := range strings.Split(limits, ",") {
		limit, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || limit < 1 {
			return fmt.Errorf("invalid batch size %q", s)
		}
		if _, err := pool.Exec(ctx, `UPDATE findings SET risk_dirty = true WHERE id IN
			(SELECT id FROM findings WHERE organization_id = $1 ORDER BY id LIMIT $2)`, org, n); err != nil {
			return err
		}
		total, slowest := 0, time.Duration(0)
		t := time.Now()
		for ctx.Err() == nil {
			bt := time.Now()
			k, err := risk.Recompute(ctx, pool, org, limit)
			if err != nil {
				return err
			}
			slowest = max(slowest, time.Since(bt))
			total += k
			if k < limit {
				break
			}
		}
		secs := time.Since(t).Seconds()
		fmt.Printf("%10d %10d %10.1f %12.0f %12.2f s\n", limit, total, secs, float64(total)/secs, slowest.Seconds())
	}
	return nil
}

package repos

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/logging"
)

// SCM inventory: what every connection can see, refreshed daily. The
// unmanaged-asset report compares it with the repositories in PATHOS to
// find shadow repositories (active in the SCM, unknown to PATHOS).

const (
	inventoryInterval = 24 * time.Hour
	maxInventory      = 20000
)

func (s *Service) registerInventory(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/scm-connections/{id}/inventory", s.refreshInventory)
}

// InventoryRun is one refresh of a connection's inventory.
type InventoryRun struct {
	ID           uuid.UUID  `json:"id"`
	ConnectionID uuid.UUID  `json:"scm_connection_id"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at"`
	Status       string     `json:"status"`
	Repositories int        `json:"repositories"`
	Truncated    bool       `json:"truncated"`
	Error        string     `json:"error"`
}

// RunInventory refreshes connections whose inventory is older than a day.
func (s *Service) RunInventory(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		s.inventoryDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) inventoryDue(ctx context.Context) {
	rows, err := s.DB.Query(ctx, `SELECT c.organization_id, c.id FROM scm_connections c
		WHERE c.archived_at IS NULL AND NOT EXISTS (
		  SELECT 1 FROM scm_inventory_runs r WHERE r.scm_connection_id = c.id
		    AND (r.started_at > now() - $1::interval OR (r.status = 'running' AND r.started_at > now() - interval '1 hour')))`,
		inventoryInterval.String())
	if err != nil {
		s.Log.Warn("inventory: listing connections failed", "err", err)
		return
	}
	type conn struct{ org, id uuid.UUID }
	conns, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (conn, error) {
		var c conn
		return c, r.Scan(&c.org, &c.id)
	})
	if err != nil {
		s.Log.Warn("inventory: listing connections failed", "err", err)
		return
	}
	for _, c := range conns {
		if ctx.Err() != nil {
			return
		}
		run, err := s.Inventory(ctx, c.org, c.id)
		if err != nil {
			s.Log.Warn("inventory refresh failed", "connection_id", c.id, "err", err)
			continue
		}
		s.Log.Info("inventory refreshed", "connection_id", c.id, "repositories", run.Repositories, "truncated", run.Truncated)
	}
}

// Inventory lists a connection's repositories and stores them.
func (s *Service) Inventory(ctx context.Context, orgID, connID uuid.UUID) (InventoryRun, error) {
	run := InventoryRun{ID: uuid.Must(uuid.NewV7()), ConnectionID: connID, StartedAt: time.Now(), Status: "running"}
	if _, err := s.DB.Exec(ctx, `INSERT INTO scm_inventory_runs (id, organization_id, scm_connection_id) VALUES ($1, $2, $3)`,
		run.ID, orgID, connID); err != nil {
		return run, err
	}
	finish := func(err error) (InventoryRun, error) {
		now := time.Now()
		run.FinishedAt = &now
		run.Status = "succeeded"
		if err != nil {
			run.Status, run.Error = "failed", truncate(logging.RedactString(err.Error()), 2000)
		}
		_, uerr := s.DB.Exec(context.WithoutCancel(ctx), `UPDATE scm_inventory_runs SET finished_at = now(), status = $2, repositories = $3,
			truncated = $4, error = $5 WHERE id = $1`, run.ID, run.Status, run.Repositories, run.Truncated, run.Error)
		return run, errors.Join(err, uerr)
	}
	c, err := s.getConn(ctx, s.DB, orgID, connID)
	if err != nil {
		return finish(err)
	}
	cl, err := s.client(ctx, c)
	if err != nil {
		return finish(err)
	}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	remote, err := cl.ListRepositories(lctx)
	if err != nil {
		return finish(err)
	}
	if len(remote) > maxInventory {
		remote, run.Truncated = remote[:maxInventory], true
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for _, r := range remote {
			if r.ExternalID == "" {
				continue
			}
			b.Queue(`INSERT INTO scm_remote_repositories (organization_id, scm_connection_id, external_id, full_name, url, visibility, archived,
				  pushed_at, scm_organization, scm_project)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
				ON CONFLICT (scm_connection_id, external_id) DO UPDATE SET full_name = EXCLUDED.full_name, url = EXCLUDED.url,
				  visibility = EXCLUDED.visibility, archived = EXCLUDED.archived, pushed_at = EXCLUDED.pushed_at,
				  scm_organization = EXCLUDED.scm_organization, scm_project = EXCLUDED.scm_project, last_seen_at = now()`,
				orgID, connID, truncate(r.ExternalID, 200), truncate(r.FullName, 500), truncate(r.URL, 1000), truncate(r.Visibility, 20),
				r.Archived, r.PushedAt, truncate(r.Organization, 200), truncate(r.Project, 200))
			run.Repositories++
		}
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}
		if run.Truncated {
			return nil // a partial listing proves nothing about removals
		}
		// Repositories the connection no longer sees.
		_, err := tx.Exec(ctx, `DELETE FROM scm_remote_repositories WHERE scm_connection_id = $1 AND last_seen_at < $2`, connID, run.StartedAt)
		return err
	})
	return finish(err)
}

func (s *Service) refreshInventory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !canDiscover(p) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.getConn(ctx, s.DB, p.OrganizationID, id); err != nil {
		s.fail(w, r, err)
		return
	}
	run, err := s.Inventory(ctx, p.OrganizationID, id)
	if err != nil && run.Status != "failed" {
		s.fail(w, r, err)
		return
	}
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "scm.inventory_refresh", TargetType: "scm_connection", TargetID: id.String(),
		Metadata: map[string]any{"status": run.Status, "repositories": run.Repositories}})
	if run.Status == "failed" {
		httpx.WriteJSON(w, http.StatusBadGateway, map[string]any{"error": httpx.ErrorObject(r, httpx.E(http.StatusBadGateway, "inventory_failed", run.Error)), "request_id": httpx.RequestID(r), "run": run})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, run)
}

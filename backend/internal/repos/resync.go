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
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
)

// ResyncResult summarizes a metadata re-sync of one connection.
type ResyncResult struct {
	Checked  int `json:"checked"`
	Updated  int `json:"updated"`
	Missing  int `json:"missing"` // imported but no longer visible to the credential
	Archived int `json:"archived_upstream"`
}

// Resync refreshes metadata (name, URLs, default branch, visibility,
// description, upstream archive flag, last push) of imported repositories
// from the SCM. Placement, classification and tags are PATHOS data and are
// never touched. Repositories the credential can no longer see are counted
// but not changed.
func (s *Service) Resync(ctx context.Context, orgID, connID uuid.UUID) (ResyncResult, error) {
	var res ResyncResult
	c, err := s.getConn(ctx, s.DB, orgID, connID)
	if err != nil {
		return res, err
	}
	remote, err := s.listRemote(ctx, c)
	if err != nil {
		return res, err
	}
	byID := make(map[string]scm.RemoteRepo, len(remote))
	for _, rr := range remote {
		byID[rr.ExternalID] = rr
	}
	rows, err := s.DB.Query(ctx, `SELECT id, external_id FROM repositories WHERE organization_id = $1 AND scm_connection_id = $2`, orgID, connID)
	if err != nil {
		return res, err
	}
	type local struct {
		id  uuid.UUID
		ext string
	}
	locals, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (local, error) {
		var l local
		return l, row.Scan(&l.id, &l.ext)
	})
	if err != nil {
		return res, err
	}
	for _, l := range locals {
		res.Checked++
		rr, ok := byID[l.ext]
		if !ok {
			res.Missing++
			continue
		}
		vis := rr.Visibility
		if vis != "public" && vis != "internal" {
			vis = "private"
		}
		if rr.Archived {
			res.Archived++
		}
		tag, err := s.DB.Exec(ctx, `
			UPDATE repositories SET full_name = $3, name = $4, url = $5, clone_url = $6,
			       default_branch = CASE WHEN $7 <> '' THEN $7 ELSE default_branch END,
			       visibility = $8, description = $9, remote_archived = $10, last_pushed_at = COALESCE($11, last_pushed_at),
			       updated_at = now()
			WHERE organization_id = $1 AND id = $2
			  AND (full_name, name, url, clone_url, default_branch, visibility, description, remote_archived, last_pushed_at)
			      IS DISTINCT FROM ($3, $4, $5, $6, CASE WHEN $7 <> '' THEN $7 ELSE default_branch END, $8, $9, $10, COALESCE($11, last_pushed_at))`,
			orgID, l.id, rr.FullName, rr.Name, rr.URL, rr.CloneURL, rr.DefaultBranch, vis, truncate(rr.Description, 2000), rr.Archived, rr.PushedAt)
		if err != nil {
			return res, err
		}
		res.Updated += int(tag.RowsAffected())
	}
	_, err = s.DB.Exec(ctx, `UPDATE scm_connections SET last_synced_at = now() WHERE id = $1`, connID)
	return res, err
}

// ResyncAll re-syncs every active connection. Errors are logged per
// connection so one broken credential does not stop the others.
func (s *Service) ResyncAll(ctx context.Context) {
	rows, err := s.DB.Query(ctx, `SELECT organization_id, id FROM scm_connections WHERE archived_at IS NULL`)
	if err != nil {
		s.Log.Error("repository re-sync: list connections", "err", err)
		return
	}
	type pair struct{ org, id uuid.UUID }
	conns, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (pair, error) {
		var p pair
		return p, row.Scan(&p.org, &p.id)
	})
	if err != nil {
		s.Log.Error("repository re-sync: list connections", "err", err)
		return
	}
	for _, c := range conns {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		res, err := s.Resync(cctx, c.org, c.id)
		cancel()
		if err != nil {
			s.Log.Warn("repository re-sync failed", "connection_id", c.id, "err", err)
			continue
		}
		s.Log.Info("repository metadata re-synced", "connection_id", c.id, "checked", res.Checked, "updated", res.Updated, "missing", res.Missing)
	}
}

func (s *Service) resyncConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermSCMManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.Resync(ctx, p.OrganizationID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		s.fail(w, r, errNotFound)
		return
	}
	if err != nil {
		// SCM client errors are safe to show (they are already stored as
		// connection status messages); they never contain credentials.
		s.fail(w, r, httpx.E(http.StatusBadGateway, "scm_error", "re-sync failed: "+err.Error()))
		return
	}
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "scm.resync", TargetType: "scm_connection", TargetID: id.String(),
		Metadata: map[string]any{"checked": res.Checked, "updated": res.Updated, "missing": res.Missing}})
	httpx.WriteJSON(w, http.StatusOK, res)
}

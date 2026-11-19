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

// Resync reconciles every repository of a connection with the provider
// (scheduled synchronization): metadata, head commit of the tracked branch,
// and deletion / archive / permission changes. Placement, classification and
// tags are PATHOS data and are never touched. Source code is not
// downloaded; head commits are only looked up when the listing shows a
// push since the last known commit. Sync runs are recorded when something
// changed or failed.
func (s *Service) Resync(ctx context.Context, orgID, connID uuid.UUID) (ResyncResult, error) {
	var res ResyncResult
	c, err := s.getConn(ctx, s.DB, orgID, connID)
	if err != nil {
		return res, err
	}
	cl, err := s.client(ctx, c)
	if err != nil {
		return res, err
	}
	lctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	remote, err := cl.ListRepositories(lctx)
	cancel()
	if err != nil {
		return res, err
	}
	byID := make(map[string]scm.RemoteRepo, len(remote))
	for _, rr := range remote {
		byID[rr.ExternalID] = rr
	}
	rows, err := s.DB.Query(ctx, `SELECT id FROM repositories WHERE organization_id = $1 AND scm_connection_id = $2 AND archived_at IS NULL`, orgID, connID)
	if err != nil {
		return res, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return res, err
	}
	for _, id := range ids {
		t, err := loadSyncTarget(ctx, s.DB, orgID, id)
		if err != nil {
			return res, err
		}
		res.Checked++
		run := SyncRun{ID: uuid.Must(uuid.NewV7()), Trigger: "schedule", StartedAt: time.Now(), PreviousCommitSHA: t.LatestSHA}
		rctx, cancel := context.WithTimeout(ctx, time.Minute)
		var serr error
		if rr, ok := byID[t.ExternalID]; ok {
			serr = s.syncWith(rctx, cl, t, &run, &rr)
		} else {
			// Not in the listing: confirm whether it was deleted or the
			// credential lost access.
			serr = s.syncWith(rctx, cl, t, &run, nil)
			if serr != nil {
				res.Missing++
				s.Log.Info("repository no longer visible to the connection", "repository_id", id, "error_code", "PTH-SYNC-1002", "err", serr)
			}
		}
		cancel()
		if serr != nil {
			run.Status, run.Error = syncStatusFor(serr), truncate(serr.Error(), 500)
		}
		if run.Status == "archived_upstream" {
			res.Archived++
		}
		if run.Changed {
			res.Updated++
		}
		if run.Changed || run.Status != "ok" || t.SyncStatus != run.Status {
			if err := s.saveSyncRun(ctx, t, run, nil); err != nil {
				return res, err
			}
			continue
		}
		if _, err := s.DB.Exec(ctx, `UPDATE repositories SET last_sync_at = now(), last_sync_ok_at = now(), sync_status = 'ok', sync_error = ''
			WHERE organization_id = $1 AND id = $2`, orgID, id); err != nil {
			return res, err
		}
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
		cctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		res, err := s.Resync(cctx, c.org, c.id)
		cancel()
		if err != nil {
			s.Log.Warn("repository re-sync failed", "connection_id", c.id, "err", err, "error_code", resyncCode(err))
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
	// getConn maps a missing (or archived) connection to errNotFound.
	if errors.Is(err, errNotFound) || errors.Is(err, pgx.ErrNoRows) {
		s.fail(w, r, errNotFound)
		return
	}
	if err != nil {
		// SCM client errors are safe to show (they are already stored as
		// connection status messages); they never contain credentials.
		s.fail(w, r, httpx.E(http.StatusBadGateway, "scm_error", "re-sync failed: "+err.Error()).WithDiag(resyncCode(err)))
		return
	}
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "scm.resync", TargetType: "scm_connection", TargetID: id.String(),
		Metadata: map[string]any{"checked": res.Checked, "updated": res.Updated, "missing": res.Missing}})
	httpx.WriteJSON(w, http.StatusOK, res)
}

// resyncCode is the catalogue code of a re-sync failure.
func resyncCode(err error) string {
	if c := scm.DiagCode(err); c != "" {
		return c
	}
	return "PTH-CONN-1012"
}

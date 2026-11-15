package scans

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scanners"
	"pathos/internal/scm"
)

// Worker is a registered scan worker.
type Worker struct {
	ID         uuid.UUID         `json:"id"`
	Name       string            `json:"name"`
	Family     string            `json:"family"`
	Version    string            `json:"version"`
	Scanners   map[string]string `json:"scanners"`
	LastSeenAt *time.Time        `json:"last_seen_at"`
	RevokedAt  *time.Time        `json:"revoked_at"`
	CreatedAt  time.Time         `json:"created_at"`
	Online     bool              `json:"online"`
	ActiveJobs int               `json:"active_jobs"`

	orgID uuid.UUID
}

type workerCtxKey struct{}

func workerFrom(ctx context.Context) *Worker {
	w, _ := ctx.Value(workerCtxKey{}).(*Worker)
	return w
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// InternalHandler serves /internal/worker/v1/* on the worker-only listener.
// It is never exposed through the edge proxy.
func (s *Service) InternalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/worker/v1/register", s.register)
	authed := http.NewServeMux()
	authed.HandleFunc("POST /internal/worker/v1/lease", s.lease)
	authed.HandleFunc("POST /internal/worker/v1/jobs/{id}/heartbeat", s.heartbeat)
	authed.HandleFunc("POST /internal/worker/v1/jobs/{id}/results", s.uploadResult)
	authed.HandleFunc("POST /internal/worker/v1/jobs/{id}/complete", s.complete)
	mux.Handle("/internal/worker/v1/", s.workerAuth(authed))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	return mux
}

func bearer(r *http.Request) string {
	t, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return strings.TrimSpace(t)
}

func (s *Service) workerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if len(tok) < 32 {
			httpx.WriteError(w, r, s.Log, httpx.ErrUnauthenticated)
			return
		}
		var wk Worker
		var sc []byte
		err := s.DB.QueryRow(r.Context(), `UPDATE workers SET last_seen_at = now() WHERE token_sha256 = $1 AND revoked_at IS NULL
			RETURNING id, organization_id, name, family, version, scanners`, hashToken(tok)).
			Scan(&wk.ID, &wk.orgID, &wk.Name, &wk.Family, &wk.Version, &sc)
		if err != nil {
			httpx.WriteError(w, r, s.Log, httpx.ErrUnauthenticated)
			return
		}
		_ = json.Unmarshal(sc, &wk.Scanners)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), workerCtxKey{}, &wk)))
	})
}

var workerNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

type registerRequest struct {
	Name     string            `json:"name"`
	Family   string            `json:"family"`
	Version  string            `json:"version"`
	Scanners map[string]string `json:"scanners"`
}

// register exchanges the bootstrap token for a per-worker credential. A
// worker name that an administrator revoked cannot re-register until the
// record is deleted.
func (s *Service) register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.BootstrapToken == "" || subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.BootstrapToken)) != 1 {
		httpx.WriteError(w, r, s.Log, httpx.ErrUnauthenticated)
		return
	}
	var req registerRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if !workerNameRe.MatchString(req.Name) || req.Family == "" || len(req.Family) > 40 || len(req.Version) > 100 || len(req.Scanners) > 100 {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid worker registration"))
		return
	}
	for k, v := range req.Scanners {
		if _, ok := scanners.Lookup(k); !ok || len(v) > 100 {
			delete(req.Scanners, k)
		}
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	token := base64.RawURLEncoding.EncodeToString(raw)
	sc, _ := json.Marshal(req.Scanners)
	var id uuid.UUID
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var revoked *time.Time
		err := tx.QueryRow(ctx, `SELECT id, revoked_at FROM workers WHERE organization_id = $1 AND name = $2 FOR UPDATE`, s.OrgID, req.Name).Scan(&id, &revoked)
		switch {
		case err == nil && revoked != nil:
			return httpx.E(http.StatusForbidden, "worker_revoked", "this worker was revoked by an administrator")
		case err == nil:
			_, err = tx.Exec(ctx, `UPDATE workers SET token_sha256 = $2, family = $3, version = $4, scanners = $5, last_seen_at = now() WHERE id = $1`,
				id, hashToken(token), req.Family, req.Version, sc)
			if err != nil {
				return err
			}
		case errors.Is(err, pgx.ErrNoRows):
			id = uuid.Must(uuid.NewV7())
			if _, err := tx.Exec(ctx, `INSERT INTO workers (id, organization_id, name, family, version, token_sha256, scanners, last_seen_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, now())`, id, s.OrgID, req.Name, req.Family, req.Version, hashToken(token), sc); err != nil {
				return err
			}
		default:
			return err
		}
		// Jobs leased by a previous incarnation of this worker are requeued.
		if _, err := tx.Exec(ctx, `UPDATE scan_jobs SET status = 'queued', leased_by = NULL, lease_expires_at = NULL
			WHERE leased_by = $1 AND status = 'running'`, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: s.OrgID, Action: "worker.register", TargetType: "worker", TargetID: id.String(),
			Metadata: map[string]any{"name": req.Name, "family": req.Family, "version": req.Version}})
	})
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"worker_id": id, "token": token})
}

// leaseDuration is extended by heartbeats.
const leaseDuration = 5 * time.Minute

// LeasedJob is what a worker receives.
type LeasedJob struct {
	JobID          uuid.UUID        `json:"job_id"`
	RepositoryID   uuid.UUID        `json:"repository_id"`
	FullName       string           `json:"full_name"`
	CloneURL       string           `json:"clone_url"`
	Ref            string           `json:"ref"`
	CommitSHA      string           `json:"commit_sha"`
	TimeoutSeconds int              `json:"timeout_seconds"`
	Exclusions     []string         `json:"exclusions"`
	Scanners       []ProfileScanner `json:"scanners"`
	Credential     *scm.Credential  `json:"credential,omitempty"`
	// Public repositories may be cloned anonymously if the credential fails.
	Public bool `json:"public"`
}

// requeueExpired returns expired leases to the queue (or fails them).
func requeueExpired(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, `
		UPDATE scan_jobs j SET
		  status = CASE WHEN j.attempts >= j.max_attempts THEN 'failed' ELSE 'queued' END,
		  error = CASE WHEN j.attempts >= j.max_attempts THEN 'worker lease expired ' || j.attempts || ' times' ELSE j.error END,
		  finished_at = CASE WHEN j.attempts >= j.max_attempts THEN now() ELSE NULL END,
		  leased_by = NULL, lease_expires_at = NULL
		WHERE j.status = 'running' AND j.lease_expires_at < now()
		  AND NOT EXISTS (SELECT 1 FROM scan_jobs q WHERE q.repository_id = j.repository_id AND q.status = 'queued')`)
	return err
}

func (s *Service) lease(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wk := workerFrom(ctx)
	if err := requeueExpired(ctx, s.DB); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	var job LeasedJob
	var connID, profileVersion uuid.UUID
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			UPDATE scan_jobs j SET status = 'running', leased_by = $2, lease_expires_at = now() + $3::interval,
			       attempts = attempts + 1, started_at = now(), error = ''
			WHERE j.id = (
			  SELECT q.id FROM scan_jobs q
			  WHERE q.organization_id = $1 AND q.status = 'queued'
			    AND NOT EXISTS (SELECT 1 FROM scan_jobs x WHERE x.repository_id = q.repository_id AND x.status = 'running')
			  ORDER BY q.priority DESC, q.queued_at FOR UPDATE SKIP LOCKED LIMIT 1)
			RETURNING j.id, j.repository_id, j.ref, j.commit_sha, j.profile_version_id`,
			wk.orgID, wk.ID, leaseDuration.String()).Scan(&job.JobID, &job.RepositoryID, &job.Ref, &job.CommitSHA, &profileVersion)
		if err != nil {
			return err
		}
		// A retried job starts from a clean slate.
		if _, err := tx.Exec(ctx, `DELETE FROM scan_results WHERE scan_job_id = $1`, job.JobID); err != nil {
			return err
		}
		var visibility string
		if err := tx.QueryRow(ctx, `SELECT full_name, clone_url, scm_connection_id, visibility FROM repositories WHERE id = $1`, job.RepositoryID).
			Scan(&job.FullName, &job.CloneURL, &connID, &visibility); err != nil {
			return err
		}
		job.Public = visibility == "public"
		v, err := scanVersion(tx.QueryRow(ctx, versionSelect+` WHERE v.id = $1`, profileVersion))
		if err != nil {
			return err
		}
		job.TimeoutSeconds, job.Exclusions, job.Scanners = v.TimeoutSeconds, v.Exclusions, v.Scanners
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if s.CloneCredential != nil {
		cred, err := s.CloneCredential(ctx, wk.orgID, connID)
		if err != nil {
			s.failJob(ctx, job.JobID, "could not obtain clone credential: "+safeErr(err))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		job.Credential = &cred
	}
	s.Log.Info("scan leased", "job_id", job.JobID, "repository", job.FullName, "worker", wk.Name)
	httpx.WriteJSON(w, http.StatusOK, job)
}

func safeErr(err error) string {
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

func (s *Service) failJob(ctx context.Context, id uuid.UUID, msg string) {
	_, _ = s.DB.Exec(ctx, `UPDATE scan_jobs SET status = 'failed', error = $2, finished_at = now(), lease_expires_at = NULL
		WHERE id = $1 AND status = 'running'`, id, msg)
}

// ownedJob checks the job is running and leased by this worker.
func (s *Service) ownedJob(ctx context.Context, wk *Worker, id uuid.UUID) (status string, err error) {
	var leasedBy *uuid.UUID
	err = s.DB.QueryRow(ctx, `SELECT status, leased_by FROM scan_jobs WHERE id = $1 AND organization_id = $2`, id, wk.orgID).Scan(&status, &leasedBy)
	if err != nil {
		return "", errNotFound
	}
	if leasedBy == nil || *leasedBy != wk.ID {
		return status, httpx.E(http.StatusConflict, "lease_lost", "this job is not leased by this worker")
	}
	return status, nil
}

func (s *Service) heartbeat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wk := workerFrom(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	status, err := s.ownedJob(ctx, wk, id)
	if err != nil && status != "cancelled" {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if status == "cancelled" {
		httpx.WriteJSON(w, http.StatusOK, map[string]bool{"cancel": true})
		return
	}
	_, _ = s.DB.Exec(ctx, `UPDATE scan_jobs SET lease_expires_at = now() + $2::interval WHERE id = $1 AND status = 'running'`, id, leaseDuration.String())
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"cancel": false})
}

// ResultUpload is one scanner's output.
type ResultUpload struct {
	Scanner     string `json:"scanner"`
	Version     string `json:"version"`
	Status      string `json:"status"` // succeeded | failed | skipped | timed_out
	DurationMS  int    `json:"duration_ms"`
	Error       string `json:"error"`
	ContentType string `json:"content_type"`
	// OutputGzip is the gzip-compressed raw tool output, base64 encoded.
	OutputGzip string `json:"output_gzip"`
}

const maxResultBody = 96 << 20

func (s *Service) uploadResult(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wk := workerFrom(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	if status, err := s.ownedJob(ctx, wk, id); err != nil || status != "running" {
		if err == nil {
			err = httpx.Conflict("job is " + status)
		}
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxResultBody)
	var up ResultUpload
	if err := json.NewDecoder(r.Body).Decode(&up); err != nil {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid result payload"))
		return
	}
	switch up.Status {
	case "succeeded", "failed", "skipped", "timed_out":
	default:
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid status"))
		return
	}
	if _, ok := scanners.Lookup(up.Scanner); !ok {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("unknown scanner"))
		return
	}
	var gz []byte
	if up.OutputGzip != "" {
		if gz, err = base64.StdEncoding.DecodeString(up.OutputGzip); err != nil {
			httpx.WriteError(w, r, s.Log, httpx.BadRequest("output_gzip is not base64"))
			return
		}
	}
	n, err := s.Ingest(ctx, wk.orgID, id, up, gz)
	if err != nil {
		var he *httpx.Error
		if !errors.As(err, &he) {
			s.Log.Error("result ingestion failed", "job_id", id, "scanner", up.Scanner, "err", err)
		}
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]int{"findings": n})
}

// gunzipLimited decompresses with a size cap (zip bomb protection).
func gunzipLimited(gz []byte, limit int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, httpx.BadRequest("output is not gzip")
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, limit+1))
	if err != nil {
		return nil, httpx.BadRequest("output is corrupt")
	}
	if int64(len(out)) > limit {
		return nil, httpx.E(http.StatusRequestEntityTooLarge, "too_large", "decompressed output exceeds the limit")
	}
	return out, nil
}

type completeRequest struct {
	Status string `json:"status"` // succeeded | failed
	Error  string `json:"error"`
}

func (s *Service) complete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wk := workerFrom(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	if status, err := s.ownedJob(ctx, wk, id); err != nil || status != "running" {
		if err == nil {
			err = httpx.Conflict("job is " + status)
		}
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	var req completeRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	job, err := s.Finalize(ctx, id, req.Status == "failed", req.Error)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	s.Log.Info("scan finished", "job_id", id, "status", job.Status, "new", job.FindingsNew, "fixed", job.FindingsFixed)
	if s.OnScanFinished != nil && job.Status != "failed" {
		s.OnScanFinished(context.WithoutCancel(ctx), wk.orgID, id)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": job.Status})
}

// --- admin -----------------------------------------------------------------

func (s *Service) registerWorkersAdmin(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/workers", s.listWorkers)
	mux.HandleFunc("POST /api/v1/workers/{id}/revoke", s.revokeWorker)
	mux.HandleFunc("DELETE /api/v1/workers/{id}", s.deleteWorker)
}

func (s *Service) listWorkers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermScansRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT id, name, family, version, scanners, last_seen_at, revoked_at, created_at,
		(SELECT count(*) FROM scan_jobs j WHERE j.leased_by = wk.id AND j.status = 'running')
		FROM workers wk WHERE organization_id = $1 ORDER BY name`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Worker, error) {
		var wk Worker
		var sc []byte
		err := row.Scan(&wk.ID, &wk.Name, &wk.Family, &wk.Version, &sc, &wk.LastSeenAt, &wk.RevokedAt, &wk.CreatedAt, &wk.ActiveJobs)
		_ = json.Unmarshal(sc, &wk.Scanners)
		wk.Online = wk.RevokedAt == nil && wk.LastSeenAt != nil && time.Since(*wk.LastSeenAt) < 2*time.Minute
		return wk, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []Worker{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) workerAdminAction(w http.ResponseWriter, r *http.Request, action, sql string) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if err := s.Authz.Require(ctx, p, authz.PermScannersManage, s.orgScope(p)); err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var name string
		if err := tx.QueryRow(ctx, sql, id, p.OrganizationID).Scan(&name); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE scan_jobs SET status = 'queued', leased_by = NULL, lease_expires_at = NULL
			WHERE leased_by = $1 AND status = 'running'
			  AND NOT EXISTS (SELECT 1 FROM scan_jobs q WHERE q.repository_id = scan_jobs.repository_id AND q.status = 'queued')`, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: action, TargetType: "worker", TargetID: id.String(), Metadata: map[string]any{"name": name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) revokeWorker(w http.ResponseWriter, r *http.Request) {
	s.workerAdminAction(w, r, "worker.revoke",
		`UPDATE workers SET revoked_at = now() WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL RETURNING name`)
}

func (s *Service) deleteWorker(w http.ResponseWriter, r *http.Request) {
	s.workerAdminAction(w, r, "worker.delete", `DELETE FROM workers WHERE id = $1 AND organization_id = $2 RETURNING name`)
}

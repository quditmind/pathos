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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/logging"
	"pathos/internal/platform/objstore"
	"pathos/internal/reach"
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
	authed.HandleFunc("GET /internal/worker/v1/jobs/{id}/source", s.jobSource)
	authed.HandleFunc("GET /internal/worker/v1/jobs/{id}/target-file", s.jobTargetFile)
	authed.HandleFunc("POST /internal/worker/v1/jobs/{id}/imports", s.jobImports)
	authed.HandleFunc("POST /internal/worker/v1/jobs/{id}/events", s.workerEvents)
	authed.HandleFunc("POST /internal/worker/v1/fix-lease", s.fixLease)
	authed.HandleFunc("POST /internal/worker/v1/fix-jobs/{id}/result", s.fixResult)
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
	// Plugins describes the declarative adapters among Scanners.
	Plugins map[string]pluginMeta `json:"plugins"`
}

type pluginMeta struct {
	Name     string `json:"name"`
	Homepage string `json:"homepage"`
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
	plugins := map[string]pluginMeta{}
	for k, v := range req.Scanners {
		if len(v) > 100 {
			delete(req.Scanners, k)
			continue
		}
		if _, ok := scanners.Lookup(k); ok {
			continue
		}
		if meta, ok := req.Plugins[k]; ok && scanners.IsPluginKey(k) && len(meta.Name) <= 100 && len(meta.Homepage) <= 300 {
			plugins[k] = meta
			continue
		}
		delete(req.Scanners, k)
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
		// Declarative adapters become selectable in scan profiles.
		for k, meta := range plugins {
			sc, _ := scanners.ResolvePlugin(k)
			name := meta.Name
			if name == "" {
				name = sc.Name
			}
			if _, err := tx.Exec(ctx, `SELECT pathos_register_plugin_scanner($1, $2, $3, $4)`, k, name, sc.Category, meta.Homepage); err != nil {
				return err
			}
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
	// Source is set for uploaded repositories: the worker downloads the
	// snapshot from GET /internal/worker/v1/jobs/{id}/source.
	Source      *JobSource `json:"source,omitempty"`
	FullHistory bool       `json:"full_history"`
	// Target replaces the repository source for scan-target jobs.
	Target *LeasedTarget `json:"target,omitempty"`
}

// JobSource describes a snapshot to download instead of cloning.
type JobSource struct {
	Type   string `json:"type"` // snapshot
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// WorkerOnlineWindow is how recently a worker must have polled to count as
// online. Workers poll every few seconds while idle.
const WorkerOnlineWindow = 2 * time.Minute

// RequeueExpired returns expired leases to the queue (or fails them). The
// lease handler and the scheduler both call it, so jobs held by a dead worker
// recover even when no other worker is polling.
func RequeueExpired(ctx context.Context, q db.Querier) error { return requeueExpired(ctx, q) }

func requeueExpired(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, `
		UPDATE scan_jobs j SET
		  status = CASE WHEN j.attempts >= j.max_attempts THEN 'failed' ELSE 'queued' END,
		  error = CASE WHEN j.attempts >= j.max_attempts THEN 'worker lease expired ' || j.attempts || ' times' ELSE j.error END,
		  finished_at = CASE WHEN j.attempts >= j.max_attempts THEN now() ELSE NULL END,
		  leased_by = NULL, lease_expires_at = NULL
		WHERE j.status = 'running' AND j.lease_expires_at < now()
		  AND NOT EXISTS (SELECT 1 FROM scan_jobs q WHERE q.repository_id = j.repository_id AND q.target_id IS NOT DISTINCT FROM j.target_id AND q.status = 'queued')`)
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
	var profileVersion uuid.UUID
	var connID, snapshotID *uuid.UUID
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
		var targetID *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT r.full_name, r.clone_url, r.scm_connection_id, r.visibility, r.full_history, j.snapshot_id, j.target_id
			FROM repositories r JOIN scan_jobs j ON j.id = $2 WHERE r.id = $1`, job.RepositoryID, job.JobID).
			Scan(&job.FullName, &job.CloneURL, &connID, &visibility, &job.FullHistory, &snapshotID, &targetID); err != nil {
			return err
		}
		job.Public = visibility == "public"
		if snapshotID != nil {
			var src JobSource
			if err := tx.QueryRow(ctx, `SELECT snapshot_sha256, snapshot_size FROM source_snapshots WHERE id = $1`, *snapshotID).
				Scan(&src.SHA256, &src.Size); err != nil {
				return err
			}
			src.Type = "snapshot"
			job.Source, job.CloneURL, job.FullHistory = &src, "", false
		}
		v, err := scanVersion(tx.QueryRow(ctx, versionSelect+` WHERE v.id = $1`, profileVersion))
		if err != nil {
			return err
		}
		job.TimeoutSeconds, job.Exclusions, job.Scanners = v.TimeoutSeconds, v.Exclusions, v.Scanners
		if targetID != nil {
			connID, snapshotID = nil, nil
			return s.leaseTarget(ctx, tx, wk.orgID, *targetID, &job)
		}
		// Target scanners (image, DAST) never run against a repository.
		job.Scanners = slices.DeleteFunc(job.Scanners, func(ps ProfileScanner) bool { return scanners.IsTargetOnly(ps.Key) })
		// Opengrep receives the custom rule files pinned in the snapshot.
		for i, sc := range job.Scanners {
			if sc.Key != scanners.Opengrep {
				continue
			}
			rules, err := customRulesFor(ctx, tx, job.JobID.String())
			if err != nil {
				return err
			}
			if len(rules) == 0 {
				break
			}
			cfg := map[string]any{}
			_ = json.Unmarshal(sc.Config, &cfg)
			cfg["custom_rules"] = rules
			raw, _ := json.Marshal(cfg)
			job.Scanners[i].Config = raw
		}
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
	if s.CloneCredential != nil && connID != nil && job.Source == nil {
		cred, err := s.CloneCredential(ctx, wk.orgID, *connID)
		if err != nil {
			s.failJob(ctx, job.JobID, "could not obtain clone credential: "+safeErr(err))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		job.Credential = &cred
	}
	if err := AddEvent(ctx, s.DB, wk.orgID, job.JobID, "leased", "", "info", "picked up by worker "+wk.Name); err == nil {
		_ = updateProgress(ctx, s.DB, job.JobID)
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
	if _, ok := scanners.Lookup(up.Scanner); !ok && !scanners.IsPluginKey(up.Scanner) {
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
	if err == nil {
		st := map[string]string{"succeeded": "succeeded", "failed": "failed", "skipped": "skipped", "timed_out": "timed_out"}[up.Status]
		if st == "" {
			st = "info"
		}
		msg := up.Error
		if msg == "" {
			msg = up.Scanner + " " + up.Status
		}
		if err := AddEvent(ctx, s.DB, wk.orgID, id, "scanner", up.Scanner, st, logging.RedactString(msg)); err == nil {
			_ = updateProgress(ctx, s.DB, id)
		}
	}
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
	// CommitSHA is the commit the worker actually scanned (Git sources).
	CommitSHA string `json:"commit_sha"`
}

// jobSource streams the decrypted snapshot of an uploaded repository to
// the worker that holds the job's lease.
func (s *Service) jobSource(w http.ResponseWriter, r *http.Request) {
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
	var snapshotID *uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT snapshot_id FROM scan_jobs WHERE id = $1`, id).Scan(&snapshotID); err != nil || snapshotID == nil || s.OpenSnapshot == nil {
		httpx.WriteError(w, r, s.Log, httpx.E(http.StatusNotFound, "no_snapshot", "this job has no source snapshot"))
		return
	}
	rc, _, size, err := s.OpenSnapshot(ctx, wk.orgID, *snapshotID)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	defer rc.Close()
	// Snapshots can be large; extend the listener's write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Hour))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
	// Decryption errors surface as a short body; the worker verifies the
	// SHA-256 and size before scanning.
	if _, err := io.Copy(w, rc); err != nil {
		s.Log.Warn("snapshot stream interrupted", "job_id", id, "err", err)
	}
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
	if shaRe.MatchString(req.CommitSHA) {
		_, _ = s.DB.Exec(ctx, `UPDATE scan_jobs SET commit_sha = $2 WHERE id = $1 AND (commit_sha = '' OR $2 LIKE commit_sha || '%')`, id, req.CommitSHA)
	}
	job, err := s.Finalize(ctx, id, req.Status == "failed", req.Error)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	_ = AddEvent(ctx, s.DB, wk.orgID, id, "finalize", "", map[bool]string{true: "failed", false: "succeeded"}[job.Status == "failed"],
		"scan "+job.Status)
	_ = updateProgress(ctx, s.DB, id)
	s.Log.Info("scan finished", "job_id", id, "status", job.Status, "new", job.FindingsNew, "fixed", job.FindingsFixed)
	if job.PullRequest > 0 {
		s.postPRStatus(context.WithoutCancel(ctx), id)
	} else if s.OnScanFinished != nil && job.Status != "failed" {
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
		wk.Online = wk.RevokedAt == nil && wk.LastSeenAt != nil && time.Since(*wk.LastSeenAt) < WorkerOnlineWindow
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

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// jobTargetFile serves an SBOM target to the worker that holds the job.
func (s *Service) jobTargetFile(w http.ResponseWriter, r *http.Request) {
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
	var gz []byte
	var key *string
	if err := s.DB.QueryRow(ctx, `SELECT COALESCE(t.sbom_gzip, t.artifact_gzip), t.artifact_key FROM scan_jobs j JOIN scan_targets t ON t.id = j.target_id
		WHERE j.id = $1 AND t.kind IN ('sbom', 'artifact')`, id).Scan(&gz, &key); err != nil || (len(gz) == 0 && key == nil) {
		httpx.WriteError(w, r, s.Log, httpx.E(http.StatusNotFound, "no_target_file", "this job has no uploaded target file"))
		return
	}
	if key != nil {
		if gz, err = objstore.Load(ctx, s.Artifacts, key, nil); err != nil {
			httpx.WriteError(w, r, s.Log, err)
			return
		}
	}
	raw, err := gunzipLimited(gz, maxArtifactBytes+1)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// jobImports stores a repository's code inventory (from the worker holding
// the job) and recomputes the reachability of its dependency findings.
func (s *Service) jobImports(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	var inv struct {
		Version      int                 `json:"version"`
		FilesScanned int                 `json:"files_scanned"`
		Imports      map[string][]string `json:"imports"`
		Strings      map[string][]string `json:"strings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&inv); err != nil || inv.Version != 1 {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid import inventory"))
		return
	}
	var repoID uuid.UUID
	var target *uuid.UUID
	var pr *int
	if err := s.DB.QueryRow(ctx, `SELECT repository_id, target_id, pull_request FROM scan_jobs WHERE id = $1`, id).Scan(&repoID, &target, &pr); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if pr != nil {
		// The repository's code inventory tracks its scan branch.
		httpx.WriteJSON(w, http.StatusOK, map[string]int{"findings_updated": 0})
		return
	}
	if target != nil {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("scan target jobs have no code inventory"))
		return
	}
	var changed int
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := reach.StoreInventory(ctx, tx, wk.orgID, repoID, inv.Imports, inv.Strings, max(inv.FilesScanned, 0)); err != nil {
			return err
		}
		var err error
		changed, err = reach.Update(ctx, tx, repoID)
		return err
	})
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]int{"findings_updated": changed})
}

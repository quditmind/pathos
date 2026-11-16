package scans

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/logging"
)

// maxLogLines bounds the execution log of one scan.
const maxLogLines = 5000

var (
	eventStages   = []string{"queued", "leased", "source", "scanner", "ingest", "finalize", "cancel", "retry"}
	eventStatuses = []string{"started", "succeeded", "failed", "skipped", "timed_out", "info"}
	logLevels     = []string{"debug", "info", "warn", "error"}
)

// WorkerEvent is a stage event reported by a scan worker.
type WorkerEvent struct {
	Stage   string    `json:"stage"`
	Scanner string    `json:"scanner"`
	Status  string    `json:"status"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

// WorkerLog is one execution log line reported by a scan worker.
type WorkerLog struct {
	At      time.Time `json:"at"`
	Level   string    `json:"level"`
	Source  string    `json:"source"` // "worker" or a scanner key
	Message string    `json:"message"`
}

type workerEventsRequest struct {
	Events []WorkerEvent `json:"events"`
	Logs   []WorkerLog   `json:"logs"`
}

// clampTime keeps worker clocks from writing far-future or ancient times.
func clampTime(t, floor, now time.Time) time.Time {
	if t.IsZero() || t.After(now.Add(5*time.Minute)) || t.Before(floor) {
		return now
	}
	return t
}

// workerEvents records stage events and log lines for a leased job.
func (s *Service) workerEvents(w http.ResponseWriter, r *http.Request) {
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
	var req workerEventsRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if len(req.Events) > 200 || len(req.Logs) > 1000 {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("at most 200 events and 1000 log lines per request"))
		return
	}
	now := time.Now()
	var started time.Time
	_ = s.DB.QueryRow(ctx, `SELECT COALESCE(started_at, queued_at) FROM scan_jobs WHERE id = $1`, id).Scan(&started)
	floor := started.Add(-time.Hour)
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		for _, e := range req.Events {
			if !slices.Contains(eventStages, e.Stage) || !slices.Contains(eventStatuses, e.Status) || len(e.Scanner) > 50 {
				return httpx.BadRequest("invalid event")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO scan_job_events (organization_id, scan_job_id, stage, scanner_key, status, message, at)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`, wk.orgID, id, e.Stage, e.Scanner, e.Status,
				truncate(logging.RedactString(e.Message), 2000), clampTime(e.At, floor, now)); err != nil {
				return err
			}
		}
		if len(req.Logs) > 0 {
			var have int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM scan_job_logs WHERE scan_job_id = $1`, id).Scan(&have); err != nil {
				return err
			}
			room := maxLogLines - have
			for i, l := range req.Logs {
				if !slices.Contains(logLevels, l.Level) {
					l.Level = "info"
				}
				src := strings.TrimSpace(l.Source)
				if src == "" || len(src) > 50 {
					src = "worker"
				}
				msg := l.Message
				if i >= room {
					if i == room {
						src, l.Level, msg = "platform", "warn", "log limit reached; further lines were dropped"
					} else {
						break
					}
				}
				if _, err := tx.Exec(ctx, `INSERT INTO scan_job_logs (organization_id, scan_job_id, at, level, source, message)
					VALUES ($1, $2, $3, $4, $5, $6)`, wk.orgID, id, clampTime(l.At, floor, now), l.Level, src,
					truncate(logging.RedactString(msg), 2000)); err != nil {
					return err
				}
			}
		}
		return updateProgress(ctx, tx, id)
	})
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// updateProgress derives stage and progress from recorded facts: lease,
// source events, finished scanner results and finalization. Nothing is
// estimated: progress moves only when a stage actually completes.
func updateProgress(ctx context.Context, q db.Querier, jobID uuid.UUID) error {
	_, err := q.Exec(ctx, `
		WITH j AS (SELECT id, status, config_snapshot FROM scan_jobs WHERE id = $1),
		     total AS (SELECT GREATEST(COALESCE(jsonb_array_length(j.config_snapshot->'scanners'),
		                 (SELECT count(*) FROM profile_scanners ps JOIN scan_jobs x ON x.profile_version_id = ps.profile_version_id WHERE x.id = $1)), 1) AS n FROM j),
		     done AS (SELECT count(*) AS n FROM scan_results WHERE scan_job_id = $1),
		     src AS (SELECT bool_or(stage = 'source' AND status = 'succeeded') AS ok,
		                    bool_or(stage = 'source' AND status = 'started') AS started,
		                    (SELECT scanner_key FROM scan_job_events e2 WHERE e2.scan_job_id = $1 AND e2.stage = 'scanner' AND e2.status = 'started'
		                       ORDER BY e2.at DESC, e2.id DESC LIMIT 1) AS current
		             FROM scan_job_events WHERE scan_job_id = $1)
		UPDATE scan_jobs s SET
		  progress = CASE
		    WHEN j.status IN ('succeeded', 'partial', 'failed', 'cancelled') THEN 100
		    WHEN j.status = 'queued' THEN 0
		    ELSE LEAST(95, 5 + CASE WHEN src.ok OR done.n > 0 THEN 10 ELSE 0 END + (80 * LEAST(done.n, total.n) / total.n)::int) END,
		  stage = CASE
		    WHEN j.status IN ('succeeded', 'partial', 'failed', 'cancelled') THEN 'finished'
		    WHEN j.status = 'queued' THEN 'queued'
		    WHEN done.n >= total.n THEN 'finalizing'
		    WHEN done.n > 0 OR src.ok THEN 'scanning' || COALESCE(':' || src.current, '')
		    WHEN src.started THEN 'fetching_source'
		    ELSE 'starting' END
		FROM j, total, done, src WHERE s.id = j.id`, jobID)
	return err
}

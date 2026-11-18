package scans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/eol"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Worker uploads that complete a repository scan: the declared runtimes
// (end-of-life matching) and the introducing commits of code findings
// (git blame). Push and merge scans also get a change summary.

func (s *Service) registerWorkerProvenance(mux *http.ServeMux) {
	mux.HandleFunc("POST /internal/worker/v1/jobs/{id}/runtimes", s.jobRuntimes)
	mux.HandleFunc("POST /internal/worker/v1/jobs/{id}/blame", s.jobBlame)
}

// repoJob resolves a running job leased by the calling worker. ok=false
// means the response was written. skip is true for jobs whose results do
// not belong to the repository's code (pull requests, scan targets).
func (s *Service) repoJob(w http.ResponseWriter, r *http.Request) (orgID, jobID, repoID uuid.UUID, skip, ok bool) {
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
	var target *uuid.UUID
	var pr *int
	if err := s.DB.QueryRow(ctx, `SELECT repository_id, target_id, pull_request FROM scan_jobs WHERE id = $1`, id).Scan(&repoID, &target, &pr); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	return wk.orgID, id, repoID, target != nil || pr != nil, true
}

var runtimeNameRe = regexp.MustCompile(`^[a-z][a-z0-9.+-]{0,30}$`)

// jobRuntimes replaces the repository's declared runtimes and base images.
func (s *Service) jobRuntimes(w http.ResponseWriter, r *http.Request) {
	orgID, jobID, repoID, skip, ok := s.repoJob(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var inv struct {
		Version  int `json:"version"`
		Runtimes []struct {
			Kind    string `json:"kind"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Path    string `json:"path"`
		} `json:"runtimes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&inv); err != nil || inv.Version != 1 || len(inv.Runtimes) > 1000 {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid runtime inventory"))
		return
	}
	if skip {
		httpx.WriteJSON(w, http.StatusOK, map[string]int{"stored": 0})
		return
	}
	ctx := r.Context()
	n := 0
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM repository_runtimes WHERE repository_id = $1`, repoID); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for _, rt := range inv.Runtimes {
			name, ver, path := strings.TrimSpace(rt.Name), strings.TrimSpace(rt.Version), strings.TrimSpace(rt.Path)
			switch rt.Kind {
			case "runtime":
				if !runtimeNameRe.MatchString(name) || ver == "" {
					continue
				}
			case "image":
				if _, err := ValidateImageRef(name); err != nil {
					continue
				}
			default:
				continue
			}
			if len(ver) > 300 || len(path) > 1000 || !printable(name+ver+path) {
				continue
			}
			b.Queue(`INSERT INTO repository_runtimes (id, organization_id, repository_id, kind, name, version, source_path, scan_job_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`,
				uuid.Must(uuid.NewV7()), orgID, repoID, rt.Kind, name, ver, path, jobID)
			n++
		}
		return tx.SendBatch(ctx, b).Close()
	})
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]int{"stored": n})
}

func printable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

var fullSHARe = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// BlameUpload mirrors worker.BlameReport.
type BlameUpload struct {
	Version int    `json:"version"`
	Mode    string `json:"mode"` // full | shallow
	Entries []struct {
		File   string    `json:"file"`
		Line   int       `json:"line"`
		Commit string    `json:"commit"`
		Author string    `json:"author"`
		Time   time.Time `json:"time"`
	} `json:"entries"`
	Missing []struct {
		File string `json:"file"`
		Line int    `json:"line"`
	} `json:"missing"`
}

// codeCategories have file and line locations that git blame can explain.
var codeCategories = []string{"sast", "secrets", "iac"}

// jobBlame records the introducing commit of the job's code findings. A
// commit, once known, is kept: later edits of the line do not change who
// introduced the finding.
func (s *Service) jobBlame(w http.ResponseWriter, r *http.Request) {
	orgID, jobID, repoID, skip, ok := s.repoJob(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var up BlameUpload
	if err := json.NewDecoder(r.Body).Decode(&up); err != nil || up.Version != 1 || (up.Mode != "full" && up.Mode != "shallow") ||
		len(up.Entries) > 5000 || len(up.Missing) > 5000 {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid blame report"))
		return
	}
	if skip {
		httpx.WriteJSON(w, http.StatusOK, map[string]int{"findings_updated": 0})
		return
	}
	ctx := r.Context()
	updated := int64(0)
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if up.Mode == "shallow" {
			tag, err := tx.Exec(ctx, `UPDATE findings SET introduced_status = 'shallow_clone'
				WHERE repository_id = $1 AND last_scan_job_id = $2 AND category = ANY($3) AND start_line IS NOT NULL AND file_path <> ''
				  AND introduced_status = ''`, repoID, jobID, codeCategories)
			updated = tag.RowsAffected()
			return err
		}
		// Author names are personal data: they are kept only while the
		// organization has developer attribution turned on (off by default;
		// turning it off erases them). The commit and its date are always kept.
		var keepAuthors bool
		_ = tx.QueryRow(ctx, `SELECT attribution_enabled FROM developer_insight_settings WHERE organization_id = $1`, orgID).Scan(&keepAuthors)
		b := &pgx.Batch{}
		for _, e := range up.Entries {
			if e.Line <= 0 || e.File == "" || len(e.File) > 1000 || !fullSHARe.MatchString(e.Commit) {
				continue
			}
			if !keepAuthors {
				e.Author = ""
			}
			author := strings.Map(func(r rune) rune {
				if unicode.IsControl(r) {
					return -1
				}
				return r
			}, e.Author)
			var at *time.Time
			if e.Time.Year() >= 1970 && e.Time.Before(time.Now().Add(48*time.Hour)) {
				t := e.Time
				at = &t
			}
			b.Queue(`UPDATE findings SET introduced_status = 'known', introduced_commit_sha = $4, introduced_author = $5, introduced_at = $6
				WHERE repository_id = $1 AND last_scan_job_id = $2 AND category = ANY($3) AND file_path = $7 AND start_line = $8
				  AND introduced_status <> 'known'`,
				repoID, jobID, codeCategories, e.Commit, truncate(author, 200), at, e.File, e.Line)
		}
		for _, m := range up.Missing {
			if m.Line <= 0 || m.File == "" || len(m.File) > 1000 {
				continue
			}
			b.Queue(`UPDATE findings SET introduced_status = 'not_found'
				WHERE repository_id = $1 AND last_scan_job_id = $2 AND category = ANY($3) AND file_path = $4 AND start_line = $5
				  AND introduced_status IN ('', 'shallow_clone')`, repoID, jobID, codeCategories, m.File, m.Line)
		}
		br := tx.SendBatch(ctx, b)
		for range b.QueuedQueries {
			tag, err := br.Exec()
			if err != nil {
				_ = br.Close()
				return err
			}
			updated += tag.RowsAffected()
		}
		return br.Close()
	})
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]int64{"findings_updated": updated})
}

// ChangeSummary compares a push or merge scan with the previous scan of
// the repository's code.
type ChangeSummary struct {
	BaseCommit string         `json:"base_commit"`
	BaseScanID *uuid.UUID     `json:"base_scan_id"`
	HeadCommit string         `json:"head_commit"`
	New        map[string]int `json:"new"`
	Fixed      map[string]int `json:"fixed"`
	NewTotal   int            `json:"new_total"`
	FixedTotal int            `json:"fixed_total"`
}

// changeSummary builds the summary of a finished push or merge scan.
func changeSummary(ctx context.Context, tx pgx.Tx, jobID, repoID uuid.UUID, head string, fixedBySeverity map[string]int) (*ChangeSummary, error) {
	cs := &ChangeSummary{HeadCommit: head, New: map[string]int{}, Fixed: map[string]int{}}
	var baseID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id, commit_sha FROM scan_jobs WHERE repository_id = $1 AND id <> $2 AND target_id IS NULL
		AND pull_request IS NULL AND status IN ('succeeded', 'partial') AND finished_at IS NOT NULL
		ORDER BY finished_at DESC LIMIT 1`, repoID, jobID).Scan(&baseID, &cs.BaseCommit)
	switch {
	case err == nil:
		cs.BaseScanID = &baseID
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT severity, count(*) FROM findings WHERE repository_id = $1 AND first_scan_job_id = $2 GROUP BY severity`, repoID, jobID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return nil, err
		}
		cs.New[sev] = n
		cs.NewTotal += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for sev, n := range fixedBySeverity {
		cs.Fixed[sev] = n
		cs.FixedTotal += n
	}
	return cs, nil
}

// syncEOL updates the repository's end-of-life status after a scan. A
// failure is recorded on the scan and never fails it.
func (s *Service) syncEOL(ctx context.Context, tx pgx.Tx, orgID, repoID, jobID uuid.UUID) error {
	cat, err := eol.LoadCatalog(ctx, tx)
	if err != nil || cat == nil {
		return err
	}
	sp, err := tx.Begin(ctx) // savepoint
	if err != nil {
		return err
	}
	st, err := eol.SyncRepository(ctx, sp, cat, orgID, repoID, &jobID, time.Now().UTC())
	if err != nil {
		_ = sp.Rollback(ctx)
		if s.Log != nil {
			s.Log.Warn("end-of-life update failed", "job_id", jobID, "err", err)
		}
		return AddEvent(ctx, tx, orgID, jobID, "finalize", "", "info", "end-of-life status not updated: "+safeErr(err))
	}
	if err := sp.Commit(ctx); err != nil {
		return err
	}
	if st.EOL+st.Approaching == 0 {
		return nil
	}
	return AddEvent(ctx, tx, orgID, jobID, "finalize", "", "info",
		fmt.Sprintf("end of life (endoflife.date): %d end-of-life and %d approaching end of life", st.EOL, st.Approaching))
}

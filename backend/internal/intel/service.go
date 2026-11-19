package intel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/eol"
	"pathos/internal/platform/httpx"
)

// Service exposes feed management and CVE lookups.
type Service struct {
	DB        *pgxpool.Pool
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	// HTTP downloads online feeds (public hosts only).
	HTTP *http.Client
	// Offline: air-gapped deployment; feeds are imported from files only.
	Offline bool
}

// Run is one feed update.
type Run struct {
	ID        uuid.UUID  `json:"id"`
	Feed      string     `json:"feed"`
	Mode      string     `json:"mode"`
	Status    string     `json:"status"`
	Records   int        `json:"records"`
	AsOf      string     `json:"as_of"`
	Error     string     `json:"error"`
	StartedAt time.Time  `json:"started_at"`
	Finished  *time.Time `json:"finished_at"`
}

// Feed is a feed with its configuration and latest runs.
type Feed struct {
	Feed          string     `json:"feed"`
	Label         string     `json:"label"`
	Enabled       bool       `json:"enabled"`
	URL           string     `json:"url"`
	IntervalHours int        `json:"interval_hours"`
	Records       int        `json:"records"`
	LastRun       *Run       `json:"last_run"`
	LastSuccess   *Run       `json:"last_success"`
	NextDue       *time.Time `json:"next_due"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

var labels = map[string]string{EPSS: "FIRST EPSS (exploit prediction scores)", KEV: "CISA Known Exploited Vulnerabilities",
	OSV:      "OSV vulnerability records (descriptions, references, vendor CVSS)",
	DepsDev:  "deps.dev package health (latest versions, deprecations, OpenSSF Scorecard)",
	eol.Feed: "endoflife.date end-of-life dates of runtimes, frameworks, databases and operating systems"}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/intel/feeds", s.listFeeds)
	mux.HandleFunc("PUT /api/v1/intel/feeds/{feed}", s.updateFeed)
	mux.HandleFunc("POST /api/v1/intel/feeds/{feed}/run", s.runFeed)
	mux.HandleFunc("POST /api/v1/intel/feeds/{feed}/import", s.importFeed)
	mux.HandleFunc("GET /api/v1/intel/cves/{id}", s.cve)
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, pgx.ErrNoRows):
		err = httpx.ErrNotFound
	}
	httpx.WriteError(w, r, s.Log, err)
}

func scanRun(row pgx.Row) (*Run, error) {
	var r Run
	err := row.Scan(&r.ID, &r.Feed, &r.Mode, &r.Status, &r.Records, &r.AsOf, &r.Error, &r.StartedAt, &r.Finished)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

const runCols = `id, feed, mode, status, records, as_of, error, started_at, finished_at`

func (s *Service) feeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.DB.Query(ctx, `SELECT feed, enabled, url, interval_hours, updated_at,
		CASE feed WHEN 'epss' THEN (SELECT count(*) FROM intel_epss) WHEN 'kev' THEN (SELECT count(*) FROM intel_kev)
		  WHEN 'osv' THEN (SELECT count(*) FROM intel_vulns WHERE found)
		  WHEN 'endoflife' THEN (SELECT count(*) FROM eol_products)
		  ELSE (SELECT count(*) FROM package_health WHERE found) END
		FROM intel_feeds ORDER BY feed`)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Feed, error) {
		var f Feed
		err := r.Scan(&f.Feed, &f.Enabled, &f.URL, &f.IntervalHours, &f.UpdatedAt, &f.Records)
		f.Label = labels[f.Feed]
		return f, err
	})
	if err != nil {
		return nil, err
	}
	for i := range out {
		f := &out[i]
		if f.LastRun, err = scanRun(s.DB.QueryRow(ctx, `SELECT `+runCols+` FROM intel_feed_runs WHERE feed = $1 ORDER BY started_at DESC LIMIT 1`, f.Feed)); err != nil {
			return nil, err
		}
		if f.LastSuccess, err = scanRun(s.DB.QueryRow(ctx, `SELECT `+runCols+` FROM intel_feed_runs WHERE feed = $1 AND status = 'succeeded'
			ORDER BY started_at DESC LIMIT 1`, f.Feed)); err != nil {
			return nil, err
		}
		if f.Enabled {
			due := time.Now()
			if f.LastSuccess != nil {
				due = f.LastSuccess.StartedAt.Add(time.Duration(f.IntervalHours) * time.Hour)
			}
			f.NextDue = &due
		}
	}
	return out, nil
}

func (s *Service) listFeeds(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermFindingsRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	out, err := s.feeds(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "offline": s.Offline})
}

func validFeed(f string) bool {
	return f == EPSS || f == KEV || f == OSV || f == DepsDev || f == eol.Feed
}

func (s *Service) admin(r *http.Request) (*authz.Principal, string, error) {
	p := s.Principal(r.Context())
	if !p.HasOrgWide(authz.PermSettingsManage) {
		return p, "", authz.ErrForbidden
	}
	feed := r.PathValue("feed")
	if !validFeed(feed) {
		return p, "", httpx.ErrNotFound
	}
	return p, feed, nil
}

type feedRequest struct {
	Enabled       *bool   `json:"enabled"`
	URL           *string `json:"url"`
	IntervalHours *int    `json:"interval_hours"`
}

func (s *Service) updateFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, feed, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req feedRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.URL != nil {
		u, err := url.Parse(strings.TrimSpace(*req.URL))
		if err != nil || u.Scheme != "https" || u.Host == "" || len(*req.URL) > 500 || u.User != nil {
			s.fail(w, r, httpx.BadRequest("the feed URL must be an https URL"))
			return
		}
		v := u.String()
		req.URL = &v
	}
	if req.IntervalHours != nil && (*req.IntervalHours < 1 || *req.IntervalHours > 720) {
		s.fail(w, r, httpx.BadRequest("interval_hours must be 1-720"))
		return
	}
	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE intel_feeds SET enabled = COALESCE($2, enabled), url = COALESCE($3, url),
			interval_hours = COALESCE($4, interval_hours), updated_by = $5, updated_at = now() WHERE feed = $1`,
			feed, req.Enabled, req.URL, req.IntervalHours, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "intel.feed_update", TargetType: "intel_feed", TargetID: feed, Metadata: map[string]any{"enabled": req.Enabled, "url": req.URL,
				"interval_hours": req.IntervalHours}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.listFeeds(w, r)
}

func uid(p *authz.Principal) *[16]byte {
	a := [16]byte(p.UserID)
	return &a
}

// running reports whether a run of feed started recently and has not
// finished (one update at a time).
func (s *Service) running(ctx context.Context, feed string) bool {
	var busy bool
	_ = s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM intel_feed_runs WHERE feed = $1 AND status = 'running' AND started_at > now() - interval '30 minutes')`,
		feed).Scan(&busy)
	return busy
}

// Fetch downloads and loads a feed now.
func (s *Service) Fetch(ctx context.Context, feed string, by *[16]byte) (Run, error) {
	var u string
	if err := s.DB.QueryRow(ctx, `SELECT url FROM intel_feeds WHERE feed = $1`, feed).Scan(&u); err != nil {
		return Run{}, err
	}
	if s.Offline {
		return Run{}, errors.New("PATHOS runs offline (PATHOS_OFFLINE=true): import the feed from a file instead")
	}
	if s.HTTP == nil {
		return Run{}, errors.New("online feeds are not available in this process")
	}
	if feed == OSV {
		// OSV is looked up per identifier, not downloaded whole.
		return s.fetchOSV(ctx, u, by)
	}
	if feed == DepsDev {
		return s.fetchDepsDev(ctx, u, by)
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return Run{}, err
	}
	req.Header.Set("User-Agent", "PATHOS-ASPM")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return s.recordFailure(ctx, feed, by, fmt.Errorf("download failed: %w", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return s.recordFailure(ctx, feed, by, fmt.Errorf("download failed: HTTP %d from %s", resp.StatusCode, req.URL.Host))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxFeedBytes+1))
	if err != nil {
		return s.recordFailure(ctx, feed, by, fmt.Errorf("download failed: %w", err))
	}
	if len(data) > MaxFeedBytes {
		return s.recordFailure(ctx, feed, by, errors.New("the feed is larger than 64 MiB"))
	}
	return Load(ctx, s.DB, feed, "online", by, data)
}

func (s *Service) recordFailure(ctx context.Context, feed string, by *[16]byte, cause error) (Run, error) {
	var actor any
	if by != nil {
		actor = uuid.UUID(*by)
	}
	run := Run{Feed: feed, Mode: "online", Status: "failed", Error: clip(cause.Error(), 1000)}
	_ = s.DB.QueryRow(ctx, `INSERT INTO intel_feed_runs (feed, mode, status, error, triggered_by, finished_at) VALUES ($1, 'online', 'failed', $2, $3, now())
		RETURNING id, started_at`, feed, run.Error, actor).Scan(&run.ID, &run.StartedAt)
	return run, cause
}

func (s *Service) runFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, feed, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.running(ctx, feed) {
		s.fail(w, r, httpx.Conflict("an update of this feed is already running"))
		return
	}
	run, err := s.Fetch(ctx, feed, uid(p))
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "intel.feed_run", TargetType: "intel_feed", TargetID: feed, Metadata: map[string]any{"status": run.Status, "records": run.Records}})
	if err != nil {
		s.fail(w, r, httpx.E(http.StatusBadGateway, "feed_failed", "the feed update failed: "+run.Error))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, run)
}

// importFeed loads a feed file uploaded by an administrator (offline).
func (s *Service) importFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, feed, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "multipart/form-data" {
		s.fail(w, r, httpx.E(http.StatusUnsupportedMediaType, "unsupported_media_type", "upload the feed file as multipart/form-data (field \"file\")"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxFeedBytes+1<<20)
	file, _, err := r.FormFile("file")
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			s.fail(w, r, httpx.E(http.StatusRequestEntityTooLarge, "too_large", "feed files are limited to 64 MiB"))
			return
		}
		s.fail(w, r, httpx.BadRequest("a feed file is required (field \"file\")"))
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxFeedBytes+1))
	if err != nil || len(data) > MaxFeedBytes {
		s.fail(w, r, httpx.E(http.StatusRequestEntityTooLarge, "too_large", "feed files are limited to 64 MiB"))
		return
	}
	if s.running(ctx, feed) {
		s.fail(w, r, httpx.Conflict("an update of this feed is already running"))
		return
	}
	run, err := Load(ctx, s.DB, feed, "file", uid(p), data)
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "intel.feed_import", TargetType: "intel_feed", TargetID: feed, Metadata: map[string]any{"status": run.Status, "records": run.Records,
			"sha256": sha256Hex(data)}})
	if err != nil {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "invalid_feed", run.Error))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, run)
}

// CVE is the intelligence PATHOS holds about one CVE.
type CVE struct {
	ID       string     `json:"id"`
	EPSS     *float64   `json:"epss"`
	EPSSPct  *float64   `json:"epss_percentile"`
	EPSSAsOf *time.Time `json:"epss_as_of"`
	KEV      *KEVInfo   `json:"kev"`
	Findings int        `json:"open_findings"`
	// OSV is the vulnerability record (description, references, vendor
	// CVSS, CWEs, fixed versions), when known.
	OSV *Vuln `json:"osv"`
}

// KEVInfo is a KEV catalog entry.
type KEVInfo struct {
	Vendor          string     `json:"vendor"`
	Product         string     `json:"product"`
	Name            string     `json:"name"`
	Description     string     `json:"description"`
	RequiredAction  string     `json:"required_action"`
	AddedOn         *time.Time `json:"added_on"`
	DueDate         *time.Time `json:"due_date"`
	KnownRansomware string     `json:"known_ransomware"`
}

func (s *Service) cve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermFindingsRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	id := strings.ToUpper(strings.TrimSpace(r.PathValue("id")))
	if strings.HasPrefix(id, "GHSA-") {
		id = "GHSA-" + strings.ToLower(id[5:])
	}
	if !cveRe.MatchString(id) && !ghsaRe.MatchString(id) {
		s.fail(w, r, httpx.BadRequest("invalid CVE or GHSA identifier"))
		return
	}
	out := CVE{ID: id}
	_ = s.DB.QueryRow(ctx, `SELECT score::float8, percentile::float8, as_of FROM intel_epss WHERE cve_id = $1`, id).Scan(&out.EPSS, &out.EPSSPct, &out.EPSSAsOf)
	var k KEVInfo
	if err := s.DB.QueryRow(ctx, `SELECT vendor, product, name, description, required_action, added_on, due_date, known_ransomware FROM intel_kev WHERE cve_id = $1`, id).
		Scan(&k.Vendor, &k.Product, &k.Name, &k.Description, &k.RequiredAction, &k.AddedOn, &k.DueDate, &k.KnownRansomware); err == nil {
		out.KEV = &k
	}
	if v, err := LookupVuln(ctx, s.DB, id); err == nil {
		out.OSV = v
	}
	// Counted within the caller's scope only.
	f := authz.FilterFor(p, authz.PermFindingsRead)
	if f.All {
		_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM findings WHERE organization_id = $1 AND cve = $2 AND status IN ('open', 'in_progress', 'needs_review')`,
			p.OrganizationID, id).Scan(&out.Findings)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// RunBackground keeps enabled feeds current (jobs role).
func (s *Service) RunBackground(ctx context.Context) {
	if s.Offline {
		s.Log.Info("offline mode: intelligence feeds are not downloaded; import them from files")
		return
	}
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		rows, err := s.DB.Query(ctx, `SELECT f.feed FROM intel_feeds f WHERE f.enabled AND NOT EXISTS (
			SELECT 1 FROM intel_feed_runs r WHERE r.feed = f.feed AND (
			  (r.status = 'succeeded' AND r.started_at > now() - make_interval(hours => f.interval_hours))
			  OR (r.status = 'running' AND r.started_at > now() - interval '30 minutes')
			  -- back off for an hour after a failure
			  OR (r.status = 'failed' AND r.started_at > now() - interval '1 hour')))`)
		if err == nil {
			due, _ := pgx.CollectRows(rows, pgx.RowTo[string])
			for _, f := range due {
				run, err := s.Fetch(ctx, f, nil)
				if err != nil {
					s.Log.Warn("intel feed update failed", "feed", f, "err", err, "error_code", "PTH-SYNC-1020")
				} else {
					s.Log.Info("intel feed updated", "feed", f, "records", run.Records, "as_of", run.AsOf)
				}
			}
		} else if ctx.Err() == nil {
			s.Log.Warn("intel feed scheduler", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

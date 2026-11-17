package scans

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
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
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/reach"
	"pathos/internal/scanners"
	"pathos/internal/vuln"
)

// Imports bring results and SBOMs from tools PATHOS does not run into the
// same pipeline as scans: an import is a scan execution (trigger "import")
// whose results are normalised, de-duplicated, risk-scored and reviewable
// like any other (docs/api-reference/imports.md#importing-results).

// maxImportBytes bounds an uploaded report (compressed or not).
const maxImportBytes = 64 << 20

var commitRe = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

func (s *Service) registerImports(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/imports/results", s.importResults)
	mux.HandleFunc("POST /api/v1/imports/sbom", s.importSBOM)
	mux.HandleFunc("GET /api/v1/imports/history", s.importHistory)
}

// ImportJob is a recorded import.
type ImportJob struct {
	ID             uuid.UUID  `json:"id"`
	Kind           string     `json:"kind"`
	Format         string     `json:"format"`
	Tool           string     `json:"tool"`
	ScannerKey     *string    `json:"scanner_key"`
	Category       string     `json:"category"`
	RepositoryID   uuid.UUID  `json:"repository_id"`
	RepositoryName string     `json:"repository_name"`
	ScanJobID      *uuid.UUID `json:"scan_job_id"`
	ScanKey        *string    `json:"scan_key"`
	FileName       string     `json:"file_name"`
	SHA256         string     `json:"sha256"`
	SizeBytes      int64      `json:"size_bytes"`
	CommitSHA      string     `json:"commit_sha"`
	ResolveMissing bool       `json:"resolve_missing"`
	Status         string     `json:"status"`
	Records        int        `json:"records"`
	Error          string     `json:"error"`
	CreatedBy      *string    `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
}

const importSelect = `SELECT i.id, i.kind, i.format, i.tool, i.scanner_key, i.category, i.repository_id, r.full_name, i.scan_job_id, j.scan_key,
	i.file_name, i.sha256, i.size_bytes, i.commit_sha, i.resolve_missing, i.status, i.records, i.error,
	COALESCE(NULLIF(u.display_name, ''), u.email), i.created_at
	FROM import_jobs i JOIN repositories r ON r.id = i.repository_id LEFT JOIN scan_jobs j ON j.id = i.scan_job_id LEFT JOIN users u ON u.id = i.created_by`

// readUpload reads the multipart form: the file (optionally gzip) and the
// other fields.
func readUpload(w http.ResponseWriter, r *http.Request) (data []byte, name string, form map[string]string, err error) {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "multipart/form-data" {
		return nil, "", nil, httpx.E(http.StatusUnsupportedMediaType, "unsupported_media_type", "upload the report as multipart/form-data (field \"file\")")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBytes+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, "", nil, httpx.BadRequest("invalid multipart body")
	}
	form = map[string]string{}
	tooLarge := httpx.E(http.StatusRequestEntityTooLarge, "too_large", "reports are limited to 64 MiB")
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return nil, "", nil, tooLarge
			}
			return nil, "", nil, httpx.BadRequest("invalid multipart body")
		}
		if part.FormName() == "file" {
			name = part.FileName()
			data, err = io.ReadAll(io.LimitReader(part, maxImportBytes+1))
			if err != nil {
				var mbe *http.MaxBytesError
				if errors.As(err, &mbe) {
					return nil, "", nil, tooLarge
				}
				return nil, "", nil, httpx.BadRequest("could not read the file")
			}
			if len(data) > maxImportBytes {
				return nil, "", nil, tooLarge
			}
			continue
		}
		b, err := io.ReadAll(io.LimitReader(part, 4096))
		if err != nil {
			return nil, "", nil, httpx.BadRequest("invalid multipart body")
		}
		form[part.FormName()] = strings.TrimSpace(string(b))
	}
	if len(data) == 0 {
		return nil, "", nil, httpx.BadRequest("a report file is required (field \"file\")")
	}
	// Transparent gzip.
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		plain, err := gunzipLimited(data, maxRawReport)
		if err != nil {
			return nil, "", nil, httpx.BadRequest("the gzip file could not be read")
		}
		data = plain
	}
	if len(name) > 255 {
		name = name[:255]
	}
	return data, name, form, nil
}

func (s *Service) importTarget(ctx context.Context, p *authz.Principal, form map[string]string) (uuid.UUID, error) {
	repoID, err := uuid.Parse(form["repository_id"])
	if err != nil {
		return uuid.Nil, httpx.BadRequest("repository_id is required")
	}
	var archived *time.Time
	if err := s.DB.QueryRow(ctx, `SELECT archived_at FROM repositories WHERE organization_id = $1 AND id = $2`, p.OrganizationID, repoID).Scan(&archived); err != nil {
		return uuid.Nil, httpx.BadRequest("repository_id does not exist")
	}
	if archived != nil {
		return uuid.Nil, httpx.Conflict("the repository is archived")
	}
	if err := s.requireRepo(ctx, p, authz.PermScansRun, repoID); err != nil {
		return uuid.Nil, err
	}
	return repoID, nil
}

func (s *Service) recordImport(ctx context.Context, p *authz.Principal, j ImportJob) (ImportJob, error) {
	j.ID = uuid.Must(uuid.NewV7())
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO import_jobs (id, organization_id, kind, format, tool, scanner_key, category, repository_id, scan_job_id,
			file_name, sha256, size_bytes, commit_sha, resolve_missing, status, records, error, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
			j.ID, p.OrganizationID, j.Kind, j.Format, j.Tool, j.ScannerKey, j.Category, j.RepositoryID, j.ScanJobID, j.FileName, j.SHA256,
			j.SizeBytes, j.CommitSHA, j.ResolveMissing, j.Status, j.Records, truncate(j.Error, 2000), p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "import." + j.Kind, TargetType: "repository", TargetID: j.RepositoryID.String(), Outcome: map[bool]string{true: audit.Success, false: audit.Failure}[j.Status == "succeeded"],
			Metadata: map[string]any{"import_id": j.ID, "format": j.Format, "tool": j.Tool, "sha256": j.SHA256, "records": j.Records, "scan_job_id": j.ScanJobID}})
	})
	if err != nil {
		return j, err
	}
	return scanImport(s.DB.QueryRow(ctx, importSelect+` WHERE i.id = $1`, j.ID))
}

func scanImport(row pgx.Row) (ImportJob, error) {
	var j ImportJob
	err := row.Scan(&j.ID, &j.Kind, &j.Format, &j.Tool, &j.ScannerKey, &j.Category, &j.RepositoryID, &j.RepositoryName, &j.ScanJobID, &j.ScanKey,
		&j.FileName, &j.SHA256, &j.SizeBytes, &j.CommitSHA, &j.ResolveMissing, &j.Status, &j.Records, &j.Error, &j.CreatedBy, &j.CreatedAt)
	return j, err
}

func sum256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// importResults imports a SARIF 2.1, Grype JSON or PATHOS findings JSON
// report as a scan execution of the repository.
func (s *Service) importResults(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	data, name, form, err := readUpload(w, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	repoID, err := s.importTarget(ctx, p, form)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	tool := strings.TrimSpace(form["tool"])
	category := form["category"]
	if category == "" {
		category = "other"
	}
	key, err := scanners.ImportKey(category, tool)
	if err != nil {
		s.fail(w, r, httpx.BadRequest(err.Error()))
		return
	}
	commit := form["commit_sha"]
	if commit != "" && !commitRe.MatchString(commit) {
		s.fail(w, r, httpx.BadRequest("commit_sha must be a commit SHA"))
		return
	}
	ref := strings.TrimSpace(form["branch"])
	if len(ref) > 200 {
		s.fail(w, r, httpx.BadRequest("branch is too long"))
		return
	}
	resolve, _ := strconv.ParseBool(form["resolve_missing"])
	format := scanners.DetectImportFormat(data)
	job := ImportJob{Kind: "results", Format: format, Tool: truncate(tool, 100), ScannerKey: &key, Category: category, RepositoryID: repoID,
		FileName: name, SHA256: sum256(data), SizeBytes: int64(len(data)), CommitSHA: strings.ToLower(commit), ResolveMissing: resolve}
	fail := func(msg string) {
		job.Status, job.Error = "failed", msg
		if job.Format == "" {
			job.Format = "sarif"
		}
		rec, err := s.recordImport(ctx, p, job)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]any{"code": "invalid_report", "message": msg}, "import": rec})
	}
	// Validate before anything is written.
	parsed, err := scanners.Parse(key, data)
	if err != nil && len(parsed) == 0 {
		fail(safeErr(err))
		return
	}
	if _, err := s.DB.Exec(ctx, `SELECT pathos_register_import_tool($1, $2, $3)`, key, truncate(tool, 100)+" (imported)", category); err != nil {
		s.fail(w, r, err)
		return
	}
	jobID, err := s.createImportJob(ctx, p, repoID, key, tool, ref, job.CommitSHA)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	job.ScanJobID = &jobID
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(data)
	_ = zw.Close()
	n, ierr := s.Ingest(ctx, p.OrganizationID, jobID, ResultUpload{Scanner: key, Version: truncate(tool, 100), Status: "succeeded"}, gz.Bytes())
	fj, ferr := s.FinalizeWith(context.WithoutCancel(ctx), jobID, ierr != nil, errText(ierr), FinalizeOpts{NoAutoResolve: !resolve})
	if ierr != nil || ferr != nil {
		s.Log.Warn("import failed", "job_id", jobID, "ingest_err", ierr, "finalize_err", ferr)
		fail("the report could not be imported: " + safeErr(errors.Join(ierr, ferr)))
		return
	}
	if s.OnScanFinished != nil && fj.Status != "failed" {
		s.OnScanFinished(context.WithoutCancel(ctx), p.OrganizationID, jobID)
	}
	job.Status, job.Records = "succeeded", n
	rec, err := s.recordImport(ctx, p, job)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, rec)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return safeErr(err)
}

// createImportJob creates the running execution an import is recorded as.
func (s *Service) createImportJob(ctx context.Context, p *authz.Principal, repoID uuid.UUID, key, tool, ref, commit string) (uuid.UUID, error) {
	var profileVersion *uuid.UUID
	var scanBranch, defaultBranch string
	if err := s.DB.QueryRow(ctx, `SELECT COALESCE((SELECT current_version_id FROM scan_profiles WHERE id = r.scan_profile_id AND archived_at IS NULL),
		  (SELECT current_version_id FROM scan_profiles WHERE organization_id = r.organization_id AND is_default AND archived_at IS NULL)),
		  r.scan_branch, r.default_branch FROM repositories r WHERE r.id = $1`, repoID).Scan(&profileVersion, &scanBranch, &defaultBranch); err != nil {
		return uuid.Nil, err
	}
	if profileVersion == nil {
		return uuid.Nil, fmt.Errorf("%w: no scan profile available; create a default profile", ErrScanPrerequisite)
	}
	if ref == "" {
		ref = firstNonEmpty(scanBranch, defaultBranch, "import")
	}
	snapshot, _, err := configSnapshot(ctx, s.DB, *profileVersion)
	if err != nil {
		return uuid.Nil, err
	}
	id := uuid.Must(uuid.NewV7())
	_, err = s.DB.Exec(ctx, `INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, priority, status, ref, commit_sha,
		requested_by, name, config_snapshot, started_at, stage, progress)
		VALUES ($1, $2, $3, $4, 'import', 50, 'running', $5, $6, $7, $8, $9, now(), 'scanning', 50)`,
		id, p.OrganizationID, repoID, *profileVersion, ref, commit, p.UserID, truncate("Import · "+tool, 200), snapshot)
	if db.IsUniqueViolation(err) {
		return uuid.Nil, httpx.Conflict("a scan of this repository is running; import again when it has finished")
	}
	if err != nil {
		return uuid.Nil, err
	}
	_ = AddEvent(ctx, s.DB, p.OrganizationID, id, "queued", key, "info", "results imported by "+p.Email)
	return id, nil
}

// importSBOM replaces a repository's component inventory with an uploaded
// CycloneDX or SPDX JSON SBOM (licence policy applies immediately).
func (s *Service) importSBOM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	data, name, form, err := readUpload(w, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	repoID, err := s.importTarget(ctx, p, form)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	job := ImportJob{Kind: "sbom", RepositoryID: repoID, FileName: name, SHA256: sum256(data), SizeBytes: int64(len(data)), Tool: truncate(form["tool"], 100)}
	format, comps, perr := vuln.ParseSBOM(data)
	job.Format = format
	if perr != nil || len(comps) == 0 {
		if job.Format == "" {
			job.Format = "cyclonedx"
		}
		msg := "the SBOM contains no components"
		if perr != nil {
			msg = safeErr(perr)
		}
		job.Status, job.Error = "failed", msg
		rec, err := s.recordImport(ctx, p, job)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]any{"code": "invalid_sbom", "message": msg}, "import": rec})
		return
	}
	if err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := vuln.StoreImportedSBOM(ctx, tx, p.OrganizationID, repoID, data); err != nil {
			return err
		}
		// A new dependency graph changes reachability.
		_, err := reach.Update(ctx, tx, repoID)
		return err
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	job.Status, job.Records = "succeeded", len(comps)
	rec, err := s.recordImport(ctx, p, job)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, rec)
}

func (s *Service) importHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermScansRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	scope, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 2)
	args := append([]any{p.OrganizationID}, sargs...)
	where := []string{"i.organization_id = $1", scope}
	if v := r.URL.Query().Get("repository_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid repository_id"))
			return
		}
		args = append(args, id)
		where = append(where, fmt.Sprintf("i.repository_id = $%d", len(args)))
	}
	if v := r.URL.Query().Get("kind"); v != "" {
		if !slices.Contains([]string{"results", "sbom"}, v) {
			s.fail(w, r, httpx.BadRequest("kind must be results or sbom"))
			return
		}
		args = append(args, v)
		where = append(where, fmt.Sprintf("i.kind = $%d", len(args)))
	}
	rows, err := s.DB.Query(ctx, importSelect+` WHERE `+strings.Join(where, " AND ")+` ORDER BY i.created_at DESC LIMIT 200`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ImportJob, error) { return scanImport(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []ImportJob{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "formats": map[string][]string{
		"results": {"sarif", "grype", "pathos"}, "sbom": {"cyclonedx", "spdx"}}, "categories": scanners.ImportCategories})
}

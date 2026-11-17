package review

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/ai"
	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/objstore"
	"pathos/internal/repos"
	"pathos/internal/scm"
)

// SourceReader reads repository source at the scanned commit (repos.Service).
type SourceReader interface {
	ReadSourceFile(ctx context.Context, orgID, repoID uuid.UUID, ref repos.SourceRef, path string) ([]byte, string, error)
	SourceHistory(ctx context.Context, orgID, repoID uuid.UUID, commit, path string, limit int) ([]scm.Commit, error)
	BranchHead(ctx context.Context, orgID, repoID uuid.UUID, branch string) (scm.Commit, error)
}

// BlobStore keeps evidence files encrypted at rest (the source store).
type BlobStore interface {
	Put(ctx context.Context, key string, r io.Reader) (int64, error)
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, keys ...string) error
}

// Assistant produces AI suggestions (ai.Service).
type Assistant interface {
	Assist(ctx context.Context, orgID uuid.UUID, kind string, in ai.AssistInput, sendCode bool) (ai.AssistResult, error)
}

// Service holds dependencies.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	// Artifacts holds raw scanner reports (nil: inline in PostgreSQL).
	Artifacts objstore.Store
	// Source reads code at the scanned commit (nil: source unavailable).
	Source SourceReader
	// Evidence stores uploaded files (nil: file uploads disabled).
	Evidence BlobStore
	// AI provides suggestions (nil: AI assistance unavailable).
	AI Assistant
	// Now is the clock (tests).
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/human-review/catalog", s.catalog)
	mux.HandleFunc("GET /api/v1/human-review/settings", s.getSettings)
	mux.HandleFunc("PUT /api/v1/human-review/settings", s.putSettings)
	mux.HandleFunc("GET /api/v1/human-review/overview", s.overview)
	mux.HandleFunc("GET /api/v1/human-review/workload", s.workload)
	mux.HandleFunc("GET /api/v1/human-review/reviewers", s.reviewers)
	mux.HandleFunc("GET /api/v1/human-review/reports", s.reports)
	mux.HandleFunc("GET /api/v1/human-review/reports/export", s.exportCSV)
	mux.HandleFunc("POST /api/v1/human-review/sync", s.sync)

	mux.HandleFunc("GET /api/v1/human-reviews", s.list)
	mux.HandleFunc("POST /api/v1/human-reviews", s.create)
	mux.HandleFunc("POST /api/v1/human-reviews/bulk", s.bulk)
	mux.HandleFunc("GET /api/v1/human-reviews/{id}", s.get)
	mux.HandleFunc("PATCH /api/v1/human-reviews/{id}", s.patch)
	mux.HandleFunc("POST /api/v1/human-reviews/{id}/assign", s.assign)
	mux.HandleFunc("POST /api/v1/human-reviews/{id}/start", s.start)
	mux.HandleFunc("POST /api/v1/human-reviews/{id}/status", s.setStatus)
	mux.HandleFunc("PUT /api/v1/human-reviews/{id}/assessment", s.saveAssessment)
	mux.HandleFunc("PUT /api/v1/human-reviews/{id}/severity", s.setSeverity)
	mux.HandleFunc("POST /api/v1/human-reviews/{id}/decision", s.decide)
	mux.HandleFunc("POST /api/v1/human-reviews/{id}/independent-review", s.independentReview)
	mux.HandleFunc("POST /api/v1/human-reviews/{id}/reopen", s.reopen)
	mux.HandleFunc("PUT /api/v1/human-reviews/{id}/remediation", s.setRemediation)
	mux.HandleFunc("GET /api/v1/human-reviews/{id}/history", s.history)
	mux.HandleFunc("GET /api/v1/human-reviews/{id}/comments", s.listComments)
	mux.HandleFunc("POST /api/v1/human-reviews/{id}/comments", s.addComment)
	mux.HandleFunc("GET /api/v1/human-reviews/{id}/source", s.source)
	mux.HandleFunc("GET /api/v1/human-reviews/{id}/source/commits", s.sourceCommits)
	mux.HandleFunc("GET /api/v1/human-reviews/{id}/dataflow", s.dataflow)
	mux.HandleFunc("GET /api/v1/human-reviews/{id}/evidence", s.listEvidence)
	mux.HandleFunc("POST /api/v1/human-reviews/{id}/evidence", s.uploadEvidence)
	mux.HandleFunc("GET /api/v1/human-reviews/{id}/evidence/{eid}/content", s.downloadEvidence)
	mux.HandleFunc("DELETE /api/v1/human-reviews/{id}/evidence/{eid}", s.deleteEvidence)
	mux.HandleFunc("GET /api/v1/human-reviews/{id}/ai", s.listRecommendations)
	mux.HandleFunc("POST /api/v1/human-reviews/{id}/ai", s.requestRecommendation)
	mux.HandleFunc("POST /api/v1/human-reviews/{id}/ai/{rid}/patch-decision", s.decidePatch)
	mux.HandleFunc("GET /api/v1/human-reviews/{id}/ai/{rid}/patch", s.downloadPatch)
}

var errNotFound = errors.New("not found")

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	case db.IsForeignKeyViolation(err):
		err = httpx.BadRequest("a referenced user or item does not exist")
	}
	httpx.WriteError(w, r, s.Log, err)
}

func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		return uuid.Nil, errNotFound
	}
	return id, nil
}

func (s *Service) catalog(w http.ResponseWriter, r *http.Request) {
	if !s.Principal(r.Context()).HasAnywhere(authz.PermReviewsRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, TheCatalog())
}

// --- review records and authorization -------------------------------------

// rec is the authorization-relevant state of one review.
type rec struct {
	ID, OrgID, FindingID, RepoID uuid.UUID
	Key                          string
	Status                       string
	Disposition                  *string
	Remediation                  *string
	Priority                     string
	ReviewerID, IndependentID    *uuid.UUID
	Round                        int
	OriginalSeverity             string
	AssessedSeverity             *string
	Category                     string
	CommitSHA, Branch            string
	SnapshotID, ScanJobID        *uuid.UUID
	FilePath                     string
	StartLine                    *int
	ScannerKey                   string
	Fingerprint                  string
	DueAt                        *time.Time
	FindingStatus                string
	RiskAcceptanceID             *uuid.UUID
}

const recSelect = `SELECT h.id, h.organization_id, h.finding_id, h.repository_id, h.review_key, h.status, h.disposition, h.remediation_status,
	h.priority, h.reviewer_id, h.independent_reviewer_id, h.round, h.original_severity, h.assessed_severity, f.category, h.commit_sha, h.branch,
	h.snapshot_id, h.scan_job_id, h.file_path, h.start_line, h.scanner_key, f.fingerprint, h.due_at, f.status, h.risk_acceptance_id
	FROM human_reviews h JOIN findings f ON f.id = h.finding_id`

func scanRec(row pgx.Row) (rec, error) {
	var v rec
	err := row.Scan(&v.ID, &v.OrgID, &v.FindingID, &v.RepoID, &v.Key, &v.Status, &v.Disposition, &v.Remediation, &v.Priority, &v.ReviewerID,
		&v.IndependentID, &v.Round, &v.OriginalSeverity, &v.AssessedSeverity, &v.Category, &v.CommitSHA, &v.Branch, &v.SnapshotID, &v.ScanJobID,
		&v.FilePath, &v.StartLine, &v.ScannerKey, &v.Fingerprint, &v.DueAt, &v.FindingStatus, &v.RiskAcceptanceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, errNotFound
	}
	return v, err
}

// EffectiveSeverity is the human-assessed severity when set, else the
// scanner's.
func (v rec) EffectiveSeverity() string {
	if v.AssessedSeverity != nil {
		return *v.AssessedSeverity
	}
	return v.OriginalSeverity
}

func repoScope(id uuid.UUID) authz.Scope { return authz.Scope{Type: authz.ScopeRepository, ID: id} }

// isWorker reports whether p takes part in reviews anywhere (beyond
// read-only access).
func isWorker(p *authz.Principal) bool {
	return p.HasAnywhere(authz.PermReviewsAssess) || p.HasAnywhere(authz.PermReviewsAssign) || p.HasAnywhere(authz.PermReviewsApprove)
}

// load fetches a review and checks that p may read it. Read-only users see
// completed assessments only. Reviews outside p's scope are not found.
func (s *Service) load(ctx context.Context, q db.Querier, p *authz.Principal, id uuid.UUID, lock bool) (rec, error) {
	if p == nil {
		return rec{}, authz.ErrForbidden
	}
	sql := recSelect + ` WHERE h.organization_id = $1 AND (h.id = $2 OR h.finding_id = $2)`
	if lock {
		sql += " FOR UPDATE OF h"
	}
	v, err := scanRec(q.QueryRow(ctx, sql, p.OrganizationID, id))
	if err != nil {
		return v, err
	}
	ok, err := s.Authz.Can(ctx, p, authz.PermReviewsRead, repoScope(v.RepoID))
	if err != nil {
		return v, err
	}
	if !ok {
		return v, errNotFound
	}
	if !isWorker(p) && v.Status != StatusCompleted {
		return v, errNotFound
	}
	return v, nil
}

func (s *Service) can(ctx context.Context, p *authz.Principal, perm authz.Permission, repo uuid.UUID) bool {
	ok, err := s.Authz.Can(ctx, p, perm, repoScope(repo))
	return err == nil && ok
}

func (s *Service) require(ctx context.Context, p *authz.Principal, perm authz.Permission, repo uuid.UUID) error {
	return s.Authz.Require(ctx, p, perm, repoScope(repo))
}

// requireAssessor checks that p may work on v's assessment: reviews.assess
// on the repository and assigned to v (or a review manager, or the
// configuration lets unassigned reviewers assess).
func (s *Service) requireAssessor(ctx context.Context, q db.Querier, p *authz.Principal, v rec) error {
	if err := s.require(ctx, p, authz.PermReviewsAssess, v.RepoID); err != nil {
		return err
	}
	if v.ReviewerID != nil && *v.ReviewerID == p.UserID {
		return nil
	}
	if s.can(ctx, p, authz.PermReviewsAssign, v.RepoID) {
		return nil
	}
	st, err := loadSettings(ctx, q, p.OrganizationID)
	if err != nil {
		return err
	}
	if st.UnassignedCanAssess {
		return nil
	}
	if v.ReviewerID == nil {
		return httpx.E(http.StatusForbidden, "forbidden", "assign the review to yourself first (Start review)")
	}
	return httpx.E(http.StatusForbidden, "forbidden", "this review is assigned to another analyst")
}

// requireEditable rejects changes to reviews that are closed or locked
// while an independent reviewer decides.
func requireEditable(v rec) error {
	switch v.Status {
	case StatusCompleted:
		return httpx.Conflict("the review is completed; reopen it to make changes")
	case StatusAwaitingIndependent:
		return httpx.Conflict("the review awaits independent review and cannot be changed")
	}
	return nil
}

// --- history and audit ------------------------------------------------------

func jsonValue(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	if string(b) == "null" {
		return nil
	}
	return b
}

// hist appends one immutable history entry.
func hist(ctx context.Context, q db.Querier, v rec, actor *uuid.UUID, action, field string, old, new any, note string) error {
	if len(note) > 8000 {
		note = note[:8000]
	}
	_, err := q.Exec(ctx, `INSERT INTO human_review_history (organization_id, review_id, finding_id, round, actor_id, action, field, old_value, new_value, note)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, v.OrgID, v.ID, v.FindingID, v.Round, actor, action, field, jsonValue(old), jsonValue(new), note)
	return err
}

func (s *Service) audit(ctx context.Context, q db.Querier, p *authz.Principal, action string, v rec, meta map[string]any) error {
	if meta == nil {
		meta = map[string]any{}
	}
	meta["review_key"] = v.Key
	meta["finding_id"] = v.FindingID
	return audit.Write(ctx, q, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "human_review." + action, TargetType: "human_review", TargetID: v.ID.String(), Metadata: meta})
}

func strPtr(s string) *string { return &s }

func trimmed(s string, max int) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return "", httpx.BadRequest("text is too long")
	}
	return s, nil
}

// activeUser checks that id is an active user of the organization.
func activeUser(ctx context.Context, q db.Querier, orgID, id uuid.UUID) error {
	var status string
	if err := q.QueryRow(ctx, `SELECT status FROM users WHERE organization_id = $1 AND id = $2`, orgID, id).Scan(&status); err != nil || status != "active" {
		return httpx.BadRequest("the user must be an active user")
	}
	return nil
}

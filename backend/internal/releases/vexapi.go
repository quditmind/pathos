package releases

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/vuln"
)

// maxVEXBytes bounds an imported document.
const maxVEXBytes = 10 << 20

// vexFindingCols reads a finding (current decision) for export: the
// latest status reason, the approved risk acceptance justification and the
// component purl from the inventory.
const vexFindingCols = `f.cve, f.package_name, f.package_version,
	COALESCE((SELECT c.purl FROM sbom_components c WHERE c.repository_id = f.repository_id AND c.name = f.package_name
	          AND c.version = f.package_version AND c.purl <> '' LIMIT 1), ''),
	f.fixed_version, f.status, f.reachability,
	COALESCE(CASE WHEN f.status = 'accepted_risk' THEN
	  (SELECT ra.justification FROM risk_acceptances ra WHERE ra.finding_id = f.id AND ra.status = 'approved' ORDER BY ra.created_at DESC LIMIT 1)
	ELSE (SELECT h.reason FROM finding_status_history h WHERE h.finding_id = f.id AND h.to_status = f.status ORDER BY h.created_at DESC LIMIT 1) END, ''),
	f.accepted_until`

func scanVEXFindings(rows pgx.Rows) ([]VEXFinding, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (VEXFinding, error) {
		var f VEXFinding
		err := row.Scan(&f.Vulnerability, &f.PackageName, &f.PackageVersion, &f.PURL, &f.FixedVersion, &f.Status, &f.Reachability, &f.Reason, &f.AcceptedUntil)
		return f, err
	})
}

func (s *Service) writeVEX(w http.ResponseWriter, r *http.Request, p *authz.Principal, subject, subjectVersion string, fs []VEXFinding) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "openvex"
	}
	stmts := Statements(fs)
	var out []byte
	var err error
	ct, ext := "application/json", ".openvex.json"
	switch format {
	case "openvex":
		docID := "https://pathos.local/vex/" + uuid.NewString()
		out, err = OpenVEXDocument("PATHOS ("+p.Email+")", docID, stmts, time.Now())
	case "cyclonedx":
		ct, ext = "application/vnd.cyclonedx+json", ".vex.cdx.json"
		out, err = CycloneDXVEXDocument(subject, subjectVersion, stmts, time.Now())
	default:
		s.fail(w, r, httpx.BadRequest("format must be openvex or cyclonedx"))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = audit.Write(r.Context(), s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "vex.export", TargetType: "vex", TargetID: subject, Metadata: map[string]any{"format": format, "version": subjectVersion, "statements": len(stmts)}})
	name := safeFilename(subject)
	if subjectVersion != "" {
		name += "-" + safeFilename(subjectVersion)
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+ext+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// #nosec G705 -- a JSON document served as an attachment with a JSON content type and nosniff, never rendered as HTML
	_, _ = w.Write(out)
}

// exportRepoVEX exports statements for a repository's findings with a
// vulnerability identifier.
func (s *Service) exportRepoVEX(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermFindingsExport, id); err != nil {
		s.fail(w, r, err)
		return
	}
	var name string
	if err := s.DB.QueryRow(ctx, `SELECT full_name FROM repositories WHERE id = $1`, id).Scan(&name); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT `+vexFindingCols+` FROM findings f
		WHERE f.repository_id = $1 AND f.scan_target_id IS NULL AND f.cve <> '' ORDER BY f.cve`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	fs, err := scanVEXFindings(rows)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeVEX(w, r, p, name, "", fs)
}

// exportVersionVEX exports statements for the findings frozen in an
// application version, with each finding's current decision. Only
// repositories the caller may export findings for are included.
func (s *Service) exportVersionVEX(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, a, err := s.appForRead(r, authz.PermFindingsExport)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.version(r, p.OrganizationID, a)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var allowed []uuid.UUID
	rows, err := s.DB.Query(ctx, `SELECT repository_id FROM application_version_repositories WHERE version_id = $1`, v.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, rid := range ids {
		if s.canOnRepo(ctx, p, authz.PermFindingsExport, rid) {
			allowed = append(allowed, rid)
		}
	}
	if len(allowed) == 0 {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	// Frozen findings whose finding still exists use the current decision;
	// deleted ones keep the status they had at release.
	rows, err = s.DB.Query(ctx, `
		SELECT `+vexFindingCols+` FROM application_version_findings x JOIN findings f ON f.id = x.finding_id
		WHERE x.version_id = $1 AND x.repository_id = ANY($2) AND f.cve <> ''
		UNION ALL
		SELECT x.cve, x.package_name, x.package_version,
		       COALESCE((SELECT c.purl FROM application_version_components c WHERE c.version_id = x.version_id AND c.repository_id = x.repository_id
		                 AND c.name = x.package_name AND c.version = x.package_version AND c.purl <> '' LIMIT 1), ''),
		       x.fixed_version, x.status, 'unknown', '', NULL::timestamptz
		FROM application_version_findings x WHERE x.version_id = $1 AND x.repository_id = ANY($2) AND x.finding_id IS NULL AND x.cve <> ''`, v.ID, allowed)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	fs, err := scanVEXFindings(rows)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeVEX(w, r, p, a.Name, v.Version, fs)
}

func readVEX(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxVEXBytes))
	if err != nil {
		return nil, httpx.E(http.StatusRequestEntityTooLarge, "too_large", "the VEX document is larger than 10 MB")
	}
	return raw, nil
}

// ImportResult summarizes an import.
type ImportResult struct {
	ImportID    uuid.UUID `json:"import_id"`
	Format      string    `json:"format"`
	Statements  int       `json:"statements"`
	Matched     int       `json:"matched"`
	Suggestions int       `json:"suggestions"`
	// Informational statements (affected, under_investigation) are counted
	// but never suggested: PATHOS already tracks those findings as open.
	Informational int `json:"informational"`
	// Unmatched statements name no finding the importer may triage.
	Unmatched int `json:"unmatched"`
}

type candidateRow struct {
	id, repo uuid.UUID
	status   string
	cand     Candidate
}

func (s *Service) importRepoVEX(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermFindingsTriage, id); err != nil {
		s.fail(w, r, err)
		return
	}
	raw, err := readVEX(w, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.importVEX(ctx, p, raw, r.URL.Query().Get("filename"), &id, nil, []uuid.UUID{id})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, res)
}

func (s *Service) importVersionVEX(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, a, err := s.appForRead(r, authz.PermFindingsTriage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.version(r, p.OrganizationID, a)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT repository_id FROM application_version_repositories WHERE version_id = $1`, v.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var allowed []uuid.UUID
	for _, rid := range ids {
		if s.canOnRepo(ctx, p, authz.PermFindingsTriage, rid) {
			allowed = append(allowed, rid)
		}
	}
	if len(allowed) == 0 {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	raw, err := readVEX(w, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.importVEX(ctx, p, raw, r.URL.Query().Get("filename"), nil, &v.ID, allowed)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, res)
}

// importVEX parses a document and records pending suggestions for
// not_affected and fixed statements that match findings in repos. It never
// changes a finding.
func (s *Service) importVEX(ctx context.Context, p *authz.Principal, raw []byte, filename string, repoID, versionID *uuid.UUID, repos []uuid.UUID) (ImportResult, error) {
	format, author, stmts, err := ParseVEX(raw)
	if err != nil {
		return ImportResult{}, httpx.BadRequest(err.Error())
	}
	sum := sha256.Sum256(raw)
	if len(filename) > 255 {
		filename = filename[:255]
	}
	if len(author) > 300 {
		author = author[:300]
	}
	res := ImportResult{ImportID: uuid.Must(uuid.NewV7()), Format: format, Statements: len(stmts)}
	// Candidate findings: vulnerabilities of the repositories, with the
	// purls of their components.
	rows, err := s.DB.Query(ctx, `SELECT f.id, f.repository_id, f.status, f.cve, f.rule_id, f.package_name, f.package_version,
		  COALESCE((SELECT array_agg(DISTINCT c.purl) FROM sbom_components c WHERE c.repository_id = f.repository_id
		            AND c.name = f.package_name AND c.version = f.package_version AND c.purl <> ''), '{}')
		FROM findings f WHERE f.organization_id = $1 AND f.repository_id = ANY($2) AND f.scan_target_id IS NULL
		  AND (f.cve <> '' OR f.category IN ('sca', 'container'))`, p.OrganizationID, repos)
	if err != nil {
		return res, err
	}
	cands, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (candidateRow, error) {
		var c candidateRow
		err := row.Scan(&c.id, &c.repo, &c.status, &c.cand.Vulnerability, &c.cand.RuleID, &c.cand.PackageName, &c.cand.PackageVersion, &c.cand.PURLs)
		return c, err
	})
	if err != nil {
		return res, err
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO vex_imports (id, organization_id, repository_id, application_version_id, format, filename,
			document_sha256, author, statements, imported_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			res.ImportID, p.OrganizationID, repoID, versionID, format, filename, hex.EncodeToString(sum[:]), author, len(stmts), p.UserID); err != nil {
			return err
		}
		for _, st := range stmts {
			matched := false
			for _, c := range cands {
				if !st.Matches(c.cand) {
					continue
				}
				matched = true
				res.Matched++
				if st.Status != VEXNotAffected && st.Status != VEXFixed {
					continue
				}
				// Nothing to suggest when the finding already says so.
				if (st.Status == VEXNotAffected && c.status == "false_positive") || (st.Status == VEXFixed && c.status == "fixed") {
					continue
				}
				impact := st.ImpactStatement
				if impact == "" {
					impact = st.ActionStatement
				}
				tag, err := tx.Exec(ctx, `INSERT INTO vex_suggestions (id, organization_id, import_id, finding_id, repository_id, vulnerability,
					vex_status, justification, impact_statement, requested_by)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
					ON CONFLICT (finding_id, vex_status) WHERE status = 'pending' DO NOTHING`,
					uuid.Must(uuid.NewV7()), p.OrganizationID, res.ImportID, c.id, c.repo, clip(st.Vulnerability, 200), st.Status,
					clip(st.Justification, 200), clip(impact, 4000), p.UserID)
				if err != nil {
					return err
				}
				res.Suggestions += int(tag.RowsAffected())
			}
			switch {
			case !matched:
				res.Unmatched++
			case st.Status != VEXNotAffected && st.Status != VEXFixed:
				res.Informational++
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE vex_imports SET matched = $2 WHERE id = $1`, res.ImportID, res.Matched); err != nil {
			return err
		}
		meta := map[string]any{"format": format, "sha256": hex.EncodeToString(sum[:]), "statements": len(stmts), "matched": res.Matched, "suggestions": res.Suggestions}
		target := ""
		if repoID != nil {
			target, meta["repository_id"] = repoID.String(), repoID.String()
		}
		if versionID != nil {
			target, meta["application_version_id"] = versionID.String(), versionID.String()
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "vex.import", TargetType: "vex_import", TargetID: res.ImportID.String(), Metadata: map[string]any{"target": target, "summary": meta}})
	})
	return res, err
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// VEXImport is an import record.
type VEXImport struct {
	ID                   uuid.UUID  `json:"id"`
	RepositoryID         *uuid.UUID `json:"repository_id"`
	Repository           string     `json:"repository"`
	ApplicationVersionID *uuid.UUID `json:"application_version_id"`
	Application          string     `json:"application"`
	Version              string     `json:"version"`
	Format               string     `json:"format"`
	Filename             string     `json:"filename"`
	SHA256               string     `json:"document_sha256"`
	Author               string     `json:"author"`
	Statements           int        `json:"statements"`
	Matched              int        `json:"matched"`
	Pending              int        `json:"pending"`
	ImportedBy           string     `json:"imported_by"`
	CreatedAt            time.Time  `json:"created_at"`
}

// listImports lists imports; the caller sees those of repositories (or
// versions) within the findings.read scope.
func (s *Service) listImports(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermFindingsRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	scope, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 2)
	rows, err := s.DB.Query(ctx, `SELECT i.id, i.repository_id, COALESCE(rr.full_name, ''), i.application_version_id, COALESCE(a.name, ''),
		  COALESCE(v.version, ''), i.format, i.filename, i.document_sha256, i.author, i.statements, i.matched,
		  (SELECT count(*) FROM vex_suggestions s WHERE s.import_id = i.id AND s.status = 'pending'),
		  COALESCE(NULLIF(u.display_name, ''), u.email, ''), i.created_at
		FROM vex_imports i LEFT JOIN repositories rr ON rr.id = i.repository_id
		LEFT JOIN application_versions v ON v.id = i.application_version_id LEFT JOIN applications a ON a.id = v.application_id
		LEFT JOIN users u ON u.id = i.imported_by
		WHERE i.organization_id = $1 AND EXISTS (SELECT 1 FROM repositories r WHERE (r.id = i.repository_id
		  OR r.id IN (SELECT repository_id FROM application_version_repositories x WHERE x.version_id = i.application_version_id)) AND `+scope+`)
		ORDER BY i.created_at DESC LIMIT 200`, append([]any{p.OrganizationID}, sargs...)...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[VEXImport])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []VEXImport{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// Suggestion is a VEX statement awaiting (or after) review.
type Suggestion struct {
	ID              uuid.UUID  `json:"id"`
	ImportID        uuid.UUID  `json:"import_id"`
	FindingID       uuid.UUID  `json:"finding_id"`
	FindingTitle    string     `json:"finding_title"`
	FindingStatus   string     `json:"finding_status"`
	Severity        string     `json:"severity"`
	PackageName     string     `json:"package_name"`
	PackageVersion  string     `json:"package_version"`
	RepositoryID    uuid.UUID  `json:"repository_id"`
	Repository      string     `json:"repository"`
	Vulnerability   string     `json:"vulnerability"`
	VEXStatus       string     `json:"vex_status"`
	Justification   string     `json:"justification"`
	ImpactStatement string     `json:"impact_statement"`
	Status          string     `json:"status"`
	RequestedByID   uuid.UUID  `json:"requested_by_id"`
	RequestedBy     string     `json:"requested_by"`
	DecidedBy       string     `json:"decided_by"`
	DecidedAt       *time.Time `json:"decided_at"`
	DecisionNote    string     `json:"decision_note"`
	CreatedAt       time.Time  `json:"created_at"`
	CanDecide       bool       `json:"can_decide"`
	CannotReason    string     `json:"cannot_decide_reason,omitempty"`
}

const suggestionSelect = `SELECT s.id, s.import_id, s.finding_id, f.title, f.status, f.severity, f.package_name, f.package_version,
	  s.repository_id, r.full_name, s.vulnerability, s.vex_status, s.justification, s.impact_statement, s.status, s.requested_by,
	  COALESCE(NULLIF(u.display_name, ''), u.email, ''), COALESCE(NULLIF(d.display_name, ''), d.email, ''), s.decided_at,
	  s.decision_note, s.created_at
	FROM vex_suggestions s JOIN findings f ON f.id = s.finding_id JOIN repositories r ON r.id = s.repository_id
	LEFT JOIN users u ON u.id = s.requested_by LEFT JOIN users d ON d.id = s.decided_by`

func scanSuggestion(row pgx.Row) (Suggestion, error) {
	var x Suggestion
	err := row.Scan(&x.ID, &x.ImportID, &x.FindingID, &x.FindingTitle, &x.FindingStatus, &x.Severity, &x.PackageName, &x.PackageVersion,
		&x.RepositoryID, &x.Repository, &x.Vulnerability, &x.VEXStatus, &x.Justification, &x.ImpactStatement, &x.Status, &x.RequestedByID,
		&x.RequestedBy, &x.DecidedBy, &x.DecidedAt, &x.DecisionNote, &x.CreatedAt)
	return x, err
}

func (s *Service) listSuggestions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermFindingsRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "approved", "rejected", "superseded":
	default:
		s.fail(w, r, httpx.BadRequest("invalid status"))
		return
	}
	var importID *uuid.UUID
	if v := r.URL.Query().Get("import_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid import_id"))
			return
		}
		importID = &id
	}
	scope, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 4)
	rows, err := s.DB.Query(ctx, suggestionSelect+` WHERE s.organization_id = $1 AND ($2 = '' OR s.status = $2)
		AND ($3::uuid IS NULL OR s.import_id = $3) AND `+scope+` ORDER BY s.created_at DESC LIMIT 500`,
		append([]any{p.OrganizationID, status, importID}, sargs...)...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Suggestion, error) { return scanSuggestion(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	can := map[uuid.UUID]bool{}
	for i := range out {
		x := &out[i]
		if x.Status != "pending" {
			continue
		}
		c, ok := can[x.RepositoryID]
		if !ok {
			c = s.canOnRepo(ctx, p, authz.PermFindingsAcceptRisk, x.RepositoryID)
			can[x.RepositoryID] = c
		}
		switch {
		case x.RequestedByID == p.UserID:
			x.CannotReason = "You imported this statement; another reviewer must decide it."
		case !c:
			x.CannotReason = "Deciding requires findings.accept_risk on the repository."
		default:
			x.CanDecide = true
		}
	}
	if out == nil {
		out = []Suggestion{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type decisionRequest struct {
	Note string `json:"note"`
}

// decideSuggestion approves or rejects a pending suggestion. Approval
// needs findings.accept_risk on the repository and a reviewer other than
// the importer. Approving not_affected closes the finding as a false
// positive (with history and audit, like a manual change); approving fixed
// records the statement only: findings are resolved by scans.
func (s *Service) decideSuggestion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	action := r.PathValue("action")
	if action != "approve" && action != "reject" {
		s.fail(w, r, httpx.ErrNotFound)
		return
	}
	var req decisionRequest
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, &req); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if len(req.Note) > 2000 {
		s.fail(w, r, httpx.BadRequest("note must be at most 2000 characters"))
		return
	}
	var out Suggestion
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		x, err := scanSuggestion(tx.QueryRow(ctx, suggestionSelect+` WHERE s.organization_id = $1 AND s.id = $2 FOR UPDATE OF s`, p.OrganizationID, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		if !s.canOnRepo(ctx, p, authz.PermFindingsRead, x.RepositoryID) {
			return errNotFound
		}
		if err := s.Authz.Require(ctx, p, authz.PermFindingsAcceptRisk, repoScope(x.RepositoryID)); err != nil {
			return err
		}
		if x.Status != "pending" {
			return httpx.Conflict("this suggestion was already " + x.Status)
		}
		if x.RequestedByID == p.UserID {
			return httpx.E(http.StatusForbidden, "four_eyes", "the person who imported a VEX statement cannot decide it")
		}
		status := "rejected"
		if action == "approve" {
			status = "approved"
			if x.VEXStatus == VEXNotAffected {
				if err := s.closeAsNotAffected(ctx, tx, p, x); err != nil {
					return err
				}
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE vex_suggestions SET status = $2, decided_by = $3, decided_at = now(), decision_note = $4 WHERE id = $1`,
			x.ID, status, p.UserID, req.Note); err != nil {
			return err
		}
		meta := map[string]any{"finding_id": x.FindingID, "vulnerability": x.Vulnerability, "vex_status": x.VEXStatus, "note": req.Note}
		if action == "approve" && x.VEXStatus == VEXFixed {
			meta["effect"] = "informational: the finding is resolved only when a scan no longer detects it"
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "vex_suggestion." + action, TargetType: "vex_suggestion", TargetID: x.ID.String(), Metadata: meta}); err != nil {
			return err
		}
		out, err = scanSuggestion(tx.QueryRow(ctx, suggestionSelect+` WHERE s.id = $1`, x.ID))
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// closeAsNotAffected applies an approved not_affected statement: the
// finding becomes a false positive through the same lifecycle path as a
// manual change (history row via the change context, audit entry).
func (s *Service) closeAsNotAffected(ctx context.Context, tx pgx.Tx, p *authz.Principal, x Suggestion) error {
	var from string
	if err := tx.QueryRow(ctx, `SELECT status FROM findings WHERE id = $1 FOR UPDATE`, x.FindingID).Scan(&from); err != nil {
		return err
	}
	if from == "false_positive" {
		return nil
	}
	if !vuln.CanTransition(from, "false_positive") {
		return httpx.Conflict("the finding is " + strings.ReplaceAll(from, "_", " ") + " and cannot be closed as not affected; reject this suggestion or reopen the finding first")
	}
	reason := "VEX not_affected (" + x.Vulnerability + ")"
	if x.Justification != "" {
		reason += ": " + x.Justification
	}
	if x.ImpactStatement != "" {
		reason += ". " + x.ImpactStatement
	}
	reason += ". Imported by " + x.RequestedBy + ", approved by " + p.Email
	uid := [16]byte(p.UserID)
	if err := db.SetChangeContext(ctx, tx, &uid, "user", reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'false_positive', updated_at = now() WHERE id = $1`, x.FindingID); err != nil {
		return err
	}
	return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "finding.status", TargetType: "finding", TargetID: x.FindingID.String(),
		Metadata: map[string]any{"from": from, "to": "false_positive", "reason": clip(reason, 2000), "vex_suggestion_id": x.ID}})
}

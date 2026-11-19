package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/depfix"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// FindingRef is a finding of an item.
type FindingRef struct {
	ID          uuid.UUID  `json:"id"`
	Title       string     `json:"title"`
	Severity    string     `json:"severity"`
	Status      string     `json:"status"`
	Category    string     `json:"category"`
	RuleID      string     `json:"rule_id"`
	FilePath    string     `json:"file_path"`
	StartLine   *int       `json:"start_line"`
	ScannerKeys []string   `json:"scanner_keys"`
	SLADueAt    *time.Time `json:"sla_due_at"`
}

// Guidance is one piece of secure fix guidance with its evidence label
// (rule 5): verified (a worker proved it), scanner (the tool's advisory),
// ai_inferred (an AI review) or human (a Human Eye reviewer).
type Guidance struct {
	Source   string `json:"source"`
	Evidence string `json:"evidence"`
	Title    string `json:"title"`
	Text     string `json:"text"`
	Link     string `json:"link,omitempty"`
}

// Detail is an item with its findings, guidance, fix pull requests and
// verifications.
type Detail struct {
	Item
	Findings                []FindingRef   `json:"findings"`
	Guidance                []Guidance     `json:"guidance"`
	FixPRs                  []FixPRRef     `json:"fix_prs"`
	Verifications           []Verification `json:"verifications"`
	CanVerify               bool           `json:"can_verify"`
	VerifyUnavailableReason string         `json:"verify_unavailable_reason"`
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := itemID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	it, err := s.loadItem(ctx, p, id, authz.PermRemediationRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := Detail{Item: it}
	if d.Findings, err = s.itemFindings(ctx, id); err != nil {
		s.fail(w, r, err)
		return
	}
	if d.Guidance, err = s.guidance(ctx, id); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT x.id, x.status, x.pr_url, x.kind, x.created_at FROM fix_pull_requests x
		WHERE x.id = (SELECT fix_pull_request_id FROM remediation_items WHERE id = $1)
		   OR x.id IN (SELECT ff.fix_pull_request_id FROM fix_pull_request_findings ff JOIN remediation_item_findings rf ON rf.finding_id = ff.finding_id
		               WHERE rf.item_id = $1)
		ORDER BY x.created_at DESC`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.FixPRs, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (FixPRRef, error) {
		var f FixPRRef
		return f, r.Scan(&f.ID, &f.Status, &f.PRURL, &f.Kind, &f.CreatedAt)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if d.FixPRs == nil {
		d.FixPRs = []FixPRRef{}
	}
	if d.Verifications, err = s.listVerifications(ctx, id); err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.plan(ctx, p.OrganizationID, it, nil); err != nil {
		d.VerifyUnavailableReason = reasonOf(err)
	} else {
		d.CanVerify = true
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (s *Service) itemFindings(ctx context.Context, itemID uuid.UUID) ([]FindingRef, error) {
	rows, err := s.DB.Query(ctx, `SELECT f.id, f.title, f.severity, f.status, f.category, f.rule_id, f.file_path, f.start_line, f.scanner_keys, f.sla_due_at
		FROM remediation_item_findings x JOIN findings f ON f.id = x.finding_id WHERE x.item_id = $1
		ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.severity), f.file_path, f.start_line`, itemID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (FindingRef, error) {
		var f FindingRef
		return f, r.Scan(&f.ID, &f.Title, &f.Severity, &f.Status, &f.Category, &f.RuleID, &f.FilePath, &f.StartLine, &f.ScannerKeys, &f.SLADueAt)
	})
	if out == nil {
		out = []FindingRef{}
	}
	return out, err
}

// guidance gathers the secure fix guidance of an item's findings from what
// PATHOS already has; nothing is generated here.
func (s *Service) guidance(ctx context.Context, itemID uuid.UUID) ([]Guidance, error) {
	out := []Guidance{}
	// Verified AI fixes (a worker proved the scanner no longer reports the
	// finding on the patched file).
	rows, err := s.DB.Query(ctx, `SELECT p.id, p.finding_id, p.summary, p.file_path, p.scanner_key FROM ai_fix_proposals p
		JOIN remediation_item_findings x ON x.finding_id = p.finding_id
		WHERE x.item_id = $1 AND p.status = 'verified' ORDER BY p.finished_at DESC NULLS LAST LIMIT 10`, itemID)
	if err != nil {
		return nil, err
	}
	type fix struct {
		id, finding        uuid.UUID
		summary, file, key string
	}
	fixes, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (fix, error) {
		var f fix
		return f, r.Scan(&f.id, &f.finding, &f.summary, &f.file, &f.key)
	})
	if err != nil {
		return nil, err
	}
	for _, f := range fixes {
		out = append(out, Guidance{Source: "verified_ai_fix", Evidence: "verified", Title: "Verified fix for " + f.file,
			Text: clip(f.summary, 2000) + "\n\nProposed by AI and verified by PATHOS: the original check no longer reports the finding on the patched file.",
			Link: "/vulnerabilities/" + f.finding.String()})
	}
	// Dependency upgrades (depfix picks the target version from the
	// scanner's fixed versions).
	rows, err = s.DB.Query(ctx, `SELECT DISTINCT f.package_name, f.package_version, f.fixed_version FROM remediation_item_findings x
		JOIN findings f ON f.id = x.finding_id WHERE x.item_id = $1 AND f.category = 'sca' AND f.package_name <> '' AND f.fixed_version <> ''
		ORDER BY 1 LIMIT 50`, itemID)
	if err != nil {
		return nil, err
	}
	type dep struct{ name, cur, fixed string }
	deps, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (dep, error) {
		var d dep
		return d, r.Scan(&d.name, &d.cur, &d.fixed)
	})
	if err != nil {
		return nil, err
	}
	for _, d := range deps {
		g := Guidance{Source: "dependency_upgrade", Evidence: "scanner", Title: "Upgrade " + d.name}
		if t := depfix.PickTarget(d.cur, d.fixed); t != "" {
			g.Text = fmt.Sprintf("Upgrade %s from %s to %s (the lowest fixed version the advisory lists). An automatic fix pull request can do this where the repository allows it.", d.name, d.cur, t)
		} else {
			g.Text = fmt.Sprintf("Upgrade %s from %s to a fixed version: %s.", d.name, d.cur, clip(d.fixed, 300))
		}
		out = append(out, g)
	}
	// Human Eye reviewers' remediation guidance.
	var human []byte
	err = s.DB.QueryRow(ctx, `SELECT a.remediation FROM human_review_assessments a JOIN human_reviews h ON h.id = a.review_id
		JOIN remediation_item_findings x ON x.finding_id = h.finding_id WHERE x.item_id = $1 AND a.remediation <> '{}'::jsonb
		ORDER BY a.updated_at DESC LIMIT 1`, itemID).Scan(&human)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if txt := jsonText(human); txt != "" {
		out = append(out, Guidance{Source: "human_review", Evidence: "human", Title: "Reviewer guidance", Text: clip(txt, 4000)})
	}
	// AI reviews (applied ones only): labelled AI-inferred.
	rows, err = s.DB.Query(ctx, `SELECT DISTINCT ON (ar.finding_id) ar.remediation FROM ai_reviews ar JOIN remediation_item_findings x ON x.finding_id = ar.finding_id
		WHERE x.item_id = $1 AND ar.status = 'applied' AND ar.remediation <> '' ORDER BY ar.finding_id, ar.created_at DESC LIMIT 5`, itemID)
	if err != nil {
		return nil, err
	}
	ais, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	for _, t := range ais {
		out = append(out, Guidance{Source: "ai_review", Evidence: "ai_inferred", Title: "AI review suggestion", Text: clip(t, 4000)})
	}
	// The scanners' own descriptions.
	rows, err = s.DB.Query(ctx, `SELECT DISTINCT ON (f.rule_id) f.rule_id, f.description FROM remediation_item_findings x JOIN findings f ON f.id = x.finding_id
		WHERE x.item_id = $1 AND f.description <> '' ORDER BY f.rule_id LIMIT 5`, itemID)
	if err != nil {
		return nil, err
	}
	type desc struct{ rule, text string }
	ds, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (desc, error) {
		var d desc
		return d, r.Scan(&d.rule, &d.text)
	})
	if err != nil {
		return nil, err
	}
	for _, d := range ds {
		out = append(out, Guidance{Source: "finding", Evidence: "scanner", Title: "Advisory", Text: clip(d.text, 3000)})
	}
	return out, nil
}

// jsonText joins the string values of a JSON object (a reviewer's
// remediation form), in key order.
func jsonText(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			parts = append(parts, strings.ReplaceAll(k, "_", " ")+": "+strings.TrimSpace(v))
		}
	}
	return strings.Join(parts, "\n")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return truncate(s, n) + "…"
}

// --- saved views --------------------------------------------------------------------

// View is a saved filter set of the workspace.
type View struct {
	ID         uuid.UUID      `json:"id"`
	Name       string         `json:"name"`
	Filters    map[string]any `json:"filters"`
	Shared     bool           `json:"shared"`
	OwnerEmail string         `json:"owner_email"`
	Mine       bool           `json:"mine"`
	CreatedAt  time.Time      `json:"created_at"`
}

func (s *Service) listViews(w http.ResponseWriter, r *http.Request) {
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermRemediationRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT v.id, v.name, v.filters, v.shared, COALESCE(u.email, ''), v.owner_id = $2, v.created_at
		FROM remediation_views v LEFT JOIN users u ON u.id = v.owner_id WHERE v.organization_id = $1 AND (v.owner_id = $2 OR v.shared)
		ORDER BY v.owner_id = $2 DESC, lower(v.name)`, p.OrganizationID, p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (View, error) {
		var v View
		var f []byte
		if err := r.Scan(&v.ID, &v.Name, &f, &v.Shared, &v.OwnerEmail, &v.Mine, &v.CreatedAt); err != nil {
			return v, err
		}
		return v, json.Unmarshal(f, &v.Filters)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []View{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// viewFilterKeys are the filters a view may save (the list's parameters).
var viewFilterKeys = []string{"status", "owner_id", "unassigned", "priority", "repository_id", "application_id", "overdue", "q", "sort"}

type viewInput struct {
	Name    string            `json:"name"`
	Filters map[string]string `json:"filters"`
	Shared  bool              `json:"shared"`
}

func (s *Service) createView(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermRemediationRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var in viewInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		s.fail(w, r, httpx.BadRequest("name: 1 to 100 characters"))
		return
	}
	q := map[string][]string{}
	for k, v := range in.Filters {
		if !contains(viewFilterKeys, k) {
			s.fail(w, r, httpx.BadRequest("unknown filter "+k))
			return
		}
		if len(v) > 200 {
			s.fail(w, r, httpx.BadRequest("filter "+k+": at most 200 characters"))
			return
		}
		q[k] = []string{v}
	}
	if _, _, err := listFilter(p, q); err != nil {
		s.fail(w, r, err)
		return
	}
	if v, ok := in.Filters["sort"]; ok {
		if _, ok := sorts[v]; !ok {
			s.fail(w, r, httpx.BadRequest("unknown sort"))
			return
		}
	}
	if in.Filters == nil {
		in.Filters = map[string]string{}
	}
	f, _ := json.Marshal(in.Filters)
	id := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO remediation_views (id, organization_id, owner_id, name, filters, shared) VALUES ($1, $2, $3, $4, $5, $6)`,
			id, p.OrganizationID, p.UserID, in.Name, f, in.Shared); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "remediation_view.create", TargetType: "remediation_view", TargetID: id.String(), Metadata: map[string]any{"name": in.Name, "shared": in.Shared}})
	})
	if err != nil {
		if db.IsUniqueViolation(err) {
			err = httpx.Conflict("you already have a view with this name")
		}
		s.fail(w, r, err)
		return
	}
	filters := map[string]any{}
	for k, v := range in.Filters {
		filters[k] = v
	}
	httpx.WriteJSON(w, http.StatusCreated, View{ID: id, Name: in.Name, Filters: filters, Shared: in.Shared, OwnerEmail: p.Email, Mine: true, CreatedAt: time.Now().UTC()})
}

func (s *Service) deleteView(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, httpx.ErrNotFound)
		return
	}
	// Only the owner deletes a view (shared views are read-only to others).
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM remediation_views WHERE organization_id = $1 AND id = $2 AND owner_id = $3`, p.OrganizationID, id, p.UserID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return httpx.ErrNotFound
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "remediation_view.delete", TargetType: "remediation_view", TargetID: id.String()})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

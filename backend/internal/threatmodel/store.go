package threatmodel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
	"pathos/internal/threatmodel/frameworks"
)

// Person is a user reference.
type Person struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// Model is one version of a threat model (API form).
type Model struct {
	ID                   uuid.UUID      `json:"id"`
	LineageID            uuid.UUID      `json:"lineage_id"`
	Version              int            `json:"version"`
	PreviousVersionID    *uuid.UUID     `json:"previous_version_id"`
	ApplicationID        uuid.UUID      `json:"application_id"`
	ApplicationName      string         `json:"application_name"`
	RepositoryID         *uuid.UUID     `json:"repository_id"`
	RepositoryName       string         `json:"repository_name"`
	Status               string         `json:"status"`
	Method               string         `json:"method"`
	ImportedFormat       string         `json:"imported_format"`
	Title                string         `json:"title"`
	Summary              string         `json:"summary"`
	CodegraphSnapshotIDs []uuid.UUID    `json:"codegraph_snapshot_ids"`
	GeneratedAt          *time.Time     `json:"generated_at"`
	Generation           map[string]any `json:"generation"`
	CreatedBy            *Person        `json:"created_by"`
	SubmittedBy          *Person        `json:"submitted_by"`
	SubmittedAt          *time.Time     `json:"submitted_at"`
	ApprovedBy           *Person        `json:"approved_by"`
	ApprovedAt           *time.Time     `json:"approved_at"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
	Counts               Counts         `json:"counts"`
	CanEdit              bool           `json:"can_edit"`
	CanApprove           bool           `json:"can_approve"`
	orgID                uuid.UUID
}

// Counts summarises a version's threats.
type Counts struct {
	Total             int            `json:"total"`
	Open              int            `json:"open"`
	Mitigated         int            `json:"mitigated"`
	Accepted          int            `json:"accepted"`
	NotApplicable     int            `json:"not_applicable"`
	BySeverity        map[string]int `json:"by_severity"`
	ByCategory        map[string]int `json:"by_category"`
	ByEvidence        map[string]int `json:"by_evidence"`
	ByChange          map[string]int `json:"by_change"`
	Unverified        int            `json:"unverified"`
	WithoutMitigation int            `json:"without_mitigation"`
}

const modelSelect = `SELECT m.id, m.lineage_id, m.version, m.previous_version_id, m.application_id, a.name, m.repository_id,
	COALESCE(NULLIF(r.display_name, ''), r.full_name, ''), m.status, m.method, m.imported_format, m.title, m.summary,
	m.codegraph_snapshot_ids, m.generated_at, m.generation, m.created_by, COALESCE(NULLIF(cu.display_name, ''), cu.email, ''),
	m.submitted_by, COALESCE(NULLIF(su.display_name, ''), su.email, ''), m.submitted_at,
	m.approved_by, COALESCE(NULLIF(au.display_name, ''), au.email, ''), m.approved_at, m.created_at, m.updated_at, m.organization_id
	FROM threat_models m JOIN applications a ON a.id = m.application_id
	LEFT JOIN repositories r ON r.id = m.repository_id
	LEFT JOIN users cu ON cu.id = m.created_by LEFT JOIN users su ON su.id = m.submitted_by LEFT JOIN users au ON au.id = m.approved_by`

func person(id *uuid.UUID, name string) *Person {
	if id == nil {
		return nil
	}
	return &Person{ID: *id, Name: name}
}

func scanModel(row pgx.Row) (Model, error) {
	var m Model
	var gen []byte
	var cb, sb, ab *uuid.UUID
	var cn, sn, an string
	err := row.Scan(&m.ID, &m.LineageID, &m.Version, &m.PreviousVersionID, &m.ApplicationID, &m.ApplicationName, &m.RepositoryID,
		&m.RepositoryName, &m.Status, &m.Method, &m.ImportedFormat, &m.Title, &m.Summary, &m.CodegraphSnapshotIDs, &m.GeneratedAt, &gen,
		&cb, &cn, &sb, &sn, &m.SubmittedAt, &ab, &an, &m.ApprovedAt, &m.CreatedAt, &m.UpdatedAt, &m.orgID)
	if err != nil {
		return m, err
	}
	m.CreatedBy, m.SubmittedBy, m.ApprovedBy = person(cb, cn), person(sb, sn), person(ab, an)
	_ = json.Unmarshal(gen, &m.Generation)
	if m.Generation == nil {
		m.Generation = map[string]any{}
	}
	if m.CodegraphSnapshotIDs == nil {
		m.CodegraphSnapshotIDs = []uuid.UUID{}
	}
	return m, nil
}

func getModel(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (Model, error) {
	m, err := scanModel(q.QueryRow(ctx, modelSelect+` WHERE m.organization_id = $1 AND m.id = $2`, orgID, id))
	if err != nil {
		return m, err
	}
	return m, fillCounts(ctx, q, []*Model{&m})
}

func fillCounts(ctx context.Context, q db.Querier, ms []*Model) error {
	if len(ms) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(ms))
	by := map[uuid.UUID]*Model{}
	for i, m := range ms {
		ids[i] = m.ID
		m.Counts = Counts{BySeverity: map[string]int{}, ByCategory: map[string]int{}, ByEvidence: map[string]int{}, ByChange: map[string]int{}}
		by[m.ID] = m
	}
	rows, err := q.Query(ctx, `SELECT threat_model_id, status, severity, category, evidence_type, change_state, mitigation = '', count(*)
		FROM threats WHERE threat_model_id = ANY($1) GROUP BY 1, 2, 3, 4, 5, 6, 7`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var status, sev, cat, evt, change string
		var noMit bool
		var n int
		if err := rows.Scan(&id, &status, &sev, &cat, &evt, &change, &noMit, &n); err != nil {
			return err
		}
		c := &by[id].Counts
		c.Total += n
		switch status {
		case "open":
			c.Open += n
		case "mitigated":
			c.Mitigated += n
		case "accepted":
			c.Accepted += n
		case "not_applicable":
			c.NotApplicable += n
		}
		if status != "not_applicable" {
			c.BySeverity[sev] += n
			c.ByCategory[cat] += n
		}
		c.ByEvidence[evt] += n
		if change != "" {
			c.ByChange[change] += n
		}
		if evt == EvidenceUnverified && status != "not_applicable" {
			c.Unverified += n
		}
		if noMit && (status == "open" || status == "accepted") {
			c.WithoutMitigation += n
		}
	}
	return rows.Err()
}

// ThreatOut is the API form of a threat.
type ThreatOut struct {
	ID                 uuid.UUID    `json:"id"`
	ThreatModelID      uuid.UUID    `json:"threat_model_id"`
	Fingerprint        string       `json:"fingerprint"`
	Title              string       `json:"title"`
	Description        string       `json:"description"`
	Category           string       `json:"category"`
	Method             string       `json:"method"`
	RuleID             string       `json:"rule_id"`
	RuleVersion        string       `json:"rule_version"`
	EvidenceType       string       `json:"evidence_type"`
	Label              string       `json:"label"`
	Evidence           Evidence     `json:"evidence"`
	Severity           string       `json:"severity"`
	SeverityReason     string       `json:"severity_reason"`
	SeverityOverridden bool         `json:"severity_overridden"`
	Confidence         float64      `json:"confidence"`
	ConfidenceReason   string       `json:"confidence_reason"`
	Status             string       `json:"status"`
	StatusReason       string       `json:"status_reason"`
	Mitigation         string       `json:"mitigation"`
	MitigationEdited   bool         `json:"mitigation_edited"`
	ChangeState        string       `json:"change_state"`
	Owner              *Person      `json:"owner"`
	Elements           []ElementOut `json:"elements"`
	Findings           []FindingOut `json:"findings"`
	Mappings           []MappingOut `json:"mappings"`
	CreatedAt          time.Time    `json:"created_at"`
	UpdatedAt          time.Time    `json:"updated_at"`
}

// ElementOut is a diagram element.
type ElementOut struct {
	ID           uuid.UUID      `json:"id"`
	Kind         string         `json:"kind"`
	Name         string         `json:"name"`
	CodegraphKey string         `json:"codegraph_key"`
	NodeType     string         `json:"node_type"`
	RepositoryID *uuid.UUID     `json:"repository_id"`
	SourceKey    string         `json:"source_key,omitempty"`
	TargetKey    string         `json:"target_key,omitempty"`
	Attrs        map[string]any `json:"attrs,omitempty"`
	ElementKey   string         `json:"element_key"`
}

// FindingOut is a linked finding.
type FindingOut struct {
	ID       uuid.UUID `json:"id"`
	Title    string    `json:"title"`
	Severity string    `json:"severity"`
	Status   string    `json:"status"`
	CWE      string    `json:"cwe,omitempty"`
	Href     string    `json:"href"`
	Source   string    `json:"source"`
}

// MappingOut is a framework mapping with the entry's name.
type MappingOut struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Source    string `json:"source"`
}

// Label is the rule 5 label shown for a threat.
func Label(evidenceType, method string) string {
	switch evidenceType {
	case EvidenceUnverified:
		if method == MethodImported {
			return "imported, unverified"
		}
		return "manual, unverified"
	case EvidenceAIInferred:
		return "AI-inferred"
	}
	return evidenceType
}

const threatSelect = `SELECT t.id, t.threat_model_id, t.fingerprint, t.title, t.description, t.category, t.method, t.rule_id, t.rule_version,
	t.evidence_type, t.evidence, t.severity, t.severity_reason, t.severity_overridden, t.confidence::float8, t.confidence_reason,
	t.status, t.status_reason, t.mitigation, t.mitigation_edited, t.change_state, t.owner_id, COALESCE(NULLIF(ou.display_name, ''), ou.email, ''),
	t.created_at, t.updated_at
	FROM threats t LEFT JOIN users ou ON ou.id = t.owner_id`

func scanThreat(row pgx.Row) (ThreatOut, error) {
	var t ThreatOut
	var ev []byte
	var owner *uuid.UUID
	var ownerName string
	err := row.Scan(&t.ID, &t.ThreatModelID, &t.Fingerprint, &t.Title, &t.Description, &t.Category, &t.Method, &t.RuleID, &t.RuleVersion,
		&t.EvidenceType, &ev, &t.Severity, &t.SeverityReason, &t.SeverityOverridden, &t.Confidence, &t.ConfidenceReason,
		&t.Status, &t.StatusReason, &t.Mitigation, &t.MitigationEdited, &t.ChangeState, &owner, &ownerName, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return t, err
	}
	_ = json.Unmarshal(ev, &t.Evidence)
	t.Owner = person(owner, ownerName)
	t.Label = Label(t.EvidenceType, t.Method)
	t.Elements, t.Findings, t.Mappings = []ElementOut{}, []FindingOut{}, []MappingOut{}
	return t, nil
}

// ThreatFilter narrows a threat list.
type ThreatFilter struct {
	Status, Category, Severity, ChangeState, Method string
	IDs                                             []uuid.UUID
}

func listThreats(ctx context.Context, q db.Querier, modelID uuid.UUID, f ThreatFilter) ([]ThreatOut, error) {
	rows, err := q.Query(ctx, threatSelect+` WHERE t.threat_model_id = $1
		AND ($2 = '' OR t.status = $2) AND ($3 = '' OR t.category = $3) AND ($4 = '' OR t.severity = $4)
		AND ($5 = '' OR t.change_state = $5) AND ($6 = '' OR t.method = $6) AND ($7::uuid[] IS NULL OR t.id = ANY($7))
		ORDER BY array_position(ARRAY['critical', 'high', 'medium', 'low', 'info'], t.severity), t.status = 'not_applicable', t.title, t.id`,
		modelID, f.Status, f.Category, f.Severity, f.ChangeState, f.Method, f.IDs)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ThreatOut, error) { return scanThreat(r) })
	if err != nil {
		return nil, err
	}
	return out, attachThreatDetails(ctx, q, out)
}

func attachThreatDetails(ctx context.Context, q db.Querier, ts []ThreatOut) error {
	if len(ts) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(ts))
	idx := map[uuid.UUID]int{}
	for i, t := range ts {
		ids[i] = t.ID
		idx[t.ID] = i
	}
	rows, err := q.Query(ctx, `SELECT te.threat_id, e.id, e.kind, e.name, e.codegraph_key, e.node_type, e.repository_id, e.source_key, e.target_key, e.element_key
		FROM threat_elements te JOIN threat_model_elements e ON e.id = te.element_id WHERE te.threat_id = ANY($1) ORDER BY te.threat_id, te.position`, ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var tid uuid.UUID
		var e ElementOut
		if err := rows.Scan(&tid, &e.ID, &e.Kind, &e.Name, &e.CodegraphKey, &e.NodeType, &e.RepositoryID, &e.SourceKey, &e.TargetKey, &e.ElementKey); err != nil {
			rows.Close()
			return err
		}
		ts[idx[tid]].Elements = append(ts[idx[tid]].Elements, e)
	}
	rows.Close()
	rows, err = q.Query(ctx, `SELECT tf.threat_id, f.id, f.title, f.severity, f.status, COALESCE(f.cwe[1], ''), tf.source
		FROM threat_findings tf JOIN findings f ON f.id = tf.finding_id WHERE tf.threat_id = ANY($1)
		ORDER BY tf.threat_id, array_position(ARRAY['critical', 'high', 'medium', 'low', 'info'], f.severity), f.title`, ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var tid uuid.UUID
		var f FindingOut
		if err := rows.Scan(&tid, &f.ID, &f.Title, &f.Severity, &f.Status, &f.CWE, &f.Source); err != nil {
			rows.Close()
			return err
		}
		f.CWE = NormalizeCWE(f.CWE)
		f.Href = "/findings?finding=" + f.ID.String()
		ts[idx[tid]].Findings = append(ts[idx[tid]].Findings, f)
	}
	rows.Close()
	rows, err = q.Query(ctx, `SELECT threat_id, framework, entry_id, source FROM threat_framework_mappings WHERE threat_id = ANY($1)
		ORDER BY threat_id, array_position(ARRAY['attack', 'capec', 'cwe', 'd3fend', 'linddun'], framework), entry_id`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tid uuid.UUID
		var m MappingOut
		if err := rows.Scan(&tid, &m.Framework, &m.ID, &m.Source); err != nil {
			return err
		}
		if e, ok := frameworks.Lookup(m.Framework, m.ID); ok {
			m.Name, m.URL = e.Name, e.URL
		}
		ts[idx[tid]].Mappings = append(ts[idx[tid]].Mappings, m)
	}
	return rows.Err()
}

func getThreat(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (ThreatOut, error) {
	t, err := scanThreat(q.QueryRow(ctx, threatSelect+` WHERE t.organization_id = $1 AND t.id = $2`, orgID, id))
	if err != nil {
		return t, err
	}
	ts := []ThreatOut{t}
	if err := attachThreatDetails(ctx, q, ts); err != nil {
		return t, err
	}
	return ts[0], nil
}

func listElements(ctx context.Context, q db.Querier, modelID uuid.UUID) ([]ElementOut, error) {
	rows, err := q.Query(ctx, `SELECT id, kind, name, codegraph_key, node_type, repository_id, source_key, target_key, attrs, element_key
		FROM threat_model_elements WHERE threat_model_id = $1 ORDER BY kind, name, id`, modelID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ElementOut, error) {
		var e ElementOut
		var attrs []byte
		err := r.Scan(&e.ID, &e.Kind, &e.Name, &e.CodegraphKey, &e.NodeType, &e.RepositoryID, &e.SourceKey, &e.TargetKey, &attrs, &e.ElementKey)
		_ = json.Unmarshal(attrs, &e.Attrs)
		return e, err
	})
}

// Event is a threat history entry.
type Event struct {
	ID     uuid.UUID `json:"id"`
	Action string    `json:"action"`
	From   string    `json:"from"`
	To     string    `json:"to"`
	Reason string    `json:"reason"`
	Actor  *Person   `json:"actor"`
	At     time.Time `json:"at"`
	// Version: the model version the event happened in.
	Version int `json:"version"`
}

// threatEvents returns the history of a threat across versions (a copied
// threat's events continue those of the threat it was copied from).
func threatEvents(ctx context.Context, q db.Querier, threatID uuid.UUID) ([]Event, error) {
	var out []Event
	id := threatID
	for hop := 0; hop < 50; hop++ {
		rows, err := q.Query(ctx, `SELECT e.id, e.action, e.from_value, e.to_value, e.reason, e.actor_id,
			COALESCE(NULLIF(u.display_name, ''), u.email, ''), e.created_at, m.version
			FROM threat_events e JOIN threats t ON t.id = e.threat_id JOIN threat_models m ON m.id = t.threat_model_id
			LEFT JOIN users u ON u.id = e.actor_id WHERE e.threat_id = $1 ORDER BY e.created_at DESC, e.id DESC`, id)
		if err != nil {
			return nil, err
		}
		var prev string
		for rows.Next() {
			var e Event
			var actor *uuid.UUID
			var name string
			if err := rows.Scan(&e.ID, &e.Action, &e.From, &e.To, &e.Reason, &actor, &name, &e.At, &e.Version); err != nil {
				rows.Close()
				return nil, err
			}
			e.Actor = person(actor, name)
			if e.Action == "copied" {
				prev = e.From
			}
			out = append(out, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		pid, err := uuid.Parse(prev)
		if prev == "" || err != nil {
			break
		}
		id = pid
	}
	if out == nil {
		out = []Event{}
	}
	return out, nil
}

func addEvent(ctx context.Context, q db.Querier, orgID, threatID uuid.UUID, action, from, to, reason string, actor *uuid.UUID) error {
	_, err := q.Exec(ctx, `INSERT INTO threat_events (id, organization_id, threat_id, action, from_value, to_value, reason, actor_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, uuid.Must(uuid.NewV7()), orgID, threatID, action, clip(from, 2000), clip(to, 2000), clip(reason, 2000), actor)
	return err
}

// Approval is a review decision.
type Approval struct {
	ID            uuid.UUID `json:"id"`
	ThreatModelID uuid.UUID `json:"threat_model_id"`
	Version       int       `json:"version"`
	Decision      string    `json:"decision"`
	Actor         *Person   `json:"actor"`
	Note          string    `json:"note"`
	DecidedAt     time.Time `json:"decided_at"`
}

func listApprovals(ctx context.Context, q db.Querier, lineage uuid.UUID) ([]Approval, error) {
	rows, err := q.Query(ctx, `SELECT a.id, a.threat_model_id, a.version, a.decision, a.actor_id, COALESCE(NULLIF(u.display_name, ''), u.email, ''), a.note, a.decided_at
		FROM threat_model_approvals a LEFT JOIN users u ON u.id = a.actor_id WHERE a.lineage_id = $1 ORDER BY a.decided_at DESC, a.id DESC`, lineage)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Approval, error) {
		var a Approval
		var actor *uuid.UUID
		var name string
		err := r.Scan(&a.ID, &a.ThreatModelID, &a.Version, &a.Decision, &actor, &name, &a.Note, &a.DecidedAt)
		a.Actor = person(actor, name)
		return a, err
	})
}

func addApproval(ctx context.Context, q db.Querier, m Model, decision string, actor uuid.UUID, note string) error {
	_, err := q.Exec(ctx, `INSERT INTO threat_model_approvals (id, organization_id, threat_model_id, lineage_id, version, decision, actor_id, note)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, uuid.Must(uuid.NewV7()), m.orgID, m.ID, m.LineageID, m.Version, decision, actor, clip(note, 4000))
	return err
}

// --- writes --------------------------------------------------------------------

// elementKey is the per-model identity of an element.
func elementKey(repoID *uuid.UUID, key string) string {
	r := ""
	if repoID != nil {
		r = repoID.String()
	}
	return clip(r+"|"+key, 800)
}

// upsertElement inserts or updates an element and returns its id.
func upsertElement(ctx context.Context, q db.Querier, orgID, modelID uuid.UUID, repoID *uuid.UUID, e ElementRef, attrs map[string]any) (uuid.UUID, error) {
	if attrs == nil {
		attrs = map[string]any{}
	}
	ab, _ := json.Marshal(attrs)
	name := clip(strings.TrimSpace(e.Name), 500)
	if name == "" {
		name = clip(e.Key, 500)
	}
	if name == "" {
		name = "element"
	}
	var id uuid.UUID
	err := q.QueryRow(ctx, `INSERT INTO threat_model_elements (id, organization_id, threat_model_id, kind, name, repository_id, codegraph_key,
		node_type, source_key, target_key, attrs, element_key) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (threat_model_id, element_key) DO UPDATE SET kind = EXCLUDED.kind, name = EXCLUDED.name, node_type = EXCLUDED.node_type,
		source_key = EXCLUDED.source_key, target_key = EXCLUDED.target_key, attrs = EXCLUDED.attrs
		RETURNING id`, uuid.Must(uuid.NewV7()), orgID, modelID, e.Kind, name, repoID, clip(e.Key, 700), clip(e.NodeType, 64),
		clip(e.Source, 700), clip(e.Target, 700), ab, elementKey(repoID, e.Key)).Scan(&id)
	return id, err
}

// threatRow is what is written for a threat.
type threatRow struct {
	Fingerprint, Title, Description, Category, Method, RuleID, RuleVersion, EvidenceType string
	Evidence                                                                             Evidence
	Severity, SeverityReason                                                             string
	Confidence                                                                           float64
	ConfidenceReason, Status, StatusReason, Mitigation, ChangeState                      string
	SeverityOverridden, MitigationEdited                                                 bool
	OwnerID, CreatedBy                                                                   *uuid.UUID
}

func insertThreat(ctx context.Context, q db.Querier, orgID, modelID uuid.UUID, t threatRow) (uuid.UUID, error) {
	ev, err := json.Marshal(t.Evidence)
	if err != nil {
		return uuid.Nil, err
	}
	if t.Status == "" {
		t.Status = "open"
	}
	id := uuid.Must(uuid.NewV7())
	_, err = q.Exec(ctx, `INSERT INTO threats (id, organization_id, threat_model_id, fingerprint, title, description, category, method, rule_id,
		rule_version, evidence_type, evidence, severity, severity_reason, severity_overridden, confidence, confidence_reason, status, status_reason,
		mitigation, mitigation_edited, change_state, evidence_hash, owner_id, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)`,
		id, orgID, modelID, clip(t.Fingerprint, 900), clip(t.Title, 300), clip(t.Description, 8000), t.Category, t.Method, t.RuleID, t.RuleVersion,
		t.EvidenceType, ev, t.Severity, clip(t.SeverityReason, 2000), t.SeverityOverridden, t.Confidence, clip(t.ConfidenceReason, 2000), t.Status,
		clip(t.StatusReason, 2000), clip(t.Mitigation, 8000), t.MitigationEdited, t.ChangeState, t.Evidence.Hash(), t.OwnerID, t.CreatedBy)
	return id, err
}

func setMappings(ctx context.Context, q db.Querier, orgID, threatID uuid.UUID, ms []Mapping, replaceSources ...string) error {
	if len(replaceSources) > 0 {
		if _, err := q.Exec(ctx, `DELETE FROM threat_framework_mappings WHERE threat_id = $1 AND source = ANY($2)`, threatID, replaceSources); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, m := range ms {
		k := m.Framework + "|" + m.ID
		if seen[k] || m.ID == "" {
			continue
		}
		seen[k] = true
		if _, err := q.Exec(ctx, `INSERT INTO threat_framework_mappings (organization_id, threat_id, framework, entry_id, source)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT (threat_id, framework, entry_id) DO NOTHING`, orgID, threatID, m.Framework, clip(m.ID, 50), m.Source); err != nil {
			return err
		}
	}
	return nil
}

func linkElements(ctx context.Context, q db.Querier, orgID, threatID uuid.UUID, elementIDs []uuid.UUID, replace bool) error {
	if replace {
		if _, err := q.Exec(ctx, `DELETE FROM threat_elements WHERE threat_id = $1`, threatID); err != nil {
			return err
		}
	}
	for i, eid := range elementIDs {
		if _, err := q.Exec(ctx, `INSERT INTO threat_elements (organization_id, threat_id, element_id, position) VALUES ($1, $2, $3, $4)
			ON CONFLICT (threat_id, element_id) DO NOTHING`, orgID, threatID, eid, min(i, 32000)); err != nil {
			return err
		}
	}
	return nil
}

func linkFindings(ctx context.Context, q db.Querier, orgID, threatID uuid.UUID, ids []uuid.UUID, source string, replaceSource bool) error {
	if replaceSource {
		if _, err := q.Exec(ctx, `DELETE FROM threat_findings WHERE threat_id = $1 AND source = $2`, threatID, source); err != nil {
			return err
		}
	}
	for _, f := range ids {
		if _, err := q.Exec(ctx, `INSERT INTO threat_findings (organization_id, threat_id, finding_id, source)
			SELECT $1, $2, f.id, $4 FROM findings f WHERE f.organization_id = $1 AND f.id = $3
			ON CONFLICT (threat_id, finding_id) DO NOTHING`, orgID, threatID, f, source); err != nil {
			return err
		}
	}
	return nil
}

// copyVersion creates the next draft version of a model with every
// element, threat (and its human edits), link and mapping.
func copyVersion(ctx context.Context, tx pgx.Tx, from Model, actor *uuid.UUID) (uuid.UUID, error) {
	id := uuid.Must(uuid.NewV7())
	var next int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version), 0) + 1 FROM threat_models WHERE lineage_id = $1`, from.LineageID).Scan(&next); err != nil {
		return id, err
	}
	gen, _ := json.Marshal(from.Generation)
	if _, err := tx.Exec(ctx, `INSERT INTO threat_models (id, organization_id, lineage_id, version, previous_version_id, application_id, repository_id,
		status, method, imported_format, title, summary, codegraph_snapshot_ids, generated_at, generation, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'draft', $8, $9, $10, $11, $12, $13, $14, $15)`,
		id, from.orgID, from.LineageID, next, from.ID, from.ApplicationID, from.RepositoryID, from.Method, from.ImportedFormat, from.Title,
		from.Summary, from.CodegraphSnapshotIDs, from.GeneratedAt, gen, actor); err != nil {
		return id, err
	}
	// Elements: new ids (UUIDv7 from the application), same keys.
	rows, err := tx.Query(ctx, `SELECT id FROM threat_model_elements WHERE threat_model_id = $1 ORDER BY id`, from.ID)
	if err != nil {
		return id, err
	}
	oldEls, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return id, err
	}
	for _, oe := range oldEls {
		if _, err := tx.Exec(ctx, `INSERT INTO threat_model_elements (id, organization_id, threat_model_id, kind, name, repository_id, codegraph_key,
			node_type, source_key, target_key, attrs, element_key)
			SELECT $3, organization_id, $2, kind, name, repository_id, codegraph_key, node_type, source_key, target_key, attrs, element_key
			FROM threat_model_elements WHERE id = $1`, oe, id, uuid.Must(uuid.NewV7())); err != nil {
			return id, err
		}
	}
	rows, err = tx.Query(ctx, `SELECT id FROM threats WHERE threat_model_id = $1 ORDER BY id`, from.ID)
	if err != nil {
		return id, err
	}
	old, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return id, err
	}
	for _, oid := range old {
		nid := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO threats (id, organization_id, threat_model_id, fingerprint, title, description, category, method,
			rule_id, rule_version, evidence_type, evidence, ai_evidence_id, severity, severity_reason, severity_overridden, confidence, confidence_reason,
			status, status_reason, mitigation, mitigation_edited, change_state, evidence_hash, owner_id, created_by, created_at)
			SELECT $3, organization_id, $2, fingerprint, title, description, category, method, rule_id, rule_version, evidence_type, evidence,
			ai_evidence_id, severity, severity_reason, severity_overridden, confidence, confidence_reason, status, status_reason, mitigation,
			mitigation_edited, change_state, evidence_hash, owner_id, created_by, created_at FROM threats WHERE id = $1`, oid, id, nid); err != nil {
			return id, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO threat_elements (organization_id, threat_id, element_id, position)
			SELECT te.organization_id, $2, ne.id, te.position FROM threat_elements te
			JOIN threat_model_elements oe ON oe.id = te.element_id
			JOIN threat_model_elements ne ON ne.threat_model_id = $3 AND ne.element_key = oe.element_key
			WHERE te.threat_id = $1`, oid, nid, id); err != nil {
			return id, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO threat_findings (organization_id, threat_id, finding_id, source)
			SELECT organization_id, $2, finding_id, source FROM threat_findings WHERE threat_id = $1`, oid, nid); err != nil {
			return id, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO threat_framework_mappings (organization_id, threat_id, framework, entry_id, source)
			SELECT organization_id, $2, framework, entry_id, source FROM threat_framework_mappings WHERE threat_id = $1`, oid, nid); err != nil {
			return id, err
		}
		if err := addEvent(ctx, tx, from.orgID, nid, "copied", oid.String(), fmt.Sprintf("version %d", next), "", actor); err != nil {
			return id, err
		}
	}
	return id, nil
}

var errState = errors.New("state")

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

func uniqueUUIDs(in []uuid.UUID) []uuid.UUID {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	return slices.Compact(out)
}

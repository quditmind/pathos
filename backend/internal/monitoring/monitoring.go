// Package monitoring is the continuous monitoring feed and architecture
// drift of PATHOS 3.0 M9 (flag "continuous_monitoring", off by default).
//
// The feed is a per-organization stream of the lifecycle feedback loops
// and other changes (docs/user-guide/monitoring.md):
//
//  1. new commit → CodeGraph rediscovery (rediscovery.queued)
//  2. dependency change → SBOM reassessment (dependency.changed)
//  3. architecture change → threat model update (architecture.drift,
//     threat_model.updated, threat_model.review_needed)
//  4. new vulnerability intelligence → risk re-score (risk.rescored)
//  5. fix merged or marked submitted → targeted rescan
//     (fix.verification_queued, fix.verified)
//  6. gate failure → developer feedback (gate.failed)
//  7. new findings → AI triage (findings.new, ai.triage_queued)
//
// Writers call Record in their own transaction or with the pool; Record
// does nothing unless the organization has the flag on, so the source
// modules behave exactly as before while the flag is off. Rows are never
// updated. Every event states its evidence label (rule 5) and the
// references it rests on.
//
// This package is a leaf for the modules that write events (codegraph,
// risk, remediation, gates, ai): it imports none of them.
package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/featureflags"
	"pathos/internal/platform/db"
)

// Flag is the feature flag of the module.
const Flag = "continuous_monitoring"

// Event types.
const (
	TypeRediscoveryQueued     = "rediscovery.queued"
	TypeDependencyChanged     = "dependency.changed"
	TypeArchitectureDrift     = "architecture.drift"
	TypeThreatModelUpdated    = "threat_model.updated"
	TypeThreatModelReview     = "threat_model.review_needed"
	TypeRiskRescored          = "risk.rescored"
	TypeFixVerificationQueued = "fix.verification_queued"
	TypeFixVerified           = "fix.verified"
	TypeGateFailed            = "gate.failed"
	TypeFindingsNew           = "findings.new"
	TypeAITriageQueued        = "ai.triage_queued"
)

// Evidence labels (rule 5).
const (
	EvidenceVerified   = "verified"
	EvidenceObserved   = "observed"
	EvidenceAIInferred = "ai_inferred"
)

// TypeDef describes an event type.
type TypeDef struct {
	Type        string `json:"type"`
	Label       string `json:"label"`
	Loop        *int   `json:"loop"`
	Description string `json:"description"`
}

func loopN(n int) *int { return &n }

// Types is the catalogue, in display order.
var Types = []TypeDef{
	{TypeRediscoveryQueued, "CodeGraph rediscovery queued", loopN(1), "A new commit was scanned on a repository with a CodeGraph; PATHOS queued a rediscovery (rate-limited)."},
	{TypeDependencyChanged, "Dependencies changed", loopN(2), "A new CodeGraph snapshot has other components than the previous one; PATHOS re-evaluated the component policies and re-scores the repository's dependency findings."},
	{TypeArchitectureDrift, "Architecture drift", loopN(3), "A new CodeGraph snapshot adds or removes routes, external services, datastores, internet exposure or trust-boundary crossings."},
	{TypeThreatModelUpdated, "Threat model draft updated", loopN(3), "After an architecture change PATHOS regenerated the application's threat model as a draft; approved versions are never changed."},
	{TypeThreatModelReview, "Threat model needs review", loopN(3), "The architecture changed after the threat model was generated, and automatic updates are off: review the model."},
	{TypeRiskRescored, "Risk re-scored after new intelligence", loopN(4), "Vulnerability intelligence (EPSS, CISA KEV, OSV) changed the risk of existing findings."},
	{TypeFixVerificationQueued, "Fix verification queued", loopN(5), "A fix pull request was merged or an item was marked fix submitted; PATHOS queued a targeted rescan of the affected files."},
	{TypeFixVerified, "Fix verification finished", loopN(5), "A targeted rescan finished: fixed, still present, regressed or inconclusive, with before-and-after evidence."},
	{TypeGateFailed, "Gate failed", loopN(6), "A security gate blocked or required approval under an explicit policy; developers got feedback in the pull request, through webhooks and in PATHOS."},
	{TypeFindingsNew, "New findings", loopN(7), "A scan reported findings that were not known before."},
	{TypeAITriageQueued, "Queued for AI triage", loopN(7), "New findings were queued for AI review. AI conclusions are labelled AI-inferred and never approve anything on their own."},
}

// LookupType returns the definition of an event type.
func LookupType(t string) (TypeDef, bool) {
	i := slices.IndexFunc(Types, func(d TypeDef) bool { return d.Type == t })
	if i < 0 {
		return TypeDef{}, false
	}
	return Types[i], true
}

// Severities from the strongest.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// SeverityRank is 0 for critical … 4 for info (5 for unknown).
func SeverityRank(s string) int {
	if i := slices.Index(Severities, s); i >= 0 {
		return i
	}
	return len(Severities)
}

// Highest returns the stronger of two severities.
func Highest(a, b string) string {
	if SeverityRank(b) < SeverityRank(a) {
		return b
	}
	return a
}

// Event is one feed entry to record.
type Event struct {
	OrgID         uuid.UUID
	ApplicationID *uuid.UUID
	RepositoryID  *uuid.UUID
	Type          string
	Severity      string
	Title         string
	Summary       string
	EvidenceLabel string
	Evidence      map[string]any
	SubjectType   string
	SubjectID     *uuid.UUID
	Details       map[string]any
}

// ErrUnknownType is returned for an event type outside the catalogue.
var ErrUnknownType = errors.New("unknown monitoring event type")

// Enabled reports whether the organization has the feed on.
func Enabled(ctx context.Context, q db.Querier, orgID uuid.UUID) (bool, error) {
	return featureflags.Enabled(ctx, q, orgID, Flag)
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// Record stores an event when the organization has the flag on. It
// returns the event id, or uuid.Nil when the flag is off. The application
// of a repository event is filled in when not given.
func Record(ctx context.Context, q db.Querier, ev Event) (uuid.UUID, error) {
	def, ok := LookupType(ev.Type)
	if !ok {
		return uuid.Nil, ErrUnknownType
	}
	on, err := Enabled(ctx, q, ev.OrgID)
	if err != nil || !on {
		return uuid.Nil, err
	}
	if ev.Severity == "" || !slices.Contains(Severities, ev.Severity) {
		ev.Severity = "info"
	}
	if ev.EvidenceLabel == "" {
		ev.EvidenceLabel = EvidenceVerified
	}
	if ev.Evidence == nil {
		ev.Evidence = map[string]any{}
	}
	if ev.Details == nil {
		ev.Details = map[string]any{}
	}
	if ev.Title == "" {
		ev.Title = def.Label
	}
	evJSON, err := json.Marshal(ev.Evidence)
	if err != nil {
		return uuid.Nil, err
	}
	detJSON, err := json.Marshal(ev.Details)
	if err != nil {
		return uuid.Nil, err
	}
	if len(detJSON) > 30000 {
		detJSON = []byte(`{"truncated":true}`)
	}
	id := uuid.Must(uuid.NewV7())
	var loop *int
	if def.Loop != nil {
		loop = def.Loop
	}
	_, err = q.Exec(ctx, `INSERT INTO monitoring_events (id, organization_id, application_id, repository_id, event_type, feedback_loop, severity,
		title, summary, evidence_label, evidence, subject_type, subject_id, details)
		VALUES ($1, $2, COALESCE($3, (SELECT application_id FROM repositories WHERE id = $4 AND organization_id = $2)), $4, $5, $6, $7,
		        $8, $9, $10, $11, $12, $13, $14)`,
		id, ev.OrgID, ev.ApplicationID, ev.RepositoryID, ev.Type, loop, ev.Severity, clip(ev.Title, 300), clip(ev.Summary, 2000),
		ev.EvidenceLabel, evJSON, clip(ev.SubjectType, 40), ev.SubjectID, detJSON)
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// Settings are an organization's monitoring settings.
type Settings struct {
	DriftAlerts           bool       `json:"drift_alerts"`
	DriftAlertMinSeverity string     `json:"drift_alert_min_severity"`
	UpdatedAt             *time.Time `json:"updated_at"`
	UpdatedBy             *string    `json:"updated_by"`
}

// DefaultSettings apply without a stored row: drift alerts off.
var DefaultSettings = Settings{DriftAlerts: false, DriftAlertMinSeverity: "high"}

// LoadSettings returns the organization's settings (defaults without a row).
func LoadSettings(ctx context.Context, q db.Querier, orgID uuid.UUID) (Settings, error) {
	st := DefaultSettings
	var at time.Time
	var by *string
	err := q.QueryRow(ctx, `SELECT s.drift_alerts, s.drift_alert_min_severity, s.updated_at, u.email FROM monitoring_settings s
		LEFT JOIN users u ON u.id = s.updated_by AND u.organization_id = s.organization_id WHERE s.organization_id = $1`, orgID).
		Scan(&st.DriftAlerts, &st.DriftAlertMinSeverity, &at, &by)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultSettings, nil
	}
	if err != nil {
		return st, err
	}
	st.UpdatedAt, st.UpdatedBy = &at, by
	return st, nil
}

// FillCommits completes the commit evidence of drift records and their
// feed events once the discovery execution reported its commit (the
// worker reports it with the completion, after the graph upload).
func FillCommits(ctx context.Context, q db.Querier, orgID *uuid.UUID) error {
	if _, err := q.Exec(ctx, `UPDATE architecture_drifts d SET to_commit = s.commit_sha FROM codegraph_snapshots s
		WHERE s.id = d.to_snapshot_id AND d.to_commit = '' AND s.commit_sha <> '' AND ($1::uuid IS NULL OR d.organization_id = $1)`, orgID); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE monitoring_events e SET evidence = jsonb_set(e.evidence, '{commit}', to_jsonb(s.commit_sha))
		FROM codegraph_snapshots s WHERE e.event_type IN ('architecture.drift', 'dependency.changed', 'threat_model.updated', 'threat_model.review_needed')
		  AND ($1::uuid IS NULL OR e.organization_id = $1) AND COALESCE(e.evidence->>'commit', '') = ''
		  AND s.id::text = COALESCE(e.evidence->>'to_snapshot_id', e.evidence->>'snapshot_id') AND s.commit_sha <> ''`, orgID)
	return err
}

// Prune deletes events older than the retention (jobs role). Drift rows
// follow their snapshots.
func Prune(ctx context.Context, q db.Querier, days int) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM monitoring_events WHERE created_at < now() - make_interval(days => $1)`, days)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

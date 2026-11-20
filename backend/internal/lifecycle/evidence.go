// Package lifecycle computes the lifecycle evidence sections of the
// technical and compliance reports (PATHOS 3.0 M9): CodeGraph, threat
// models, remediation and gates, for the repositories of a report's scope.
// Every section states where its figures come from and whether they are
// available (module flag on, caller permission); figures are counted from
// stored records only, never estimated.
package lifecycle

import (
	"context"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/featureflags"
	"pathos/internal/platform/db"
)

// Section is one lifecycle evidence section of a report.
type Section struct {
	Key       string `json:"key"`
	Title     string `json:"title"`
	Available bool   `json:"available"`
	// Reason says why the section has no figures (flag off, permission).
	Reason        string         `json:"reason,omitempty"`
	EvidenceLabel string         `json:"evidence_label"`
	Evidence      string         `json:"evidence"`
	Metrics       map[string]int `json:"metrics"`
}

// Scope selects the repositories of a report: RepoCond is a SQL condition
// on the alias r (repositories) whose placeholders start at $2 ($1 is the
// organization) with Args as their values.
type Scope struct {
	OrgID    uuid.UUID
	RepoCond string
	Args     []any
}

func (sc Scope) args() []any { return append([]any{sc.OrgID}, sc.Args...) }

// inScope: the repositories of the scope.
func (sc Scope) repos() string {
	return `(SELECT r.id FROM repositories r WHERE r.organization_id = $1 AND r.archived_at IS NULL AND ` + sc.RepoCond + `)`
}

// apps: the applications with a repository in the scope.
func (sc Scope) apps() string {
	return `(SELECT DISTINCT r.application_id FROM repositories r WHERE r.organization_id = $1 AND r.archived_at IS NULL AND r.application_id IS NOT NULL AND ` +
		sc.RepoCond + `)`
}

func scan(ctx context.Context, q db.Querier, sql string, args []any, names []string) (map[string]int, error) {
	vals := make([]int, len(names))
	ptrs := make([]any, len(names))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := q.QueryRow(ctx, sql, args...).Scan(ptrs...); err != nil {
		return nil, err
	}
	out := make(map[string]int, len(names))
	for i, n := range names {
		out[n] = vals[i]
	}
	return out, nil
}

// Sections returns the four sections for the scope.
func Sections(ctx context.Context, q db.Querier, p *authz.Principal, sc Scope) ([]Section, error) {
	flags, err := featureflags.Load(ctx, q, sc.OrgID)
	if err != nil {
		return nil, err
	}
	out := []Section{}
	unavailable := func(s Section, reason string) Section {
		s.Reason, s.Metrics = reason, map[string]int{}
		return s
	}

	cg := Section{Key: "codegraph", Title: "Architecture (CodeGraph)", EvidenceLabel: "verified",
		Evidence: "Counted from the newest ready CodeGraph snapshot of each repository in scope; every edge rests on stored evidence (file and line, SBOM, scan or runtime record)."}
	switch {
	case !flags["codegraph"]:
		out = append(out, unavailable(cg, "CodeGraph is not enabled for this organization"))
	case !p.HasAnywhere(authz.PermFindingsRead):
		out = append(out, unavailable(cg, "you cannot view findings and architecture"))
	default:
		// #nosec G202 -- the scope condition is built from placeholders
		m, err := scan(ctx, q, `WITH latest AS (
			SELECT DISTINCT ON (s.repository_id) s.id FROM codegraph_snapshots s
			WHERE s.organization_id = $1 AND s.repository_id IN `+sc.repos()+` AND s.status IN ('ready', 'partial') AND s.storage = 'rows'
			ORDER BY s.repository_id, s.created_at DESC)
			SELECT (SELECT count(*) FROM latest),
			       (SELECT count(*) FROM codegraph_nodes n WHERE n.snapshot_id IN (SELECT id FROM latest) AND n.type IN ('route', 'api_operation')),
			       (SELECT count(*) FROM codegraph_nodes n WHERE n.snapshot_id IN (SELECT id FROM latest) AND n.type = 'external_service'),
			       (SELECT count(*) FROM codegraph_nodes n WHERE n.snapshot_id IN (SELECT id FROM latest) AND n.type = 'datastore'),
			       (SELECT count(*) FROM codegraph_edges e JOIN codegraph_nodes t ON t.id = e.target_id WHERE e.snapshot_id IN (SELECT id FROM latest)
			          AND e.type = 'crosses_boundary' AND t.type = 'trust_boundary' AND (lower(t.node_key || ' ' || t.label) LIKE '%internet%'
			          OR lower(t.node_key || ' ' || t.label) LIKE '%public%')),
			       (SELECT count(*) FROM codegraph_edges e WHERE e.snapshot_id IN (SELECT id FROM latest) AND e.evidence = 'verified'),
			       (SELECT count(*) FROM codegraph_edges e WHERE e.snapshot_id IN (SELECT id FROM latest) AND e.evidence = 'observed'),
			       (SELECT count(*) FROM codegraph_edges e WHERE e.snapshot_id IN (SELECT id FROM latest) AND e.evidence = 'ai_inferred'),
			       (SELECT count(*) FROM architecture_drifts d WHERE d.organization_id = $1 AND d.repository_id IN `+sc.repos()+`
			          AND d.has_changes AND d.created_at >= now() - interval '90 days')`, sc.args(),
			[]string{"repositories_with_graph", "routes", "external_services", "datastores", "internet_exposed_edges",
				"verified_edges", "observed_edges", "ai_inferred_edges", "drifts_90_days"})
		if err != nil {
			return nil, err
		}
		cg.Available, cg.Metrics = true, m
		out = append(out, cg)
	}

	tm := Section{Key: "threat_models", Title: "Threat models", EvidenceLabel: "verified",
		Evidence: "Counted from the latest version of each threat model of the applications in scope; each threat states its own evidence type (verified, observed, AI-inferred or unverified)."}
	switch {
	case !flags["threat_models"]:
		out = append(out, unavailable(tm, "Threat modelling is not enabled for this organization"))
	case !p.HasAnywhere(authz.PermThreatsRead):
		out = append(out, unavailable(tm, "you cannot view threat models (threats.read)"))
	default:
		// #nosec G202 -- the scope condition is built from placeholders
		m, err := scan(ctx, q, `WITH latest AS (
			SELECT m.id, m.status FROM threat_models m WHERE m.organization_id = $1 AND m.application_id IN `+sc.apps()+`
			  AND m.status <> 'archived' AND m.version = (SELECT max(x.version) FROM threat_models x WHERE x.lineage_id = m.lineage_id))
			SELECT (SELECT count(*) FROM latest),
			       (SELECT count(*) FROM latest WHERE status = 'approved'),
			       (SELECT count(*) FROM latest WHERE status IN ('draft', 'in_review')),
			       (SELECT count(*) FROM threats t WHERE t.threat_model_id IN (SELECT id FROM latest) AND t.status = 'open'),
			       (SELECT count(*) FROM threats t WHERE t.threat_model_id IN (SELECT id FROM latest) AND t.status = 'open' AND t.severity IN ('critical', 'high')),
			       (SELECT count(*) FROM threats t WHERE t.threat_model_id IN (SELECT id FROM latest) AND t.status = 'mitigated'),
			       (SELECT count(*) FROM threats t WHERE t.threat_model_id IN (SELECT id FROM latest) AND t.evidence_type = 'verified'),
			       (SELECT count(*) FROM threats t WHERE t.threat_model_id IN (SELECT id FROM latest) AND t.evidence_type = 'observed'),
			       (SELECT count(*) FROM threats t WHERE t.threat_model_id IN (SELECT id FROM latest) AND t.evidence_type = 'ai_inferred'),
			       (SELECT count(*) FROM threats t WHERE t.threat_model_id IN (SELECT id FROM latest) AND t.evidence_type = 'unverified')`, sc.args(),
			[]string{"threat_models", "approved", "awaiting_review", "open_threats", "open_critical_high", "mitigated",
				"verified_threats", "observed_threats", "ai_inferred_threats", "unverified_threats"})
		if err != nil {
			return nil, err
		}
		tm.Available, tm.Metrics = true, m
		out = append(out, tm)
	}

	remOK := flags["remediation_workspace"] && p.HasAnywhere(authz.PermRemediationRead)
	remReason := "the remediation workspace is not enabled for this organization"
	if flags["remediation_workspace"] {
		remReason = "you cannot view remediation (remediation.read)"
	}
	rem := Section{Key: "remediation", Title: "Remediation", EvidenceLabel: "verified",
		Evidence: "Counted from remediation items and their verifications; an item closes only when a targeted rescan or a finished scan proves the fix (before-and-after evidence)."}
	gate := Section{Key: "gates", Title: "Security gates", EvidenceLabel: "verified",
		Evidence: "Counted from recorded gate decisions of the last 90 days; a decision blocks only under an explicit security policy, and every decision keeps its reasons and evidence."}
	if !remOK {
		out = append(out, unavailable(rem, remReason), unavailable(gate, remReason))
		return out, nil
	}
	itemScope := `(i.repository_id IN ` + sc.repos() + ` OR (i.repository_id IS NULL AND i.application_id IN ` + sc.apps() + `))`
	// #nosec G202 -- the scope condition is built from placeholders
	m, err := scan(ctx, q, `SELECT count(*) FILTER (WHERE i.status NOT IN ('closed', 'wont_fix')),
		count(*) FILTER (WHERE i.status NOT IN ('closed', 'wont_fix') AND i.due_at < now()),
		count(*) FILTER (WHERE i.status = 'closed' AND i.closed_at >= now() - interval '90 days'),
		count(*) FILTER (WHERE i.kind = 'threat_mitigation' AND i.threat_id IS NOT NULL),
		(SELECT count(*) FROM remediation_verifications v WHERE v.organization_id = $1 AND v.repository_id IN `+sc.repos()+`
		   AND v.result = 'fixed' AND v.finished_at >= now() - interval '90 days'),
		(SELECT count(*) FROM remediation_verifications v WHERE v.organization_id = $1 AND v.repository_id IN `+sc.repos()+`
		   AND v.result IN ('still_present', 'regressed') AND v.finished_at >= now() - interval '90 days')
		FROM remediation_items i WHERE i.organization_id = $1 AND `+itemScope, sc.args(),
		[]string{"open_items", "overdue_items", "closed_90_days", "linked_to_threats", "verified_fixed_90_days", "verification_failed_90_days"})
	if err != nil {
		return nil, err
	}
	rem.Available, rem.Metrics = true, m
	out = append(out, rem)
	decScope := `(d.repository_id IN ` + sc.repos() + ` OR (d.repository_id IS NULL AND d.application_id IN ` + sc.apps() + `))`
	// #nosec G202 -- the scope condition is built from placeholders
	g, err := scan(ctx, q, `SELECT count(*), count(*) FILTER (WHERE d.outcome = 'block'), count(*) FILTER (WHERE d.outcome = 'approval_required'),
		count(*) FILTER (WHERE d.outcome = 'warn'), count(*) FILTER (WHERE d.outcome = 'exception_applied'),
		count(*) FILTER (WHERE d.outcome IN ('block', 'approval_required') AND cardinality(d.policy_ids) = 0)
		FROM gate_decisions d WHERE d.organization_id = $1 AND d.created_at >= now() - interval '90 days' AND `+decScope, sc.args(),
		[]string{"decisions_90_days", "blocked", "approval_required", "warned", "exceptions_applied", "blocked_without_policy"})
	if err != nil {
		return nil, err
	}
	gate.Available, gate.Metrics = true, g
	out = append(out, gate)
	return out, nil
}

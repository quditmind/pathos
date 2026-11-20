// Package feedback wires the lifecycle feedback loops that span modules
// (PATHOS 3.0 M9, docs/user-guide/monitoring.md). Loops owned by one
// module live there and record their own feed events:
//
//  1. new commit → rediscovery: internal/codegraph (OnScanFinished)
//  4. new intelligence → risk re-score: internal/risk (Recompute)
//  5. fix merged / submitted → targeted rescan: internal/remediation
//  6. gate failure → developer feedback: internal/gates (Evaluate)
//  7. new findings → AI triage: internal/ai (OnScanFinished)
//
// This package runs, after each new CodeGraph snapshot:
//
//  2. dependency change → reassessment: the component policies of the
//     organization are re-evaluated and the repository's dependency
//     findings re-scored;
//  3. architecture change → threat model: the application's threat models
//     regenerate a draft (approved versions never change) or are flagged
//     for review;
//
// plus drift alerts (opt-in) and the "new findings" feed entry after scans.
// Everything here needs the continuous_monitoring flag, except the threat
// model update, which keeps its own M5 behaviour (threat_models flag and
// auto_update setting).
package feedback

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/monitoring"
	"pathos/internal/platform/tenant"
	"pathos/internal/releases"
	"pathos/internal/threatmodel"
)

// Loops runs the cross-module feedback loops.
type Loops struct {
	DB      *pgxpool.Pool
	Log     *slog.Logger
	Threats *threatmodel.Service
}

type driftRow struct {
	id            uuid.UUID
	repoID        uuid.UUID
	severity      string
	hasChanges    bool
	architectural bool
	counts        map[string]int
	from          *uuid.UUID
	commit        string
	repoName      string
	components    []monitoring.DriftItem
}

func (l *Loops) loadDrift(ctx context.Context, orgID, snapshotID uuid.UUID) (*driftRow, error) {
	var d driftRow
	var items []monitoring.DriftItem
	err := l.DB.QueryRow(ctx, `SELECT d.id, d.repository_id, d.severity, d.has_changes, d.counts, d.from_snapshot_id, d.to_commit, d.items,
		COALESCE(NULLIF(r.display_name, ''), r.full_name)
		FROM architecture_drifts d JOIN repositories r ON r.id = d.repository_id WHERE d.organization_id = $1 AND d.to_snapshot_id = $2`,
		orgID, snapshotID).Scan(&d.id, &d.repoID, &d.severity, &d.hasChanges, &d.counts, &d.from, &d.commit, &items, &d.repoName)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		if it.Category == "component" {
			d.components = append(d.components, it)
		} else {
			d.architectural = true
		}
	}
	return &d, nil
}

// OnSnapshotReady is the CodeGraph hook (after the drift is stored).
func (l *Loops) OnSnapshotReady(ctx context.Context, orgID, appID, snapshotID uuid.UUID) {
	ctx = tenant.WithOrg(ctx, orgID)
	log := l.Log.With("application_id", appID, "snapshot_id", snapshotID)
	on, err := monitoring.Enabled(ctx, l.DB, orgID)
	if err != nil {
		log.Warn("monitoring flag lookup failed", "err", err)
	}
	var d *driftRow
	if on {
		if d, err = l.loadDrift(ctx, orgID, snapshotID); err != nil {
			// The drift was not computed (logged by CodeGraph with
			// PTH-MON-1103); the threat model loop still runs.
			d = nil
		}
	}
	// Loop 3: architecture change → threat model (M5 behaviour, recorded).
	if l.Threats != nil {
		outcomes, err := l.Threats.AutoUpdate(ctx, orgID, appID, snapshotID)
		if err != nil {
			log.Warn("threat model feedback loop failed", "err", err, "error_code", monitoring.CodeLoopFailed)
		}
		if on {
			l.recordThreatOutcomes(ctx, orgID, appID, snapshotID, d, outcomes)
		}
	}
	if !on || d == nil {
		return
	}
	// Loop 2: dependency change → reassessment.
	if len(d.components) > 0 {
		l.reassessDependencies(ctx, orgID, appID, snapshotID, d)
	}
	// Drift alerts through the notification channels (opt-in).
	if d.hasChanges {
		l.driftAlert(ctx, orgID, d)
	}
}

func (l *Loops) recordThreatOutcomes(ctx context.Context, orgID, appID, snapshotID uuid.UUID, d *driftRow, outcomes []threatmodel.AutoUpdateOutcome) {
	for _, oc := range outcomes {
		ev := monitoring.Event{OrgID: orgID, ApplicationID: &appID, EvidenceLabel: monitoring.EvidenceVerified, SubjectType: "threat_model"}
		mid := oc.ModelID
		ev.SubjectID = &mid
		ev.Evidence = map[string]any{"snapshot_id": snapshotID, "threat_model_id": oc.ModelID, "version": oc.Version}
		if d != nil {
			ev.Evidence["drift_id"] = d.id
			ev.Evidence["commit"] = d.commit
			ev.RepositoryID = &d.repoID
		}
		switch {
		case oc.Updated:
			ev.Type, ev.Severity = monitoring.TypeThreatModelUpdated, "info"
			r := oc.Result
			ev.Title = fmt.Sprintf("Threat model %q: draft v%d regenerated (%d new, %d changed, %d resolved threats)", oc.Title, oc.Version,
				r.New, r.Changed, r.Resolved)
			if r.New > 0 {
				ev.Severity = "medium"
			}
			ev.Summary = "The new CodeGraph snapshot regenerated the draft; it needs review and approval before it replaces the approved model."
			if oc.CreatedVersion && oc.ApprovedVersion > 0 {
				ev.Summary = fmt.Sprintf("A new draft version v%d was created; the approved version v%d is unchanged until the draft is approved.",
					oc.Version, oc.ApprovedVersion)
			}
			ev.Details = map[string]any{"result": r, "created_version": oc.CreatedVersion, "approved_version": oc.ApprovedVersion}
		case d != nil && d.architectural:
			ev.Type, ev.Severity = monitoring.TypeThreatModelReview, monitoring.Highest("low", d.severity)
			ev.Title = fmt.Sprintf("Threat model %q needs review after an architecture change", oc.Title)
			ev.Summary = "The architecture changed (" + summarizeCounts(d.counts) + ") but the model was not regenerated: " + oc.Reason + "."
			ev.Details = map[string]any{"reason": oc.Reason, "counts": d.counts}
		default:
			continue
		}
		if _, err := monitoring.Record(ctx, l.DB, ev); err != nil {
			l.Log.Warn("monitoring event not recorded", "err", err, "error_code", monitoring.CodeRecordFailed)
		}
	}
}

func summarizeCounts(c map[string]int) string {
	var parts []string
	for _, k := range []string{"added_internet_exposure", "added_boundary_crossings", "added_external_services", "added_datastores", "added_routes",
		"removed_routes", "removed_external_services", "removed_datastores"} {
		if n := c[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", strings.ReplaceAll(k, "_", " "), n))
		}
	}
	if len(parts) == 0 {
		return "architectural elements changed"
	}
	return strings.Join(parts, ", ")
}

// reassessDependencies is loop 2: the snapshot's components differ from
// the previous snapshot's. The organization's component policies are
// re-evaluated now (not at the next hourly run) and the repository's
// dependency findings are marked for re-scoring; components that have no
// scanned SBOM entry yet are reported so the next scan covers them.
func (l *Loops) reassessDependencies(ctx context.Context, orgID, appID, snapshotID uuid.UUID, d *driftRow) {
	added, removed, changed := 0, 0, 0
	var names []string
	for _, c := range d.components {
		switch c.Change {
		case "added":
			added++
		case "removed":
			removed++
		case "changed":
			changed++
		}
		if c.Change != "removed" && len(names) < 20 {
			names = append(names, c.Label)
		}
	}
	stats, perr := releases.EvaluateOrganization(ctx, l.DB, orgID)
	if perr != nil {
		l.Log.Warn("dependency reassessment: component policies not evaluated", "err", perr, "error_code", monitoring.CodeLoopFailed)
	}
	tag, rerr := l.DB.Exec(ctx, `UPDATE findings SET risk_dirty = true WHERE organization_id = $1 AND repository_id = $2 AND package_name <> ''
		AND status IN ('open', 'in_progress', 'needs_review') AND NOT risk_dirty`, orgID, d.repoID)
	if rerr != nil {
		l.Log.Warn("dependency reassessment: findings not marked for re-scoring", "err", rerr, "error_code", monitoring.CodeLoopFailed)
	}
	var withVulns, unscanned int
	_ = l.DB.QueryRow(ctx, `WITH comps AS (
		SELECT lower(COALESCE(NULLIF(n.attrs->>'name', ''), n.label)) AS name, COALESCE(n.attrs->>'version', '') AS version,
		       COALESCE(n.attrs->>'purl', '') AS purl
		FROM codegraph_nodes n WHERE n.snapshot_id = $1 AND n.type = 'component' AND n.node_key = ANY($3))
		SELECT count(*) FILTER (WHERE EXISTS (SELECT 1 FROM findings f WHERE f.repository_id = $2 AND f.status IN ('open', 'in_progress', 'needs_review')
		         AND lower(f.package_name) = c.name)),
		       count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM sbom_components s WHERE s.repository_id = $2
		         AND ((c.purl <> '' AND s.purl = c.purl) OR (lower(s.name) = c.name AND s.version = c.version))))
		FROM comps c`, snapshotID, d.repoID, componentKeys(d.components)).Scan(&withVulns, &unscanned)
	sev := "low"
	if withVulns > 0 {
		sev = "medium"
	}
	summary := fmt.Sprintf("Component policies re-evaluated (%d policies, %d violations); %d dependency findings queued for re-scoring.",
		stats.Policies, stats.Violations, tag.RowsAffected())
	if unscanned > 0 {
		summary += fmt.Sprintf(" %d new or changed components are not in the scanned SBOM yet; the next repository scan assesses them.", unscanned)
	}
	if perr != nil || rerr != nil {
		summary += " Part of the reassessment failed (PTH-MON-1104); see the jobs log."
	}
	repo := d.repoID
	if _, err := monitoring.Record(ctx, l.DB, monitoring.Event{OrgID: orgID, ApplicationID: &appID, RepositoryID: &repo,
		Type: monitoring.TypeDependencyChanged, Severity: sev,
		Title:         fmt.Sprintf("Dependencies changed in %s: %d added, %d changed, %d removed", d.repoName, added, changed, removed),
		Summary:       summary,
		EvidenceLabel: monitoring.EvidenceVerified,
		Evidence:      map[string]any{"from_snapshot_id": d.from, "to_snapshot_id": snapshotID, "commit": d.commit, "drift_id": d.id},
		SubjectType:   "drift", SubjectID: &d.id,
		Details: map[string]any{"added": added, "changed": changed, "removed": removed, "components": names, "with_open_findings": withVulns,
			"not_in_scanned_sbom": unscanned, "policies_evaluated": stats.Policies, "policy_violations": stats.Violations,
			"findings_rescored": tag.RowsAffected()}}); err != nil {
		l.Log.Warn("monitoring event not recorded", "err", err, "error_code", monitoring.CodeRecordFailed)
	}
}

func componentKeys(items []monitoring.DriftItem) []string {
	out := []string{}
	for _, c := range items {
		if c.Change != "removed" {
			out = append(out, c.Key)
		}
	}
	return out
}

// driftAlert sends a drift through the notification channels when the
// organization turned drift alerts on and the drift reaches the minimum
// severity (event architecture.drift: in-app, e-mail and webhooks).
func (l *Loops) driftAlert(ctx context.Context, orgID uuid.UUID, d *driftRow) {
	st, err := monitoring.LoadSettings(ctx, l.DB, orgID)
	if err != nil || !st.DriftAlerts || monitoring.SeverityRank(d.severity) > monitoring.SeverityRank(st.DriftAlertMinSeverity) {
		return
	}
	if _, err := l.DB.Exec(ctx, `INSERT INTO notification_events (organization_id, event_key, repository_id, severity, subject_id, payload)
		VALUES ($1, 'architecture.drift', $2, $3, $4, $5)`, orgID, d.repoID, d.severity, d.id,
		map[string]any{"drift_id": d.id, "counts": d.counts, "commit": d.commit, "summary": summarizeCounts(d.counts)}); err != nil {
		l.Log.Warn("drift alert not queued", "err", err, "error_code", monitoring.CodeLoopFailed)
	}
}

// OnScanFinished records the "new findings" entry of a scan (the source of
// loop 7; the AI queue records ai.triage_queued itself).
func (l *Loops) OnScanFinished(ctx context.Context, orgID, jobID uuid.UUID) {
	ctx = tenant.WithOrg(ctx, orgID)
	var repo uuid.UUID
	var n int
	var trigger, commit string
	var pr *int
	if err := l.DB.QueryRow(ctx, `SELECT repository_id, findings_new, trigger, commit_sha, pull_request FROM scan_jobs
		WHERE id = $1 AND organization_id = $2 AND target_id IS NULL`, jobID, orgID).Scan(&repo, &n, &trigger, &commit, &pr); err != nil || n == 0 || pr != nil {
		return
	}
	bySev := map[string]int{}
	top := "info"
	rows, err := l.DB.Query(ctx, `SELECT severity, count(*) FROM findings WHERE first_scan_job_id = $1 AND organization_id = $2 GROUP BY 1`, jobID, orgID)
	if err == nil {
		for rows.Next() {
			var sv string
			var c int
			if rows.Scan(&sv, &c) == nil {
				bySev[sv] = c
				top = monitoring.Highest(top, sv)
			}
		}
		rows.Close()
	}
	if _, err := monitoring.Record(ctx, l.DB, monitoring.Event{OrgID: orgID, RepositoryID: &repo, Type: monitoring.TypeFindingsNew, Severity: top,
		Title:         fmt.Sprintf("%d new finding%s", n, map[bool]string{true: "", false: "s"}[n == 1]),
		Summary:       "A " + trigger + " scan reported findings that were not known before.",
		EvidenceLabel: monitoring.EvidenceVerified, Evidence: map[string]any{"scan_job_id": jobID, "commit": commit},
		SubjectType: "scan_job", SubjectID: &jobID, Details: map[string]any{"by_severity": bySev, "trigger": trigger}}); err != nil {
		l.Log.Warn("monitoring event not recorded", "err", err, "error_code", monitoring.CodeRecordFailed)
	}
}

package remediation

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/monitoring"
	"pathos/internal/platform/httpx"
)

// Feedback loop 5 (PATHOS 3.0 M9, flag continuous_monitoring): a fix pull
// request merged (QueueMergedFixPRs, M8) or an item marked fix submitted
// (here) queues the targeted verification rescan; both, and every
// verification result, appear in the monitoring feed.

// verifySubmitted queues a verification after a person marked the item
// fix_submitted, when the organization has continuous monitoring on, the
// item has findings and no fix pull request is still open (an open fix
// pull request is verified when it is merged). A fix that cannot be
// verified gets a failed verification with the reason.
func (s *Service) verifySubmitted(ctx context.Context, tx pgx.Tx, p *authz.Principal, itemID uuid.UUID) error {
	on, err := monitoring.Enabled(ctx, tx, p.OrganizationID)
	if err != nil || !on {
		return err
	}
	it, err := scanItem(tx.QueryRow(ctx, itemSelect+" WHERE i.id = $1", itemID))
	if err != nil {
		return err
	}
	if it.FindingCount == 0 || it.RepositoryID == nil {
		return nil
	}
	var fixPR *uuid.UUID
	if it.FixPullRequest != nil {
		if it.FixPullRequest.Status != "merged" {
			return nil
		}
		fixPR = &it.FixPullRequest.ID
	}
	_, err = s.Queue(ctx, tx, p.OrganizationID, it, nil, "fix_submitted", fixPR, &p.UserID, p.Email)
	var he *httpx.Error
	if errors.As(err, &he) && he.DiagCode() == "PTH-REM-1102" {
		_, err = tx.Exec(ctx, `INSERT INTO remediation_verifications (id, organization_id, item_id, repository_id, trigger, status,
			failure_reason, fix_pull_request_id, requested_by, finished_at) VALUES ($1, $2, $3, $4, 'fix_submitted', 'failed', $5, $6, $7, now())`,
			uuid.Must(uuid.NewV7()), p.OrganizationID, it.ID, it.RepositoryID, truncate(he.Message, 2000), fixPR, p.UserID)
	}
	return err
}

var triggerText = map[string]string{
	"manual":        "requested by a person",
	"fix_pr_merged": "after the fix pull request was merged",
	"existing_scan": "with a finished scan of the repository",
	"fix_submitted": "after the item was marked fix submitted",
}

// recordQueued adds fix.verification_queued to the feed.
func recordQueued(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, it Item, vid uuid.UUID, trigger string, pl plan, fixPR *uuid.UUID) error {
	item := it.ID
	_, err := monitoring.Record(ctx, tx, monitoring.Event{OrgID: orgID, ApplicationID: it.ApplicationID, RepositoryID: it.RepositoryID,
		Type: monitoring.TypeFixVerificationQueued, Severity: "info",
		Title:         "Fix verification queued: " + it.Title,
		Summary:       fmt.Sprintf("Targeted rescan of %d file(s) %s; before commit %s.", len(pl.files), triggerText[trigger], shortCommit(pl.beforeCommit)),
		EvidenceLabel: monitoring.EvidenceVerified,
		Evidence:      map[string]any{"verification_id": vid, "before_scan_job_id": pl.beforeJob, "commit": pl.beforeCommit, "fix_pull_request_id": fixPR},
		SubjectType:   "remediation_item", SubjectID: &item, Details: map[string]any{"trigger": trigger, "files": pl.files}})
	return err
}

// recordFinished adds fix.verified to the feed.
func recordFinished(ctx context.Context, tx pgx.Tx, orgID, itemID, vid uuid.UUID, status, result, reason, afterCommit string, regressions int) error {
	var title string
	var app, repo *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT title, application_id, repository_id FROM remediation_items WHERE id = $1`, itemID).Scan(&title, &app, &repo); err != nil {
		return err
	}
	sev, outcome := "info", result
	switch {
	case status != "completed":
		sev, outcome = "low", "could not run"
	case result == "regressed":
		sev = "high"
	case result == "still_present":
		sev = "medium"
	}
	summary := "Before-and-after evidence is on the item."
	if reason != "" {
		summary = reason
	}
	item := itemID
	_, err := monitoring.Record(ctx, tx, monitoring.Event{OrgID: orgID, ApplicationID: app, RepositoryID: repo,
		Type: monitoring.TypeFixVerified, Severity: sev,
		Title:         fmt.Sprintf("Fix verification %s: %s", outcome, title),
		Summary:       summary,
		EvidenceLabel: monitoring.EvidenceVerified,
		Evidence:      map[string]any{"verification_id": vid, "commit": afterCommit},
		SubjectType:   "remediation_item", SubjectID: &item,
		Details: map[string]any{"status": status, "result": result, "regressions": regressions}})
	return err
}

func shortCommit(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "unknown"
	}
	return s
}

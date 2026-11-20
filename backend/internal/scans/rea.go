package scans

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
	"pathos/internal/scanners"
)

// Reverse-engineering executions (PATHOS 3.0 M10, package rea): a scan
// execution with trigger "rea" of an artifact target, using the
// organization's reverse-engineering system profile, whose only scanner is
// pathos-rea with the analysis configuration recorded in the execution's
// configuration snapshot. The input policy (own builds by default) is
// checked by the rea package before EnqueueREA; the lease runs the job only
// on a worker-rea worker (reaLaneCondition).

// REAEnqueue describes one analysis to queue.
type REAEnqueue struct {
	TargetID         uuid.UUID
	ProfileVersionID uuid.UUID
	// Config is pathos-rea's configuration (worker.REAConfig).
	Config json.RawMessage
	// TimeoutSeconds bounds the whole execution.
	TimeoutSeconds int
	RequestedBy    *uuid.UUID
}

// EnqueueREA queues a reverse-engineering execution of an artifact target
// (or returns the one already queued for it).
func EnqueueREA(ctx context.Context, q db.Querier, orgID uuid.UUID, in REAEnqueue) (EnqueueResult, error) {
	var res EnqueueResult
	var repoID uuid.UUID
	var kind, name, reference, repoName string
	var enabled bool
	var archived *time.Time
	err := q.QueryRow(ctx, `SELECT t.repository_id, t.kind, t.name, t.reference, t.enabled, r.archived_at,
		COALESCE(NULLIF(r.display_name, ''), r.full_name)
		FROM scan_targets t JOIN repositories r ON r.id = t.repository_id WHERE t.organization_id = $1 AND t.id = $2`, orgID, in.TargetID).
		Scan(&repoID, &kind, &name, &reference, &enabled, &archived, &repoName)
	if errors.Is(err, pgx.ErrNoRows) {
		return res, errNotFound
	}
	if err != nil {
		return res, err
	}
	if !artifactKind(kind) {
		return res, fmt.Errorf("%w: only uploaded build artifacts can be analysed", ErrScanPrerequisite)
	}
	if archived != nil || !enabled {
		return res, fmt.Errorf("%w: the target is disabled or its repository is archived", ErrNotScannable)
	}
	err = q.QueryRow(ctx, `SELECT id FROM scan_jobs WHERE organization_id = $1 AND target_id = $2 AND trigger = 'rea' AND status = 'queued'`,
		orgID, in.TargetID).Scan(&res.JobID)
	if err == nil {
		res.Coalesced = true
		return res, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return res, err
	}
	snap, profileName, err := configSnapshot(ctx, q, in.ProfileVersionID)
	if err != nil {
		return res, err
	}
	var m map[string]any
	if err := json.Unmarshal(snap, &m); err != nil {
		return res, err
	}
	cfg := in.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}
	m["scanners"] = []map[string]any{{"key": scanners.PathosREA, "config": cfg}}
	delete(m, "custom_rules")
	if in.TimeoutSeconds > 0 {
		m["timeout_seconds"] = in.TimeoutSeconds
	}
	m["target"] = map[string]any{"id": in.TargetID, "kind": kind, "name": name, "reference": reference}
	if snap, err = json.Marshal(m); err != nil {
		return res, err
	}
	res.JobID = uuid.Must(uuid.NewV7())
	jobName := truncate(repoName+" · "+name+" · "+profileName, 200)
	if _, err := q.Exec(ctx, `
		INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, priority, ref, commit_sha, requested_by,
		  name, config_snapshot, target_id, target_kind)
		VALUES ($1, $2, $3, $4, 'rea', $5, $6, '', $7, $8, $9, $10, $11)`,
		res.JobID, orgID, repoID, in.ProfileVersionID, priorities["rea"], kind, in.RequestedBy, jobName, snap, in.TargetID, kind); err != nil {
		return res, err
	}
	return res, AddEvent(ctx, q, orgID, res.JobID, "queued", "", "info", "queued for reverse engineering ("+kind+" target "+name+")")
}

// leaseREA prepares a leased reverse-engineering execution: the artifact
// (downloaded and verified by SHA-256 by the worker; no signature material
// or credentials) and pathos-rea with the recorded configuration.
func (s *Service) leaseREA(ctx context.Context, tx pgx.Tx, orgID, targetID uuid.UUID, job *LeasedJob) error {
	var t LeasedTarget
	var snap []byte
	if err := tx.QueryRow(ctx, `SELECT t.kind, t.reference, t.sbom_sha256, t.sbom_size, t.artifact_name, j.config_snapshot
		FROM scan_targets t JOIN scan_jobs j ON j.id = $3 WHERE t.organization_id = $1 AND t.id = $2`, orgID, targetID, job.JobID).
		Scan(&t.Kind, &t.Reference, &t.SHA256, &t.Size, &t.FileName, &snap); err != nil {
		return err
	}
	if !artifactKind(t.Kind) {
		return errors.New("reverse engineering needs an artifact target")
	}
	var cs struct {
		Scanners       []ProfileScanner `json:"scanners"`
		TimeoutSeconds int              `json:"timeout_seconds"`
	}
	if err := json.Unmarshal(snap, &cs); err != nil {
		return err
	}
	job.Scanners = nil
	for _, ps := range cs.Scanners {
		if scanners.IsREATool(ps.Key) {
			job.Scanners = append(job.Scanners, ps)
		}
	}
	if len(job.Scanners) == 0 {
		job.Scanners = []ProfileScanner{{Key: scanners.PathosREA}}
	}
	if cs.TimeoutSeconds > 0 {
		job.TimeoutSeconds = cs.TimeoutSeconds
	}
	job.Exclusions = nil
	job.Target = &t
	job.Source, job.CloneURL, job.FullHistory, job.Credential = nil, "", false, nil
	return nil
}

// InsertReviewFinding creates (or refreshes) a finding from a person's
// decision on a reverse-engineering proposal: status needs_review (a
// finding that still needs triage, never confirmed by the analysis
// itself), attributed to the analysis execution and the artifact target.
// identity names the finding across analyses of the same artifact.
func InsertReviewFinding(ctx context.Context, tx pgx.Tx, orgID, repoID, jobID, targetID uuid.UUID, f scanners.Finding, identity string) (uuid.UUID, error) {
	sum := sha256.Sum256([]byte(f.ScannerKey + "\x00" + identity))
	fp := targetFingerprint(targetID, hex.EncodeToString(sum[:]))
	cwe := f.CWE
	if cwe == nil {
		cwe = []string{}
	}
	var id uuid.UUID
	err := tx.QueryRow(ctx, `INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title,
		  description, severity, cwe, file_path, first_scan_job_id, last_scan_job_id, confidence, scan_target_id, status)
		VALUES ($1, $2, $3, $4, $5, ARRAY[$6], $7, $8, $9, $10, $11, $12, $13, $13, $14, $15, 'needs_review')
		ON CONFLICT (repository_id, fingerprint) DO UPDATE SET last_seen_at = now(), last_scan_job_id = EXCLUDED.last_scan_job_id,
		  description = EXCLUDED.description, updated_at = now(),
		  status = CASE WHEN findings.status = 'fixed' THEN 'needs_review' ELSE findings.status END,
		  resolved_at = CASE WHEN findings.status = 'fixed' THEN NULL ELSE findings.resolved_at END
		RETURNING id`,
		uuid.Must(uuid.NewV7()), orgID, repoID, fp, f.Category, f.ScannerKey, truncate(f.RuleID, 300), truncate(f.Title, 300),
		f.Description, f.Severity, cwe, truncate(f.FilePath, 1000), jobID, confidenceOrUnknown(f.Confidence), targetID).Scan(&id)
	return id, err
}

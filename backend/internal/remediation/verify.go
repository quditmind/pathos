package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/aifix"
	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/logging"
	"pathos/internal/scans"
	"pathos/internal/scm"
)

// Fix verification. "Verify fix" queues a targeted rescan: a worker that
// has the findings' scanners clones the repository at the commit where the
// findings were last reported (before) and at the head of the scan branch
// (after), runs each scanner on the affected files only — the
// verified-AI-fix machinery (internal/aifix, worker scanFiles) — and
// reports the results in those files. PATHOS decides:
//
//   - fixed: every finding was reproduced before and is gone after, and no
//     new result appeared in the affected files → the item closes;
//   - regressed: the findings are gone but new results appeared in the
//     affected files (listed as regressions) → the item stays open;
//   - still_present: a finding is still reported after;
//   - inconclusive: a finding was not reproduced before, so absence after
//     proves nothing.
//
// A finished scan of the repository can also serve as the "after" evidence
// (scan_job_id). Findings themselves are never changed here: scans resolve
// them, as for fix pull requests.

const (
	verifyLeaseDuration = 20 * time.Minute
	verifyMaxAttempts   = 3
	maxVerifyResultBody = 8 << 20
	maxResultsPerSide   = 5000
)

// Verification is the before-and-after evidence of a fix.
type Verification struct {
	ID               uuid.UUID          `json:"id"`
	ItemID           uuid.UUID          `json:"item_id"`
	Status           string             `json:"status"`
	Result           *string            `json:"result"`
	Trigger          string             `json:"trigger"`
	ScannerKeys      []string           `json:"scanner_keys"`
	ScannerVersions  map[string]string  `json:"scanner_versions"`
	Files            []string           `json:"files"`
	Before           Side               `json:"before"`
	After            Side               `json:"after"`
	Findings         []FindingVerdict   `json:"findings"`
	Regressions      []aifix.Result     `json:"regressions"`
	FixPullRequestID *uuid.UUID         `json:"fix_pull_request_id"`
	FailureReason    string             `json:"failure_reason"`
	RequestedByEmail string             `json:"requested_by_email"`
	CreatedAt        time.Time          `json:"created_at"`
	FinishedAt       *time.Time         `json:"finished_at"`
	Results          map[string]Results `json:"-"`
}

// Side is one side of the evidence.
type Side struct {
	ScanJobID   *uuid.UUID `json:"scan_job_id"`
	Commit      string     `json:"commit"`
	Ref         string     `json:"ref,omitempty"`
	ResultCount *int       `json:"result_count"`
}

// FindingVerdict is the verdict for one finding.
type FindingVerdict struct {
	FindingID    uuid.UUID `json:"finding_id"`
	RuleID       string    `json:"rule_id"`
	File         string    `json:"file"`
	ScannerKey   string    `json:"scanner_key"`
	StatusBefore string    `json:"status_before"`
	StatusAfter  string    `json:"status_after"`
	Reproduced   bool      `json:"reproduced"`
	Removed      bool      `json:"removed"`
}

// Results are a scanner's results in the affected files.
type Results struct {
	Before []aifix.Result `json:"before"`
	After  []aifix.Result `json:"after"`
}

// target is a finding to prove gone.
type target struct {
	FindingID   uuid.UUID `json:"finding_id"`
	RuleID      string    `json:"rule_id"`
	File        string    `json:"file"`
	Line        int       `json:"line,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	ScannerKey  string    `json:"scanner_key"`
	Status      string    `json:"status"`
}

type evidence struct {
	Findings    []FindingVerdict   `json:"findings"`
	Regressions []aifix.Result     `json:"regressions"`
	Results     map[string]Results `json:"results,omitempty"`
}

const verificationSelect = `SELECT v.id, v.item_id, v.status, v.result, v.trigger, v.scanner_keys, v.scanner_versions, v.files,
	v.before_scan_job_id, v.before_commit, v.before_count, v.after_scan_job_id, v.after_commit, v.after_ref, v.after_count,
	v.evidence, v.fix_pull_request_id, v.failure_reason, COALESCE(u.email, ''), v.created_at, v.finished_at, v.targets
	FROM remediation_verifications v LEFT JOIN users u ON u.id = v.requested_by`

func scanVerification(row pgx.Row) (Verification, error) {
	var v Verification
	var versions, ev, targets []byte
	err := row.Scan(&v.ID, &v.ItemID, &v.Status, &v.Result, &v.Trigger, &v.ScannerKeys, &versions, &v.Files, &v.Before.ScanJobID, &v.Before.Commit,
		&v.Before.ResultCount, &v.After.ScanJobID, &v.After.Commit, &v.After.Ref, &v.After.ResultCount, &ev, &v.FixPullRequestID, &v.FailureReason,
		&v.RequestedByEmail, &v.CreatedAt, &v.FinishedAt, &targets)
	if err != nil {
		return v, err
	}
	_ = json.Unmarshal(versions, &v.ScannerVersions)
	var e evidence
	_ = json.Unmarshal(ev, &e)
	v.Findings, v.Regressions, v.Results = e.Findings, e.Regressions, e.Results
	if v.Findings == nil {
		// Not finished: the findings being verified.
		var ts []target
		_ = json.Unmarshal(targets, &ts)
		v.Findings = []FindingVerdict{}
		for _, t := range ts {
			v.Findings = append(v.Findings, FindingVerdict{FindingID: t.FindingID, RuleID: t.RuleID, File: t.File, ScannerKey: t.ScannerKey, StatusBefore: t.Status})
		}
	}
	if v.Regressions == nil {
		v.Regressions = []aifix.Result{}
	}
	if v.ScannerVersions == nil {
		v.ScannerVersions = map[string]string{}
	}
	return v, nil
}

func (s *Service) listVerifications(ctx context.Context, itemID uuid.UUID) ([]Verification, error) {
	rows, err := s.DB.Query(ctx, verificationSelect+" WHERE v.item_id = $1 ORDER BY v.created_at DESC LIMIT 100", itemID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Verification, error) { return scanVerification(r) })
	if out == nil {
		out = []Verification{}
	}
	return out, err
}

func (s *Service) verifications(w http.ResponseWriter, r *http.Request) {
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
	if _, err := s.loadItem(ctx, p, id, authz.PermRemediationRead); err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := s.listVerifications(ctx, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// --- planning ------------------------------------------------------------------

type plan struct {
	repoID       uuid.UUID
	targets      []target
	scanners     []string
	configs      map[string]json.RawMessage
	files        []string
	beforeJob    *uuid.UUID
	beforeCommit string
	afterRef     string
}

func reasonOf(err error) string {
	var he *httpx.Error
	if errors.As(err, &he) {
		return he.Message
	}
	return err.Error()
}

// plan checks that an item's fix can be verified (with a targeted rescan,
// or with a finished scan when scanJobID is set) and gathers what the
// verification needs.
func (s *Service) plan(ctx context.Context, orgID uuid.UUID, it Item, scanJobID *uuid.UUID) (plan, error) {
	var pl plan
	switch {
	case slices.Contains(terminal, it.Status):
		return pl, ErrNotVerifiable("the item is " + strings.ReplaceAll(it.Status, "_", " "))
	case it.RepositoryID == nil:
		return pl, ErrNotVerifiable("the item has no repository")
	}
	var running bool
	if err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM remediation_verifications WHERE item_id = $1 AND status IN ('queued', 'running'))`,
		it.ID).Scan(&running); err != nil {
		return pl, err
	}
	if running {
		return pl, ErrVerificationRunning
	}
	pl.repoID = *it.RepositoryID
	var source, cloneURL, scanBranch, defBranch string
	var conn *uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT source_type, COALESCE(clone_url, ''), scm_connection_id, scan_branch, default_branch FROM repositories
		WHERE organization_id = $1 AND id = $2`, orgID, pl.repoID).Scan(&source, &cloneURL, &conn, &scanBranch, &defBranch); err != nil {
		return pl, err
	}
	pl.afterRef = scanBranch
	if pl.afterRef == "" {
		pl.afterRef = defBranch
	}
	rows, err := s.DB.Query(ctx, `SELECT f.id, f.rule_id, f.file_path, COALESCE(f.start_line, 0), f.fingerprint, f.scanner_keys, f.status,
		f.last_scan_job_id, COALESCE(j.commit_sha, ''), f.scan_target_id IS NOT NULL
		FROM remediation_item_findings x JOIN findings f ON f.id = x.finding_id LEFT JOIN scan_jobs j ON j.id = f.last_scan_job_id
		WHERE x.item_id = $1 ORDER BY j.finished_at DESC NULLS LAST, f.id`, it.ID)
	if err != nil {
		return pl, err
	}
	type frow struct {
		t      target
		keys   []string
		job    *uuid.UUID
		commit string
		tgt    bool
	}
	fs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (frow, error) {
		var f frow
		return f, r.Scan(&f.t.FindingID, &f.t.RuleID, &f.t.File, &f.t.Line, &f.t.Fingerprint, &f.keys, &f.t.Status, &f.job, &f.commit, &f.tgt)
	})
	if err != nil {
		return pl, err
	}
	if len(fs) == 0 {
		return pl, ErrNotVerifiable("the item has no findings")
	}
	pl.configs = map[string]json.RawMessage{}
	for _, f := range fs {
		t := f.t
		if scanJobID == nil {
			// A targeted rescan proves only what it can reproduce.
			if t.Status == "fixed" || t.Status == "false_positive" || t.Status == "accepted_risk" {
				continue
			}
			switch {
			case f.tgt:
				return pl, ErrNotVerifiable("finding " + t.FindingID.String() + " comes from a scan target, not from the repository's source")
			case t.File == "" || !scm.ValidRepoPath(t.File):
				return pl, ErrNotVerifiable("finding " + t.FindingID.String() + " has no file location to rescan")
			case f.commit == "" || !scm.ValidCommit(f.commit):
				return pl, ErrNotVerifiable("the last scan of finding " + t.FindingID.String() + " did not record a commit")
			}
			t.ScannerKey = scans.VerifyScanner(f.keys)
			if t.ScannerKey == "" {
				return pl, ErrNotVerifiable("finding " + t.FindingID.String() + " comes only from an imported report, which PATHOS cannot re-run")
			}
			if pl.beforeJob == nil {
				pl.beforeJob, pl.beforeCommit = f.job, f.commit
			}
			if !slices.Contains(pl.scanners, t.ScannerKey) {
				pl.scanners = append(pl.scanners, t.ScannerKey)
				cfg := json.RawMessage(`{}`)
				if s.ScannerConfig != nil {
					cfg = s.ScannerConfig(ctx, f.job, t.ScannerKey)
				}
				pl.configs[t.ScannerKey] = cfg
			}
			if !slices.Contains(pl.files, t.File) {
				pl.files = append(pl.files, t.File)
			}
		} else if len(f.keys) > 0 {
			t.ScannerKey = f.keys[0]
		}
		pl.targets = append(pl.targets, t)
	}
	if scanJobID != nil {
		return pl, nil
	}
	switch {
	case len(pl.targets) == 0:
		return pl, ErrNotVerifiable("no finding of the item is open; verify with a finished scan of the repository instead")
	case source == "upload":
		return pl, ErrNotVerifiable("uploaded repositories have no SCM connection to check out the fixed code")
	case conn == nil || cloneURL == "":
		return pl, ErrNotVerifiable("the repository has no SCM connection")
	case pl.afterRef == "":
		return pl, ErrNotVerifiable("the repository has no scan branch")
	}
	sort.Strings(pl.files)
	return pl, nil
}

// --- request ------------------------------------------------------------------

type verifyInput struct {
	ScanJobID *uuid.UUID `json:"scan_job_id"`
}

func (s *Service) verify(w http.ResponseWriter, r *http.Request) {
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
	it, err := s.loadItem(ctx, p, id, authz.PermRemediationManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if it.RepositoryID != nil {
		// Queuing a rescan runs a scanner on the repository's code.
		if err := s.requireRepo(ctx, p, authz.PermScansRun, *it.RepositoryID); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	var in verifyInput
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, &in); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	var vid uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		vid, err = s.Queue(ctx, tx, p.OrganizationID, it, in.ScanJobID, "manual", nil, &p.UserID, p.Email)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := scanVerification(s.DB.QueryRow(ctx, verificationSelect+" WHERE v.id = $1", vid))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, v)
}

// Queue plans and records a verification of an item in tx: a queued
// targeted rescan, or (scanJobID set) an immediate verdict from a finished
// scan of the repository.
func (s *Service) Queue(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, it Item, scanJobID *uuid.UUID, trigger string, fixPR *uuid.UUID, by *uuid.UUID, byEmail string) (uuid.UUID, error) {
	// Serialize verifications of one item.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM remediation_items WHERE id = $1 FOR UPDATE`, it.ID); err != nil {
		return uuid.Nil, err
	}
	pl, err := s.plan(ctx, orgID, it, scanJobID)
	if err != nil {
		return uuid.Nil, err
	}
	id := uuid.Must(uuid.NewV7())
	targets, _ := json.Marshal(pl.targets)
	configs, _ := json.Marshal(pl.configs)
	if scanJobID != nil {
		trigger = "existing_scan"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO remediation_verifications (id, organization_id, item_id, repository_id, trigger, status, scanner_keys,
		scanner_configs, files, targets, before_scan_job_id, before_commit, after_ref, fix_pull_request_id, requested_by)
		VALUES ($1, $2, $3, $4, $5, 'queued', $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		id, orgID, it.ID, pl.repoID, trigger, nonNil(pl.scanners), configs, nonNil(pl.files), targets, pl.beforeJob, pl.beforeCommit,
		truncate(pl.afterRef, 255), fixPR, by); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE remediation_items SET status = 'verifying', updated_at = now() WHERE id = $1`, it.ID); err != nil {
		return uuid.Nil, err
	}
	if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: orgID, ActorID: by, ActorEmail: byEmail,
		Action: "remediation_item.verify", TargetType: "remediation_item", TargetID: it.ID.String(),
		Metadata: map[string]any{"verification_id": id.String(), "trigger": trigger, "scan_job_id": scanJobID, "fix_pull_request_id": fixPR,
			"scanners": pl.scanners, "files": pl.files}}); err != nil {
		return uuid.Nil, err
	}
	if scanJobID != nil {
		if err := s.verifyWithScan(ctx, tx, orgID, it.ID, id, pl, *scanJobID); err != nil {
			return uuid.Nil, err
		}
	}
	return id, nil
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// verifyWithScan decides a verification from a finished scan of the
// repository: each finding must be absent from that scan while the
// scanners that reported it ran successfully in it.
func (s *Service) verifyWithScan(ctx context.Context, tx pgx.Tx, orgID, itemID, vid uuid.UUID, pl plan, jobID uuid.UUID) error {
	var repo uuid.UUID
	var status, commit string
	var pr *int
	err := tx.QueryRow(ctx, `SELECT repository_id, status, commit_sha, pull_request FROM scan_jobs WHERE organization_id = $1 AND id = $2`,
		orgID, jobID).Scan(&repo, &status, &commit, &pr)
	if errors.Is(err, pgx.ErrNoRows) {
		return httpx.BadRequest("scan_job_id: no such scan")
	}
	if err != nil {
		return err
	}
	switch {
	case repo != pl.repoID:
		return httpx.BadRequest("scan_job_id: the scan is of another repository")
	case pr != nil:
		return ErrNotVerifiable("a pull request scan does not change what is tracked for the repository; use a scan of the scan branch")
	case status != "succeeded":
		return ErrNotVerifiable("the scan has not succeeded (status " + status + ")")
	}
	ev := evidence{Findings: []FindingVerdict{}, Regressions: []aifix.Result{}}
	fixed := true
	inconclusive := false
	files := []string{}
	for _, t := range pl.targets {
		var keys []string
		var seen, ran bool
		var after string
		if err := tx.QueryRow(ctx, `SELECT f.scanner_keys, f.status,
			EXISTS (SELECT 1 FROM finding_occurrences o JOIN scan_results sr ON sr.id = o.scan_result_id WHERE o.finding_id = f.id AND sr.scan_job_id = $2),
			EXISTS (SELECT 1 FROM scan_results sr WHERE sr.scan_job_id = $2 AND sr.scanner_key = ANY(f.scanner_keys) AND sr.status = 'succeeded')
			FROM findings f WHERE f.id = $1`, t.FindingID, jobID).Scan(&keys, &after, &seen, &ran); err != nil {
			return err
		}
		fv := FindingVerdict{FindingID: t.FindingID, RuleID: t.RuleID, File: t.File, ScannerKey: t.ScannerKey, StatusBefore: t.Status, StatusAfter: after,
			Reproduced: true, Removed: !seen && ran}
		if !ran {
			inconclusive = true
		} else if seen {
			fixed = false
		}
		ev.Findings = append(ev.Findings, fv)
		if t.File != "" && !slices.Contains(files, t.File) {
			files = append(files, t.File)
		}
	}
	// Regressions: findings that scan first reported in the affected files.
	rows, err := tx.Query(ctx, `SELECT f.rule_id, f.file_path, COALESCE(f.start_line, 0), f.title FROM findings f
		WHERE f.first_scan_job_id = $1 AND f.file_path = ANY($2) ORDER BY f.file_path, f.start_line LIMIT 200`, jobID, files)
	if err != nil {
		return err
	}
	ev.Regressions, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (aifix.Result, error) {
		var x aifix.Result
		return x, r.Scan(&x.RuleID, &x.File, &x.Line, &x.Title)
	})
	if err != nil {
		return err
	}
	if ev.Regressions == nil {
		ev.Regressions = []aifix.Result{}
	}
	result := "fixed"
	switch {
	case inconclusive:
		result = "inconclusive"
	case !fixed:
		result = "still_present"
	case len(ev.Regressions) > 0:
		result = "regressed"
	}
	after := len(ev.Regressions)
	for _, f := range ev.Findings {
		if !f.Removed {
			after++
		}
	}
	before := len(ev.Findings)
	return s.finish(ctx, tx, orgID, itemID, vid, "completed", result, ev, &before, &after, commit, &jobID, "", map[string]string{}, files)
}

// finish records a verdict and applies it to the item: fixed closes it;
// anything else returns it to in progress.
func (s *Service) finish(ctx context.Context, tx pgx.Tx, orgID, itemID, vid uuid.UUID, status, result string, ev evidence, before, after *int,
	afterCommit string, afterJob *uuid.UUID, reason string, versions map[string]string, files []string) error {
	evJSON, _ := json.Marshal(ev)
	verJSON, _ := json.Marshal(versions)
	var res *string
	if status == "completed" {
		res = &result
	}
	if _, err := tx.Exec(ctx, `UPDATE remediation_verifications SET status = $2, result = $3, evidence = $4, before_count = $5, after_count = $6,
		after_commit = $7, after_scan_job_id = COALESCE($8, after_scan_job_id), failure_reason = $9, scanner_versions = $10,
		files = CASE WHEN cardinality(files) = 0 THEN $11 ELSE files END, finished_at = now(), leased_by = NULL, lease_expires_at = NULL
		WHERE id = $1`, vid, status, res, evJSON, before, after, truncate(afterCommit, 64), afterJob, truncate(reason, 2000), verJSON, nonNil(files)); err != nil {
		return err
	}
	if status == "completed" && result == "fixed" {
		if _, err := tx.Exec(ctx, `UPDATE remediation_items SET status = 'closed', closed_at = now(), closed_by_verification_id = $2, updated_at = now()
			WHERE id = $1`, itemID, vid); err != nil {
			return err
		}
	} else if _, err := tx.Exec(ctx, `UPDATE remediation_items SET status = 'in_progress', updated_at = now() WHERE id = $1 AND status = 'verifying'`, itemID); err != nil {
		return err
	}
	action := "remediation_item.verification_" + status
	meta := map[string]any{"verification_id": vid.String(), "status": status, "reason": reason, "regressions": len(ev.Regressions)}
	if res != nil {
		meta["result"] = *res
	}
	if status == "completed" && result == "fixed" {
		action = "remediation_item.closed"
	}
	return audit.Write(ctx, tx, audit.Entry{OrganizationID: orgID, Action: action, TargetType: "remediation_item", TargetID: itemID.String(), Metadata: meta})
}

// Decide compares the scanners' results in the affected files before and
// after the fix for each target and returns the verdict.
func Decide(targets []target, results map[string]Results) (string, evidence) {
	ev := evidence{Findings: []FindingVerdict{}, Regressions: []aifix.Result{}, Results: results}
	allRemoved, allReproduced := true, true
	for _, t := range targets {
		rs := results[t.ScannerKey]
		v := aifix.Compare(rs.Before, rs.After, aifix.Target{RuleID: t.RuleID, File: t.File, Line: t.Line}, nil)
		fv := FindingVerdict{FindingID: t.FindingID, RuleID: t.RuleID, File: t.File, ScannerKey: t.ScannerKey, StatusBefore: t.Status,
			Reproduced: v.Reproduced, Removed: v.Reproduced && v.Removed}
		if !fv.Reproduced {
			allReproduced = false
		} else if !fv.Removed {
			allRemoved = false
		}
		ev.Findings = append(ev.Findings, fv)
	}
	ev.Regressions = Regressions(results)
	switch {
	case !allRemoved:
		return "still_present", ev
	case !allReproduced:
		return "inconclusive", ev
	case len(ev.Regressions) > 0:
		return "regressed", ev
	}
	return "fixed", ev
}

// Regressions are results that appear more often after than before (per
// scanner, rule and file; lines move when code changes).
func Regressions(results map[string]Results) []aifix.Result {
	out := []aifix.Result{}
	keys := make([]string, 0, len(results))
	for k := range results {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rs := results[k]
		before := map[string]int{}
		for _, r := range rs.Before {
			before[r.RuleID+"\x00"+r.File]++
		}
		for _, r := range rs.After {
			key := r.RuleID + "\x00" + r.File
			if before[key] > 0 {
				before[key]--
				continue
			}
			out = append(out, r)
		}
	}
	return out
}

// --- worker protocol -------------------------------------------------------------

// RegisterWorker mounts the worker endpoints (authenticated worker API).
func (s *Service) RegisterWorker(mux *http.ServeMux) {
	mux.HandleFunc("POST /internal/worker/v1/remediation-lease", s.lease)
	mux.HandleFunc("POST /internal/worker/v1/remediation-jobs/{id}/result", s.result)
}

// LeasedVerification is a targeted rescan as a worker receives it.
type LeasedVerification struct {
	VerificationID uuid.UUID                  `json:"verification_id"`
	FullName       string                     `json:"full_name"`
	CloneURL       string                     `json:"clone_url"`
	Ref            string                     `json:"ref"`
	BeforeCommit   string                     `json:"before_commit"`
	Credential     *scm.Credential            `json:"credential,omitempty"`
	Public         bool                       `json:"public"`
	Scanners       map[string]json.RawMessage `json:"scanners"`
	Files          []string                   `json:"files"`
	TimeoutSeconds int                        `json:"timeout_seconds"`
}

// requeueExpired returns expired leases to the queue (or fails them after
// the last attempt), in one organization (orgID) or all (nil, jobs role).
func requeueExpired(ctx context.Context, q db.Querier, orgID *uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE remediation_verifications SET
		status = CASE WHEN attempts >= $1 THEN 'failed' ELSE 'queued' END,
		failure_reason = CASE WHEN attempts >= $1 THEN 'the worker lease expired ' || attempts || ' times' ELSE failure_reason END,
		finished_at = CASE WHEN attempts >= $1 THEN now() ELSE NULL END,
		leased_by = NULL, lease_expires_at = NULL
		WHERE status = 'running' AND lease_expires_at < now() AND ($2::uuid IS NULL OR organization_id = $2)`, verifyMaxAttempts, orgID)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `UPDATE remediation_items i SET status = 'in_progress', updated_at = now() WHERE i.status = 'verifying'
		AND ($1::uuid IS NULL OR i.organization_id = $1)
		AND NOT EXISTS (SELECT 1 FROM remediation_verifications v WHERE v.item_id = i.id AND v.status IN ('queued', 'running'))`, orgID)
	return err
}

func (s *Service) lease(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wk := scans.WorkerFrom(ctx)
	if wk == nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrUnauthenticated)
		return
	}
	org := wk.OrganizationID
	if err := requeueExpired(ctx, s.DB, &org); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	keys := make([]string, 0, len(wk.Scanners))
	for k := range wk.Scanners {
		keys = append(keys, k)
	}
	var job LeasedVerification
	var conn *uuid.UUID
	var visibility, cloneURL string
	var configs []byte
	err := s.DB.QueryRow(ctx, `
		UPDATE remediation_verifications v SET status = 'running', leased_by = $2, lease_expires_at = now() + $3::interval, attempts = attempts + 1
		FROM repositories r
		WHERE r.id = v.repository_id AND v.id = (
		  SELECT q.id FROM remediation_verifications q WHERE q.organization_id = $1 AND q.status = 'queued' AND q.scanner_keys <@ $4::text[]
		    AND cardinality(q.scanner_keys) > 0
		  ORDER BY q.created_at FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING v.id, r.full_name, COALESCE(r.clone_url, ''), r.scm_connection_id, r.visibility, v.after_ref, v.before_commit, v.scanner_configs, v.files`,
		wk.OrganizationID, wk.ID, verifyLeaseDuration.String(), keys).Scan(&job.VerificationID, &job.FullName, &cloneURL, &conn, &visibility,
		&job.Ref, &job.BeforeCommit, &configs, &job.Files)
	if errors.Is(err, pgx.ErrNoRows) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	job.CloneURL = cloneURL
	job.Public = visibility == "public"
	job.TimeoutSeconds = int(verifyLeaseDuration.Seconds()) - 120
	_ = json.Unmarshal(configs, &job.Scanners)
	fail := func(msg string) {
		_ = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
			var item uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT item_id FROM remediation_verifications WHERE id = $1`, job.VerificationID).Scan(&item); err != nil {
				return err
			}
			return s.finish(ctx, tx, wk.OrganizationID, item, job.VerificationID, "failed", "", evidence{}, nil, nil, "", nil, msg, map[string]string{}, nil)
		})
		w.WriteHeader(http.StatusNoContent)
	}
	if conn == nil || cloneURL == "" {
		fail("the repository has no SCM connection")
		return
	}
	if s.CloneCredential != nil {
		cred, err := s.CloneCredential(ctx, wk.OrganizationID, *conn)
		if err != nil {
			fail("could not obtain a clone credential: " + logging.RedactString(err.Error()))
			return
		}
		job.Credential = &cred
	}
	s.Log.Info("fix verification leased", "verification_id", job.VerificationID, "repository", job.FullName, "worker", wk.Name)
	httpx.WriteJSON(w, http.StatusOK, job)
}

// VerificationResult is what a worker reports.
type VerificationResult struct {
	Status        string             `json:"status"` // completed | failed
	FailureReason string             `json:"failure_reason"`
	BeforeCommit  string             `json:"before_commit"`
	AfterCommit   string             `json:"after_commit"`
	Versions      map[string]string  `json:"scanner_versions"`
	Results       map[string]Results `json:"results"`
}

func (s *Service) result(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wk := scans.WorkerFrom(ctx)
	if wk == nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrUnauthenticated)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	var status string
	var leasedBy *uuid.UUID
	var item uuid.UUID
	var targetsRaw []byte
	var keys, files []string
	if err := s.DB.QueryRow(ctx, `SELECT status, leased_by, item_id, targets, scanner_keys, files FROM remediation_verifications
		WHERE id = $1 AND organization_id = $2`, id, wk.OrganizationID).Scan(&status, &leasedBy, &item, &targetsRaw, &keys, &files); err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	if status != "running" || leasedBy == nil || *leasedBy != wk.ID {
		httpx.WriteError(w, r, s.Log, httpx.E(http.StatusConflict, "lease_lost", "this verification is not leased by this worker"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxVerifyResultBody)
	var res VerificationResult
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil || (res.Status != "completed" && res.Status != "failed") {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid verification result"))
		return
	}
	var targets []target
	_ = json.Unmarshal(targetsRaw, &targets)
	versions := map[string]string{}
	for k, v := range res.Versions {
		if slices.Contains(keys, k) {
			versions[k] = truncate(logging.RedactString(v), 100)
		}
	}
	if res.Status == "completed" {
		// Results only for the planned scanners and files; titles redacted.
		clean := map[string]Results{}
		for _, k := range keys {
			rs, ok := res.Results[k]
			if !ok {
				res.Status, res.FailureReason = "failed", "the worker reported no results for "+k
				break
			}
			if len(rs.Before) > maxResultsPerSide || len(rs.After) > maxResultsPerSide {
				res.Status, res.FailureReason = "failed", "too many results reported"
				break
			}
			clean[k] = Results{Before: cleanResults(rs.Before, files), After: cleanResults(rs.After, files)}
		}
		if res.Status == "completed" && (!scm.ValidCommit(res.AfterCommit) || len(res.AfterCommit) < 40) {
			res.Status, res.FailureReason = "failed", "the worker reported an invalid commit"
		}
		res.Results = clean
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if res.Status == "failed" {
			reason := strings.TrimSpace(logging.RedactString(res.FailureReason))
			if reason == "" {
				reason = "the targeted rescan failed"
			}
			return s.finish(ctx, tx, wk.OrganizationID, item, id, "failed", "", evidence{}, nil, nil, res.AfterCommit, nil, reason, versions, nil)
		}
		result, ev := Decide(targets, res.Results)
		before, after := 0, 0
		for _, rs := range res.Results {
			before += len(rs.Before)
			after += len(rs.After)
		}
		return s.finish(ctx, tx, wk.OrganizationID, item, id, "completed", result, ev, &before, &after, res.AfterCommit, nil, "", versions, nil)
	})
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if res.Status == "failed" {
		s.Log.Warn("fix verification failed", "verification_id", id, "worker", wk.Name, "error_code", "PTH-REM-1105")
	} else {
		s.Log.Info("fix verification result", "verification_id", id, "worker", wk.Name)
	}
	w.WriteHeader(http.StatusNoContent)
}

func cleanResults(in []aifix.Result, files []string) []aifix.Result {
	out := []aifix.Result{}
	for _, r := range in {
		if !slices.Contains(files, r.File) {
			continue // only the affected files are compared
		}
		out = append(out, aifix.Result{RuleID: truncate(r.RuleID, 300), File: r.File, Line: r.Line, Title: truncate(logging.RedactString(r.Title), 300)})
	}
	return out
}

// --- feedback loop: fix merged → targeted rescan -----------------------------------

// QueueMergedFixPRs queues a targeted rescan for every active item whose
// fix pull request was merged after the item's last verification, in the
// organizations with the remediation workspace on. An item that cannot be
// verified gets a failed verification with the reason (so it is not
// retried until the next merge). Returns the number of verifications.
func (s *Service) QueueMergedFixPRs(ctx context.Context) (int, error) {
	rows, err := s.DB.Query(ctx, `SELECT i.organization_id, i.id, fp.id FROM remediation_items i
		JOIN fix_pull_requests fp ON fp.id = `+fixPRExpr+`
		JOIN feature_flags ff ON ff.organization_id = i.organization_id AND ff.name = 'remediation_workspace' AND ff.enabled
		WHERE fp.status = 'merged' AND i.status NOT IN ('closed', 'wont_fix', 'verifying')
		  AND NOT EXISTS (SELECT 1 FROM remediation_verifications v WHERE v.item_id = i.id AND v.created_at >= COALESCE(fp.finished_at, fp.updated_at))
		ORDER BY fp.finished_at LIMIT 100`)
	if err != nil {
		return 0, err
	}
	type row struct{ org, item, pr uuid.UUID }
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		return x, r.Scan(&x.org, &x.item, &x.pr)
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, x := range list {
		err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
			it, err := scanItem(tx.QueryRow(ctx, itemSelect+" WHERE i.id = $1", x.item))
			if err != nil {
				return err
			}
			pr := x.pr
			_, err = s.Queue(ctx, tx, x.org, it, nil, "fix_pr_merged", &pr, nil, "")
			var he *httpx.Error
			if errors.As(err, &he) && he.DiagCode() == "PTH-REM-1102" {
				// Record why the merged fix could not be verified.
				vid := uuid.Must(uuid.NewV7())
				if _, err := tx.Exec(ctx, `INSERT INTO remediation_verifications (id, organization_id, item_id, repository_id, trigger, status,
					failure_reason, fix_pull_request_id, finished_at) VALUES ($1, $2, $3, $4, 'fix_pr_merged', 'failed', $5, $6, now())`,
					vid, x.org, x.item, it.RepositoryID, truncate(he.Message, 2000), pr); err != nil {
					return err
				}
				return nil
			}
			return err
		})
		if err != nil {
			if s.Log != nil {
				s.Log.Warn("fix verification after merge not queued", "item_id", x.item, "fix_pr_id", x.pr, "err", err, "error_code", "PTH-REM-1105")
			}
			continue
		}
		n++
	}
	return n, nil
}

// RunBackground runs the feedback loop (jobs role): merged fix pull
// requests queue a targeted rescan of their items.
func (s *Service) RunBackground(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n, err := s.QueueMergedFixPRs(ctx); err != nil {
			s.Log.Warn("fix verification feedback loop failed", "err", err)
		} else if n > 0 {
			s.Log.Info("fix verifications queued after merged fix pull requests", "count", n)
		}
		if err := requeueExpired(ctx, s.DB, nil); err != nil {
			s.Log.Warn("fix verification requeue failed", "err", fmt.Sprint(err))
		}
	}
}

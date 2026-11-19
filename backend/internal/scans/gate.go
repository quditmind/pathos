package scans

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
	"pathos/internal/policy"
	"pathos/internal/scanners"
)

// Gate is the evaluation of an execution's security gate for CI
// (docs/api-reference/scans.md#evaluate-the-security-gate): the execution's
// own gate (profile and blocking security policies) plus an optional
// severity threshold over its new findings or the repository's open ones.
type Gate struct {
	ScanID           uuid.UUID      `json:"scan_id"`
	ScanKey          string         `json:"scan_key"`
	RepositoryID     uuid.UUID      `json:"repository_id"`
	RepositoryName   string         `json:"repository_name"`
	Status           string         `json:"status"`
	Finished         bool           `json:"finished"`
	GateFailed       bool           `json:"gate_failed"`
	BlockingPolicies []string       `json:"blocking_policies"`
	FailOn           string         `json:"fail_on"`
	Scope            string         `json:"scope"`
	AllowPartial     bool           `json:"allow_partial"`
	BySeverity       map[string]int `json:"by_severity"`
	ThresholdCount   int            `json:"threshold_count"`
	Passed           bool           `json:"passed"`
	Reasons          []string       `json:"reasons"`
	// ErrorCode is the error catalogue code when the gate does not pass:
	// PTH-GATE-1002 when the scan did not succeed, else PTH-GATE-1001.
	ErrorCode string `json:"error_code,omitempty"`
}

// openStatuses are the stored finding statuses that count as open.
const openStatuses = `('open', 'in_progress', 'needs_review')`

func (s *Service) scanGate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	failOn := q.Get("fail_on")
	if failOn == "" {
		failOn = "none"
	}
	switch failOn {
	case "critical", "high", "medium", "low", "none":
	default:
		s.fail(w, r, httpx.BadRequest("fail_on must be critical, high, medium, low or none"))
		return
	}
	scope := q.Get("scope")
	if scope == "" {
		scope = "new"
	}
	if scope != "new" && scope != "all" {
		s.fail(w, r, httpx.BadRequest("scope must be new or all"))
		return
	}
	allowPartial := false
	if v := q.Get("allow_partial"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("allow_partial must be true or false"))
			return
		}
		allowPartial = b
	}
	_, j, err := s.loadJobFor(r, authz.PermScansRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	g, err := s.evaluateGate(r.Context(), j, failOn, scope, allowPartial)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}

func (s *Service) evaluateGate(ctx context.Context, j Job, failOn, scope string, allowPartial bool) (Gate, error) {
	g := Gate{ScanID: j.ID, ScanKey: j.ScanKey, RepositoryID: j.RepositoryID, RepositoryName: j.RepositoryName, Status: j.Status,
		GateFailed: j.GateFailed, FailOn: failOn, Scope: scope, AllowPartial: allowPartial, BlockingPolicies: []string{}, Reasons: []string{},
		BySeverity: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
	g.Finished = j.Status != "queued" && j.Status != "running"
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return g, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if g.Finished {
		names, err := policy.Blocking(ctx, tx, j.ID)
		if err != nil {
			return g, err
		}
		if names != nil {
			g.BlockingPolicies = names
		}
	}
	where := `f.first_scan_job_id = $1`
	arg := any(j.ID)
	if scope == "all" {
		where, arg = `f.repository_id = $1`, j.RepositoryID
	}
	rows, err := tx.Query(ctx, `SELECT f.severity, count(*) FROM findings f WHERE `+where+` AND f.status IN `+openStatuses+` GROUP BY 1`, arg)
	if err != nil {
		return g, err
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return g, err
		}
		g.BySeverity[sev] += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return g, err
	}
	if failOn != "none" {
		for sev, n := range g.BySeverity {
			if scanners.SeverityRank(sev) >= scanners.SeverityRank(failOn) {
				g.ThresholdCount += n
			}
		}
	}

	switch {
	case !g.Finished:
		g.Reasons = append(g.Reasons, "scan has not finished")
		g.ErrorCode = "PTH-GATE-1002"
	case j.Status == "succeeded":
	case j.Status == "partial" && allowPartial:
	default:
		g.Reasons = append(g.Reasons, "scan status is "+j.Status)
		g.ErrorCode = "PTH-GATE-1002"
	}
	if g.GateFailed {
		g.Reasons = append(g.Reasons, "the execution's security gate failed")
	}
	for _, n := range g.BlockingPolicies {
		g.Reasons = append(g.Reasons, "blocked by security policy "+n)
	}
	if g.ThresholdCount > 0 {
		what := "new"
		if scope == "all" {
			what = "open"
		}
		g.Reasons = append(g.Reasons, fmt.Sprintf("%d %s finding(s) at or above %s", g.ThresholdCount, what, failOn))
	}
	g.Passed = len(g.Reasons) == 0
	if !g.Passed && g.ErrorCode == "" {
		g.ErrorCode = "PTH-GATE-1001"
	}
	return g, nil
}

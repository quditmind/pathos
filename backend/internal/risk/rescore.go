package risk

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/monitoring"
)

// Feedback loop 4 (PATHOS 3.0 M9, flag continuous_monitoring): when
// vulnerability intelligence changes (EPSS, CISA KEV, OSV feeds mark the
// findings with a CVE dirty) the findings are re-scored here; a finding
// that was scored before and is now listed in KEV, changed risk band or
// moved by at least 10 EPSS percentile points appears in the monitoring
// feed, one event per repository and run.

type rescore struct {
	id       uuid.UUID
	repo     uuid.UUID
	cve      string
	severity string
	scored   bool
	score    *float64
	kev      bool
	epssPct  *float64
	newScore float64
	newKEV   bool
	newEPSS  *float64
}

const epssDelta = 0.10

// meaningful reports what changed for a finding scored before.
func (c rescore) meaningful() (kevAdded, bandChanged, epssMoved bool) {
	if !c.scored {
		return
	}
	kevAdded = c.newKEV && !c.kev
	old := 0.0
	if c.score != nil {
		old = *c.score
	}
	bandChanged = Band(old) != Band(c.newScore)
	switch {
	case c.epssPct == nil && c.newEPSS != nil, c.epssPct != nil && c.newEPSS == nil:
		epssMoved = true
	case c.epssPct != nil && c.newEPSS != nil:
		d := *c.newEPSS - *c.epssPct
		epssMoved = d >= epssDelta || d <= -epssDelta
	}
	return
}

func recordRescores(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, list []rescore) error {
	type agg struct {
		n, kev, raised, lowered, epss int
		severity                      string
		ids                           []string
		cves                          []string
	}
	by := map[uuid.UUID]*agg{}
	for _, c := range list {
		k, b, e := c.meaningful()
		if !k && !b && !e {
			continue
		}
		a := by[c.repo]
		if a == nil {
			a = &agg{severity: "info"}
			by[c.repo] = a
		}
		a.n++
		if k {
			a.kev++
		}
		if b {
			old := 0.0
			if c.score != nil {
				old = *c.score
			}
			if c.newScore > old {
				a.raised++
			} else {
				a.lowered++
			}
		}
		if e {
			a.epss++
		}
		if k || (b && c.newScore > valueOr(c.score)) {
			a.severity = monitoring.Highest(a.severity, c.severity)
		}
		if len(a.ids) < 50 {
			a.ids = append(a.ids, c.id.String())
		}
		if c.cve != "" && len(a.cves) < 20 {
			a.cves = append(a.cves, c.cve)
		}
	}
	if len(by) == 0 {
		return nil
	}
	if on, err := monitoring.Enabled(ctx, tx, orgID); err != nil || !on {
		return err
	}
	repos := make([]uuid.UUID, 0, len(by))
	for r := range by {
		repos = append(repos, r)
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].String() < repos[j].String() })
	for _, r := range repos {
		a := by[r]
		sev := a.severity
		if sev == "info" && a.epss > 0 {
			sev = "low"
		}
		repo := r
		title := fmt.Sprintf("%d finding%s re-scored after new vulnerability intelligence", a.n, map[bool]string{true: "", false: "s"}[a.n == 1])
		if a.kev > 0 {
			title = fmt.Sprintf("%d finding%s now listed as actively exploited (CISA KEV)", a.kev, map[bool]string{true: "", false: "s"}[a.kev == 1])
		}
		if _, err := monitoring.Record(ctx, tx, monitoring.Event{OrgID: orgID, RepositoryID: &repo, Type: monitoring.TypeRiskRescored, Severity: sev,
			Title: title,
			Summary: fmt.Sprintf("%d newly in KEV, %d risk band raised, %d lowered, %d with a large EPSS change.",
				a.kev, a.raised, a.lowered, a.epss),
			EvidenceLabel: monitoring.EvidenceVerified,
			Evidence:      map[string]any{"feeds": []string{"epss", "kev", "osv"}, "cves": a.cves},
			SubjectType:   "repository", SubjectID: &repo,
			Details: map[string]any{"finding_ids": a.ids, "kev_added": a.kev, "band_raised": a.raised, "band_lowered": a.lowered,
				"epss_moved": a.epss}}); err != nil {
			return err
		}
	}
	return nil
}

func valueOr(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

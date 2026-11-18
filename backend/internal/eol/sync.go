package eol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/platform/db"
	"pathos/internal/scanners"
)

// Match is the end-of-life status of one component, runtime or image.
type Match struct {
	Source    string // sbom | runtime | image
	Component string
	Version   string
	PURL      string
	Path      string
	TargetID  *uuid.UUID
	Product   *Product
	Cycle     *Cycle
	Status    string
}

// Inputs are what a repository declares or contains.
type Inputs struct {
	Components []Component
	Runtimes   []Runtime
	Images     []Image
}

// Component is an SBOM component.
type Component struct{ Name, Version, PURL string }

// Runtime is a declared runtime or a base image in a repository file.
type Runtime struct{ Kind, Name, Version, Path string }

// Image is a container image scan target.
type Image struct {
	TargetID  uuid.UUID
	Reference string
}

// Compute matches the inputs to release cycles (pure; unit-tested).
func (c *Catalog) Compute(in Inputs, now time.Time) []Match {
	if c == nil {
		return nil
	}
	var out []Match
	seen := map[string]bool{}
	add := func(m Match) {
		key := m.Source + "|" + m.Component + "|" + m.Version + "|" + m.Path + "|" + m.Product.Name + "|" + m.Cycle.Name
		if m.TargetID != nil {
			key += "|" + m.TargetID.String()
		}
		if seen[key] {
			return
		}
		seen[key] = true
		m.Status = m.Cycle.Status(now)
		out = append(out, m)
	}
	for _, comp := range in.Components {
		p := c.ByPURL(comp.PURL)
		if p == nil {
			continue
		}
		if cy := p.CycleFor(comp.Version); cy != nil {
			add(Match{Source: "sbom", Component: comp.Name, Version: comp.Version, PURL: comp.PURL, Product: p, Cycle: cy})
		}
	}
	for _, r := range in.Runtimes {
		if r.Kind == "image" {
			for _, im := range c.MatchImage(r.Name) {
				add(Match{Source: "runtime", Component: r.Name, Version: im.Version, Path: r.Path, Product: im.Product, Cycle: im.Cycle})
			}
			continue
		}
		p := c.RuntimeProduct(r.Name)
		if cy := p.CycleFor(r.Version); cy != nil {
			add(Match{Source: "runtime", Component: r.Name, Version: r.Version, Path: r.Path, Product: p, Cycle: cy})
		}
	}
	for _, img := range in.Images {
		id := img.TargetID
		for _, im := range c.MatchImage(img.Reference) {
			add(Match{Source: "image", Component: img.Reference, Version: im.Version, TargetID: &id, Product: im.Product, Cycle: im.Cycle})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		rank := map[string]int{"eol": 0, "approaching": 1, "supported": 2}
		if rank[out[i].Status] != rank[out[j].Status] {
			return rank[out[i].Status] < rank[out[j].Status]
		}
		return out[i].Product.Name+out[i].Cycle.Name < out[j].Product.Name+out[j].Cycle.Name
	})
	return out
}

// latestSupported is the newest cycle that is not end-of-life.
func (p *Product) latestSupported(now time.Time) *Cycle {
	var best *Cycle
	for i := range p.Cycles {
		c := &p.Cycles[i]
		if c.Status(now) == "eol" {
			continue
		}
		if best == nil || (c.Released != nil && (best.Released == nil || c.Released.After(*best.Released))) {
			best = c
		}
	}
	return best
}

// FindingFor describes the finding of an end-of-life product cycle.
type FindingFor struct {
	Fingerprint string
	Title       string
	Description string
	Severity    string
	Product     string
	Cycle       string
	Path        string
	TargetID    *uuid.UUID
}

// Findings groups end-of-life matches into one finding per product cycle
// (and image target): several packages of one framework are one problem.
func Findings(ms []Match, now time.Time) []FindingFor {
	type group struct {
		m     Match
		comps []string
		paths []string
	}
	groups := map[string]*group{}
	var order []string
	for _, m := range ms {
		if m.Status != "eol" {
			continue
		}
		key := m.Product.Name + "|" + m.Cycle.Name
		if m.TargetID != nil {
			key += "|" + m.TargetID.String()
		}
		g := groups[key]
		if g == nil {
			g = &group{m: m}
			groups[key] = g
			order = append(order, key)
		}
		label := m.Component
		if m.Version != "" && m.Source != "image" {
			label += " " + m.Version
		}
		if len(g.comps) < 20 && !contains(g.comps, label) {
			g.comps = append(g.comps, label)
		}
		if m.Path != "" && len(g.paths) < 20 && !contains(g.paths, m.Path) {
			g.paths = append(g.paths, m.Path)
		}
	}
	var out []FindingFor
	for _, key := range order {
		g := groups[key]
		p, c := g.m.Product, g.m.Cycle
		name := firstNonEmpty(p.Label, p.Name)
		cycleLabel := firstNonEmpty(c.Label, c.Name)
		title := fmt.Sprintf("%s %s is end-of-life", name, cycleLabel)
		sev := "medium"
		since := ""
		if c.EOL != nil {
			since = c.EOL.Format(time.DateOnly)
			title += " (since " + since + ")"
			if now.Sub(*c.EOL) > 365*24*time.Hour {
				sev = "high"
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s %s no longer receives security updates", name, cycleLabel)
		if since != "" {
			fmt.Fprintf(&b, " (end of support: %s)", since)
		}
		b.WriteString(", according to endoflife.date.")
		if ls := p.latestSupported(now); ls != nil {
			fmt.Fprintf(&b, " Upgrade to a supported release, such as %s", firstNonEmpty(ls.Label, ls.Name))
			if ls.LatestVersion != "" {
				fmt.Fprintf(&b, " (latest %s)", ls.LatestVersion)
			}
			b.WriteString(".")
		}
		fmt.Fprintf(&b, "\n\nFound in: %s", strings.Join(g.comps, ", "))
		if len(g.paths) > 0 {
			fmt.Fprintf(&b, "\nDeclared in: %s", strings.Join(g.paths, ", "))
		}
		if p.Link != "" {
			fmt.Fprintf(&b, "\nRelease policy: %s", p.Link)
		}
		f := scanners.Finding{ScannerKey: scanners.EndOfLife, Category: "eol", RuleID: "eol/" + p.Name + "/" + c.Name}
		fp := scanners.Fingerprint(f, "")
		if g.m.TargetID != nil {
			sum := sha256.Sum256([]byte("target:" + g.m.TargetID.String() + ":" + fp))
			fp = hex.EncodeToString(sum[:])
		}
		path := ""
		if len(g.paths) > 0 {
			path = g.paths[0]
		}
		out = append(out, FindingFor{Fingerprint: fp, Title: clip(title, 300), Description: clip(b.String(), 4000), Severity: sev,
			Product: p.Name, Cycle: c.Name, Path: path, TargetID: g.m.TargetID})
	}
	return out
}

func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// inputs reads a repository's components, runtimes and image targets.
func inputs(ctx context.Context, tx pgx.Tx, repoID uuid.UUID) (Inputs, error) {
	var in Inputs
	rows, err := tx.Query(ctx, `SELECT DISTINCT name, version, purl FROM sbom_components WHERE repository_id = $1 AND purl <> '' LIMIT 20000`, repoID)
	if err != nil {
		return in, err
	}
	in.Components, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Component, error) {
		var c Component
		return c, r.Scan(&c.Name, &c.Version, &c.PURL)
	})
	if err != nil {
		return in, err
	}
	rows, err = tx.Query(ctx, `SELECT kind, name, version, source_path FROM repository_runtimes WHERE repository_id = $1 ORDER BY source_path, name LIMIT 1000`, repoID)
	if err != nil {
		return in, err
	}
	in.Runtimes, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Runtime, error) {
		var x Runtime
		return x, r.Scan(&x.Kind, &x.Name, &x.Version, &x.Path)
	})
	if err != nil {
		return in, err
	}
	rows, err = tx.Query(ctx, `SELECT id, reference FROM scan_targets WHERE repository_id = $1 AND kind = 'image' AND enabled`, repoID)
	if err != nil {
		return in, err
	}
	in.Images, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Image, error) {
		var x Image
		return x, r.Scan(&x.TargetID, &x.Reference)
	})
	return in, err
}

// SyncRepository recomputes a repository's end-of-life status and its
// "eol" findings: new end-of-life cycles become findings, findings whose
// cycle is no longer used are resolved. jobID, when set, is the scan whose
// results triggered the update (the findings count as found by it). It does
// nothing when the feed was never loaded.
func SyncRepository(ctx context.Context, tx pgx.Tx, cat *Catalog, orgID, repoID uuid.UUID, jobID *uuid.UUID, now time.Time) (Stats, error) {
	var st Stats
	if cat == nil {
		return st, nil
	}
	in, err := inputs(ctx, tx, repoID)
	if err != nil {
		return st, err
	}
	ms := cat.Compute(in, now)
	if _, err := tx.Exec(ctx, `DELETE FROM component_eol WHERE repository_id = $1`, repoID); err != nil {
		return st, err
	}
	rows := make([][]any, 0, len(ms))
	for _, m := range ms {
		rows = append(rows, []any{uuid.Must(uuid.NewV7()), orgID, repoID, m.TargetID, m.Source, clip(m.Component, 600), clip(m.Version, 300),
			clip(m.PURL, 1000), clip(m.Path, 1000), m.Product.Name, firstNonEmpty(m.Product.Label, m.Product.Name), m.Cycle.Name, m.Cycle.EOL,
			m.Status, m.Cycle.LatestVersion})
		switch m.Status {
		case "eol":
			st.EOL++
		case "approaching":
			st.Approaching++
		}
	}
	if len(rows) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"component_eol"}, []string{"id", "organization_id", "repository_id", "scan_target_id", "source",
			"component", "version", "purl", "source_path", "product", "product_label", "cycle", "eol_date", "status", "latest_version"},
			pgx.CopyFromRows(rows)); err != nil {
			return st, err
		}
	}
	if err := db.SetChangeContext(ctx, tx, nil, "scanner", "end-of-life status from endoflife.date"); err != nil {
		return st, err
	}
	fs := Findings(ms, now)
	keep := make([]string, 0, len(fs))
	for _, f := range fs {
		keep = append(keep, f.Fingerprint)
		var inserted bool
		if err := tx.QueryRow(ctx, `
			INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, description, severity,
			  package_name, package_version, file_path, first_scan_job_id, last_scan_job_id, confidence, scan_target_id)
			VALUES ($1, $2, $3, $4, 'eol', ARRAY['endoflife'], $5, $6, $7, $8, $9, $10, $11, $12, $12, 'high', $13)
			ON CONFLICT (repository_id, fingerprint) DO UPDATE SET
			  last_seen_at = now(), last_scan_job_id = COALESCE(EXCLUDED.last_scan_job_id, findings.last_scan_job_id),
			  title = EXCLUDED.title, description = EXCLUDED.description, file_path = EXCLUDED.file_path,
			  severity = CASE WHEN array_position(ARRAY['info','low','medium','high','critical'], EXCLUDED.severity)
			                     > array_position(ARRAY['info','low','medium','high','critical'], findings.severity)
			                  THEN EXCLUDED.severity ELSE findings.severity END,
			  status = CASE WHEN findings.status = 'fixed' THEN 'open' ELSE findings.status END,
			  resolved_at = CASE WHEN findings.status = 'fixed' THEN NULL ELSE findings.resolved_at END,
			  updated_at = now()
			RETURNING (xmax = 0)`,
			uuid.Must(uuid.NewV7()), orgID, repoID, f.Fingerprint, clip("eol/"+f.Product+"/"+f.Cycle, 300), f.Title, f.Description, f.Severity,
			clip(f.Product, 300), clip(f.Cycle, 100), clip(f.Path, 1000), jobID, f.TargetID).Scan(&inserted); err != nil {
			return st, err
		}
		if inserted {
			st.New++
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE findings SET status = 'fixed', resolved_at = now(), updated_at = now()
		WHERE repository_id = $1 AND category = 'eol' AND 'endoflife' = ANY(scanner_keys)
		  AND status IN ('open', 'in_progress', 'needs_review') AND NOT (fingerprint = ANY($2))`, repoID, keep)
	if err != nil {
		return st, err
	}
	st.Resolved = int(tag.RowsAffected())
	return st, nil
}

// Stats summarizes a sync.
type Stats struct {
	EOL, Approaching, New, Resolved int
}

// SyncAll recomputes every repository (after a feed update, and daily so
// that cycles reaching their end date become findings).
func SyncAll(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	cat, err := LoadCatalog(ctx, pool)
	if err != nil || cat == nil {
		return err
	}
	rows, err := pool.Query(ctx, `SELECT r.organization_id, r.id FROM repositories r WHERE r.archived_at IS NULL AND (
		EXISTS (SELECT 1 FROM sbom_components c WHERE c.repository_id = r.id)
		OR EXISTS (SELECT 1 FROM repository_runtimes t WHERE t.repository_id = r.id)
		OR EXISTS (SELECT 1 FROM scan_targets s WHERE s.repository_id = r.id AND s.kind = 'image')
		OR EXISTS (SELECT 1 FROM component_eol e WHERE e.repository_id = r.id))`)
	if err != nil {
		return err
	}
	type repo struct{ org, id uuid.UUID }
	repos, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (repo, error) {
		var x repo
		return x, r.Scan(&x.org, &x.id)
	})
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var total Stats
	for _, rp := range repos {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := db.InTx(ctx, pool, func(tx pgx.Tx) error {
			st, err := SyncRepository(ctx, tx, cat, rp.org, rp.id, nil, now)
			total.EOL, total.Approaching, total.New, total.Resolved = total.EOL+st.EOL, total.Approaching+st.Approaching, total.New+st.New, total.Resolved+st.Resolved
			return err
		})
		if err != nil && log != nil {
			log.Warn("end-of-life update failed", "repository_id", rp.id, "err", err)
		}
	}
	if log != nil {
		log.Info("end-of-life status updated", "repositories", len(repos), "eol", total.EOL, "approaching", total.Approaching,
			"new_findings", total.New, "resolved_findings", total.Resolved)
	}
	return nil
}

// RunBackground recomputes the status daily (jobs role), so cycles that
// reach their end date become findings even without a feed update.
func RunBackground(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Minute):
	}
	for {
		if err := SyncAll(ctx, pool, log); err != nil && ctx.Err() == nil {
			log.Warn("end-of-life update failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

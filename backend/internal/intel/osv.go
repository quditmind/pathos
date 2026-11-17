package intel

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/review"
)

// OSV vulnerability records (https://ossf.github.io/osv-schema/): the
// description, aliases, references, vendor CVSS vectors and CWEs of the
// CVEs and advisories that findings reference.
//
// Online: open findings' identifiers are looked up at the configured OSV
// API (https://api.osv.dev/v1/vulns/<id>), at most osvBatch per run, and
// refreshed after a week. Offline: administrators import OSV JSON (one
// record, an array, or a zip of records such as OSV's all.zip exports).

const (
	OSV      = "osv"
	osvBatch = 300
	// A record is fetched again after this long.
	osvRefresh = 7 * 24 * time.Hour
)

var osvIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{2,100}$`)

// Vuln is a stored OSV record.
type Vuln struct {
	ID         string      `json:"id"`
	Aliases    []string    `json:"aliases"`
	Summary    string      `json:"summary"`
	Details    string      `json:"details"`
	Published  *time.Time  `json:"published"`
	Modified   *time.Time  `json:"modified"`
	CVSS       []string    `json:"cvss_vectors"`
	CWEs       []string    `json:"cwes"`
	References []Reference `json:"references"`
	// ExploitRefs counts EVIDENCE references (proofs of concept, exploits).
	ExploitRefs int        `json:"exploit_references"`
	Affected    []Affected `json:"affected"`
	Withdrawn   *time.Time `json:"withdrawn"`
	Source      string     `json:"source"`
	FetchedAt   time.Time  `json:"fetched_at"`
}

// Reference is a link of a record.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Affected is an affected package with its fixed versions.
type Affected struct {
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	Fixed     []string `json:"fixed"`
}

type osvDoc struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	References []Reference `json:"references"`
	Affected   []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific struct {
		CWEIDs []string `json:"cwe_ids"`
	} `json:"database_specific"`
}

func parseTime(s string) *time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t
	}
	return nil
}

func (d osvDoc) toVuln(source string) (Vuln, bool) {
	if !osvIDRe.MatchString(d.ID) {
		return Vuln{}, false
	}
	v := Vuln{ID: strings.ToUpper(d.ID), Summary: clip(d.Summary, 1000), Details: clip(d.Details, 20000), Source: source,
		Published: parseTime(d.Published), Modified: parseTime(d.Modified), Withdrawn: parseTime(d.Withdrawn),
		Aliases: []string{}, CVSS: []string{}, CWEs: []string{}, References: []Reference{}, Affected: []Affected{}}
	if strings.HasPrefix(v.ID, "GHSA-") {
		v.ID = "GHSA-" + strings.ToLower(v.ID[5:]) // GHSA identifiers are lower case after the prefix
	}
	for _, a := range d.Aliases {
		if osvIDRe.MatchString(a) && len(v.Aliases) < 50 {
			a = strings.ToUpper(a)
			if strings.HasPrefix(a, "GHSA-") {
				a = "GHSA-" + strings.ToLower(a[5:])
			}
			v.Aliases = append(v.Aliases, a)
		}
	}
	for _, s := range d.Severity {
		if strings.HasPrefix(s.Type, "CVSS_V") && len(s.Score) <= 300 && strings.HasPrefix(s.Score, "CVSS:") {
			v.CVSS = append(v.CVSS, s.Score)
		}
	}
	for _, c := range d.DatabaseSpecific.CWEIDs {
		if strings.HasPrefix(c, "CWE-") && len(c) <= 12 {
			v.CWEs = append(v.CWEs, c)
		}
	}
	for _, r := range d.References {
		if len(v.References) >= 100 || len(r.URL) > 1000 || !(strings.HasPrefix(r.URL, "https://") || strings.HasPrefix(r.URL, "http://")) {
			continue
		}
		v.References = append(v.References, Reference{Type: clip(strings.ToUpper(r.Type), 20), URL: r.URL})
		if strings.EqualFold(r.Type, "EVIDENCE") {
			v.ExploitRefs++
		}
	}
	for _, a := range d.Affected {
		if len(v.Affected) >= 50 {
			break
		}
		af := Affected{Ecosystem: clip(a.Package.Ecosystem, 50), Package: clip(a.Package.Name, 300), Fixed: []string{}}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f := e["fixed"]; f != "" && len(f) <= 100 && !slices.Contains(af.Fixed, f) && len(af.Fixed) < 20 {
					af.Fixed = append(af.Fixed, f)
				}
			}
		}
		v.Affected = append(v.Affected, af)
	}
	return v, true
}

// ParseOSV reads OSV JSON: one record, an array of records, or a zip
// archive of record files.
func ParseOSV(data []byte, source string) ([]Vuln, error) {
	var out []Vuln
	add := func(raw []byte) error {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			return nil
		}
		if raw[0] == '[' {
			var docs []osvDoc
			if err := json.Unmarshal(raw, &docs); err != nil {
				return err
			}
			for _, d := range docs {
				if v, ok := d.toVuln(source); ok {
					out = append(out, v)
				}
			}
			return nil
		}
		var d osvDoc
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		if v, ok := d.toVuln(source); ok {
			out = append(out, v)
		}
		return nil
	}
	if len(data) > 4 && bytes.Equal(data[:4], []byte("PK\x03\x04")) {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, fmt.Errorf("invalid zip archive: %w", err)
		}
		var total int64
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
				continue
			}
			if len(out) >= 500000 {
				break
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			raw, err := io.ReadAll(io.LimitReader(rc, 4<<20+1))
			_ = rc.Close()
			if err != nil {
				return nil, err
			}
			total += int64(len(raw))
			if len(raw) > 4<<20 || total > 1<<30 {
				return nil, errors.New("the archive contains oversized records")
			}
			if err := add(raw); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Name, err)
			}
		}
	} else if err := add(data); err != nil {
		return nil, fmt.Errorf("invalid OSV JSON: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("no OSV records found")
	}
	return out, nil
}

// LoadOSV stores records and applies them to the findings that reference
// them: vendor CVSS vectors where the scanner gave none, and a re-score
// (exploit references count as exploit evidence).
func LoadOSV(ctx context.Context, tx pgx.Tx, vulns []Vuln) (int, error) {
	b := &pgx.Batch{}
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		refs, _ := json.Marshal(v.References)
		aff, _ := json.Marshal(v.Affected)
		b.Queue(`INSERT INTO intel_vulns (id, aliases, summary, details, published, modified, withdrawn, cvss_vectors, cwes, refs, exploit_refs,
			  affected, source, found, fetched_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, true, now())
			ON CONFLICT (id) DO UPDATE SET aliases = EXCLUDED.aliases, summary = EXCLUDED.summary, details = EXCLUDED.details,
			  published = EXCLUDED.published, modified = EXCLUDED.modified, withdrawn = EXCLUDED.withdrawn,
			  cvss_vectors = EXCLUDED.cvss_vectors, cwes = EXCLUDED.cwes, refs = EXCLUDED.refs, exploit_refs = EXCLUDED.exploit_refs,
			  affected = EXCLUDED.affected, source = EXCLUDED.source, found = true, fetched_at = now()`,
			v.ID, v.Aliases, v.Summary, v.Details, v.Published, v.Modified, v.Withdrawn, v.CVSS, v.CWEs, refs, v.ExploitRefs, aff, v.Source)
		ids = append(ids, v.ID)
		ids = append(ids, v.Aliases...)
	}
	if err := tx.SendBatch(ctx, b).Close(); err != nil {
		return 0, err
	}
	return len(vulns), applyOSV(ctx, tx, ids)
}

// applyOSV fills vendor CVSS vectors (and the 3.x base score) on findings
// without one, and marks the findings for re-scoring.
func applyOSV(ctx context.Context, tx pgx.Tx, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT f.id, v.cvss_vectors FROM findings f
		JOIN intel_vulns v ON (v.id = f.cve OR f.cve = ANY(v.aliases) OR v.id = f.rule_id) AND v.found
		WHERE f.cve <> '' AND (f.cve = ANY($1) OR f.rule_id = ANY($1)) AND f.cvss_vector = '' AND cardinality(v.cvss_vectors) > 0`, ids)
	if err != nil {
		return err
	}
	var fills []vectorFill
	for rows.Next() {
		var id uuid.UUID
		var vectors []string
		if err := rows.Scan(&id, &vectors); err != nil {
			rows.Close()
			return err
		}
		if f, ok := pickVector(id, vectors); ok {
			fills = append(fills, f)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	fb := &pgx.Batch{}
	for _, f := range fills {
		fb.Queue(`UPDATE findings SET cvss_vector = $2, cvss_version = $3, cvss = COALESCE(cvss, $4) WHERE id = $1`, f.id, f.vector, f.ver, f.score)
	}
	if err := tx.SendBatch(ctx, fb).Close(); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE findings SET risk_dirty = true WHERE NOT risk_dirty AND (cve = ANY($1) OR rule_id = ANY($1))`, ids)
	return err
}

type vectorFill struct {
	id     uuid.UUID
	vector string
	ver    string
	score  *float64
}

// pickVector prefers CVSS 3.x (it has a computable base score), then 4.0.
func pickVector(id uuid.UUID, vectors []string) (vectorFill, bool) {
	for _, pref := range []string{"CVSS:3.1/", "CVSS:3.0/", "CVSS:4.0/"} {
		for _, vec := range vectors {
			if !strings.HasPrefix(vec, pref) {
				continue
			}
			if c, err := review.ParseCVSS(vec); err == nil {
				return vectorFill{id, vec, c.Version, c.Score}, true
			}
		}
	}
	return vectorFill{}, false
}

// osvCandidates are identifiers of open findings without a recent record.
func osvCandidates(ctx context.Context, q pgx.Tx) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT x.id FROM (
		  SELECT DISTINCT cve AS id FROM findings WHERE cve <> '' AND status IN ('open', 'in_progress', 'needs_review')
		  UNION SELECT DISTINCT rule_id FROM findings WHERE rule_id LIKE 'GHSA-%' AND status IN ('open', 'in_progress', 'needs_review')) x
		WHERE NOT EXISTS (SELECT 1 FROM intel_vulns v WHERE (v.id = x.id OR x.id = ANY(v.aliases)) AND v.fetched_at > now() - $1::interval)
		ORDER BY x.id LIMIT $2`, osvRefresh.String(), osvBatch)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// fetchOSV looks up the open findings' identifiers at the OSV API.
func (s *Service) fetchOSV(ctx context.Context, base string, by *[16]byte) (Run, error) {
	run := Run{Feed: OSV, Mode: "online"}
	var actor any
	if by != nil {
		actor = uuid.UUID(*by)
	}
	if err := s.DB.QueryRow(ctx, `INSERT INTO intel_feed_runs (feed, mode, triggered_by) VALUES ('osv', 'online', $1) RETURNING id, started_at`,
		actor).Scan(&run.ID, &run.StartedAt); err != nil {
		return run, err
	}
	var ids []string
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		ids, err = osvCandidates(ctx, tx)
		return err
	})
	var (
		mu       sync.Mutex
		vulns    []Vuln
		missing  []string
		failures int
		lastErr  error
	)
	if err == nil && len(ids) > 0 {
		sem := make(chan struct{}, 4)
		var wg sync.WaitGroup
		for _, id := range ids {
			wg.Add(1)
			sem <- struct{}{}
			go func(id string) {
				defer wg.Done()
				defer func() { <-sem }()
				v, found, ferr := s.getOSV(ctx, base, id)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case ferr != nil:
					failures++
					lastErr = ferr
				case !found:
					missing = append(missing, id)
				default:
					vulns = append(vulns, v)
				}
			}(id)
		}
		wg.Wait()
		if failures > 0 && failures == len(ids) {
			err = fmt.Errorf("every lookup failed: %w", lastErr)
		}
	}
	n := 0
	if err == nil {
		err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
			// Unknown identifiers are remembered so they are not asked again
			// before the refresh period.
			for _, id := range missing {
				if _, err := tx.Exec(ctx, `INSERT INTO intel_vulns (id, source, found, fetched_at) VALUES ($1, 'osv-online', false, now())
					ON CONFLICT (id) DO UPDATE SET fetched_at = now() WHERE NOT intel_vulns.found`, id); err != nil {
					return err
				}
			}
			var err error
			n, err = LoadOSV(ctx, tx, vulns)
			return err
		})
	}
	status, msg := "succeeded", ""
	if err != nil {
		status, msg = "failed", clip(err.Error(), 1000)
	} else if failures > 0 {
		msg = clip(fmt.Sprintf("%d of %d lookups failed: %v", failures, len(ids), lastErr), 1000)
	}
	_, uerr := s.DB.Exec(context.WithoutCancel(ctx), `UPDATE intel_feed_runs SET status = $2, records = $3, as_of = $4, error = $5, finished_at = now() WHERE id = $1`,
		run.ID, status, n, time.Now().UTC().Format(time.DateOnly), msg)
	run.Status, run.Records, run.Error = status, n, msg
	if err != nil {
		return run, err
	}
	return run, uerr
}

func (s *Service) getOSV(ctx context.Context, base, id string) (Vuln, bool, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, strings.TrimRight(base, "/")+"/"+id, nil)
	if err != nil {
		return Vuln{}, false, err
	}
	req.Header.Set("User-Agent", "PATHOS-ASPM")
	req.Header.Set("Accept", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return Vuln{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Vuln{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return Vuln{}, false, fmt.Errorf("HTTP %d for %s", resp.StatusCode, id)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Vuln{}, false, err
	}
	var d osvDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return Vuln{}, false, err
	}
	v, ok := d.toVuln("osv-online")
	return v, ok, nil
}

// LookupVuln returns the stored record for a CVE or advisory identifier
// (directly or by alias).
func LookupVuln(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id string) (*Vuln, error) {
	var v Vuln
	var refs, aff []byte
	err := q.QueryRow(ctx, `SELECT id, aliases, summary, details, published, modified, withdrawn, cvss_vectors, cwes, refs, exploit_refs,
		affected, source, fetched_at FROM intel_vulns WHERE found AND (id = $1 OR $1 = ANY(aliases))
		ORDER BY (id = $1) DESC, id LIMIT 1`, id).
		Scan(&v.ID, &v.Aliases, &v.Summary, &v.Details, &v.Published, &v.Modified, &v.Withdrawn, &v.CVSS, &v.CWEs, &refs, &v.ExploitRefs,
			&aff, &v.Source, &v.FetchedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(refs, &v.References)
	_ = json.Unmarshal(aff, &v.Affected)
	return &v, nil
}

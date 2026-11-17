// Package intel maintains vulnerability intelligence: FIRST EPSS scores and
// the CISA Known Exploited Vulnerabilities catalog. Feeds are downloaded on
// a schedule (online) or imported from files (offline / air-gapped), stored
// as organization-independent reference data, and joined to findings by
// CVE when the risk engine scores them.
package intel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Feeds.
const (
	EPSS = "epss"
	KEV  = "kev"
)

// MaxFeedBytes bounds a downloaded or uploaded feed (compressed) and
// MaxExpandedBytes its decompressed size.
const (
	MaxFeedBytes     = 64 << 20
	MaxExpandedBytes = 512 << 20
)

var (
	cveRe  = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	ghsaRe = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
)

// EPSSRow is one EPSS score.
type EPSSRow struct {
	CVE        string
	Score      float64
	Percentile float64
}

// maybeGunzip returns a reader of the plain content.
func maybeGunzip(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	head, _ := br.Peek(2)
	if len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("invalid gzip: %w", err)
		}
		return io.LimitReader(zr, MaxExpandedBytes), nil
	}
	return io.LimitReader(br, MaxExpandedBytes), nil
}

// ParseEPSS reads the EPSS CSV (optionally gzip). The first line may be a
// comment with the model version and score date:
//
//	#model_version:v2025.03.14,score_date:2026-11-16T12:55:00Z
//	cve,epss,percentile
//	CVE-2024-0001,0.00043,0.11
func ParseEPSS(r io.Reader, fn func(EPSSRow) error) (asOf string, n int, err error) {
	pr, err := maybeGunzip(r)
	if err != nil {
		return "", 0, err
	}
	br := bufio.NewReader(pr)
	for {
		b, err := br.Peek(1)
		if err != nil || b[0] != '#' {
			break
		}
		line, _ := br.ReadString('\n')
		for _, part := range strings.Split(strings.TrimPrefix(strings.TrimSpace(line), "#"), ",") {
			if k, v, ok := strings.Cut(part, ":"); ok && k == "score_date" {
				asOf = strings.TrimSpace(v)
			}
		}
	}
	cr := csv.NewReader(br)
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return asOf, 0, fmt.Errorf("EPSS: missing header: %w", err)
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	ci, ok1 := idx["cve"]
	ei, ok2 := idx["epss"]
	pi, ok3 := idx["percentile"]
	if !ok1 || !ok2 || !ok3 {
		return asOf, 0, errors.New("EPSS: expected columns cve, epss, percentile")
	}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return asOf, n, fmt.Errorf("EPSS line %d: %w", n+2, err)
		}
		if len(rec) <= max(ci, ei, pi) {
			continue
		}
		cve := strings.TrimSpace(rec[ci])
		s, err1 := strconv.ParseFloat(strings.TrimSpace(rec[ei]), 64)
		p, err2 := strconv.ParseFloat(strings.TrimSpace(rec[pi]), 64)
		if !cveRe.MatchString(cve) || err1 != nil || err2 != nil || s < 0 || s > 1 || p < 0 || p > 1 {
			continue // malformed rows are skipped, not fatal
		}
		if err := fn(EPSSRow{CVE: cve, Score: s, Percentile: p}); err != nil {
			return asOf, n, err
		}
		n++
	}
	if n == 0 {
		return asOf, 0, errors.New("EPSS: the file contains no scores")
	}
	return asOf, n, nil
}

// KEVEntry is one catalog entry.
type KEVEntry struct {
	CVE             string `json:"cveID"`
	Vendor          string `json:"vendorProject"`
	Product         string `json:"product"`
	Name            string `json:"vulnerabilityName"`
	DateAdded       string `json:"dateAdded"`
	Description     string `json:"shortDescription"`
	RequiredAction  string `json:"requiredAction"`
	DueDate         string `json:"dueDate"`
	KnownRansomware string `json:"knownRansomwareCampaignUse"`
}

// KEVCatalog is the CISA KEV JSON document.
type KEVCatalog struct {
	Version         string     `json:"catalogVersion"`
	Released        string     `json:"dateReleased"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// ParseKEV reads the KEV JSON (optionally gzip).
func ParseKEV(r io.Reader) (KEVCatalog, error) {
	var c KEVCatalog
	pr, err := maybeGunzip(r)
	if err != nil {
		return c, err
	}
	if err := json.NewDecoder(pr).Decode(&c); err != nil {
		return c, fmt.Errorf("KEV: invalid JSON: %w", err)
	}
	valid := c.Vulnerabilities[:0]
	for _, v := range c.Vulnerabilities {
		v.CVE = strings.TrimSpace(v.CVE)
		if cveRe.MatchString(v.CVE) {
			valid = append(valid, v)
		}
	}
	c.Vulnerabilities = valid
	if len(c.Vulnerabilities) == 0 {
		return c, errors.New("KEV: the catalog contains no vulnerabilities")
	}
	return c, nil
}

func date(s string) *time.Time {
	t, err := time.Parse("2006-01-02", strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	return &t
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// LoadEPSS replaces the EPSS table from r and marks findings with a CVE for
// re-scoring. It returns the score date and the number of rows.
func LoadEPSS(ctx context.Context, tx pgx.Tx, r io.Reader) (string, int, error) {
	var rows [][]any
	asOf, n, err := ParseEPSS(r, func(e EPSSRow) error {
		rows = append(rows, []any{e.CVE, e.Score, e.Percentile})
		return nil
	})
	if err != nil {
		return asOf, n, err
	}
	day := time.Now().UTC()
	if t, err := time.Parse(time.RFC3339, asOf); err == nil {
		day = t
	} else if t := date(asOf); t != nil {
		day = *t
	}
	// De-duplicate by CVE (last wins) to keep COPY within the primary key.
	seen := make(map[string]int, len(rows))
	uniq := rows[:0]
	for _, r := range rows {
		if i, ok := seen[r[0].(string)]; ok {
			uniq[i] = r
			continue
		}
		seen[r[0].(string)] = len(uniq)
		uniq = append(uniq, r)
	}
	for i := range uniq {
		uniq[i] = append(uniq[i], day)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM intel_epss`); err != nil {
		return asOf, 0, err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"intel_epss"}, []string{"cve_id", "score", "percentile", "as_of"}, pgx.CopyFromRows(uniq)); err != nil {
		return asOf, 0, err
	}
	_, err = tx.Exec(ctx, `UPDATE findings SET risk_dirty = true WHERE cve <> '' AND NOT risk_dirty`)
	return asOf, len(uniq), err
}

// LoadKEV replaces the KEV table from r and marks findings with a CVE for
// re-scoring.
func LoadKEV(ctx context.Context, tx pgx.Tx, r io.Reader) (string, int, error) {
	c, err := ParseKEV(r)
	if err != nil {
		return "", 0, err
	}
	rows := make([][]any, 0, len(c.Vulnerabilities))
	seen := map[string]bool{}
	for _, v := range c.Vulnerabilities {
		if seen[v.CVE] {
			continue
		}
		seen[v.CVE] = true
		rows = append(rows, []any{v.CVE, clip(v.Vendor, 300), clip(v.Product, 300), clip(v.Name, 500), clip(v.Description, 4000),
			clip(v.RequiredAction, 2000), date(v.DateAdded), date(v.DueDate), clip(v.KnownRansomware, 50), clip(c.Version, 50)})
	}
	if _, err := tx.Exec(ctx, `DELETE FROM intel_kev`); err != nil {
		return "", 0, err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"intel_kev"}, []string{"cve_id", "vendor", "product", "name", "description", "required_action",
		"added_on", "due_date", "known_ransomware", "catalog_version"}, pgx.CopyFromRows(rows)); err != nil {
		return "", 0, err
	}
	_, err = tx.Exec(ctx, `UPDATE findings SET risk_dirty = true WHERE cve <> '' AND NOT risk_dirty`)
	return c.Version, len(rows), err
}

// Load imports one feed in a transaction and records the run.
func Load(ctx context.Context, pool *pgxpool.Pool, feed, mode string, by *[16]byte, data []byte) (Run, error) {
	run := Run{Feed: feed, Mode: mode}
	sum := sha256Hex(data)
	var actor any
	if by != nil {
		actor = fmt.Sprintf("%x-%x-%x-%x-%x", by[0:4], by[4:6], by[6:8], by[8:10], by[10:16])
	}
	if err := pool.QueryRow(ctx, `INSERT INTO intel_feed_runs (feed, mode, sha256, triggered_by) VALUES ($1, $2, $3, $4) RETURNING id, started_at`,
		feed, mode, sum, actor).Scan(&run.ID, &run.StartedAt); err != nil {
		return run, err
	}
	var asOf string
	var n int
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		switch feed {
		case EPSS:
			asOf, n, err = LoadEPSS(ctx, tx, bytes.NewReader(data))
		case KEV:
			asOf, n, err = LoadKEV(ctx, tx, bytes.NewReader(data))
		case DepsDev:
			err = errors.New("package health has no file import; it is refreshed online from deps.dev")
		case OSV:
			var vulns []Vuln
			if vulns, err = ParseOSV(data, "osv-file"); err == nil {
				n, err = LoadOSV(ctx, tx, vulns)
				asOf = time.Now().UTC().Format(time.DateOnly)
			}
		default:
			err = fmt.Errorf("unknown feed %q", feed)
		}
		return err
	})
	status, msg := "succeeded", ""
	if err != nil {
		status, msg = "failed", clip(err.Error(), 1000)
	}
	_, uerr := pool.Exec(ctx, `UPDATE intel_feed_runs SET status = $2, records = $3, as_of = $4, error = $5, finished_at = now() WHERE id = $1`,
		run.ID, status, n, clip(asOf, 100), msg)
	run.Status, run.Records, run.AsOf, run.Error = status, n, asOf, msg
	if err != nil {
		return run, err
	}
	return run, uerr
}

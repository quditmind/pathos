package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Package health from deps.dev (https://docs.deps.dev/api/v3/): the latest
// version of each package in the component inventories, which versions are
// deprecated, and the OpenSSF Scorecard of the source repository of direct
// dependencies. Components are then flagged outdated or deprecated.

const (
	DepsDev      = "depsdev"
	depsDevBatch = 500
)

// PURLPackage maps a package URL to a deps.dev system and package name.
func PURLPackage(purl string) (system, name string, ok bool) {
	if !strings.HasPrefix(purl, "pkg:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	typ, path, found := strings.Cut(rest, "/")
	if !found {
		return "", "", false
	}
	if i := strings.LastIndex(path, "@"); i > 0 {
		path = path[:i]
	}
	dec, err := url.PathUnescape(path)
	if err != nil || dec == "" {
		return "", "", false
	}
	switch typ {
	case "npm":
		return "npm", dec, true
	case "pypi":
		return "pypi", strings.ToLower(dec), true
	case "golang":
		return "go", dec, true
	case "cargo":
		return "cargo", dec, true
	case "nuget":
		return "nuget", dec, true
	case "maven":
		if g, a, ok := strings.Cut(dec, "/"); ok {
			return "maven", g + ":" + a, true
		}
	}
	return "", "", false
}

// PURLBase is a package URL without qualifiers and version.
func PURLBase(purl string) string {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	if i := strings.LastIndex(purl, "@"); i > 0 && !strings.Contains(purl[i:], "/") {
		purl = purl[:i]
	}
	return purl
}

type depsVersion struct {
	VersionKey struct {
		Version string `json:"version"`
	} `json:"versionKey"`
	PublishedAt  string `json:"publishedAt"`
	IsDefault    bool   `json:"isDefault"`
	IsDeprecated bool   `json:"isDeprecated"`
}

type pkgHealth struct {
	system, name, latest, project string
	published                     *time.Time
	deprecated                    []string
	scorecard                     *float64
	found                         bool
	// provenance of the checked version (direct dependencies).
	provVersion string
	provenance  *provenance
}

type provenance struct {
	Source   string `json:"source"`
	Commit   string `json:"commit,omitempty"`
	Verified bool   `json:"verified"`
}

func (s *Service) depsGet(ctx context.Context, u string, out any) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "PATHOS-ASPM")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return true, json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

func (s *Service) lookupPackage(ctx context.Context, base, system, name, version string, direct bool) (pkgHealth, error) {
	h := pkgHealth{system: system, name: name}
	base = strings.TrimRight(base, "/")
	var pkg struct {
		Versions []depsVersion `json:"versions"`
	}
	pkgURL := fmt.Sprintf("%s/systems/%s/packages/%s", base, system, url.PathEscape(name))
	found, err := s.depsGet(ctx, pkgURL, &pkg)
	if err != nil || !found {
		return h, err
	}
	h.found = true
	for _, v := range pkg.Versions {
		if v.IsDefault {
			h.latest = v.VersionKey.Version
			if t, err := time.Parse(time.RFC3339, v.PublishedAt); err == nil {
				h.published = &t
			}
		}
		if v.IsDeprecated && len(h.deprecated) < 2000 {
			h.deprecated = append(h.deprecated, v.VersionKey.Version)
		}
	}
	if !direct || version == "" {
		return h, nil
	}
	// Scorecard of the source repository (direct dependencies only).
	var ver struct {
		SLSAProvenances []struct {
			SourceRepository string `json:"sourceRepository"`
			Commit           string `json:"commit"`
			Verified         bool   `json:"verified"`
		} `json:"slsaProvenances"`
		RelatedProjects []struct {
			ProjectKey struct {
				ID string `json:"id"`
			} `json:"projectKey"`
			RelationType string `json:"relationType"`
		} `json:"relatedProjects"`
	}
	if ok, err := s.depsGet(ctx, pkgURL+"/versions/"+url.PathEscape(version), &ver); err != nil || !ok {
		return h, nil
	}
	h.provVersion = version
	for _, p := range ver.SLSAProvenances {
		pv := provenance{Source: clip(p.SourceRepository, 300), Commit: clip(p.Commit, 64), Verified: p.Verified}
		if h.provenance == nil || (pv.Verified && !h.provenance.Verified) {
			h.provenance = &pv
		}
	}
	for _, p := range ver.RelatedProjects {
		if p.RelationType != "SOURCE_REPO" {
			continue
		}
		var proj struct {
			Scorecard *struct {
				OverallScore float64 `json:"overallScore"`
			} `json:"scorecard"`
		}
		if ok, err := s.depsGet(ctx, base+"/projects/"+url.PathEscape(p.ProjectKey.ID), &proj); err == nil && ok && proj.Scorecard != nil {
			sc := proj.Scorecard.OverallScore
			h.scorecard, h.project = &sc, p.ProjectKey.ID
		}
		break
	}
	return h, nil
}

// fetchDepsDev refreshes package health for inventory packages.
func (s *Service) fetchDepsDev(ctx context.Context, base string, by *[16]byte) (Run, error) {
	run := Run{Feed: DepsDev, Mode: "online"}
	var actor any
	if by != nil {
		actor = uuid.UUID(*by)
	}
	if err := s.DB.QueryRow(ctx, `INSERT INTO intel_feed_runs (feed, mode, triggered_by) VALUES ('depsdev', 'online', $1) RETURNING id, started_at`,
		actor).Scan(&run.ID, &run.StartedAt); err != nil {
		return run, err
	}
	type cand struct {
		purl, version string
		direct        bool
	}
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT ON (purl_base) purl, version, bool_or(depth <= 1) OVER (PARTITION BY purl_base)
		FROM (SELECT c.purl, c.version, COALESCE(c.depth, 2) AS depth, regexp_replace(split_part(c.purl, '?', 1), '@[^@/]*$', '') AS purl_base
		      FROM sbom_components c WHERE c.purl ~ '^pkg:(npm|pypi|golang|cargo|nuget|maven)/') x
		WHERE NOT EXISTS (SELECT 1 FROM package_health h WHERE h.purl_base = x.purl_base AND h.fetched_at > now() - interval '7 days')
		ORDER BY purl_base, depth LIMIT $1`, depsDevBatch)
	var cands []cand
	if err == nil {
		cands, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (cand, error) {
			var c cand
			return c, r.Scan(&c.purl, &c.version, &c.direct)
		})
	}
	var (
		mu       sync.Mutex
		results  []pkgHealth
		bases    []string
		failures int
		lastErr  error
	)
	if err == nil {
		sem := make(chan struct{}, 4)
		var wg sync.WaitGroup
		for _, c := range cands {
			system, name, ok := PURLPackage(c.purl)
			if !ok {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(c cand, system, name string) {
				defer wg.Done()
				defer func() { <-sem }()
				h, ferr := s.lookupPackage(ctx, base, system, name, c.version, c.direct)
				mu.Lock()
				defer mu.Unlock()
				if ferr != nil {
					failures++
					lastErr = ferr
					return
				}
				results = append(results, h)
				bases = append(bases, PURLBase(c.purl))
			}(c, system, name)
		}
		wg.Wait()
		if len(cands) > 0 && failures == len(cands) {
			err = fmt.Errorf("every lookup failed: %w", lastErr)
		}
	}
	if err == nil {
		err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
			b := &pgx.Batch{}
			for i, h := range results {
				// Provenance per checked version: an attested version keeps its
				// record; a version checked without provenance is recorded as
				// none (null), so "no provenance" is known, not assumed.
				prov := []byte("{}")
				if h.provVersion != "" {
					var v any
					if h.provenance != nil {
						v = h.provenance
					}
					prov, _ = json.Marshal(map[string]any{clip(h.provVersion, 100): v})
				}
				b.Queue(`INSERT INTO package_health (purl_base, system, name, found, latest_version, latest_published_at, deprecated_versions,
					scorecard, scorecard_project, provenance, fetched_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
					ON CONFLICT (purl_base) DO UPDATE SET found = EXCLUDED.found, latest_version = EXCLUDED.latest_version,
					  latest_published_at = EXCLUDED.latest_published_at, deprecated_versions = EXCLUDED.deprecated_versions,
					  scorecard = COALESCE(EXCLUDED.scorecard, package_health.scorecard),
					  scorecard_project = CASE WHEN EXCLUDED.scorecard IS NOT NULL THEN EXCLUDED.scorecard_project ELSE package_health.scorecard_project END,
					  provenance = package_health.provenance || EXCLUDED.provenance, fetched_at = now()`,
					bases[i], h.system, clip(h.name, 300), h.found, clip(h.latest, 100), h.published, nonNilStrings(h.deprecated), h.scorecard,
					clip(h.project, 300), prov)
			}
			return tx.SendBatch(ctx, b).Close()
		})
	}
	status, msg := "succeeded", ""
	if err != nil {
		status, msg = "failed", clip(err.Error(), 1000)
	} else if failures > 0 {
		msg = clip(fmt.Sprintf("%d of %d lookups failed: %v", failures, len(cands), lastErr), 1000)
	}
	_, uerr := s.DB.Exec(context.WithoutCancel(ctx), `UPDATE intel_feed_runs SET status = $2, records = $3, as_of = $4, error = $5, finished_at = now() WHERE id = $1`,
		run.ID, status, len(results), time.Now().UTC().Format(time.DateOnly), msg)
	run.Status, run.Records, run.Error = status, len(results), msg
	if err != nil {
		return run, err
	}
	return run, errors.Join(uerr)
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

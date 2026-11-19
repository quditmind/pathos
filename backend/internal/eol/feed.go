// Package eol tracks end-of-life dates of runtimes, frameworks, databases
// and operating systems from endoflife.date (opt-in intelligence feed, or a
// file import offline), matches them to the components, declared runtimes
// and container images of each repository, and keeps "eol" findings for
// components whose support has ended.
package eol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Feed is the intelligence feed key.
const Feed = "endoflife"

// Product is an endoflife.date product with its release cycles.
type Product struct {
	Name        string
	Label       string
	Category    string
	Aliases     []string
	Identifiers []string // purls without version (normalized)
	Link        string
	Cycles      []Cycle
}

// Cycle is a release cycle ("18", "3.11", "22.04").
type Cycle struct {
	Name     string
	Label    string
	Codename string
	Released *time.Time
	// EOL is the end of (security) support; IsEOL is the feed's verdict.
	EOL           *time.Time
	IsEOL         bool
	SupportUntil  *time.Time
	LTS           bool
	LatestVersion string
}

// feedDoc is the endoflife.date API v1 "products/full" document. A single
// product document ("products/{name}") is accepted as well.
type feedDoc struct {
	SchemaVersion string          `json:"schema_version"`
	GeneratedAt   string          `json:"generated_at"`
	Result        json.RawMessage `json:"result"`
}

type productDoc struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Category    string   `json:"category"`
	Aliases     []string `json:"aliases"`
	Identifiers []struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"identifiers"`
	Links struct {
		HTML string `json:"html"`
	} `json:"links"`
	Releases []struct {
		Name        string          `json:"name"`
		Codename    *string         `json:"codename"`
		Label       string          `json:"label"`
		ReleaseDate *string         `json:"releaseDate"`
		IsLTS       bool            `json:"isLts"`
		IsEOL       json.RawMessage `json:"isEol"`
		EOLFrom     *string         `json:"eolFrom"`
		EOASFrom    *string         `json:"eoasFrom"`
		EOESFrom    *string         `json:"eoesFrom"`
		Latest      *struct {
			Name string `json:"name"`
		} `json:"latest"`
	} `json:"releases"`
}

// Parse reads an endoflife.date API v1 document.
func Parse(data []byte) (products []Product, asOf string, err error) {
	var doc feedDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, "", fmt.Errorf("endoflife.date: invalid JSON: %w", err)
	}
	if !strings.HasPrefix(doc.SchemaVersion, "1.") || len(doc.Result) == 0 {
		return nil, "", errors.New("endoflife.date: expected an API v1 document (https://endoflife.date/api/v1/products/full)")
	}
	var list []productDoc
	if doc.Result[0] == '[' {
		if err := json.Unmarshal(doc.Result, &list); err != nil {
			return nil, "", fmt.Errorf("endoflife.date: %w", err)
		}
	} else {
		var one productDoc
		if err := json.Unmarshal(doc.Result, &one); err != nil {
			return nil, "", fmt.Errorf("endoflife.date: %w", err)
		}
		list = []productDoc{one}
	}
	if len(list) > 5000 {
		return nil, "", errors.New("endoflife.date: too many products")
	}
	if t, err := time.Parse(time.RFC3339, doc.GeneratedAt); err == nil {
		asOf = t.UTC().Format(time.DateOnly)
	}
	for _, p := range list {
		if p.Name == "" || len(p.Name) > 100 {
			continue
		}
		pr := Product{Name: strings.ToLower(p.Name), Label: clip(p.Label, 200), Category: clip(p.Category, 50), Link: clip(p.Links.HTML, 500)}
		for _, a := range p.Aliases {
			if a != "" && len(a) <= 100 && len(pr.Aliases) < 50 {
				pr.Aliases = append(pr.Aliases, strings.ToLower(a))
			}
		}
		for _, id := range p.Identifiers {
			if id.Type == "purl" && len(pr.Identifiers) < 200 {
				if n := NormalizePURL(id.ID); n != "" {
					pr.Identifiers = append(pr.Identifiers, n)
				}
			}
		}
		for _, r := range p.Releases {
			if r.Name == "" || len(r.Name) > 100 || len(pr.Cycles) >= 1000 {
				continue
			}
			c := Cycle{Name: r.Name, Label: clip(r.Label, 200), LTS: r.IsLTS, Released: date(r.ReleaseDate), EOL: date(r.EOLFrom)}
			if r.Codename != nil {
				c.Codename = clip(*r.Codename, 100)
			}
			// isEol is a boolean (or null when unknown).
			var b bool
			if json.Unmarshal(r.IsEOL, &b) == nil {
				c.IsEOL = b
			}
			c.SupportUntil = date(r.EOASFrom)
			if r.Latest != nil {
				c.LatestVersion = clip(r.Latest.Name, 100)
			}
			pr.Cycles = append(pr.Cycles, c)
		}
		products = append(products, pr)
	}
	if len(products) == 0 {
		return nil, "", errors.New("endoflife.date: the document lists no products")
	}
	return products, asOf, nil
}

func date(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.DateOnly, *s)
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

// NormalizePURL is a package URL without version, qualifiers and subpath,
// percent-decoded and in lower case: pkg:npm/@angular/core.
func NormalizePURL(p string) string {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(strings.ToLower(p), "pkg:") {
		return ""
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	typ, path, ok := strings.Cut(p[4:], "/")
	if !ok || typ == "" || path == "" {
		return ""
	}
	// The version follows the last "@" (an npm scope "@" starts the path).
	if i := strings.LastIndex(path, "@"); i > 0 {
		path = path[:i]
	}
	if d, err := url.PathUnescape(path); err == nil {
		path = d
	}
	p = "pkg:" + typ + "/" + strings.Trim(path, "/")
	if len(p) > 600 {
		return ""
	}
	return strings.ToLower(p)
}

// Load replaces the stored products and cycles.
func Load(ctx context.Context, tx pgx.Tx, products []Product) (int, error) {
	if _, err := tx.Exec(ctx, `DELETE FROM eol_cycles`); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM eol_products`); err != nil {
		return 0, err
	}
	prow := make([][]any, 0, len(products))
	var crow [][]any
	seen := map[string]bool{}
	for _, p := range products {
		if seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		prow = append(prow, []any{p.Name, p.Label, p.Category, nonNil(p.Aliases), nonNil(p.Identifiers), p.Link})
		cs := map[string]bool{}
		for _, c := range p.Cycles {
			if cs[c.Name] {
				continue
			}
			cs[c.Name] = true
			crow = append(crow, []any{p.Name, c.Name, c.Label, c.Codename, c.Released, c.EOL, c.IsEOL, c.SupportUntil, c.LTS, c.LatestVersion})
		}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"eol_products"}, []string{"name", "label", "category", "aliases", "identifiers", "link"},
		pgx.CopyFromRows(prow)); err != nil {
		return 0, err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"eol_cycles"}, []string{"product", "cycle", "label", "codename", "release_date", "eol_date",
		"is_eol", "support_until", "lts", "latest_version"}, pgx.CopyFromRows(crow)); err != nil {
		return 0, err
	}
	return len(prow), nil
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// LoadCatalog reads the stored products (nil when the feed was never
// loaded).
func LoadCatalog(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) (*Catalog, error) {
	rows, err := q.Query(ctx, `SELECT p.name, p.label, p.category, p.aliases, p.identifiers, p.link,
		c.cycle, c.label, c.codename, c.release_date, c.eol_date, c.is_eol, c.support_until, c.lts, c.latest_version
		FROM eol_products p LEFT JOIN eol_cycles c ON c.product = p.name ORDER BY p.name, c.release_date DESC NULLS LAST, c.cycle DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var products []Product
	for rows.Next() {
		var p Product
		var cname, clabel, ccode, clatest *string
		var rel, eolAt, sup *time.Time
		var isEOL, lts *bool
		if err := rows.Scan(&p.Name, &p.Label, &p.Category, &p.Aliases, &p.Identifiers, &p.Link,
			&cname, &clabel, &ccode, &rel, &eolAt, &isEOL, &sup, &lts, &clatest); err != nil {
			return nil, err
		}
		if n := len(products); n == 0 || products[n-1].Name != p.Name {
			products = append(products, p)
		}
		if cname != nil {
			last := &products[len(products)-1]
			last.Cycles = append(last.Cycles, Cycle{Name: *cname, Label: deref(clabel), Codename: deref(ccode), Released: rel, EOL: eolAt,
				IsEOL: isEOL != nil && *isEOL, SupportUntil: sup, LTS: lts != nil && *lts, LatestVersion: deref(clatest)})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(products) == 0 {
		return nil, nil
	}
	return NewCatalog(products), nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

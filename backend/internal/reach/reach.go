// Package reach decides package-level reachability of dependency findings:
// does the repository's code use the vulnerable package, directly or
// through a package it imports?
//
//	reachable      the code imports the package (or names it, as frameworks
//	               load some packages by name), or imports a package that
//	               depends on it
//	not_reachable  npm and Go only, with complete evidence: the SBOM has a
//	               dependency graph, the code was inventoried, and the package
//	               is neither used nor a dependency of a used package
//	unknown        otherwise (no data, Python module names that may differ
//	               from distribution names, other ecosystems)
//
// It is a package-level signal: a reachable package does not mean the
// vulnerable function is called. It only weights the risk score; findings
// are never hidden or closed because of it.
package reach

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Inventory is the code's use of packages (from the worker).
type Inventory struct {
	Imports map[string]map[string]bool // ecosystem -> names
	Strings map[string]map[string]bool
}

type component struct {
	ref, name, version, eco string
}

// pythonAliases maps PyPI distributions to their import names when they
// differ (common cases only).
var pythonAliases = map[string][]string{
	"pyyaml": {"yaml"}, "beautifulsoup4": {"bs4"}, "pillow": {"pil"}, "scikit_learn": {"sklearn"}, "python_dateutil": {"dateutil"},
	"opencv_python": {"cv2"}, "protobuf": {"google"}, "pyjwt": {"jwt"}, "python_jose": {"jose"}, "pymongo": {"pymongo", "bson", "gridfs"},
	"psycopg2_binary": {"psycopg2"}, "attrs": {"attr", "attrs"}, "msgpack_python": {"msgpack"}, "pycryptodome": {"crypto"},
	"python_multipart": {"multipart"}, "markupsafe": {"markupsafe"}, "jinja2": {"jinja2"}, "djangorestframework": {"rest_framework"},
}

func pyNorm(s string) string {
	return strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToLower(s))
}

func ecosystem(purl string) string {
	switch {
	case strings.HasPrefix(purl, "pkg:npm/"):
		return "npm"
	case strings.HasPrefix(purl, "pkg:pypi/"):
		return "pypi"
	case strings.HasPrefix(purl, "pkg:golang/"):
		return "go"
	}
	return ""
}

// used reports whether the code uses the component itself.
func (inv Inventory) used(c component) bool {
	name := strings.ToLower(c.name)
	switch c.eco {
	case "npm":
		return inv.Imports["npm"][name] || inv.Strings["npm"][name]
	case "pypi":
		n := pyNorm(name)
		mods := append([]string{n}, pythonAliases[n]...)
		for _, m := range mods {
			if inv.Imports["pypi"][m] || inv.Strings["pypi"][m] {
				return true
			}
		}
	case "go":
		for imp := range inv.Imports["go"] {
			if imp == c.name || strings.HasPrefix(imp, c.name+"/") {
				return true
			}
		}
	}
	return false
}

// Decision is the reachability of one package.
type Decision struct {
	Reachability string
	Basis        string
}

// Decide computes the reachability of every component. edges are
// parent -> children by ref.
func Decide(comps []component, edges map[string][]string, inv Inventory, haveInventory bool) map[string]Decision {
	out := map[string]Decision{}
	if !haveInventory {
		return out
	}
	byRef := map[string]component{}
	for _, c := range comps {
		if c.ref != "" {
			byRef[c.ref] = c
		}
	}
	// Breadth-first from the components the code uses, remembering which
	// used component each reachable one comes from.
	via := map[string]string{}
	var queue []string
	for _, c := range comps {
		if c.ref != "" && inv.used(c) {
			via[c.ref] = c.ref
			queue = append(queue, c.ref)
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, ch := range edges[n] {
			if _, ok := via[ch]; !ok {
				via[ch] = via[n]
				queue = append(queue, ch)
			}
		}
	}
	hasGraph := len(edges) > 0
	for _, c := range comps {
		key := strings.ToLower(c.name) + "@" + c.version
		d := Decision{Reachability: "unknown"}
		origin, reachable := via[c.ref]
		switch {
		case c.ref == "" && inv.used(c):
			d = Decision{"reachable", "the code imports or names the package"}
		case reachable && origin == c.ref:
			d = Decision{"reachable", "the code imports or names the package"}
		case reachable:
			d = Decision{"reachable", "a dependency of " + byRef[origin].name + ", which the code uses"}
		case hasGraph && c.ref != "" && (c.eco == "npm" || c.eco == "go"):
			d = Decision{"not_reachable", "neither the code nor any package it uses depends on it"}
		}
		// Duplicate name@version entries: reachable wins.
		if prev, ok := out[key]; ok && prev.Reachability == "reachable" {
			continue
		}
		if prev, ok := out[key]; ok && prev.Reachability == "unknown" && d.Reachability == "not_reachable" {
			continue
		}
		out[key] = d
	}
	return out
}

// Update recomputes the reachability of a repository's dependency
// findings from its latest SBOM and code inventory. It returns the number
// of findings changed.
func Update(ctx context.Context, tx pgx.Tx, repoID uuid.UUID) (int, error) {
	var scanned *time.Time
	if err := tx.QueryRow(ctx, `SELECT imports_scanned_at FROM repositories WHERE id = $1`, repoID).Scan(&scanned); err != nil {
		return 0, err
	}
	inv := Inventory{Imports: map[string]map[string]bool{}, Strings: map[string]map[string]bool{}}
	rows, err := tx.Query(ctx, `SELECT ecosystem, kind, name FROM repository_code_imports WHERE repository_id = $1`, repoID)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var eco, kind, name string
		if err := rows.Scan(&eco, &kind, &name); err != nil {
			rows.Close()
			return 0, err
		}
		m := inv.Imports
		if kind == "string" {
			m = inv.Strings
		}
		if m[eco] == nil {
			m[eco] = map[string]bool{}
		}
		m[eco][name] = true
	}
	rows.Close()
	var comps []component
	crows, err := tx.Query(ctx, `SELECT bom_ref, name, version, purl FROM sbom_components WHERE repository_id = $1`, repoID)
	if err != nil {
		return 0, err
	}
	for crows.Next() {
		var c component
		var purl string
		if err := crows.Scan(&c.ref, &c.name, &c.version, &purl); err != nil {
			crows.Close()
			return 0, err
		}
		c.eco = ecosystem(purl)
		comps = append(comps, c)
	}
	crows.Close()
	edges := map[string][]string{}
	erows, err := tx.Query(ctx, `SELECT parent_ref, child_ref FROM sbom_dependencies WHERE repository_id = $1`, repoID)
	if err != nil {
		return 0, err
	}
	for erows.Next() {
		var p, c string
		if err := erows.Scan(&p, &c); err != nil {
			erows.Close()
			return 0, err
		}
		edges[p] = append(edges[p], c)
	}
	erows.Close()
	decisions := Decide(comps, edges, inv, scanned != nil)

	// Dependency findings of the repository's code (not scan targets).
	frows, err := tx.Query(ctx, `SELECT id, lower(package_name) || '@' || package_version, reachability, reachability_basis FROM findings
		WHERE repository_id = $1 AND scan_target_id IS NULL AND category = 'sca' AND package_name <> ''`, repoID)
	if err != nil {
		return 0, err
	}
	type change struct {
		id           uuid.UUID
		reach, basis string
	}
	var changes []change
	for frows.Next() {
		var id uuid.UUID
		var key, cur, curBasis string
		if err := frows.Scan(&id, &key, &cur, &curBasis); err != nil {
			frows.Close()
			return 0, err
		}
		d, ok := decisions[key]
		if !ok {
			d = Decision{Reachability: "unknown"}
			if scanned != nil {
				d.Basis = "the package is not in the repository's latest SBOM"
			}
		}
		if d.Reachability != cur || d.Basis != curBasis {
			changes = append(changes, change{id, d.Reachability, d.Basis})
		}
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return 0, err
	}
	b := &pgx.Batch{}
	for _, c := range changes {
		b.Queue(`UPDATE findings SET reachability = $2, reachability_basis = $3 WHERE id = $1`, c.id, c.reach, c.basis)
	}
	if len(changes) > 0 {
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return 0, err
		}
	}
	return len(changes), nil
}

// StoreInventory replaces a repository's code inventory.
func StoreInventory(ctx context.Context, tx pgx.Tx, orgID, repoID uuid.UUID, imports, strs map[string][]string, files int) error {
	if _, err := tx.Exec(ctx, `DELETE FROM repository_code_imports WHERE repository_id = $1`, repoID); err != nil {
		return err
	}
	var rows [][]any
	for kind, m := range map[string]map[string][]string{"import": imports, "string": strs} {
		for eco, names := range m {
			if eco != "npm" && eco != "pypi" && eco != "go" {
				continue
			}
			seen := map[string]bool{}
			for _, n := range names {
				if n == "" || len(n) > 214 || seen[n] || len(seen) >= 20000 {
					continue
				}
				seen[n] = true
				rows = append(rows, []any{orgID, repoID, eco, kind, n})
			}
		}
	}
	if len(rows) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"repository_code_imports"}, []string{"organization_id", "repository_id", "ecosystem", "kind", "name"},
			pgx.CopyFromRows(rows)); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `UPDATE repositories SET imports_scanned_at = now(), imports_files = $2 WHERE id = $1`, repoID, files)
	return err
}

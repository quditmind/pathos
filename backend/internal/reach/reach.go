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
// vulnerable function is called. Where an analysis of calls exists (see
// function.go), the function-level answer replaces it. Either only weights
// the risk score; findings are never hidden or closed because of it.
package reach

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
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

// Decision is the reachability of one package (or, with a function-level
// method, of one vulnerability of it).
type Decision struct {
	Reachability string
	Basis        string
	// Method is "", import, call_graph or symbol_calls.
	Method   string
	Evidence *Evidence
	// soft: an unknown that does not override a package-level reachable.
	soft bool
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
			d = Decision{Reachability: "reachable", Basis: "the code imports or names the package", Method: MethodImport}
		case reachable && origin == c.ref:
			d = Decision{Reachability: "reachable", Basis: "the code imports or names the package", Method: MethodImport}
		case reachable:
			d = Decision{Reachability: "reachable", Basis: "a dependency of " + byRef[origin].name + ", which the code uses", Method: MethodImport}
		case hasGraph && c.ref != "" && (c.eco == "npm" || c.eco == "go"):
			d = Decision{Reachability: "not_reachable", Basis: "neither the code nor any package it uses depends on it", Method: MethodImport}
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
	reports, err := LoadReports(ctx, tx, repoID)
	if err != nil {
		return 0, err
	}

	// Dependency findings of the repository's code (not scan targets).
	frows, err := tx.Query(ctx, `SELECT id, lower(package_name) || '@' || package_version, package_name, cve, rule_id,
		reachability, reachability_basis, reachability_method, reachability_evidence FROM findings
		WHERE repository_id = $1 AND scan_target_id IS NULL AND category = 'sca' AND package_name <> ''`, repoID)
	if err != nil {
		return 0, err
	}
	type finding struct {
		id                       uuid.UUID
		key, pkg, cve, rule      string
		cur, curBasis, curMethod string
		curEvidence              []byte
	}
	var fs []finding
	var ids []string
	for frows.Next() {
		var f finding
		if err := frows.Scan(&f.id, &f.key, &f.pkg, &f.cve, &f.rule, &f.cur, &f.curBasis, &f.curMethod, &f.curEvidence); err != nil {
			frows.Close()
			return 0, err
		}
		fs = append(fs, f)
		for _, id := range []string{f.cve, f.rule} {
			if id != "" {
				ids = append(ids, id)
			}
		}
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return 0, err
	}
	// Vulnerable functions named by the advisories (vulnerability
	// intelligence), only needed when there is a report to apply them to.
	advisories := map[string]advisoryRecord{}
	if !reports.empty() && len(ids) > 0 {
		if advisories, err = loadAdvisories(ctx, tx, ids); err != nil {
			return 0, err
		}
	}
	type change struct {
		id                   uuid.UUID
		reach, basis, method string
		evidence             []byte
	}
	var changes []change
	for _, f := range fs {
		d, ok := decisions[f.key]
		if !ok {
			d = Decision{Reachability: "unknown"}
			if scanned != nil {
				d.Basis = "the package is not in the repository's latest SBOM"
			}
		}
		if !reports.empty() {
			adv := Advisory{IDs: nonEmpty(f.cve, f.rule)}
			for _, id := range []string{f.cve, f.rule} {
				if rec, ok := advisories[id]; ok {
					adv.IDs = append(adv.IDs, rec.ids...)
					adv.Ecosystem, adv.Symbols = symbolsFor(f.pkg, rec.affected)
					break
				}
			}
			if fd, ok := DecideFunction(f.pkg, adv, reports); ok && !(fd.soft && d.Reachability == "reachable") {
				d = fd
			}
		}
		if len(d.Basis) > 500 {
			d.Basis = d.Basis[:497] + "..."
		}
		var ev []byte
		if d.Evidence != nil {
			ev, _ = json.Marshal(d.Evidence)
			if len(ev) > 60000 {
				d.Evidence.Paths = d.Evidence.Paths[:min(1, len(d.Evidence.Paths))]
				ev, _ = json.Marshal(d.Evidence)
			}
		}
		if d.Reachability != f.cur || d.Basis != f.curBasis || d.Method != f.curMethod || !sameJSON(ev, f.curEvidence) {
			changes = append(changes, change{f.id, d.Reachability, d.Basis, d.Method, ev})
		}
	}
	b := &pgx.Batch{}
	for _, c := range changes {
		var ev any
		if c.evidence != nil {
			ev = c.evidence
		}
		b.Queue(`UPDATE findings SET reachability = $2, reachability_basis = $3, reachability_method = $4, reachability_evidence = $5 WHERE id = $1`,
			c.id, c.reach, c.basis, c.method, ev)
	}
	if len(changes) > 0 {
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return 0, err
		}
	}
	return len(changes), nil
}

func nonEmpty(vs ...string) []string {
	var out []string
	for _, v := range vs {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// sameJSON compares stored and computed evidence (jsonb normalizes keys).
func sameJSON(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return bytes.Equal(a, b)
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}

type advisoryRecord struct {
	ids      []string
	affected []affectedEntry
}

// loadAdvisories reads the stored OSV records of identifiers (directly or
// by alias).
func loadAdvisories(ctx context.Context, tx pgx.Tx, ids []string) (map[string]advisoryRecord, error) {
	rows, err := tx.Query(ctx, `SELECT id, aliases, affected FROM intel_vulns WHERE found AND (id = ANY($1) OR aliases && $1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]advisoryRecord{}
	for rows.Next() {
		var id string
		var aliases []string
		var raw []byte
		if err := rows.Scan(&id, &aliases, &raw); err != nil {
			return nil, err
		}
		rec := advisoryRecord{ids: append([]string{id}, aliases...)}
		_ = json.Unmarshal(raw, &rec.affected)
		for _, k := range rec.ids {
			if prev, ok := out[k]; !ok || k == id && prev.ids[0] != k {
				out[k] = rec
			}
		}
	}
	return out, rows.Err()
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
		if _, err := db.CopyFrom(ctx, tx, pgx.Identifier{"repository_code_imports"}, []string{"organization_id", "repository_id", "ecosystem", "kind", "name"},
			pgx.CopyFromRows(rows)); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `UPDATE repositories SET imports_scanned_at = now(), imports_files = $2 WHERE id = $1`, repoID, files)
	return err
}

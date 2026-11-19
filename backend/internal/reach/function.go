package reach

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/reachscan"
	"pathos/internal/scanners"
)

// Function-level reachability: does the code call the vulnerable function
// an advisory names? Two analyses feed it, both run in workers:
//
//	call_graph    govulncheck (Go): the program's call graph, dependencies
//	              included. Its depth per vulnerability decides: a call
//	              path to a vulnerable symbol is reachable, an imported or
//	              only required package is not reachable, unless the
//	              package that imports it calls methods through reflection
//	              (then unknown).
//	symbol_calls  pathos-reach (JavaScript/TypeScript, Python, Java): calls
//	              to the vulnerable functions in the repository's own code,
//	              through aliases, re-exports and typed variables. It does
//	              not see inside dependencies, so it relies on the advisory
//	              naming the functions callers use. Dynamic use of the
//	              package, or a method of that name called on a value of
//	              unknown type, makes the answer unknown, never "not
//	              reachable".
//
// Without vulnerable functions in the advisory, or without a report for
// the language, the package-level answer (import) stands.

// Reachability methods (findings.reachability_method).
const (
	MethodImport      = "import"
	MethodCallGraph   = "call_graph"
	MethodSymbolCalls = "symbol_calls"
)

// Report tools (repository_reach_reports.tool).
const (
	ToolPathosReach = "pathos-reach"
	ToolGovulncheck = "govulncheck"
)

// Evidence backs a function-level answer (findings.reachability_evidence).
type Evidence struct {
	Tool       string     `json:"tool"`
	ScanJobID  *uuid.UUID `json:"scan_job_id,omitempty"`
	AnalysedAt *time.Time `json:"analysed_at,omitempty"`
	// Symbols are the vulnerable functions checked, as the advisory names
	// them.
	Symbols []string `json:"symbols"`
	// Paths are call chains ending at a call of a vulnerable function,
	// outermost caller first.
	Paths [][]reachscan.Frame `json:"paths"`
	// Unresolved are calls of a method with a vulnerable method's name on
	// values whose type could not be resolved.
	Unresolved []reachscan.Frame `json:"unresolved,omitempty"`
	// Dynamic are the constructs that can reach the package in ways the
	// analysis cannot follow.
	Dynamic []reachscan.Dynamic `json:"dynamic,omitempty"`
	// Limits says what the method does not see.
	Limits string `json:"limits"`
}

const (
	limitsCallGraph = "govulncheck analyses the call graph of the Go program and its dependencies; calls through reflection, " +
		"unsafe or assembly are not in its graph."
	limitsSymbolCalls = "pathos-reach reads the repository's own code, not the dependencies: a call to another function of the " +
		"package that uses the vulnerable one internally is not seen, so the answer is as good as the advisory's list of " +
		"vulnerable functions. Call chains are resolved by name and show one way in."
	maxEvidencePaths = 5
	maxEvidenceItems = 10
)

// Advisory is what is known about a finding's vulnerability.
type Advisory struct {
	// IDs: the finding's rule and CVE identifiers and the record's aliases.
	IDs []string
	// Ecosystem is the OSV ecosystem of the affected package ("" unknown).
	Ecosystem string
	Symbols   []string
}

// Reports are a repository's latest reachability reports.
type Reports struct {
	Reach    *reachscan.Report
	ReachJob *uuid.UUID
	ReachAt  time.Time
	Go       []scanners.GovulnResult
	HaveGo   bool
	GoJob    *uuid.UUID
	GoAt     time.Time
}

func (r Reports) empty() bool { return r.Reach == nil && !r.HaveGo }

// LoadReports reads a repository's reports.
func LoadReports(ctx context.Context, tx pgx.Tx, repoID uuid.UUID) (Reports, error) {
	var out Reports
	rows, err := tx.Query(ctx, `SELECT tool, report, scan_job_id, created_at FROM repository_reach_reports WHERE repository_id = $1`, repoID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var tool string
		var raw []byte
		var job *uuid.UUID
		var at time.Time
		if err := rows.Scan(&tool, &raw, &job, &at); err != nil {
			return out, err
		}
		switch tool {
		case ToolPathosReach:
			var r reachscan.Report
			if json.Unmarshal(raw, &r) == nil && r.Schema == reachscan.Schema {
				out.Reach, out.ReachJob, out.ReachAt = &r, job, at
			}
		case ToolGovulncheck:
			var g struct {
				Results []scanners.GovulnResult `json:"results"`
			}
			if json.Unmarshal(raw, &g) == nil {
				out.Go, out.HaveGo, out.GoJob, out.GoAt = g.Results, true, job, at
			}
		}
	}
	return out, rows.Err()
}

// StoreReport replaces a repository's report of one tool.
func StoreReport(ctx context.Context, tx pgx.Tx, orgID, repoID, jobID uuid.UUID, tool string, report any) error {
	b, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO repository_reach_reports (repository_id, organization_id, tool, scan_job_id, report)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (repository_id, tool) DO UPDATE SET scan_job_id = EXCLUDED.scan_job_id, report = EXCLUDED.report, created_at = now()`,
		repoID, orgID, tool, jobID, b)
	return err
}

// ParseReachReport validates a pathos-reach report from a worker and
// bounds what is kept.
func ParseReachReport(raw []byte) (*reachscan.Report, error) {
	var r reachscan.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("invalid pathos-reach report: %w", err)
	}
	if r.Schema != reachscan.Schema || r.Tool != "pathos-reach" {
		return nil, fmt.Errorf("pathos-reach report: unsupported schema %d", r.Schema)
	}
	if len(r.Uses) > reachscan.MaxUses || len(r.Methods) > reachscan.MaxMethods || len(r.Dynamic) > reachscan.MaxDynamic ||
		len(r.Imports) > reachscan.MaxUses {
		return nil, fmt.Errorf("pathos-reach report: too many entries")
	}
	return &r, nil
}

// lang maps an OSV ecosystem to the ecosystems of pathos-reach.
func lang(osvEco string) string {
	switch strings.ToLower(osvEco) {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "maven":
		return "maven"
	case "go":
		return "go"
	}
	return ""
}

func capitalized(s string) bool {
	r, _ := utf8.DecodeRuneInString(s)
	return unicode.IsUpper(r)
}

func lastSeg(s string) string { return s[strings.LastIndex(s, ".")+1:] }

// normSymbol writes a symbol with dots only: Class#method, Class::method,
// Class.prototype.method, module/function and module:function become
// dotted; constructors are the class.
func normSymbol(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '('); i > 0 {
		s = s[:i]
	}
	s = strings.NewReplacer("::", ".", "#", ".", ".prototype.", ".", "/", ".", ":", ".").Replace(s)
	for _, suf := range []string{".__init__", ".<init>", ".constructor"} {
		s = strings.TrimSuffix(s, suf)
	}
	return strings.Trim(s, ".")
}

// symMatch: a use and a vulnerable symbol (both relative to the module)
// name the same function. One may be qualified further than the other
// (re-exports: "Template.render" and "environment.Template.render"); a
// single name matches a qualified one only when what precedes it is a
// module path, not a class (a function "render" is not Template.render).
func symMatch(use, vs string) bool {
	if use == vs {
		return true
	}
	a, b := use, vs
	if len(a) > len(b) {
		a, b = b, a
	}
	if a == "" || !strings.HasSuffix(b, "."+a) {
		return false
	}
	if strings.Contains(a, ".") {
		return true
	}
	parts := strings.Split(b, ".")
	return !capitalized(parts[len(parts)-2])
}

// moduleSymbols groups an advisory's symbols by the module names the code
// would import them from, relative to that module.
func moduleSymbols(eco, pkg string, symbols []string) map[string][]string {
	out := map[string][]string{}
	add := func(mod, s string) {
		if s == "" {
			s = "default"
		}
		if !slices.Contains(out[mod], s) {
			out[mod] = append(out[mod], s)
		}
	}
	switch eco {
	case "npm":
		mod := strings.ToLower(pkg)
		nm := normSymbol(mod)
		for _, raw := range symbols {
			s := normSymbol(raw)
			if s == nm || strings.HasPrefix(s, nm+".") {
				s = strings.TrimPrefix(strings.TrimPrefix(s, nm), ".")
			}
			add(mod, s)
		}
	case "pypi":
		n := pyNorm(pkg)
		mods := append([]string{n}, pythonAliases[n]...)
		for _, raw := range symbols {
			s := normSymbol(raw)
			for _, m := range mods {
				switch {
				case strings.EqualFold(s, m):
					add(m, "")
				case strings.HasPrefix(strings.ToLower(s), m+"."):
					add(m, s[len(m)+1:])
				default:
					add(m, s)
				}
			}
		}
	case "maven":
		for _, raw := range symbols {
			s := normSymbol(raw)
			parts := strings.Split(s, ".")
			p := -1
			for i, x := range parts {
				if capitalized(x) {
					p = i
					break
				}
			}
			if p <= 0 {
				continue // not a qualified class member
			}
			add(strings.Join(parts[:p], "."), strings.Join(parts[p:], "."))
		}
	}
	return out
}

func moduleKey(eco, mod string) string {
	if eco == "pypi" {
		return pyNorm(mod)
	}
	if eco == "npm" {
		return strings.ToLower(mod)
	}
	return mod
}

// DecideFunction gives the function-level reachability of a finding of
// package pkg, or false when there is nothing to decide it with.
func DecideFunction(pkg string, adv Advisory, r Reports) (Decision, bool) {
	if r.empty() {
		return Decision{}, false
	}
	if r.HaveGo {
		if d, ok := decideGo(pkg, adv, r); ok {
			return d, true
		}
	}
	eco := lang(adv.Ecosystem)
	if eco == "" || eco == "go" || r.Reach == nil || len(adv.Symbols) == 0 {
		return Decision{}, false
	}
	st := r.Reach.Languages[eco]
	if st == nil || st.Files == 0 {
		return Decision{}, false
	}
	return decideSymbols(eco, pkg, adv, r)
}

func evidenceBase(tool string, job *uuid.UUID, at time.Time, symbols []string) *Evidence {
	ev := &Evidence{Tool: tool, ScanJobID: job, Symbols: []string{}, Paths: [][]reachscan.Frame{}}
	if !at.IsZero() {
		t := at.UTC()
		ev.AnalysedAt = &t
	}
	for _, s := range symbols {
		if len(ev.Symbols) >= 50 {
			break
		}
		ev.Symbols = append(ev.Symbols, s)
	}
	return ev
}

func where(fr reachscan.Frame) string {
	if fr.File == "" {
		return fr.Function
	}
	return fmt.Sprintf("%s:%d", fr.File, fr.Line)
}

func decideGo(pkg string, adv Advisory, r Reports) (Decision, bool) {
	var best *scanners.GovulnResult
	for i := range r.Go {
		g := &r.Go[i]
		if !strings.EqualFold(g.Module, pkg) {
			continue
		}
		ids := append([]string{g.OSV}, g.Aliases...)
		if !slices.ContainsFunc(ids, func(id string) bool { return slices.Contains(adv.IDs, id) }) {
			continue
		}
		if best == nil || g.Level > best.Level {
			best = g
		}
	}
	if best == nil {
		return Decision{}, false
	}
	symbols := best.Symbols
	if len(symbols) == 0 {
		symbols = adv.Symbols
	}
	ev := evidenceBase(ToolGovulncheck, r.GoJob, r.GoAt, symbols)
	ev.Limits = limitsCallGraph
	d := Decision{Method: MethodCallGraph, Evidence: ev}
	if best.Level == 3 {
		for _, tr := range best.Traces {
			if len(ev.Paths) >= maxEvidencePaths {
				break
			}
			var p []reachscan.Frame
			for _, fr := range tr {
				p = append(p, reachscan.Frame{File: fr.File, Line: fr.Line, Function: fr.Function})
			}
			ev.Paths = append(ev.Paths, p)
		}
		d.Reachability = "reachable"
		d.Basis = "govulncheck found a call path to a vulnerable function"
		if len(ev.Paths) > 0 && len(ev.Paths[0]) > 1 {
			p := ev.Paths[0]
			d.Basis = fmt.Sprintf("govulncheck: %s calls %s", where(p[len(p)-2]), p[len(p)-1].Function)
		}
		return d, true
	}
	// Not called in govulncheck's graph: reflection in a package that
	// imports the module can still call a vulnerable method.
	if r.Reach != nil {
		for _, dy := range r.Reach.Dynamic {
			if dy.Ecosystem == "go" && !dy.Test && (dy.Module == best.Module || strings.HasPrefix(dy.Module, best.Module+"/")) &&
				len(ev.Dynamic) < maxEvidenceItems {
				ev.Dynamic = append(ev.Dynamic, dy)
			}
		}
	} else {
		ev.Limits += " pathos-reach did not run, so calls through reflection were not checked."
	}
	if len(ev.Dynamic) > 0 {
		dy := ev.Dynamic[0]
		d.Reachability = "unknown"
		d.Basis = fmt.Sprintf("govulncheck found no call, but %s:%d uses %s, which govulncheck cannot follow", dy.File, dy.Line, dy.Reason)
		return d, true
	}
	d.Reachability = "not_reachable"
	if best.Level == 2 {
		d.Basis = "govulncheck: " + strings.Join(best.Packages, ", ") + " is imported, but none of its vulnerable functions is called"
	} else {
		d.Basis = "govulncheck: the module is required, but none of its vulnerable packages is imported"
	}
	return d, true
}

func decideSymbols(eco, pkg string, adv Advisory, r Reports) (Decision, bool) {
	rep := r.Reach
	bymod := moduleSymbols(eco, pkg, adv.Symbols)
	if len(bymod) == 0 {
		return Decision{}, false
	}
	keyed := map[string][]string{}
	for m, ss := range bymod {
		keyed[moduleKey(eco, m)] = ss
	}
	ev := evidenceBase(ToolPathosReach, r.ReachJob, r.ReachAt, adv.Symbols)
	ev.Limits = limitsSymbolCalls
	d := Decision{Method: MethodSymbolCalls, Evidence: ev}

	var hits, testHits []reachscan.Use
	var hitSyms []string
	for _, u := range rep.Uses {
		if u.Ecosystem != eco {
			continue
		}
		vss, ok := keyed[moduleKey(eco, u.Module)]
		if !ok {
			continue
		}
		for _, vs := range vss {
			match := u.Kind == "method" && lastSeg(vs) == u.Symbol || u.Kind != "method" && symMatch(u.Symbol, vs)
			if !match {
				continue
			}
			if u.Test {
				testHits = append(testHits, u)
			} else {
				hits = append(hits, u)
				if q := u.Module + "." + u.Symbol; !slices.Contains(hitSyms, q) {
					hitSyms = append(hitSyms, q)
				}
			}
			break
		}
	}
	// Is the package used directly? Java: an import of the vulnerable
	// class's package, or of a package containing or contained in it (an
	// artifact ships several packages).
	inPackage := func(mod string) bool {
		if _, ok := keyed[moduleKey(eco, mod)]; ok {
			return true
		}
		if eco == "maven" {
			for k := range keyed {
				if strings.HasPrefix(k, mod+".") || strings.HasPrefix(mod, k+".") {
					return true
				}
			}
		}
		return false
	}
	imported := false
	for _, im := range rep.Imports {
		if im.Ecosystem == eco && inPackage(im.Module) {
			imported = true
			break
		}
	}
	pathsOf := func(us []reachscan.Use) {
		// calls before method-name matches, then by order
		slices.SortStableFunc(us, func(a, b reachscan.Use) int {
			return boolInt(a.Kind == "method") - boolInt(b.Kind == "method")
		})
		for _, u := range us {
			for _, p := range u.Paths {
				if len(ev.Paths) < maxEvidencePaths {
					ev.Paths = append(ev.Paths, p)
				}
			}
		}
	}
	if len(hits) > 0 {
		pathsOf(hits)
		d.Reachability = "reachable"
		u := hits[0]
		site := ""
		if len(u.Sites) > 0 {
			site = " at " + where(u.Sites[0])
		}
		switch u.Kind {
		case "method":
			d.Basis = fmt.Sprintf("the code calls %s()%s on a value obtained from %s (its class is not resolved)", u.Symbol, site, u.Module)
		default:
			d.Basis = fmt.Sprintf("the code calls %s.%s%s", u.Module, u.Symbol, site)
		}
		return d, true
	}
	for _, dy := range rep.Dynamic {
		if dy.Ecosystem != eco || dy.Test || len(ev.Dynamic) >= maxEvidenceItems {
			continue
		}
		if dy.Module == "" || inPackage(dy.Module) {
			ev.Dynamic = append(ev.Dynamic, dy)
		}
	}
	if !imported && len(testHits) == 0 {
		// Not imported directly: a transitive dependency, or not used.
		// The package-level answer stands, unless code loads modules or
		// classes by computed names (then not "not reachable").
		if len(ev.Dynamic) == 0 {
			return Decision{}, false
		}
		d.soft = true
	}
	if len(ev.Dynamic) > 0 {
		dy := ev.Dynamic[0]
		mod := dy.Module
		if mod == "" {
			mod = "any module"
		}
		d.Reachability = "unknown"
		d.Basis = fmt.Sprintf("dynamic use (%s, %s at %s:%d): the vulnerable functions may be called in ways the analysis cannot follow",
			dy.Reason, mod, dy.File, dy.Line)
		return d, true
	}
	// methods with a vulnerable method's name on values of unknown type
	var methodNames []string
	for _, vss := range keyed {
		for _, vs := range vss {
			parts := strings.Split(vs, ".")
			if len(parts) >= 2 && capitalized(parts[len(parts)-2]) && !slices.Contains(methodNames, parts[len(parts)-1]) {
				methodNames = append(methodNames, parts[len(parts)-1])
			}
		}
	}
	unresolvedName := ""
	for _, m := range rep.Methods {
		if m.Ecosystem != eco || m.Test || !slices.Contains(methodNames, m.Name) {
			continue
		}
		for _, s := range m.Sites {
			if len(ev.Unresolved) < maxEvidenceItems {
				ev.Unresolved = append(ev.Unresolved, s)
				if unresolvedName == "" {
					unresolvedName = m.Name
				}
			}
		}
	}
	if len(ev.Unresolved) > 0 {
		d.Reachability = "unknown"
		d.Basis = fmt.Sprintf("%s calls a method named %s on a value whose type the analysis cannot resolve; it may be the vulnerable method",
			where(ev.Unresolved[0]), unresolvedName)
		return d, true
	}
	if rep.Truncated {
		d.Reachability = "unknown"
		d.Basis = "the analysis reached a size limit, so a call may have been missed"
		return d, true
	}
	d.Reachability = "not_reachable"
	if len(testHits) > 0 {
		pathsOf(testHits)
		site := ""
		if len(testHits[0].Sites) > 0 {
			site = " (" + where(testHits[0].Sites[0]) + ")"
		}
		d.Basis = "only test code calls the vulnerable function" + site
		return d, true
	}
	d.Basis = fmt.Sprintf("the code uses %s but calls none of its vulnerable functions (%s)", pkg, strings.Join(firstN(adv.Symbols, 3), ", "))
	return d, true
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return append(append([]string{}, s[:n]...), fmt.Sprintf("and %d more", len(s)-n))
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// symbolsFor picks the affected entry of a record for a finding's package.
func symbolsFor(pkg string, affected []affectedEntry) (string, []string) {
	for _, a := range affected {
		if packageMatches(a.Ecosystem, a.Package, pkg) {
			return a.Ecosystem, a.Symbols
		}
	}
	return "", nil
}

type affectedEntry struct {
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	Symbols   []string `json:"symbols"`
}

func packageMatches(eco, a, b string) bool {
	if strings.EqualFold(eco, "pypi") {
		return pyNorm(a) == pyNorm(b)
	}
	return strings.EqualFold(a, b)
}

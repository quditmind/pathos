package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Routes, data access, queues and outbound HTTP calls come from the PATHOS
// graph rules (workers/graph/rules), run by Opengrep as a separate
// process. A rule's metadata.pathos_graph says what a match means; its
// message carries the values ("route|METHOD|PATH|HANDLER",
// "db|SQL-or-method", "queue|TOPIC", "http|URL"). The match location is
// the evidence.

type ogMeta struct {
	Kind           string `json:"kind"` // route | route_prefix | db | queue_publish | queue_consume | external_call
	Framework      string `json:"framework"`
	Technology     string `json:"technology"`
	Operation      string `json:"operation"` // read | write | readwrite | "" (from the SQL verb or method name)
	Method         string `json:"method"`
	RequiresImport string `json:"requires_import"` // "a|b": the file must import one of them
}

type ogResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
	} `json:"end"`
	Extra struct {
		Message  string `json:"message"`
		Metadata struct {
			PathosGraph ogMeta `json:"pathos_graph"`
		} `json:"metadata"`
	} `json:"extra"`
}

type ogOutput struct {
	Results []ogResult `json:"results"`
	Errors  []struct {
		Message string `json:"message"`
		Path    string `json:"path"`
	} `json:"errors"`
	Version string `json:"version"`
}

// safeEnv is the environment of child processes: no proxy settings and
// nothing else inherited but PATH, HOME and the temporary directory.
func safeEnv() []string {
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	for _, k := range []string{"HOME", "TMPDIR"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func toolVersion(ctx context.Context, bin string, args ...string) string {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// #nosec G204 -- binary path from the image configuration
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(safeEnv(), "SYFT_CHECK_FOR_APP_UPDATE=false")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, f := range strings.Fields(string(out)) {
		f = strings.TrimPrefix(f, "v")
		if len(f) > 0 && f[0] >= '0' && f[0] <= '9' && strings.Contains(f, ".") {
			return f
		}
	}
	return clip(strings.TrimSpace(string(out)), 40)
}

func runOpengrep(ctx context.Context, bin, rules, src string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	// #nosec G204 -- binary and rules come from the worker image
	// --no-git-ignore: sources may be uploaded snapshots or checkouts
	// whose Git metadata is not available (the skip list below applies).
	cmd := exec.CommandContext(ctx, bin, "scan", "--json", "--quiet", "--no-git-ignore", "--timeout", "30", "--max-target-bytes", "1000000",
		"--exclude", "node_modules", "--exclude", "vendor", "--exclude", "third_party", "--exclude", "dist",
		"--exclude", ".git", "--exclude", "build", "--exclude", "target", "--exclude", ".venv", "--exclude", "venv",
		"--config", rules, src)
	cmd.Env = safeEnv()
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		msg := ""
		if ee, ok := err.(*exec.ExitError); ok {
			msg = clip(strings.TrimSpace(string(ee.Stderr)), 300)
		}
		return nil, fmt.Errorf("opengrep: %v %s", err, msg)
	}
	return out, nil
}

var (
	sqlVerbRe  = regexp.MustCompile(`(?is)^\s*\(?\s*(select|with|show|explain|insert|update|delete|merge|upsert|replace|create|alter|drop|truncate|call|copy)\b`)
	readNameRe = regexp.MustCompile(`(?i)^(find|get|select|query|read|fetch|count|exists|all|first|last|load|scan|search|aggregate|pluck|where|list|h?mget|hget|keys|lrange|smembers|zrange|exec_query|filter|retrieve|to_?list|single|any)`)
	writeRe    = regexp.MustCompile(`(?i)^(insert|save|update|delete|exec|create|put|set|remove|upsert|write|destroy|persist|merge|add|bulk|replace|incr|decr|expire|hset|lpush|rpush|sadd|zadd|del|drop|truncate|commit|execute_?update|batch|store|flush|bulk_?create|new_?record|savechanges)`)
)

// dbOperation classifies an access: the SQL verb when the message is a
// statement, else the method name.
func dbOperation(op, value string) []string {
	switch op {
	case "read":
		return []string{"reads"}
	case "write":
		return []string{"writes"}
	case "readwrite":
		return []string{"reads", "writes"}
	}
	v := strings.TrimSpace(value)
	if m := sqlVerbRe.FindStringSubmatch(v); m != nil {
		switch strings.ToLower(m[1]) {
		case "select", "with", "show", "explain":
			return []string{"reads"}
		}
		return []string{"writes"}
	}
	name := v
	if i := strings.LastIndexAny(name, ".>:"); i >= 0 {
		name = name[i+1:]
	}
	switch {
	case writeRe.MatchString(name):
		return []string{"writes"}
	case readNameRe.MatchString(name):
		return []string{"reads"}
	}
	return []string{"reads"}
}

func unbound(v string) bool { return v == "" || strings.HasPrefix(v, "$") }

var httpMethods = set("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

// routeMethod normalises a framework method token (GetMapping, MapPost,
// get, HttpDelete, Any...).
func routeMethod(tok, fixed string) string {
	if fixed != "" {
		return strings.ToUpper(fixed)
	}
	t := strings.ToUpper(tok)
	for _, pre := range []string{"MAP", "HTTP"} {
		t = strings.TrimPrefix(t, pre)
	}
	t = strings.TrimSuffix(t, "MAPPING")
	if httpMethods[t] {
		return t
	}
	return "ANY"
}

func normPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	// Django and Rails paths have no leading slash.
	if !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "^") {
		p = "/" + p
	}
	return p
}

// fileImports reports whether the file imports one of the "|"-separated
// substrings.
func (p *project) fileImports(rel, req string) bool {
	if req == "" {
		return true
	}
	f := p.byRel[rel]
	if f == nil {
		return false
	}
	for _, want := range strings.Split(req, "|") {
		for _, imp := range f.imports {
			if strings.Contains(imp, want) {
				return true
			}
		}
		// PHP and Ruby load classes and gems without an import statement
		// per symbol (autoloading, Bundler): the file's use/require lines
		// count as well.
		if f.lang == "php" || f.lang == "rb" {
			for _, ln := range strings.Split(string(f.data), "\n") {
				t := strings.TrimSpace(ln)
				if (strings.HasPrefix(t, "use ") || strings.HasPrefix(t, "require")) && strings.Contains(t, want) {
					return true
				}
			}
		}
	}
	return false
}

// frameworkFor refines a route's framework from the file's imports.
func (p *project) frameworkFor(rel, declared string) string {
	f := p.byRel[rel]
	if f == nil || !strings.Contains(declared, "|") {
		return declared
	}
	for _, cand := range strings.Split(declared, "|") {
		for _, imp := range f.imports {
			if strings.Contains(strings.ToLower(imp), strings.ToLower(cand)) {
				return cand
			}
		}
	}
	return strings.Split(declared, "|")[len(strings.Split(declared, "|"))-1]
}

type routePrefix struct {
	rel        string
	start, end int
	prefix     string
}

func (p *project) applyOpengrep(data []byte, src string) (int, error) {
	var out ogOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, err
	}
	absSrc, _ := filepath.Abs(src)
	rels := func(pth string) string {
		r := pth
		if filepath.IsAbs(pth) {
			if rr, err := filepath.Rel(absSrc, pth); err == nil {
				r = rr
			}
		} else if rr, err := filepath.Rel(src, pth); err == nil && !strings.HasPrefix(rr, "..") {
			r = rr
		}
		return filepath.ToSlash(filepath.Clean(r))
	}
	sort.SliceStable(out.Results, func(i, j int) bool {
		a, b := out.Results[i], out.Results[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Start.Line < b.Start.Line
	})
	// Class-level prefixes first (Spring @RequestMapping, NestJS
	// @Controller, ASP.NET [Route]).
	var prefixes []routePrefix
	for _, r := range out.Results {
		m := r.Extra.Metadata.PathosGraph
		if m.Kind != "route_prefix" {
			continue
		}
		parts := strings.Split(r.Extra.Message, "|")
		if len(parts) < 2 || unbound(parts[1]) {
			continue
		}
		prefixes = append(prefixes, routePrefix{rel: rels(r.Path), start: r.Start.Line, end: r.End.Line, prefix: parts[1]})
	}
	n := 0
	for _, r := range out.Results {
		m := r.Extra.Metadata.PathosGraph
		rel := rels(r.Path)
		if m.Kind == "" || m.Kind == "route_prefix" || !p.fileImports(rel, m.RequiresImport) {
			continue
		}
		parts := strings.Split(r.Extra.Message, "|")
		for len(parts) < 4 {
			parts = append(parts, "")
		}
		ln := r.Start.Line
		fileKey := p.fileNode(rel, "")
		ruleID := r.CheckID
		if i := strings.Index(ruleID, "pathos-graph-"); i >= 0 {
			ruleID = ruleID[i:]
		}
		switch m.Kind {
		case "route":
			method := routeMethod(parts[1], m.Method)
			rp := parts[2]
			if unbound(rp) {
				rp = ""
			}
			// Go 1.22 patterns: "GET /path".
			if f := strings.Fields(rp); len(f) == 2 && httpMethods[strings.ToUpper(f[0])] {
				method, rp = strings.ToUpper(f[0]), f[1]
			}
			for _, pr := range prefixes {
				if pr.rel == rel && ln >= pr.start && ln <= pr.end+maxClassSpan(p, rel, pr.start) {
					rp = strings.TrimSuffix(pr.prefix, "/") + "/" + strings.TrimPrefix(rp, "/")
					break
				}
			}
			rp = normPath(rp)
			fw := p.frameworkFor(rel, m.Framework)
			key := "route:" + method + " " + rp
			if p.g.Has(key) && p.g.Node(key).Attrs["file"] != rel {
				key = "route:" + method + " " + rp + " @" + rel // same route declared in two files
			}
			if !p.g.AddNode(key, "route", method+" "+rp, fileKey, map[string]any{"method": method, "path": rp, "framework": fw,
				"file": rel, "line": ln, "language": langDisplay(p.langOf(rel)), "exposure": "http"}) {
				continue
			}
			ev := fileLine(rel, ln, fw+" route "+method+" "+rp)
			p.g.AddEdge(fileKey, "defines", key, ev)
			handler := ""
			if !unbound(parts[3]) {
				handler = p.resolveHandler(rel, parts[3])
			}
			if handler == "" {
				handler = p.functionNear(rel, ln)
			}
			if handler != "" {
				p.g.AddEdge(key, "calls", handler, fileLine(rel, ln, "handler "+strings.TrimPrefix(parts[3], "$")))
			}
			p.boundary("tb:http-ingress", "HTTP ingress")
			p.g.AddEdge(key, "crosses_boundary", "tb:http-ingress", ev)
			n++
		case "db":
			tech := m.Technology
			if tech == "" || tech == "sql" {
				tech = p.sqlTechnology(rel)
			}
			ds := "ds:" + tech
			p.g.AddNode(ds, "datastore", datastoreLabel(tech), "", map[string]any{"technology": tech})
			caller := p.enclosing(rel, ln)
			for _, op := range dbOperation(m.Operation, parts[1]) {
				p.g.AddEdge(caller, op, ds, fileLine(rel, ln, tech+" "+strings.TrimPrefix(firstLine(parts[1]), "$")))
			}
			n++
		case "queue_publish", "queue_consume":
			tech := m.Technology
			topic := parts[1]
			key, label := "queue:"+tech, tech
			if !unbound(topic) && topic != "" {
				key, label = "queue:"+tech+":"+topic, topic
			}
			p.g.AddNode(key, "queue", label, "", map[string]any{"technology": tech, "topic": strings.TrimPrefix(topic, "$")})
			typ := "publishes"
			if m.Kind == "queue_consume" {
				typ = "consumes"
			}
			caller := p.enclosing(rel, ln)
			if typ == "consumes" {
				if fn := p.functionNear(rel, ln); fn != "" {
					caller = fn
				}
			}
			p.g.AddEdge(caller, typ, key, fileLine(rel, ln, tech+" "+label))
			n++
		case "external_call":
			host := urlHost(parts[1])
			if host == "" || isLocalHost(host) {
				continue
			}
			key := "ext:" + host
			// The scheme is TLS evidence for threat modelling (rule
			// TM-I-001): https and wss are encrypted, http and ws are not.
			scheme := urlScheme(parts[1])
			p.g.AddNode(key, "external_service", host, "", map[string]any{"host": host, "technology": scheme, "scheme": scheme})
			p.g.AddEdge(p.enclosing(rel, ln), "calls", key, fileLine(rel, ln, strings.ToUpper(scheme)+" call to "+host))
			p.boundary("tb:external-network", "External network")
			p.g.AddEdge(key, "crosses_boundary", "tb:external-network", fileLine(rel, ln, "outbound call to "+host))
			n++
		}
		_ = ruleID
	}
	for _, e := range out.Errors {
		path := ""
		if e.Path != "" {
			path = rels(e.Path)
		}
		p.skip(path, "opengrep: "+clip(oneLine(e.Message), 200))
	}
	return n, nil
}

// maxClassSpan: the prefix match covers the class declaration; routes
// are inside the class body (the match end line already includes it for
// rules that match the whole class).
func maxClassSpan(p *project, rel string, line int) int {
	f := p.byRel[rel]
	if f == nil {
		return 0
	}
	for _, s := range f.syms {
		if s.kind == "class" && s.start >= line && s.start <= line+3 {
			return s.end - line
		}
	}
	return 0
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return clip(s, 120)
}

func (p *project) langOf(rel string) string {
	if f := p.byRel[rel]; f != nil {
		return f.lang
	}
	return ""
}

// sqlTechnology names the SQL database a file talks to from its imports
// (drivers), else "sql".
func (p *project) sqlTechnology(rel string) string {
	f := p.byRel[rel]
	if f == nil {
		return "sql"
	}
	hints := []struct{ sub, tech string }{
		{"jackc/pgx", "postgresql"}, {"lib/pq", "postgresql"}, {"psycopg", "postgresql"}, {"asyncpg", "postgresql"},
		{"Npgsql", "postgresql"}, {"pg-promise", "postgresql"}, {"postgres", "postgresql"},
		{"go-sql-driver/mysql", "mysql"}, {"pymysql", "mysql"}, {"mysql", "mysql"}, {"mariadb", "mysql"},
		{"sqlite", "sqlite"}, {"SqlClient", "sqlserver"}, {"mssql", "sqlserver"}, {"oracle", "oracle"},
	}
	for _, h := range hints {
		for _, imp := range f.imports {
			if strings.Contains(strings.ToLower(imp), strings.ToLower(h.sub)) {
				return h.tech
			}
		}
	}
	if f.lang == "js" || f.lang == "ts" || f.lang == "tsx" {
		for _, imp := range f.imports {
			if imp == "pg" {
				return "postgresql"
			}
		}
	}
	return "sql"
}

func datastoreLabel(tech string) string {
	labels := map[string]string{"postgresql": "PostgreSQL", "mysql": "MySQL", "sqlite": "SQLite", "sqlserver": "SQL Server",
		"oracle": "Oracle", "redis": "Redis", "mongodb": "MongoDB", "sql": "SQL database", "elasticsearch": "Elasticsearch",
		"dynamodb": "DynamoDB", "s3": "Object storage (S3)", "cassandra": "Cassandra", "memcached": "Memcached"}
	if l, ok := labels[tech]; ok {
		return l
	}
	return tech
}

var urlRe = regexp.MustCompile(`^(?i)(https?|wss?)://([^/?#\s"']+)`)

// urlScheme is the lower-case scheme of an http(s) or ws(s) URL.
func urlScheme(u string) string {
	if m := urlRe.FindStringSubmatch(strings.TrimSpace(u)); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

func urlHost(u string) string {
	m := urlRe.FindStringSubmatch(strings.TrimSpace(u))
	if m == nil {
		return ""
	}
	h := strings.ToLower(m[2])
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:] // never keep userinfo
	}
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.HasSuffix(h, "]") {
		h = h[:i]
	}
	if h == "" || strings.ContainsAny(h, "{}<>$") || !strings.Contains(h, ".") {
		return ""
	}
	return h
}

func isLocalHost(h string) bool {
	return h == "localhost" || strings.HasPrefix(h, "127.") || h == "0.0.0.0" || strings.HasSuffix(h, ".local") ||
		strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".example") || strings.HasSuffix(h, "example.com") ||
		strings.HasSuffix(h, "example.org") || strings.HasSuffix(h, "example.net") || strings.HasSuffix(h, ".test") || strings.HasSuffix(h, ".invalid")
}

func (p *project) boundary(key, label string) {
	p.g.AddNode(key, "trust_boundary", label, "", map[string]any{"technology": "network"})
}

// resolveHandler finds the function a route names ("getUser",
// "views.index", "UserController@show", "users#show", "this.handler").
func (p *project) resolveHandler(rel, h string) string {
	h = strings.Trim(strings.TrimSpace(h), `"'`)
	if h == "" || strings.ContainsAny(h, "(){} \n") {
		return ""
	}
	qual, name := "", h
	switch {
	case strings.Contains(h, "#"): // Rails "users#show"
		parts := strings.SplitN(h, "#", 2)
		ctrl := parts[0]
		name = parts[1]
		return p.findFunction(func(s *symbol, f *srcFile) bool {
			return f.lang == "rb" && s.name == name && strings.HasSuffix(f.rel, "controllers/"+ctrl+"_controller.rb")
		})
	case strings.Contains(h, "@"): // Laravel "Controller@method"
		parts := strings.SplitN(h, "@", 2)
		qual, name = cleanType(parts[0]), parts[1]
	case strings.Contains(h, "."):
		i := strings.LastIndex(h, ".")
		qual, name = h[:i], h[i+1:]
	}
	if p.ts != nil {
		if tf := p.ts.files[rel]; tf != nil {
			if k := p.resolveCall(p.ts, tf, tsCall{qual: normQual(qual), name: name}); k != "" {
				return k
			}
		}
	}
	// Go: a function of the same package, of the package the qualifier
	// names, or a method of that name defined in the same package.
	if f := p.byRel[rel]; f != nil && f.lang == "go" {
		dir := path.Dir(rel)
		if qual == "" {
			return p.findFunction(func(s *symbol, g *srcFile) bool {
				return g.lang == "go" && s.name == name && s.class == "" && path.Dir(g.rel) == dir
			})
		}
		if k := p.findFunction(func(s *symbol, g *srcFile) bool {
			return g.lang == "go" && s.name == name && s.class == "" && path.Base(path.Dir(g.rel)) == qual
		}); k != "" {
			return k
		}
		return p.findFunction(func(s *symbol, g *srcFile) bool {
			return g.lang == "go" && s.name == name && s.class != "" && path.Dir(g.rel) == dir
		})
	}
	return ""
}

// findFunction returns the only function matching ok ("" when none or
// several do).
func (p *project) findFunction(ok func(*symbol, *srcFile) bool) string {
	found := ""
	for _, f := range p.files {
		for _, s := range f.syms {
			if s.kind == "function" && ok(s, f) && p.g.Has(s.key) {
				if found != "" && found != s.key {
					return ""
				}
				found = s.key
			}
		}
	}
	return found
}

package threatmodel

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Rule is one deterministic STRIDE rule over a CodeGraph snapshot. The
// rule catalogue (ids, versions, logic, mappings) is documented in
// docs/aspm/PATHOS_THREAT_MODELLING.md §3; a change of a rule's logic
// bumps its version.
type Rule struct {
	ID         string    `json:"id"`
	Version    string    `json:"version"`
	Category   string    `json:"category"`
	Element    string    `json:"element"` // DFD element kind the rule threatens
	Title      string    `json:"title"`
	Logic      string    `json:"logic"`
	Severity   string    `json:"severity"` // base severity
	Confidence float64   `json:"confidence"`
	Mitigation string    `json:"mitigation"`
	Mappings   []Mapping `json:"mappings"`
	// Absence: the rule fires on missing evidence (authentication, audit,
	// rate limiting); its severity is capped at high and its confidence
	// is lower.
	Absence bool `json:"absence"`
	run     func(*ruleCtx) []Threat
}

func rm(framework string, ids ...string) []Mapping {
	out := make([]Mapping, 0, len(ids))
	for _, id := range ids {
		out = append(out, Mapping{Framework: framework, ID: id, Source: "rule"})
	}
	return out
}

func maps(groups ...[]Mapping) []Mapping {
	var out []Mapping
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// Rules is the rule catalogue, in evaluation order.
var Rules []Rule

func init() {
	Rules = []Rule{
		{ID: "TM-S-001", Version: "1", Category: Spoofing, Element: KindProcess, Severity: "medium", Confidence: 0.55, Absence: true,
			Title:      "Exposed entry point without authentication evidence",
			Logic:      "A route crossing an ingress trust boundary (crosses_boundary to a trust_boundary node) whose handler chain (calls, 4 deep) contains no function named like authentication (auth, login, session, token, jwt, oauth, guard, principal, current user) and whose file imports no authentication library. Health, readiness, metrics, static and sign-in paths are public by design and skipped.",
			Mitigation: "Require authentication on this entry point (session, token or mutual TLS) in a middleware that runs before the handler, or record why it is public. If authentication exists but PATHOS cannot see it (for example a gateway), set the threat to not applicable with that reason.",
			Mappings:   maps(rm("attack", "T1190", "T1078"), rm("capec", "CAPEC-115"), rm("cwe", "CWE-306"), rm("d3fend", "D3-TBA", "D3-MFA")),
			run:        ruleUnauthenticatedEntry},
		{ID: "TM-E-001", Version: "1", Category: ElevationOfPrivilege, Element: KindProcess, Severity: "medium", Confidence: 0.5, Absence: true,
			Title:      "State-changing entry point without authorization evidence",
			Logic:      "A route crossing an ingress trust boundary that changes state (method POST, PUT, PATCH or DELETE, or its handler chain writes a data store) and whose handler chain (4 deep) contains no function named like an authorization check (authorize, permission, role, policy, rbac, acl, can…, isAdmin, require…).",
			Mitigation: "Check the caller's permission for this action and resource on the server before changing state (deny by default; object-level checks for ids in the path).",
			Mappings:   maps(rm("attack", "T1190"), rm("capec", "CAPEC-122", "CAPEC-1"), rm("cwe", "CWE-862"), rm("d3fend", "D3-UAP", "D3-WSAM")),
			run:        ruleMissingAuthorization},
		{ID: "TM-T-001", Version: "1", Category: Tampering, Element: KindDataStore, Severity: "medium", Confidence: 0.8,
			Title:      "Data store written from an exposed entry point",
			Logic:      "A datastore or queue with a writes edge from a function reachable (calls, 4 deep) from a route that crosses an ingress trust boundary. SQL data stores add SQL injection mappings.",
			Mitigation: "Validate and constrain input before it is written; use parameterised queries or the ORM's bound parameters; give the application's database account only the rights it needs.",
			Mappings:   maps(rm("attack", "T1565.001")),
			run:        ruleExposedWrite},
		{ID: "TM-R-001", Version: "1", Category: Repudiation, Element: KindProcess, Severity: "low", Confidence: 0.5, Absence: true,
			Title:      "State change without audit evidence",
			Logic:      "A route crossing an ingress trust boundary whose handler chain writes a data store, while no function on the chain is named like an audit or event record (audit, journal, history, activity, event log, track) and no audit data store is written.",
			Mitigation: "Record who did what and when for this state change in an append-only audit log (actor, action, target, time, request id), outside the reach of the actor.",
			Mappings:   maps(rm("capec", "CAPEC-268"), rm("cwe", "CWE-778"), rm("d3fend", "D3-RAPA")),
			run:        ruleNoAudit},
		{ID: "TM-I-001", Version: "1", Category: InformationDisclosure, Element: KindDataFlow, Severity: "medium", Confidence: 0.85,
			Title:      "Cross-boundary data flow without TLS evidence",
			Logic:      "A calls or depends_on flow to an external service that crosses a trust boundary, where the service's scheme or technology is not https, wss or tls.",
			Mitigation: "Use TLS (https or wss) for this connection and verify the server certificate; do not send credentials or personal data over plain HTTP.",
			Mappings:   maps(rm("attack", "T1040", "T1557"), rm("capec", "CAPEC-157", "CAPEC-94"), rm("cwe", "CWE-319"), rm("d3fend", "D3-ET", "D3-MENCR")),
			run:        ruleCleartextFlow},
		{ID: "TM-I-003", Version: "1", Category: InformationDisclosure, Element: KindDataStore, Severity: "high", Confidence: 0.8,
			Title:      "Credential defined as a literal in code",
			Logic:      "A secret_ref node whose source is a literal in code (the discovery engine records its name and location only, never the value).",
			Mitigation: "Move the credential to a secret store or the deployment's secret mechanism, rotate it (it is in the repository history), and read it at run time.",
			Mappings:   maps(rm("attack", "T1552.001"), rm("capec", "CAPEC-191"), rm("cwe", "CWE-798"), rm("d3fend", "D3-CRO", "D3-CH")),
			run:        ruleLiteralSecret},
		{ID: "TM-D-001", Version: "1", Category: DenialOfService, Element: KindDataStore, Severity: "medium", Confidence: 0.6, Absence: true,
			Title:      "Unbounded input from an exposed entry point to a queue",
			Logic:      "A queue with a publishes edge from a function reachable (calls, 4 deep) from a route crossing an ingress trust boundary, with no function on the chain named like rate limiting (rate, limit, throttle, quota, bucket, backpressure).",
			Mitigation: "Limit the rate and size of messages a caller can publish (per caller quotas, request size limits, bounded queues with back-pressure).",
			Mappings:   maps(rm("attack", "T1499.003"), rm("capec", "CAPEC-125"), rm("cwe", "CWE-770"), rm("d3fend", "D3-ISVA")),
			run:        ruleUnboundedQueue},
		{ID: "TM-D-002", Version: "1", Category: DenialOfService, Element: KindTrustBoundary, Severity: "medium", Confidence: 0.6, Absence: true,
			Title:      "Internet ingress without filtering or rate-limit evidence",
			Logic:      "A container, infrastructure resource or observed workload that crosses the internet trust boundary (published port, Ingress, LoadBalancer or NodePort Service, security group open to the internet), when the graph holds no filtering or rate-limiting resource (WAF, network policy, rate-limit configuration).",
			Mitigation: "Put a filtering layer in front of this ingress (WAF or API gateway with rate limits, network policies, a security group limited to known sources).",
			Mappings:   maps(rm("attack", "T1498", "T1190"), rm("capec", "CAPEC-125"), rm("cwe", "CWE-1327"), rm("d3fend", "D3-ITF", "D3-NTF")),
			run:        ruleInternetIngress},
		{ID: "TM-E-002", Version: "1", Category: ElevationOfPrivilege, Element: KindProcess, Severity: "medium", Confidence: 0.75,
			Title:      "Container image runs as root",
			Logic:      "A container built from a Dockerfile (base_image recorded) without a USER instruction, or with USER root or 0.",
			Mitigation: "Add a USER instruction with a non-root user (and a read-only root file system where possible) so that a compromise of the process does not give root in the container.",
			Mappings:   maps(rm("attack", "T1611"), rm("cwe", "CWE-250"), rm("d3fend", "D3-EI")),
			run:        ruleRootContainer},
	}
}

// RuleByID returns a rule of the catalogue.
func RuleByID(id string) (Rule, bool) {
	for _, r := range Rules {
		if r.ID == id {
			return r, true
		}
	}
	if id == AttackPathRule.ID {
		return AttackPathRule, true
	}
	return Rule{}, false
}

// --- shared analysis -----------------------------------------------------------

var (
	// Names that indicate authentication on a handler chain or an imported library.
	authRe = regexp.MustCompile(`(?i)(auth|login|logon|signin|session|token|jwt|oauth|oidc|saml|passport|guard|principal|current_?user|credential|apikey|api_key|bearer|identity)`)
	// Names that indicate an authorization check.
	authzRe = regexp.MustCompile(`(?i)(authori[sz]|permission|perm(it)?s?\b|role|polic(y|ies)|rbac|abac|acl|\bcan[A-Z_]|^can[A-Z]|is_?admin|require_?(role|perm|scope|admin)|access_?control|enforce|guard|scope)`)
	// Names that indicate an audit or event record.
	auditRe = regexp.MustCompile(`(?i)(audit|journal|history|activity|event_?log|log_?event|record_?event|track|trail)`)
	// Names that indicate rate limiting.
	rateRe = regexp.MustCompile(`(?i)(rate|limit|throttl|quota|bucket|backpressure|back_pressure)`)
	// Resources that filter or rate-limit ingress.
	filterRe = regexp.MustCompile(`(?i)(waf|web_acl|networkpolicy|network_policy|ratelimit|rate_limit|limit-rps|limit-connections|cloud_armor|front_door|api_gateway_usage_plan|usage_plan|shield)`)
	// Paths that are public by design.
	publicPathRe = regexp.MustCompile(`(?i)^/?(healthz?|livez|readyz|ready|live|ping|status|metrics|version|favicon\.ico|robots\.txt|\.well-known(/.*)?|static(/.*)?|assets(/.*)?|login|signin|sign-in|logout|oauth2?(/.*)?|auth/callback|callback|sso(/.*)?)/?$`)
)

const chainDepth = 4

var mutating = []string{"POST", "PUT", "PATCH", "DELETE"}

// ruleCtx holds what several rules share.
type ruleCtx struct {
	g        *Graph
	entries  []*entry
	internet *Exposure
	inetEdge []*Edge
	observed bool
	skipped  []string // public-by-design routes
	filters  []string // filtering resources found
	used     map[string]bool
}

// entry is a route crossing an ingress trust boundary, with its handler chain.
type entry struct {
	route    *Node
	boundary *Edge
	api      []*Edge // api_operation -exposes-> route
	chain    []*Node // functions reachable through calls (BFS order)
	edges    []*Edge // the calls edges of the chain
	parent   map[string]*Edge
	writes   []*Edge // writes from the route or the chain
	reads    []*Edge // reads from the route or the chain
	pubs     []*Edge // publishes from the route or the chain
	method   string
	path     string
}

func newContext(g *Graph) *ruleCtx {
	c := &ruleCtx{g: g, used: map[string]bool{}}
	c.internet = &Exposure{Level: "unknown"}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Type != "trust_boundary" {
			continue
		}
		for _, e := range g.inEdges(n.Key, "crosses_boundary") {
			if isInternetBoundary(n) {
				c.inetEdge = append(c.inetEdge, e)
				src, _ := g.node(e.Source)
				reason := fmt.Sprintf("%s crosses the internet boundary", label(src))
				if r := refText(e); r != "" {
					reason += " (" + r + ")"
				}
				if e.Evidence == EvidenceObserved {
					c.observed = true
					reason += ", observed at run time"
				}
				c.internet.Reasons = append(c.internet.Reasons, reason)
			}
		}
	}
	if len(c.inetEdge) > 0 {
		c.internet.Level = "internet"
	}
	if g.PublicExposure == "yes" {
		c.internet.Level = "internet"
		c.internet.Reasons = append(c.internet.Reasons, "the repository is registered as internet-facing (asset inventory)")
	} else if c.internet.Level == "unknown" {
		c.internet.Level = "network"
	}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if (n.Type == "iac_resource" || n.Type == "container") && (filterRe.MatchString(n.Label) || filterRe.MatchString(attrString(n, "kind"))) {
			c.filters = append(c.filters, n.Label)
		}
	}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Type != "route" {
			continue
		}
		var b *Edge
		for _, e := range g.outEdges(n.Key, "crosses_boundary") {
			if tb, ok := g.node(e.Target); ok && tb.Type == "trust_boundary" {
				b = e
				break
			}
		}
		if b == nil {
			continue
		}
		en := &entry{route: n, boundary: b, method: strings.ToUpper(attrString(n, "method")), path: attrString(n, "path")}
		if en.method == "" || en.path == "" {
			if m, p, ok := strings.Cut(n.Label, " "); ok {
				en.method, en.path = strings.ToUpper(m), p
			}
		}
		if publicPathRe.MatchString(en.path) {
			c.skipped = append(c.skipped, n.Label)
			continue
		}
		en.api = g.inEdges(n.Key, "exposes")
		c.walk(en)
		c.entries = append(c.entries, en)
	}
	sort.Slice(c.entries, func(i, j int) bool { return c.entries[i].route.Key < c.entries[j].route.Key })
	return c
}

func isInternetBoundary(n *Node) bool {
	k := strings.ToLower(n.Key + " " + n.Label)
	return strings.Contains(k, "internet") || strings.Contains(k, "public")
}

func label(n *Node) string {
	if n == nil {
		return "an element"
	}
	return n.Label
}

// walk collects the handler chain of an entry: calls edges BFS from the
// route, chainDepth deep, and the data edges of the chain.
func (c *ruleCtx) walk(en *entry) {
	g := c.g
	seen := map[string]bool{en.route.Key: true}
	en.parent = map[string]*Edge{}
	frontier := []string{en.route.Key}
	collect := func(key string) {
		en.writes = append(en.writes, g.outEdges(key, "writes")...)
		en.reads = append(en.reads, g.outEdges(key, "reads")...)
		en.pubs = append(en.pubs, g.outEdges(key, "publishes")...)
	}
	collect(en.route.Key)
	for d := 0; d < chainDepth && len(frontier) > 0; d++ {
		var next []string
		for _, k := range frontier {
			for _, e := range g.outEdges(k, "calls") {
				if seen[e.Target] {
					continue
				}
				t, ok := g.node(e.Target)
				if !ok || (t.Type != "function" && t.Type != "class" && t.Type != "route") {
					continue
				}
				seen[e.Target] = true
				en.chain = append(en.chain, t)
				en.edges = append(en.edges, e)
				en.parent[e.Target] = e
				collect(e.Target)
				next = append(next, e.Target)
			}
		}
		frontier = next
	}
}

// pathTo returns the calls edges from the route to the function key.
func (en *entry) pathTo(key string) []*Edge {
	var out []*Edge
	for k := key; k != en.route.Key; {
		e := en.parent[k]
		if e == nil {
			break
		}
		out = append([]*Edge{e}, out...)
		k = e.Source
	}
	return out
}

// names returns the names on the chain (route, functions, qualified names).
func (en *entry) names() []string {
	out := []string{en.route.Label}
	for _, n := range en.chain {
		out = append(out, n.Label, attrString(n, "qualified_name"))
	}
	for _, k := range []string{"middleware", "auth", "security"} {
		if v := attrString(en.route, k); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func anyMatch(re *regexp.Regexp, names []string) string {
	for _, s := range names {
		if s != "" && re.MatchString(s) {
			return s
		}
	}
	return ""
}

// authEvidence returns what shows authentication on the entry, or "".
func (c *ruleCtx) authEvidence(en *entry) string {
	if s := anyMatch(authRe, en.names()); s != "" {
		return s
	}
	// An authentication library imported by the route's file.
	if f := en.route.File; f != "" {
		if _, ok := c.g.node("file:" + f); ok {
			for _, e := range c.g.outEdges("file:"+f, "imports", "depends_on") {
				if t, ok := c.g.node(e.Target); ok && authRe.MatchString(t.Label) {
					return t.Label
				}
			}
		}
	}
	return ""
}

func (en *entry) mutates() bool {
	return slices.Contains(mutating, en.method) || len(en.writes) > 0
}

// entryEvidence is the base evidence of an entry point.
func (c *ruleCtx) entryEvidence(en *entry) Evidence {
	ev := Evidence{Nodes: []EvNode{evNode(en.route)}, Edges: []EvEdge{evEdge(en.boundary)}}
	for _, a := range en.api {
		if n, ok := c.g.node(a.Source); ok {
			ev.Nodes = append(ev.Nodes, evNode(n))
			ev.Edges = append(ev.Edges, evEdge(a))
		}
	}
	ev.Exposure = c.exposure()
	return ev
}

func (c *ruleCtx) exposure() *Exposure {
	x := *c.internet
	x.Reasons = slices.Clone(c.internet.Reasons)
	return &x
}

// addChain adds the chain edges (and nodes) leading to key.
func addChain(ev *Evidence, g *Graph, en *entry, key string) {
	for _, e := range en.pathTo(key) {
		ev.Edges = appendEdge(ev.Edges, evEdge(e))
		if n, ok := g.node(e.Target); ok {
			ev.Nodes = appendNode(ev.Nodes, evNode(n))
		}
	}
}

func appendEdge(list []EvEdge, e EvEdge) []EvEdge {
	for _, x := range list {
		if x.Key == e.Key {
			return list
		}
	}
	return append(list, e)
}

func appendNode(list []EvNode, n EvNode) []EvNode {
	for _, x := range list {
		if x.Key == n.Key {
			return list
		}
	}
	return append(list, n)
}

// scoring applies the documented severity and confidence adjustments.
type scoring struct {
	severity   string
	confidence float64
	reasons    []string
	creasons   []string
}

func score(r Rule) *scoring {
	return &scoring{severity: r.Severity, confidence: r.Confidence,
		reasons:  []string{"base " + r.Severity + " (rule " + r.ID + ")"},
		creasons: []string{fmt.Sprintf("base %.2f (rule %s%s)", r.Confidence, r.ID, map[bool]string{true: ", absence of evidence", false: ", evidence present"}[r.Absence])}}
}

func (s *scoring) up(n int, why string) {
	s.severity = raise(s.severity, n)
	if n > 0 {
		s.reasons = append(s.reasons, "raised: "+why)
	} else {
		s.reasons = append(s.reasons, "lowered: "+why)
	}
}

func (s *scoring) conf(d float64, why string) {
	s.confidence += d
	sign := "+"
	if d < 0 {
		sign = ""
	}
	s.creasons = append(s.creasons, fmt.Sprintf("%s%.2f %s", sign, d, why))
}

// internetUp raises severity when the repository is internet-facing.
func (c *ruleCtx) internetUp(s *scoring) {
	if c.internet.Level != "internet" {
		return
	}
	why := "internet-facing"
	if len(c.internet.Reasons) > 0 {
		why += " (" + c.internet.Reasons[0] + ")"
	}
	s.up(1, why)
	if c.observed {
		s.conf(0.1, "internet exposure observed at run time")
	}
}

func (s *scoring) apply(r Rule, g *Graph, t *Threat) {
	if g.Partial {
		s.conf(-0.1, "the snapshot is partial (some discovery engines failed)")
	}
	if r.Absence && slices.Index(Severities, s.severity) < slices.Index(Severities, "high") {
		s.severity = "high"
		s.reasons = append(s.reasons, "capped at high (absence of evidence)")
	}
	t.Severity = s.severity
	t.SeverityReason = strings.Join(s.reasons, "; ")
	t.Confidence = clamp(roundConf(s.confidence))
	t.ConfidenceReason = strings.Join(s.creasons, "; ")
}

func roundConf(f float64) float64 { return float64(int(f*100+0.5)) / 100 }

// findingsUp raises severity when evidence nodes carry open high or
// critical findings.
func findingsUp(s *scoring, g *Graph, ev Evidence) {
	hi := 0
	where := ""
	for _, en := range ev.Nodes {
		n, ok := g.node(en.Key)
		if !ok {
			continue
		}
		if k := n.Findings["critical"] + n.Findings["high"]; k > 0 {
			hi += k
			if where == "" {
				where = n.Label
			}
		}
	}
	if hi > 0 {
		s.up(1, fmt.Sprintf("%d open critical or high finding(s) on %s", hi, where))
	}
}

func ruleFor(id string) Rule {
	r, _ := RuleByID(id)
	return r
}

// --- rules ---------------------------------------------------------------------

func processRef(n *Node) ElementRef {
	return ElementRef{Kind: KindProcess, Key: n.Key, Name: n.Label, NodeType: n.Type}
}

func ruleUnauthenticatedEntry(c *ruleCtx) []Threat {
	r := ruleFor("TM-S-001")
	var out []Threat
	for _, en := range c.entries {
		if c.authEvidence(en) != "" {
			continue
		}
		ev := c.entryEvidence(en)
		for _, e := range en.edges {
			if len(ev.Edges) >= 12 {
				break
			}
			ev.Edges = appendEdge(ev.Edges, evEdge(e))
		}
		ev.Absent = []string{fmt.Sprintf("no function named like authentication on the handler chain (%d functions, %d calls deep)", len(en.chain), chainDepth)}
		if en.route.File != "" {
			ev.Absent = append(ev.Absent, "no authentication library imported by "+en.route.File)
		}
		s := score(r)
		c.internetUp(s)
		if len(en.writes) > 0 {
			s.up(1, "the handler chain writes a data store")
		}
		if !en.mutates() {
			s.up(-1, "read-only method "+en.method)
		}
		findingsUp(s, c.g, ev)
		t := Threat{Title: "Unauthenticated entry point " + en.route.Label,
			Description: fmt.Sprintf("%s accepts requests across the %s boundary and PATHOS found no authentication on its handler chain. A caller may act without proving who they are.", en.route.Label, boundaryName(c.g, en.boundary)),
			Elements:    []ElementRef{processRef(en.route)}, Evidence: ev}
		s.apply(r, c.g, &t)
		out = append(out, t)
	}
	return out
}

func boundaryName(g *Graph, e *Edge) string {
	if n, ok := g.node(e.Target); ok {
		return n.Label
	}
	return "trust"
}

func ruleMissingAuthorization(c *ruleCtx) []Threat {
	r := ruleFor("TM-E-001")
	var out []Threat
	for _, en := range c.entries {
		if !en.mutates() || anyMatch(authzRe, en.names()) != "" {
			continue
		}
		ev := c.entryEvidence(en)
		for _, w := range en.writes {
			addChain(&ev, c.g, en, w.Source)
			ev.Edges = appendEdge(ev.Edges, evEdge(w))
			if n, ok := c.g.node(w.Target); ok {
				ev.Nodes = appendNode(ev.Nodes, evNode(n))
			}
		}
		ev.Absent = []string{fmt.Sprintf("no function named like an authorization check on the handler chain (%d functions, %d calls deep)", len(en.chain), chainDepth)}
		s := score(r)
		c.internetUp(s)
		if c.authEvidence(en) == "" {
			s.up(1, "no authentication evidence either (TM-S-001)")
		}
		findingsUp(s, c.g, ev)
		why := "method " + en.method
		if len(en.writes) > 0 {
			why = fmt.Sprintf("writes %d data store(s)", len(en.writes))
		}
		t := Threat{Title: "No authorization check on " + en.route.Label,
			Description: fmt.Sprintf("%s changes state (%s) and PATHOS found no authorization check on its handler chain. A caller may perform actions or reach objects beyond their rights.", en.route.Label, why),
			Elements:    []ElementRef{processRef(en.route)}, Evidence: ev}
		s.apply(r, c.g, &t)
		out = append(out, t)
	}
	return out
}

var sqlTech = []string{"postgresql", "mysql", "sqlserver", "oracle", "sqlite", "sql", "mariadb"}

func ruleExposedWrite(c *ruleCtx) []Threat {
	r := ruleFor("TM-T-001")
	type hit struct {
		en *entry
		w  *Edge
	}
	byStore := map[string][]hit{}
	for _, en := range c.entries {
		for _, w := range en.writes {
			if n, ok := c.g.node(w.Target); ok && (n.Type == "datastore" || n.Type == "queue") {
				byStore[w.Target] = append(byStore[w.Target], hit{en, w})
			}
		}
	}
	keys := make([]string, 0, len(byStore))
	for k := range byStore {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Threat
	for _, k := range keys {
		store, _ := c.g.node(k)
		hits := byStore[k]
		ev := Evidence{Nodes: []EvNode{evNode(store)}, Exposure: c.exposure()}
		unauth := 0
		var routes []string
		for i, h := range hits {
			if c.authEvidence(h.en) == "" {
				unauth++
			}
			if !slices.Contains(routes, h.en.route.Label) {
				routes = append(routes, h.en.route.Label)
			}
			if i >= 5 {
				continue
			}
			ev.Nodes = appendNode(ev.Nodes, evNode(h.en.route))
			ev.Edges = appendEdge(ev.Edges, evEdge(h.en.boundary))
			addChain(&ev, c.g, h.en, h.w.Source)
			ev.Edges = appendEdge(ev.Edges, evEdge(h.w))
		}
		s := score(r)
		c.internetUp(s)
		if unauth > 0 {
			s.up(1, fmt.Sprintf("%d writing entry point(s) without authentication evidence", unauth))
		}
		findingsUp(s, c.g, ev)
		t := Threat{Title: "Tampering with " + store.Label + " from exposed entry points",
			Description: fmt.Sprintf("%s is written by code reachable from %d exposed entry point(s) (%s). Input that is not validated can change or corrupt stored data.",
				store.Label, len(routes), strings.Join(firstN(routes, 3), ", ")),
			Elements: []ElementRef{{Kind: KindDataStore, Key: store.Key, Name: store.Label, NodeType: store.Type}}, Evidence: ev}
		for _, rt := range firstN(routes, 5) {
			for _, h := range hits {
				if h.en.route.Label == rt {
					t.Elements = append(t.Elements, processRef(h.en.route))
					break
				}
			}
		}
		if slices.Contains(sqlTech, strings.ToLower(attrString(store, "technology"))) {
			t.Mappings = maps(rm("capec", "CAPEC-66"), rm("cwe", "CWE-89"), rm("d3fend", "D3-DQSA"))
		} else {
			t.Mappings = maps(rm("capec", "CAPEC-153"), rm("cwe", "CWE-20"), rm("d3fend", "D3-CV"))
		}
		s.apply(r, c.g, &t)
		out = append(out, t)
	}
	return out
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func ruleNoAudit(c *ruleCtx) []Threat {
	r := ruleFor("TM-R-001")
	var out []Threat
	for _, en := range c.entries {
		if len(en.writes) == 0 || anyMatch(auditRe, en.names()) != "" {
			continue
		}
		audited := false
		for _, w := range en.writes {
			if n, ok := c.g.node(w.Target); ok && auditRe.MatchString(n.Label) {
				audited = true
			}
		}
		if audited {
			continue
		}
		ev := c.entryEvidence(en)
		for _, w := range en.writes {
			addChain(&ev, c.g, en, w.Source)
			ev.Edges = appendEdge(ev.Edges, evEdge(w))
		}
		ev.Absent = []string{"no function named like an audit or event record on the handler chain", "no audit data store written"}
		s := score(r)
		c.internetUp(s)
		t := Threat{Title: "State change without audit trail: " + en.route.Label,
			Description: en.route.Label + " changes stored data and PATHOS found no audit record of who made the change. A user could deny the action, and investigations lack evidence.",
			Elements:    []ElementRef{processRef(en.route)}, Evidence: ev}
		s.apply(r, c.g, &t)
		out = append(out, t)
	}
	return out
}

var tlsSchemes = []string{"https", "wss", "tls", "grpcs", "ssl", "mtls"}

func ruleCleartextFlow(c *ruleCtx) []Threat {
	r := ruleFor("TM-I-001")
	g := c.g
	var out []Threat
	for i := range g.Nodes {
		x := &g.Nodes[i]
		if x.Type != "external_service" {
			continue
		}
		cross := g.outEdges(x.Key, "crosses_boundary")
		if len(cross) == 0 {
			continue
		}
		scheme := strings.ToLower(firstNonEmpty(attrString(x, "scheme"), attrString(x, "technology")))
		if slices.Contains(tlsSchemes, scheme) {
			continue
		}
		for _, f := range g.inEdges(x.Key, "calls", "depends_on") {
			src, ok := g.node(f.Source)
			if !ok {
				continue
			}
			ev := Evidence{Nodes: []EvNode{evNode(src), evNode(x)}, Edges: []EvEdge{evEdge(f), evEdge(cross[0])}}
			shown := scheme
			if shown == "" {
				shown = "none recorded"
			}
			ev.Absent = []string{"no TLS scheme for " + x.Label + " (scheme or technology: " + shown + ")"}
			s := score(r)
			findingsUp(s, g, ev)
			t := Threat{Title: "Cleartext connection to " + x.Label,
				Description: fmt.Sprintf("%s connects to %s across the %s boundary without evidence of TLS. Data and credentials on this flow can be read or changed in transit.", src.Label, x.Label, boundaryName(g, cross[0])),
				Elements: []ElementRef{{Kind: KindDataFlow, Key: f.Key, Name: src.Label + " → " + x.Label, Source: src.Key, Target: x.Key},
					{Kind: KindExternalEntity, Key: x.Key, Name: x.Label, NodeType: x.Type}},
				Evidence: ev}
			s.apply(r, g, &t)
			out = append(out, t)
		}
	}
	return out
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func ruleLiteralSecret(c *ruleCtx) []Threat {
	r := ruleFor("TM-I-003")
	g := c.g
	var out []Threat
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Type != "secret_ref" || !strings.Contains(strings.ToLower(attrString(n, "source")), "literal") {
			continue
		}
		ev := Evidence{Nodes: []EvNode{evNode(n)}}
		for _, e := range g.inEdges(n.Key) {
			ev.Edges = appendEdge(ev.Edges, evEdge(e))
			if src, ok := g.node(e.Source); ok {
				ev.Nodes = appendNode(ev.Nodes, evNode(src))
			}
		}
		loc := n.File
		if n.Line > 0 {
			loc = fmt.Sprintf("%s:%d", n.File, n.Line)
		}
		s := score(r)
		findingsUp(s, g, ev)
		t := Threat{Title: "Hard-coded credential " + n.Label,
			Description: fmt.Sprintf("The credential %s is defined as a literal in %s. Anyone with read access to the repository or its history can use it.", n.Label, firstNonEmpty(loc, "the code")),
			Elements:    []ElementRef{{Kind: KindDataStore, Key: n.Key, Name: n.Label, NodeType: n.Type}}, Evidence: ev}
		s.apply(r, g, &t)
		out = append(out, t)
	}
	return out
}

func ruleUnboundedQueue(c *ruleCtx) []Threat {
	r := ruleFor("TM-D-001")
	var out []Threat
	done := map[string]bool{}
	for _, en := range c.entries {
		if anyMatch(rateRe, en.names()) != "" {
			continue
		}
		for _, p := range en.pubs {
			q, ok := c.g.node(p.Target)
			if !ok || q.Type != "queue" || done[q.Key+"|"+en.route.Key] {
				continue
			}
			done[q.Key+"|"+en.route.Key] = true
			ev := c.entryEvidence(en)
			addChain(&ev, c.g, en, p.Source)
			ev.Edges = appendEdge(ev.Edges, evEdge(p))
			ev.Nodes = appendNode(ev.Nodes, evNode(q))
			ev.Absent = []string{"no function named like rate limiting on the handler chain"}
			s := score(r)
			c.internetUp(s)
			t := Threat{Title: "Unbounded publishing to " + q.Label + " from " + en.route.Label,
				Description: fmt.Sprintf("%s publishes to %s for every request and PATHOS found no rate limiting. A caller can flood the queue and starve its consumers.", en.route.Label, q.Label),
				// One threat per queue and route.
				Subject:  q.Key + "#" + en.route.Key,
				Elements: []ElementRef{{Kind: KindDataStore, Key: q.Key, Name: q.Label, NodeType: q.Type}, processRef(en.route)},
				Evidence: ev}
			s.apply(r, c.g, &t)
			out = append(out, t)
		}
	}
	return out
}

func ruleInternetIngress(c *ruleCtx) []Threat {
	r := ruleFor("TM-D-002")
	if len(c.filters) > 0 {
		return nil
	}
	g := c.g
	var out []Threat
	seen := map[string]bool{}
	for _, e := range c.inetEdge {
		src, ok := g.node(e.Source)
		if !ok || seen[src.Key] {
			continue
		}
		seen[src.Key] = true
		tb, _ := g.node(e.Target)
		ev := Evidence{Nodes: []EvNode{evNode(src), evNode(tb)}, Edges: []EvEdge{evEdge(e)}, Exposure: c.exposure()}
		ev.Absent = []string{"no WAF, network policy or rate-limit resource in the graph"}
		if e.Evidence == EvidenceObserved {
			ev.Runtime = append(ev.Runtime, src.Label+" was exposed to the internet at the last runtime sync")
		}
		s := score(r)
		if e.Evidence == EvidenceObserved {
			s.conf(0.1, "exposure observed at run time")
		}
		findingsUp(s, g, ev)
		t := Threat{Title: "Internet ingress through " + src.Label + " without filtering evidence",
			Description: fmt.Sprintf("%s is reachable from the internet (%s) and the graph shows no filtering or rate limiting in front of it. Floods and scans reach the service directly.", src.Label, firstNonEmpty(refText(e), "crosses the internet boundary")),
			Elements: []ElementRef{{Kind: KindTrustBoundary, Key: e.Key, Name: "Internet → " + src.Label, Source: src.Key, Target: tb.Key},
				{Kind: KindProcess, Key: src.Key, Name: src.Label, NodeType: src.Type}},
			Evidence: ev}
		s.apply(r, g, &t)
		out = append(out, t)
	}
	return out
}

func ruleRootContainer(c *ruleCtx) []Threat {
	r := ruleFor("TM-E-002")
	g := c.g
	var out []Threat
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Type != "container" || attrString(n, "base_image") == "" {
			continue
		}
		user := strings.TrimSpace(attrString(n, "user"))
		if user != "" && user != "root" && user != "0" && !strings.HasPrefix(user, "0:") && !strings.HasPrefix(user, "root:") {
			continue
		}
		ev := Evidence{Nodes: []EvNode{evNode(n)}}
		for _, e := range g.outEdges(n.Key, "deployed_as", "crosses_boundary") {
			ev.Edges = appendEdge(ev.Edges, evEdge(e))
		}
		for _, e := range g.inEdges(n.Key, "deployed_as") {
			ev.Edges = appendEdge(ev.Edges, evEdge(e))
		}
		if user == "" {
			ev.Absent = []string{"no USER instruction in " + firstNonEmpty(n.File, "the Dockerfile")}
		}
		s := score(r)
		if c.internet.Level == "internet" {
			c.internetUp(s)
		}
		findingsUp(s, g, ev)
		what := "has no USER instruction"
		if user != "" {
			what = "sets USER " + user
		}
		t := Threat{Title: "Container " + n.Label + " runs as root",
			Description: fmt.Sprintf("The image built from %s %s, so its process runs as root. A compromise of the process gives root inside the container and eases escape to the host.", firstNonEmpty(n.File, "the Dockerfile"), what),
			Elements:    []ElementRef{processRef(n)}, Evidence: ev}
		s.apply(r, g, &t)
		out = append(out, t)
	}
	return out
}

// --- DFD elements and coverage notes -------------------------------------------

// dfdElements lists the diagram: entry points and the functions on their
// paths to data stores, queues and external services, the data stores,
// external services, deployment elements that cross a boundary, trust
// boundaries, and the data flows between them.
func (c *ruleCtx) dfdElements() []ElementRef {
	g := c.g
	in := map[string]bool{}
	var out []ElementRef
	add := func(n *Node) {
		if n == nil || in[n.Key] {
			return
		}
		in[n.Key] = true
		kind := KindProcess
		switch n.Type {
		case "datastore", "queue", "secret_ref":
			kind = KindDataStore
		case "external_service":
			kind = KindExternalEntity
		case "trust_boundary":
			kind = KindTrustBoundary
		}
		out = append(out, ElementRef{Kind: kind, Key: n.Key, Name: n.Label, NodeType: n.Type})
	}
	for _, en := range c.entries {
		add(en.route)
		if tb, ok := g.node(en.boundary.Target); ok {
			add(tb)
		}
		for _, e := range append(append(append([]*Edge{}, en.writes...), en.reads...), en.pubs...) {
			for _, ce := range en.pathTo(e.Source) {
				n, _ := g.node(ce.Target)
				add(n)
			}
			n, _ := g.node(e.Target)
			add(n)
		}
		for _, f := range en.chain {
			for _, e := range g.outEdges(f.Key, "calls") {
				if t, ok := g.node(e.Target); ok && t.Type == "external_service" {
					for _, ce := range en.pathTo(f.Key) {
						n, _ := g.node(ce.Target)
						add(n)
					}
					add(t)
				}
			}
		}
	}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		switch n.Type {
		case "datastore", "queue", "external_service":
			add(n)
		case "secret_ref":
			if strings.Contains(strings.ToLower(attrString(n, "source")), "literal") {
				add(n)
			}
		case "container", "iac_resource":
			if len(g.outEdges(n.Key, "crosses_boundary")) > 0 || attrString(n, "base_image") != "" {
				add(n)
			}
		}
	}
	for _, e := range c.inetEdge {
		n, _ := g.node(e.Source)
		add(n)
		t, _ := g.node(e.Target)
		add(t)
	}
	// External services' boundaries.
	for i := range g.Nodes {
		if n := &g.Nodes[i]; n.Type == "external_service" {
			for _, e := range g.outEdges(n.Key, "crosses_boundary") {
				t, _ := g.node(e.Target)
				add(t)
			}
		}
	}
	if len(out) > maxElements {
		out = out[:maxElements]
		in = map[string]bool{}
		for _, e := range out {
			in[e.Key] = true
		}
	}
	flowTypes := []string{"calls", "reads", "writes", "publishes", "consumes", "depends_on", "exposes", "crosses_boundary", "deployed_as"}
	flows := 0
	for i := range g.Edges {
		e := &g.Edges[i]
		if e.Evidence == EvidenceAIInferred || !in[e.Source] || !in[e.Target] || !slices.Contains(flowTypes, e.Type) {
			continue
		}
		if flows >= maxElements {
			break
		}
		flows++
		s, _ := g.node(e.Source)
		t, _ := g.node(e.Target)
		out = append(out, ElementRef{Kind: KindDataFlow, Key: e.Key, Name: s.Label + " → " + t.Label, NodeType: e.Type, Source: e.Source, Target: e.Target,
			EdgeID: e.ID, Evidence: e.Evidence})
		c.used[e.Key] = true
	}
	return out
}

const maxElements = 600

func (c *ruleCtx) notes() []string {
	var out []string
	if len(c.entries) == 0 {
		out = append(out, "No entry point (route crossing an ingress boundary) was found: the entry-point rules (TM-S-001, TM-E-001, TM-R-001, TM-D-001, TM-T-001) produced nothing. Routes of frameworks CodeGraph does not recognise are not modelled.")
	}
	if len(c.skipped) > 0 {
		out = append(out, fmt.Sprintf("%d route(s) public by design were not checked for authentication: %s.", len(c.skipped), strings.Join(firstN(c.skipped, 5), ", ")))
	}
	if len(c.filters) > 0 {
		out = append(out, "Filtering or rate-limiting resources found ("+strings.Join(firstN(c.filters, 3), ", ")+"): TM-D-002 did not fire.")
	}
	if c.internet.Level != "internet" {
		out = append(out, "No internet exposure evidence (published port, Ingress, open security group, observed exposure or the inventory's public exposure): severities were not raised for exposure.")
	}
	if c.g.Partial {
		out = append(out, "The snapshot is partial: some discovery engines failed, so elements may be missing.")
	}
	out = append(out, "Data store connections: TLS settings of database and queue connections are not discovered yet, so no rule checks them.")
	return out
}

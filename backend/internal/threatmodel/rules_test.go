package threatmodel

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/codegraph"
	"pathos/internal/posture"
	"pathos/internal/threatmodel/frameworks"
)

// fixture builds small CodeGraph graphs for the rule tests (test data).
type fixture struct{ g *Graph }

func newFixture() *fixture { return &fixture{g: &Graph{SnapshotID: "snap", RepositoryID: "repo"}} }

func (f *fixture) node(key, typ string, attrs map[string]any) *fixture {
	label := key
	if i := strings.IndexByte(key, ':'); i >= 0 {
		label = key[i+1:]
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	n := Node{ID: key, Key: key, Type: typ, Label: label, Attrs: attrs}
	if s, ok := attrs["file"].(string); ok {
		n.File = s
	}
	f.g.Nodes = append(f.g.Nodes, n)
	return f
}

func (f *fixture) edge(src, typ, dst string) *fixture {
	return f.edgeEv(src, typ, dst, EvidenceVerified)
}

func (f *fixture) edgeEv(src, typ, dst, ev string) *fixture {
	key := codegraph.EdgeKey(src, typ, dst)
	kind := "file_line"
	if ev == EvidenceObserved {
		kind = "runtime"
	}
	f.g.Edges = append(f.g.Edges, Edge{ID: key, Key: key, Source: src, Target: dst, Type: typ, Evidence: ev,
		Refs: []Ref{{Kind: kind, Ref: "app.go:10", Detail: "fixture"}}})
	return f
}

// route adds a route crossing the HTTP ingress boundary, handled by handler.
func (f *fixture) route(method, path, handler string) *fixture {
	rk := "route:" + method + " " + path
	if !slices.ContainsFunc(f.g.Nodes, func(n Node) bool { return n.Key == "tb:http-ingress" }) {
		f.node("tb:http-ingress", "trust_boundary", nil)
	}
	f.node(rk, "route", map[string]any{"method": method, "path": path, "file": "app.go"})
	f.edge(rk, "crosses_boundary", "tb:http-ingress")
	if handler != "" {
		f.node("fn:"+handler, "function", map[string]any{"file": "app.go"})
		f.edge(rk, "calls", "fn:"+handler)
	}
	return f
}

func (f *fixture) run(t *testing.T) Result {
	t.Helper()
	res := Generate(f.g)
	for _, th := range res.Threats {
		checkComplete(t, th)
	}
	return res
}

// checkComplete: the M5 done-when on one threat.
func checkComplete(t *testing.T, th Threat) {
	t.Helper()
	switch {
	case th.RuleID == "" || th.RuleVersion == "" || th.Method == "":
		t.Errorf("%s: no method or rule", th.Title)
	case !slices.Contains(Severities, th.Severity) || th.SeverityReason == "":
		t.Errorf("%s: severity %q reason %q", th.Title, th.Severity, th.SeverityReason)
	case th.Confidence <= 0 || th.Confidence > 1 || th.ConfidenceReason == "":
		t.Errorf("%s: confidence %v reason %q", th.Title, th.Confidence, th.ConfidenceReason)
	case strings.TrimSpace(th.Mitigation) == "":
		t.Errorf("%s: no mitigation", th.Title)
	case len(th.Elements) == 0:
		t.Errorf("%s: no affected element", th.Title)
	case len(th.Evidence.Nodes) == 0 && len(th.Evidence.Edges) == 0 && th.Evidence.AttackPath == nil:
		t.Errorf("%s: no evidence", th.Title)
	case th.EvidenceType != EvidenceVerified && th.EvidenceType != EvidenceObserved:
		t.Errorf("%s: evidence type %q", th.Title, th.EvidenceType)
	case th.Fingerprint == "" || !slices.Contains(StrideCategories, th.Category):
		t.Errorf("%s: fingerprint %q category %q", th.Title, th.Fingerprint, th.Category)
	}
	for _, e := range th.Evidence.Edges {
		if len(e.Refs) == 0 {
			t.Errorf("%s: evidence edge %s without references", th.Title, e.Key)
		}
	}
	for _, m := range th.Mappings {
		if _, ok := frameworks.Lookup(m.Framework, m.ID); !ok {
			t.Errorf("%s: mapping %s %s is not in the bundled data", th.Title, m.Framework, m.ID)
		}
	}
}

func byRule(res Result, id string) []Threat {
	var out []Threat
	for _, t := range res.Threats {
		if t.RuleID == id {
			out = append(out, t)
		}
	}
	return out
}

func TestRuleS001UnauthenticatedEntry(t *testing.T) {
	f := newFixture().route("POST", "/api/orders", "createOrder").route("GET", "/healthz", "health")
	res := f.run(t)
	got := byRule(res, "TM-S-001")
	if len(got) != 1 || got[0].Elements[0].Key != "route:POST /api/orders" {
		t.Fatalf("TM-S-001: %+v", got)
	}
	if got[0].Severity != "medium" || got[0].Confidence != 0.55 || len(got[0].Evidence.Absent) == 0 {
		t.Errorf("severity %s confidence %v absent %v", got[0].Severity, got[0].Confidence, got[0].Evidence.Absent)
	}
	if !slices.ContainsFunc(res.Notes, func(n string) bool { return strings.Contains(n, "/healthz") }) {
		t.Errorf("public-by-design route not noted: %v", res.Notes)
	}
	// Authentication on the chain: no threat.
	f2 := newFixture().route("POST", "/api/orders", "createOrder")
	f2.node("fn:requireAuth", "function", nil).edge("fn:createOrder", "calls", "fn:requireAuth")
	if got := byRule(f2.run(t), "TM-S-001"); len(got) != 0 {
		t.Errorf("auth on the chain still fires: %+v", got)
	}
	// An authentication library imported by the route's file: no threat.
	f3 := newFixture().route("POST", "/api/orders", "createOrder")
	f3.node("file:app.go", "file", nil).node("comp:pkg:npm/passport", "component", nil).edge("file:app.go", "imports", "comp:pkg:npm/passport")
	if got := byRule(f3.run(t), "TM-S-001"); len(got) != 0 {
		t.Errorf("auth library import still fires: %+v", got)
	}
	// Read-only route: lowered; internet-facing: raised.
	f4 := newFixture().route("GET", "/api/orders", "listOrders")
	f4.node("tb:internet", "trust_boundary", nil).node("iac:k8s:Ingress/x", "iac_resource", nil).edge("iac:k8s:Ingress/x", "crosses_boundary", "tb:internet")
	got = byRule(f4.run(t), "TM-S-001")
	if len(got) != 1 || got[0].Severity != "medium" || !strings.Contains(got[0].SeverityReason, "internet-facing") || !strings.Contains(got[0].SeverityReason, "read-only") {
		t.Errorf("GET + internet: %+v", got)
	}
	// Observed internet exposure raises confidence.
	f5 := newFixture().route("POST", "/api/orders", "createOrder")
	f5.node("tb:internet", "trust_boundary", nil).node("runtime:c/ns/Deployment/api", "container", nil).
		edgeEv("runtime:c/ns/Deployment/api", "crosses_boundary", "tb:internet", EvidenceObserved)
	got = byRule(f5.run(t), "TM-S-001")
	if len(got) != 1 || got[0].Confidence != 0.65 || got[0].Severity != "high" {
		t.Errorf("observed exposure: %+v", got)
	}
}

func TestRuleE001MissingAuthorization(t *testing.T) {
	f := newFixture().route("DELETE", "/api/orders/{id}", "deleteOrder").route("GET", "/api/orders", "listOrders")
	got := byRule(f.run(t), "TM-E-001")
	if len(got) != 1 || got[0].Elements[0].Key != "route:DELETE /api/orders/{id}" || got[0].Category != ElevationOfPrivilege {
		t.Fatalf("TM-E-001: %+v", got)
	}
	// No authentication either: raised once.
	if got[0].Severity != "high" {
		t.Errorf("severity %s (%s)", got[0].Severity, got[0].SeverityReason)
	}
	f2 := newFixture().route("DELETE", "/api/orders/{id}", "deleteOrder")
	f2.node("fn:checkPermission", "function", nil).edge("fn:deleteOrder", "calls", "fn:checkPermission")
	if got := byRule(f2.run(t), "TM-E-001"); len(got) != 0 {
		t.Errorf("authorization check still fires: %+v", got)
	}
}

func TestRuleT001ExposedWrite(t *testing.T) {
	f := newFixture().route("POST", "/api/orders", "createOrder").route("PUT", "/api/cache", "putCache")
	f.node("ds:postgresql", "datastore", map[string]any{"technology": "postgresql"}).edge("fn:createOrder", "writes", "ds:postgresql")
	f.node("ds:redis", "datastore", map[string]any{"technology": "redis"}).edge("fn:putCache", "writes", "ds:redis")
	got := byRule(f.run(t), "TM-T-001")
	if len(got) != 2 {
		t.Fatalf("TM-T-001: %d threats", len(got))
	}
	pg, rd := got[0], got[1]
	if pg.Elements[0].Key != "ds:postgresql" {
		pg, rd = rd, pg
	}
	if !slices.Contains(pg.Mappings, Mapping{Framework: "capec", ID: "CAPEC-66", Source: "rule"}) || !slices.Contains(pg.Mappings, Mapping{Framework: "cwe", ID: "CWE-89", Source: "rule"}) {
		t.Errorf("SQL data store mappings: %+v", pg.Mappings)
	}
	if !slices.Contains(rd.Mappings, Mapping{Framework: "cwe", ID: "CWE-20", Source: "rule"}) {
		t.Errorf("redis mappings: %+v", rd.Mappings)
	}
	// The write edge is in the evidence with its reference.
	if !slices.ContainsFunc(pg.Evidence.Edges, func(e EvEdge) bool { return e.Type == "writes" && len(e.Refs) > 0 }) {
		t.Errorf("write edge missing from evidence: %+v", pg.Evidence.Edges)
	}
	if pg.Severity != "high" || !strings.Contains(pg.SeverityReason, "without authentication") {
		t.Errorf("severity %s: %s", pg.Severity, pg.SeverityReason)
	}
	// Not reachable from an entry point: nothing.
	f2 := newFixture()
	f2.node("fn:job", "function", nil).node("ds:postgresql", "datastore", nil).edge("fn:job", "writes", "ds:postgresql")
	if got := byRule(f2.run(t), "TM-T-001"); len(got) != 0 {
		t.Errorf("unexposed write fires: %+v", got)
	}
}

func TestRuleR001NoAudit(t *testing.T) {
	f := newFixture().route("POST", "/api/orders", "createOrder")
	f.node("ds:postgresql", "datastore", nil).edge("fn:createOrder", "writes", "ds:postgresql")
	if got := byRule(f.run(t), "TM-R-001"); len(got) != 1 || got[0].Category != Repudiation || got[0].Severity != "low" {
		t.Fatalf("TM-R-001: %+v", got)
	}
	f.node("fn:writeAuditRecord", "function", nil).edge("fn:createOrder", "calls", "fn:writeAuditRecord")
	if got := byRule(f.run(t), "TM-R-001"); len(got) != 0 {
		t.Errorf("audit function still fires: %+v", got)
	}
}

func TestRuleI001CleartextFlow(t *testing.T) {
	f := newFixture()
	f.node("fn:sync", "function", nil).node("tb:external-network", "trust_boundary", nil)
	f.node("ext:legacy.example.net", "external_service", map[string]any{"technology": "http"}).edge("fn:sync", "calls", "ext:legacy.example.net").
		edge("ext:legacy.example.net", "crosses_boundary", "tb:external-network")
	f.node("ext:api.example.net", "external_service", map[string]any{"technology": "https"}).edge("fn:sync", "calls", "ext:api.example.net").
		edge("ext:api.example.net", "crosses_boundary", "tb:external-network")
	got := byRule(f.run(t), "TM-I-001")
	if len(got) != 1 || got[0].Elements[0].Kind != KindDataFlow || got[0].Elements[0].Target != "ext:legacy.example.net" {
		t.Fatalf("TM-I-001: %+v", got)
	}
}

func TestRuleI003LiteralSecret(t *testing.T) {
	f := newFixture()
	f.node("secret:code:API_KEY", "secret_ref", map[string]any{"source": "literal in code", "file": "cfg.go"}).node("file:cfg.go", "file", nil).
		edge("file:cfg.go", "reads", "secret:code:API_KEY")
	f.node("secret:env:DB", "secret_ref", map[string]any{"source": "environment variable"})
	got := byRule(f.run(t), "TM-I-003")
	if len(got) != 1 || got[0].Severity != "high" || got[0].Elements[0].Key != "secret:code:API_KEY" {
		t.Fatalf("TM-I-003: %+v", got)
	}
}

func TestRuleD001UnboundedQueue(t *testing.T) {
	f := newFixture().route("POST", "/api/events", "ingest")
	f.node("queue:kafka:events", "queue", nil).edge("fn:ingest", "publishes", "queue:kafka:events")
	got := byRule(f.run(t), "TM-D-001")
	if len(got) != 1 || got[0].Category != DenialOfService || got[0].Elements[0].Key != "queue:kafka:events" {
		t.Fatalf("TM-D-001: %+v", got)
	}
	if !strings.HasSuffix(got[0].Fingerprint, "queue:kafka:events#route:POST /api/events") {
		t.Errorf("fingerprint %s", got[0].Fingerprint)
	}
	f.node("fn:rateLimiter", "function", nil).edge("fn:ingest", "calls", "fn:rateLimiter")
	if got := byRule(f.run(t), "TM-D-001"); len(got) != 0 {
		t.Errorf("rate limiting still fires: %+v", got)
	}
}

func TestRuleD002InternetIngress(t *testing.T) {
	f := newFixture()
	f.node("tb:internet", "trust_boundary", nil).node("iac:k8s:Ingress/shop", "iac_resource", nil).edge("iac:k8s:Ingress/shop", "crosses_boundary", "tb:internet")
	got := byRule(f.run(t), "TM-D-002")
	if len(got) != 1 || got[0].Elements[0].Kind != KindTrustBoundary {
		t.Fatalf("TM-D-002: %+v", got)
	}
	f.node("iac:tf:aws_wafv2_web_acl.main", "iac_resource", map[string]any{"kind": "aws_wafv2_web_acl"})
	res := f.run(t)
	if got := byRule(res, "TM-D-002"); len(got) != 0 {
		t.Errorf("WAF present still fires: %+v", got)
	}
}

func TestRuleE002RootContainer(t *testing.T) {
	f := newFixture()
	f.node("container:dockerfile:Dockerfile", "container", map[string]any{"base_image": "alpine:3", "file": "Dockerfile"})
	f.node("container:dockerfile:svc/Dockerfile", "container", map[string]any{"base_image": "alpine:3", "user": "65532:65532"})
	f.node("container:dockerfile:root/Dockerfile", "container", map[string]any{"base_image": "alpine:3", "user": "root"})
	got := byRule(f.run(t), "TM-E-002")
	if len(got) != 2 {
		t.Fatalf("TM-E-002: %+v", got)
	}
	// Containers without evidence edges still carry the node (file) as evidence.
	if got[0].Evidence.Nodes[0].Key == "" {
		t.Errorf("no node evidence")
	}
}

func TestAIInferredEdgesAreIgnored(t *testing.T) {
	f := newFixture().route("POST", "/api/orders", "createOrder")
	f.node("ds:postgresql", "datastore", nil).edgeEv("fn:createOrder", "writes", "ds:postgresql", EvidenceAIInferred)
	if got := byRule(f.run(t), "TM-T-001"); len(got) != 0 {
		t.Errorf("an AI-inferred edge produced a threat: %+v", got)
	}
}

func TestPartialSnapshotLowersConfidence(t *testing.T) {
	f := newFixture().route("POST", "/api/orders", "createOrder")
	f.g.Partial = true
	got := byRule(f.run(t), "TM-S-001")
	if len(got) != 1 || got[0].Confidence != 0.45 {
		t.Errorf("partial: %+v", got)
	}
}

// TestFixtureGraph runs the engine on the discovery output of the real
// worker-graph image on the fixture repository (test data).
func TestFixtureGraph(t *testing.T) {
	raw, err := os.ReadFile("../codegraph/testdata/fixture-graph.json")
	if err != nil {
		t.Fatal(err)
	}
	var d codegraph.Doc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	g := GraphFromDoc(&d, "repo-1")
	res := Generate(g)
	if len(res.Threats) == 0 {
		t.Fatal("no threats on the fixture repository")
	}
	for _, th := range res.Threats {
		checkComplete(t, th)
	}
	rules := map[string]int{}
	for _, th := range res.Threats {
		rules[th.RuleID]++
	}
	for _, want := range []string{"TM-S-001", "TM-E-001", "TM-T-001", "TM-D-002"} {
		if rules[want] == 0 {
			t.Errorf("rule %s did not fire on the fixture: %v", want, rules)
		}
	}
	// POST /api/products calls Store.audit: no repudiation threat for it.
	for _, th := range byRule(res, "TM-R-001") {
		if th.Elements[0].Key == "route:POST /api/products" {
			t.Errorf("TM-R-001 fired although the chain audits: %+v", th)
		}
	}
	// The distroless image sets USER 65532: no root threat.
	if n := rules["TM-E-002"]; n != 0 {
		t.Errorf("TM-E-002 fired %d times on a non-root image", n)
	}
	// Deterministic.
	again := Generate(GraphFromDoc(&d, "repo-1"))
	if !reflect.DeepEqual(res.Threats, again.Threats) {
		t.Error("two generations of the same graph differ")
	}
	if len(res.Elements) == 0 || !slices.ContainsFunc(res.Elements, func(e ElementRef) bool { return e.Kind == KindDataFlow }) {
		t.Errorf("diagram elements: %d", len(res.Elements))
	}
	t.Logf("fixture: %d threats %v, %d elements", len(res.Threats), rules, len(res.Elements))
}

func TestFromAttackPath(t *testing.T) {
	fid := uuid.Must(uuid.NewV7())
	a := posture.AttackPath{FindingID: fid, Risk: 80, Severity: "critical", KEV: true, Entry: "runtime_exposure", Title: "SQL injection in search",
		Category: "sast", CWE: []string{"CWE-89"}, CVE: "", RepositoryID: uuid.Must(uuid.NewV7()), FilePath: "api/search.go", Line: 12,
		Steps: []posture.Step{{Type: "internet", Label: "Internet"}}, Reasons: []string{"observed in cluster c1"}}
	th := FromAttackPath(a, "fn:search", "search", "function")
	checkComplete(t, th)
	if th.Category != Tampering || th.Severity != "critical" || th.Confidence != 0.95 || th.EvidenceType != EvidenceObserved || th.Method != MethodAttackPath {
		t.Errorf("attack path threat: %+v", th)
	}
	if !slices.Contains(th.Mappings, Mapping{Framework: "cwe", ID: "CWE-89", Source: "finding"}) || len(th.FindingIDs) != 1 {
		t.Errorf("mappings %+v findings %v", th.Mappings, th.FindingIDs)
	}
	a.Category, a.CWE, a.KEV, a.Entry, a.CVE = "secrets", nil, false, "exposed_repository", ""
	th = FromAttackPath(a, "", "", "")
	if th.Category != InformationDisclosure || th.EvidenceType != EvidenceVerified || th.Elements[0].Key != "repository" {
		t.Errorf("secret path: %+v", th)
	}
	if NormalizeCWE("cwe-79: XSS") != "CWE-79" || NormalizeCWE("89") != "CWE-89" || NormalizeCWE("x") != "" {
		t.Error("NormalizeCWE")
	}
}

func TestRuleCatalogue(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range append(slices.Clone(Rules), AttackPathRule) {
		if seen[r.ID] || r.Version == "" || r.Logic == "" || r.Mitigation == "" || r.Title == "" {
			t.Errorf("rule %s incomplete or duplicate", r.ID)
		}
		seen[r.ID] = true
		for _, m := range r.Mappings {
			if _, ok := frameworks.Lookup(m.Framework, m.ID); !ok {
				t.Errorf("rule %s maps to %s %s, not in the bundled data", r.ID, m.Framework, m.ID)
			}
		}
	}
	// Every STRIDE category has at least one rule.
	for _, c := range StrideCategories {
		if !slices.ContainsFunc(Rules, func(r Rule) bool { return r.Category == c }) {
			t.Errorf("no rule for %s", c)
		}
	}
}

func TestCriticalNeedsAFinding(t *testing.T) {
	f := newFixture().route("POST", "/api/orders", "createOrder")
	f.node("tb:internet", "trust_boundary", nil).node("iac:k8s:Ingress/x", "iac_resource", nil).edge("iac:k8s:Ingress/x", "crosses_boundary", "tb:internet")
	f.node("ds:postgresql", "datastore", map[string]any{"technology": "postgresql"}).edge("fn:createOrder", "writes", "ds:postgresql")
	got := byRule(f.run(t), "TM-T-001")
	if len(got) != 1 || got[0].Severity != "high" || !strings.Contains(got[0].SeverityReason, "capped at high (critical needs") {
		t.Fatalf("without a finding: %+v", got)
	}
	for i := range f.g.Nodes {
		if f.g.Nodes[i].Key == "fn:createOrder" {
			f.g.Nodes[i].Findings = map[string]int{"high": 1}
		}
	}
	got = byRule(f.run(t), "TM-T-001")
	if len(got) != 1 || got[0].Severity != "critical" || !strings.Contains(got[0].SeverityReason, "open critical or high finding") {
		t.Fatalf("with a finding: %+v", got)
	}
}

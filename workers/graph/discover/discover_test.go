package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture-repo test uses real tool outputs recorded on the fixture
// with the worker-core image (Opengrep 2.0.0 with workers/graph/rules,
// Syft): testdata/fixture-repo.opengrep.json and
// testdata/fixture-repo.cdx.json, regenerated with
//
//	docker run --rm --network none -w /src -v $PWD/testdata/fixture-repo:/src:ro \
//	  -v $PWD/../rules:/rules:ro --entrypoint opengrep <worker-core image> \
//	  scan --json --quiet --config /rules .
//	docker run --rm --network none -v $PWD/testdata/fixture-repo:/src:ro \
//	  --entrypoint syft <worker-core image> scan dir:/src -o cyclonedx-json -q

func discoverFixture(t *testing.T, dir string, recorded bool) *Output {
	t.Helper()
	o := DefaultOptions()
	if recorded {
		var err error
		if o.opengrepJSON, err = os.ReadFile(dir + ".opengrep.json"); err != nil {
			t.Fatal(err)
		}
		if o.sbomJSON, err = os.ReadFile(dir + ".cdx.json"); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Discover(context.Background(), dir, o)
	if err != nil {
		t.Fatal(err)
	}
	checkContract(t, res)
	return res
}

// checkContract asserts the invariants of pathos.codegraph/v1.
func checkContract(t *testing.T, res *Output) {
	t.Helper()
	if res.Schema != Schema {
		t.Fatalf("schema %q", res.Schema)
	}
	keys := map[string]*Node{}
	repos := 0
	for _, n := range res.Nodes {
		if _, dup := keys[n.Key]; dup {
			t.Errorf("duplicate node key %s", n.Key)
		}
		keys[n.Key] = n
		if n.Type == "repository" {
			repos++
		}
		if layer, ok := nodeTypes[n.Type]; !ok || layer != n.Layer {
			t.Errorf("node %s: type %q layer %q", n.Key, n.Type, n.Layer)
		}
		if len(n.Key) > maxKey || n.Label == "" {
			t.Errorf("node %s: bad key or empty label", n.Key)
		}
		b, _ := json.Marshal(n.Attrs)
		if len(b) > 4096 {
			t.Errorf("node %s: attrs too large (%d bytes)", n.Key, len(b))
		}
	}
	if repos != 1 || keys["repository"] == nil {
		t.Fatalf("want exactly one repository node keyed \"repository\"")
	}
	for _, n := range res.Nodes {
		if n.Parent != "" && keys[n.Parent] == nil {
			t.Errorf("node %s: missing parent %s", n.Key, n.Parent)
		}
	}
	seen := map[string]bool{}
	for _, e := range res.Edges {
		id := e.Source + "|" + e.Type + "|" + e.Target
		if seen[id] {
			t.Errorf("duplicate edge %s", id)
		}
		seen[id] = true
		if keys[e.Source] == nil || keys[e.Target] == nil {
			t.Errorf("edge %s: unknown endpoint", id)
		}
		if !edgeTypes[e.Type] || e.Evidence != "verified" {
			t.Errorf("edge %s: type %q evidence %q", id, e.Type, e.Evidence)
		}
		if len(e.Refs) == 0 || len(e.Refs) > maxRefsByEdge {
			t.Errorf("edge %s: %d evidence refs (every edge needs 1..%d)", id, len(e.Refs), maxRefsByEdge)
		}
		for _, r := range e.Refs {
			if !refKinds[r.Kind] || r.Ref == "" {
				t.Errorf("edge %s: bad evidence %+v", id, r)
			}
		}
	}
	if res.Stats.NodeCount != len(res.Nodes) || res.Stats.EdgeCount != len(res.Edges) {
		t.Errorf("stats counts do not match")
	}
}

type graphIndex struct {
	nodes map[string]*Node
	edges map[string]*Edge
}

func index(res *Output) graphIndex {
	gi := graphIndex{nodes: map[string]*Node{}, edges: map[string]*Edge{}}
	for _, n := range res.Nodes {
		gi.nodes[n.Key] = n
	}
	for _, e := range res.Edges {
		gi.edges[e.Source+"|"+e.Type+"|"+e.Target] = e
	}
	return gi
}

func (gi graphIndex) wantEdges(t *testing.T, want ...string) {
	t.Helper()
	for _, w := range want {
		if gi.edges[w] == nil {
			t.Errorf("missing edge %s", w)
		}
	}
}

func (gi graphIndex) noEdges(t *testing.T, unwanted ...string) {
	t.Helper()
	for _, w := range unwanted {
		if gi.edges[w] != nil {
			t.Errorf("unexpected edge %s", w)
		}
	}
}

func (gi graphIndex) wantNodes(t *testing.T, typ string, keys ...string) {
	t.Helper()
	for _, k := range keys {
		n := gi.nodes[k]
		if n == nil {
			t.Errorf("missing node %s", k)
		} else if n.Type != typ {
			t.Errorf("node %s: type %s, want %s", k, n.Type, typ)
		}
	}
}

func TestFixtureRepo(t *testing.T) {
	res := discoverFixture(t, "testdata/fixture-repo", true)
	gi := index(res)
	gi.wantNodes(t, "route", "route:GET /api/products/{id}", "route:POST /api/products", "route:GET /healthz",
		"route:GET /api/prices/{product_id}", "route:GET /store/products")
	gi.wantNodes(t, "api_operation", "api:GET /api/products/{id}", "api:POST /api/products", "api:GET /api/prices/{product_id}")
	gi.wantNodes(t, "datastore", "ds:postgresql", "ds:redis")
	gi.wantNodes(t, "external_service", "ext:search.partner-api.net", "ext:cdn.partner-api.net")
	gi.wantNodes(t, "trust_boundary", "tb:internet", "tb:http-ingress", "tb:external-network")
	gi.wantNodes(t, "component", "comp:pkg:golang/github.com/go-chi/chi/v5", "comp:pkg:pypi/redis", "comp:pkg:npm/express")
	gi.wantNodes(t, "container", "container:dockerfile:Dockerfile", "container:compose:docker-compose.yml#api")
	gi.wantNodes(t, "iac_resource", "iac:k8s:Deployment/shop/shop-api", "iac:tf:aws_db_instance.shop")
	gi.wantNodes(t, "secret_ref", "secret:env:DATABASE_URL", "secret:k8s:shop-db", "secret:env:REDIS_PASSWORD")
	if fw := gi.nodes["route:GET /api/products/{id}"].Attrs["framework"]; fw != "chi" {
		t.Errorf("framework %v, want chi (the gin/echo rule must be dropped: the file does not import them)", fw)
	}
	gi.wantEdges(t,
		// routes, handlers, API operations, boundaries
		"route:GET /api/products/{id}|calls|fn:go:internal/httpapi.(*Handler).getProduct",
		"route:GET /api/prices/{product_id}|calls|fn:py:worker/tasks.py#get_price",
		"api:GET /api/products/{id}|exposes|route:GET /api/products/{id}",
		"route:GET /api/products/{id}|crosses_boundary|tb:http-ingress",
		// calls: Go (package, imported package, receiver field, local variable), Python, JavaScript
		"fn:go:cmd/api.main|calls|fn:go:internal/store.Open",
		"fn:go:cmd/api.main|calls|fn:go:internal/httpapi.(*Handler).Routes",
		"fn:go:internal/httpapi.(*Handler).getProduct|calls|fn:go:internal/store.(*Store).Product",
		"fn:go:internal/store.(*Store).AddProduct|calls|fn:go:internal/store.(*Store).audit",
		"fn:py:worker/tasks.py#get_price|calls|fn:py:worker/pricing.py#price_for",
		"fn:py:worker/tasks.py#get_price|calls|fn:py:worker/pricing.py#Discounts.apply",
		"fn:py:worker/pricing.py#Discounts.apply|calls|fn:py:worker/pricing.py#Discounts.round",
		"fn:js:web/src/catalog.js#listProducts|calls|fn:js:web/src/catalog.js#normalise",
		// imports
		"file:cmd/api/main.go|imports|mod:internal/store",
		"file:internal/httpapi/httpapi.go|imports|comp:pkg:golang/github.com/go-chi/chi/v5",
		"file:worker/tasks.py|imports|file:worker/pricing.py",
		"file:web/src/server.js|imports|file:web/src/catalog.js",
		// data access (code sites only)
		"fn:go:internal/store.(*Store).Product|reads|ds:postgresql",
		"fn:go:internal/store.(*Store).AddProduct|writes|ds:postgresql",
		"fn:py:worker/tasks.py#get_price|reads|ds:redis",
		"fn:py:worker/tasks.py#get_price|writes|ds:redis",
		"fn:go:internal/httpapi.notifySearch|calls|ext:search.partner-api.net",
		// deployment
		"mod:.|deployed_as|container:dockerfile:Dockerfile",
		"container:dockerfile:Dockerfile|deployed_as|container:compose:docker-compose.yml#api",
		"ds:postgresql|deployed_as|container:compose:docker-compose.yml#postgres",
		"container:compose:docker-compose.yml#api|depends_on|container:compose:docker-compose.yml#postgres",
		"container:compose:docker-compose.yml#api|crosses_boundary|tb:internet",
		"container:compose:docker-compose.yml#api|deployed_as|iac:k8s:Deployment/shop/shop-api",
		"iac:k8s:Service/shop/shop-api|exposes|iac:k8s:Deployment/shop/shop-api",
		"iac:k8s:Ingress/shop/shop|crosses_boundary|tb:internet",
		"ds:postgresql|deployed_as|iac:tf:aws_db_instance.shop",
		"iac:tf:aws_security_group.web|crosses_boundary|tb:internet",
		// secret references and SBOM
		"fn:go:cmd/api.main|reads|secret:env:DATABASE_URL",
		"iac:k8s:Deployment/shop/shop-api|reads|secret:k8s:shop-db",
		"repository|depends_on|comp:pkg:pypi/fastapi",
	)
	gi.noEdges(t,
		// redis is published on the loopback address only
		"container:compose:docker-compose.yml#redis|crosses_boundary|tb:internet",
		// no edge to a datastore without a code or config site
		"fn:go:internal/httpapi.(*Handler).getProduct|reads|ds:postgresql",
	)
	// Evidence of a call points at the call site.
	if e := gi.edges["fn:go:internal/store.(*Store).Product|reads|ds:postgresql"]; e == nil || e.Refs[0].Ref != "internal/store/store.go:32" {
		t.Errorf("reads evidence: %+v", e)
	}
	if e := gi.edges["repository|depends_on|comp:pkg:pypi/fastapi"]; e == nil || e.Refs[0].Kind != "sbom" {
		t.Errorf("SBOM evidence: %+v", e)
	}
}

// No secret value from the fixture may appear in the output.
func TestNoSecretValues(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app/settings.py", "import os\nAPI_TOKEN = \"Zx9-kq2LmP4vT7wQ1sR8\"\nDB = os.environ[\"DB_PASSWORD\"]\n")
	write(t, dir, "docker-compose.yml", "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: hunter2-Secret-Value\n")
	res, err := Discover(context.Background(), dir, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	checkContract(t, res)
	var buf bytes.Buffer
	if err := res.Write(&buf); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"Zx9-kq2LmP4vT7wQ1sR8", "hunter2-Secret-Value"} {
		if strings.Contains(buf.String(), v) {
			t.Errorf("secret value %q in the output", v)
		}
	}
	gi := index(res)
	gi.wantNodes(t, "secret_ref", "secret:literal:app/settings.py#API_TOKEN", "secret:env:DB_PASSWORD", "secret:env:POSTGRES_PASSWORD")
}

func TestDeterministic(t *testing.T) {
	a := discoverFixture(t, "testdata/fixture-repo", true)
	b := discoverFixture(t, "testdata/fixture-repo", true)
	a.Stats.DurationMS, b.Stats.DurationMS = 0, 0
	var x, y bytes.Buffer
	_ = a.Write(&x)
	_ = b.Write(&y)
	if !bytes.Equal(x.Bytes(), y.Bytes()) {
		t.Fatal("two runs on the same tree differ")
	}
}

func TestLimits(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "big.js", strings.Repeat("// x\n", 300000))
	write(t, dir, "node_modules/x/index.js", "function f() {}\n")
	write(t, dir, "a.py", "def a():\n    b()\n\ndef b():\n    pass\n")
	write(t, dir, "c.py", "def c():\n    pass\n")
	o := DefaultOptions()
	o.MaxNodes = 6
	res, err := Discover(context.Background(), dir, o)
	if err != nil {
		t.Fatal(err)
	}
	checkContract(t, res)
	if !res.Stats.Truncated {
		t.Error("node limit reached but not reported as truncated")
	}
	gi := index(res)
	for k := range gi.nodes {
		if strings.Contains(k, "node_modules") {
			t.Errorf("node_modules was read: %s", k)
		}
	}
	found := false
	for _, s := range res.Stats.Skipped {
		if s.Path == "big.js" {
			found = true
		}
	}
	if !found {
		t.Errorf("big.js not reported as skipped: %+v", res.Stats.Skipped)
	}
}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

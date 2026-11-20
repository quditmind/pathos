package main

import (
	"slices"
	"strings"
	"testing"
)

func TestGraphInvariants(t *testing.T) {
	g := newGraph(10, 10)
	if g.Validate() == nil {
		t.Error("a graph without a repository node must not validate")
	}
	g.AddNode("repository", "repository", "r", "", nil)
	g.AddNode("file:a.go", "file", "a.go", "repository", nil)
	g.AddNode("fn:a", "function", "a", "file:a.go", nil)
	if g.AddNode("x", "application", "x", "", nil) {
		t.Error("application nodes are added by the API, not discovery")
	}
	if g.AddEdge("file:a.go", "defines", "fn:a", Ref{}) {
		t.Error("an edge without evidence was accepted")
	}
	if g.AddEdge("file:a.go", "owns", "fn:a", fileLine("a.go", 1, "")) {
		t.Error("owns edges are added by the API, not discovery")
	}
	if g.AddEdge("fn:a", "calls", "fn:missing", fileLine("a.go", 1, "")) {
		t.Error("edge to an unknown node accepted")
	}
	for i := 1; i <= 8; i++ {
		g.AddEdge("file:a.go", "defines", "fn:a", fileLine("a.go", i, "x"))
	}
	if len(g.edges) != 1 || len(g.edges["file:a.go\x00defines\x00fn:a"].Refs) != maxRefsByEdge {
		t.Errorf("duplicate edges must merge, keeping %d refs", maxRefsByEdge)
	}
	if err := g.Validate(); err != nil {
		t.Error(err)
	}
	for i := 0; i < 20; i++ {
		g.AddNode("n"+strings.Repeat("x", i), "module", "m", "repository", nil)
	}
	if !g.truncated || len(g.nodes) != 10 {
		t.Errorf("node limit: %d nodes, truncated %v", len(g.nodes), g.truncated)
	}
}

func TestDBOperation(t *testing.T) {
	cases := map[[2]string][]string{
		{"", "SELECT * FROM t"}:           {"reads"},
		{"", " with x as (select 1) ..."}: {"reads"},
		{"", "INSERT INTO t VALUES (1)"}:  {"writes"},
		{"", "findMany"}:                  {"reads"},
		{"", "save"}:                      {"writes"},
		{"", "SaveChangesAsync"}:          {"writes"},
		{"", "hgetall"}:                   {"reads"},
		{"read", "anything"}:              {"reads"},
		{"write", "SELECT"}:               {"writes"},
		{"readwrite", "JpaRepository"}:    {"reads", "writes"},
	}
	for in, want := range cases {
		if got := dbOperation(in[0], in[1]); !slices.Equal(got, want) {
			t.Errorf("dbOperation(%q, %q) = %v, want %v", in[0], in[1], got, want)
		}
	}
}

func TestRouteHelpers(t *testing.T) {
	for tok, want := range map[string]string{"GetMapping": "GET", "MapPost": "POST", "HttpDelete": "DELETE", "get": "GET",
		"RequestMapping": "ANY", "route": "ANY", "All": "ANY", "PATCH": "PATCH"} {
		if got := routeMethod(tok, ""); got != want {
			t.Errorf("routeMethod(%q) = %q, want %q", tok, got, want)
		}
	}
	same := [][2]string{{"/users/{id}", "/users/:id"}, {"/a/<int:year>/", "/a/{year}"}, {"/x/{id:int}", "/x/{id}"}}
	for _, p := range same {
		if pathTemplate(p[0]) != pathTemplate(p[1]) {
			t.Errorf("%q and %q should match", p[0], p[1])
		}
	}
	if normPath("articles/") != "/articles/" || normPath("") != "/" {
		t.Error("normPath")
	}
}

func TestURLHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.stripe.com/v1/charges":   "api.stripe.com",
		"https://api.tax.example.net/v2":      "api.tax.example.net",
		"https://user:pw@hooks.example.net/x": "hooks.example.net",
		"http://localhost:8080/x":             "",
		"https://${HOST}/x":                   "",
		"/relative":                           "",
	} {
		if got := urlHost(in); got != want {
			t.Errorf("urlHost(%q) = %q, want %q", in, got, want)
		}
	}
	if !isLocalHost("db.local") || !isLocalHost("api.tax.example.net") || isLocalHost("api.stripe.com") {
		t.Error("isLocalHost")
	}
}

func TestCredentialNames(t *testing.T) {
	for _, n := range []string{"DB_PASSWORD", "API_KEY", "GITHUB_TOKEN", "DATABASE_URL", "client_secret", "JWT_SIGNING_KEY"} {
		if !credentialName(n) {
			t.Errorf("%s should be a credential reference", n)
		}
	}
	for _, n := range []string{"PORT", "LOG_LEVEL", "TOKEN_URL", "PASSWORD_FILE", "API_KEY_ID", "KEYCLOAK_URL"} {
		if credentialName(n) {
			t.Errorf("%s should not be a credential reference", n)
		}
	}
	if credentialLike("api_token") || credentialLike("secrets") || !credentialLike("Zx9-kq2LmP4vT7wQ1sR8") {
		t.Error("credentialLike")
	}
}

func TestPurlBase(t *testing.T) {
	for in, want := range map[string][2]string{
		"pkg:golang/github.com/google/uuid@v1.6.0": {"pkg:golang/github.com/google/uuid", "golang"},
		"pkg:npm/%40types/node@20.1.0":             {"pkg:npm/%40types/node", "npm"},
		"pkg:maven/org.x/art@1.0?type=jar":         {"pkg:maven/org.x/art", "maven"},
		"pkg:pypi/requests@2.32.0":                 {"pkg:pypi/requests", "pypi"},
		"not-a-purl":                               {"", ""},
	} {
		b, e := purlBase(in)
		if b != want[0] || e != want[1] {
			t.Errorf("purlBase(%q) = %q %q", in, b, e)
		}
	}
	if goModuleGuess("github.com/a/b/c/d") != "github.com/a/b" || goModuleGuess("gopkg.in/yaml.v3/x") != "gopkg.in/yaml.v3" {
		t.Error("goModuleGuess")
	}
}

func TestImageService(t *testing.T) {
	for img, want := range map[string]string{"postgres:16": "postgresql", "docker.io/library/redis:7": "redis",
		"bitnami/kafka:3.7": "kafka", "valkey/valkey:8": "redis", "example/shop-api:1.0": ""} {
		if _, tech := imageService(img); tech != want {
			t.Errorf("imageService(%q) = %q, want %q", img, tech, want)
		}
	}
}

func TestURLScheme(t *testing.T) {
	for in, want := range map[string]string{"https://api.example.net/x": "https", "HTTP://legacy.example.net": "http",
		"wss://ws.example.net": "wss", "ftp://x.example.net": ""} {
		if got := urlScheme(in); got != want {
			t.Errorf("urlScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

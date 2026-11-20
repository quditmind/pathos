package worker

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAPIOperationURLs(t *testing.T) {
	oas3 := `openapi: 3.0.3
servers: [{url: "http://api.example:8000/v1/"}]
paths:
  /users: {get: {}}
  /users/{id}/orders/{order}: {get: {}}
  relative: {get: {}}
`
	got := apiOperationURLs("http://api.example:8000", []byte(oas3))
	want := []string{"http://api.example:8000", "http://api.example:8000/v1", "http://api.example:8000/v1/users", "http://api.example:8000/v1/users/1/orders/1"}
	if !slices.Equal(got, want) {
		t.Errorf("openapi 3: got %v, want %v", got, want)
	}

	swagger := `{"swagger": "2.0", "host": "api.example", "basePath": "/api", "schemes": ["http"], "paths": {"/pets": {}}}`
	got = apiOperationURLs("http://api.example", []byte(swagger))
	want = []string{"http://api.example", "http://api.example/api", "http://api.example/api/pets"}
	if !slices.Equal(got, want) {
		t.Errorf("swagger 2: got %v, want %v", got, want)
	}

	// An unreadable document still scans the base URL; other schemes are dropped.
	if got := apiOperationURLs("https://api.example", []byte("{not yaml")); !slices.Equal(got, []string{"https://api.example"}) {
		t.Errorf("bad document: %v", got)
	}
	if got := apiOperationURLs("https://api.example", []byte(`{"openapi":"3.0.0","servers":[{"url":"file:///etc"}],"paths":{"/x":{}}}`)); slices.ContainsFunc(got, func(u string) bool { return strings.HasPrefix(u, "file:") }) {
		t.Errorf("non-http URLs must be dropped: %v", got)
	}

	// The list is bounded.
	var b strings.Builder
	b.WriteString("openapi: 3.0.0\nservers: [{url: 'https://api.example'}]\npaths:\n")
	for i := range 2 * maxAPIURLs {
		b.WriteString("  /p" + strings.Repeat("x", i%7) + "/" + string(rune('a'+i%26)) + "/" + strings.Repeat("y", i/26) + ": {}\n")
	}
	if got := apiOperationURLs("https://api.example", []byte(b.String())); len(got) != maxAPIURLs {
		t.Errorf("list size %d, want %d", len(got), maxAPIURLs)
	}

	dir := t.TempDir()
	spec, list := filepath.Join(dir, "openapi.yaml"), filepath.Join(dir, "api-urls.txt")
	_ = os.WriteFile(spec, []byte(oas3), 0o600)
	if err := writeAPIURLList("http://api.example:8000", spec, list); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(list); !strings.Contains(string(b), "http://api.example:8000/v1/users\n") {
		t.Errorf("list file: %q", b)
	}
}

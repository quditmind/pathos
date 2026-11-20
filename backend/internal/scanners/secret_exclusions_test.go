package scanners

import "testing"

func TestSecretExcluded(t *testing.T) {
	dropped := []string{
		"node_modules/lodash/index.js", "web/node_modules/x/y.js", "vendor/github.com/a/b/c.go", "third_party/x.c",
		"internal/testdata/key.pem", "test/fixtures/creds.json", "src/__snapshots__/a.snap", "a/b/c.snap",
		"package-lock.json", "ui/yarn.lock", "go.sum", "sub/Cargo.lock", "poetry.lock", "pnpm-lock.yaml",
		"static/app.min.js", "dist/site.min.css", "dist/app.js.map", "lib/jquery-min.js",
	}
	for _, p := range dropped {
		if !SecretExcluded(p, true, nil) {
			t.Errorf("%s should be excluded by default", p)
		}
		if SecretExcluded(p, false, nil) {
			t.Errorf("%s: defaults are off", p)
		}
	}
	kept := []string{"config/settings.py", ".env", "src/app.js", "deploy/values.yaml", "minimal.js", "testing/creds.go", ""}
	for _, p := range kept {
		if SecretExcluded(p, true, nil) {
			t.Errorf("%s must not be excluded", p)
		}
	}
	if !SecretExcluded("docs/examples/token.md", true, []string{"docs/**"}) || SecretExcluded("src/x.go", true, []string{"docs/**"}) {
		t.Error("profile secret exclusions")
	}
}

func TestTalismanNotRecommended(t *testing.T) {
	if !NotRecommended["talisman"] {
		t.Fatal("Talisman must never be in a default or recommended profile")
	}
	for _, sc := range Catalog {
		if sc.Key == "talisman" && sc.DefaultEnabled {
			t.Error("Talisman is default-enabled in the catalog")
		}
	}
}

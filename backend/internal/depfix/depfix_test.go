package depfix

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func changes(t *testing.T, r Result) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, c := range r.Changes {
		out[c.Path] = string(c.Content)
	}
	return out
}

func TestPyPI(t *testing.T) {
	root := tree(t, map[string]string{
		"requirements.txt":                "# deps\nDjango==4.2.1  # web\nrequests>=2.0\nflask\n",
		"svc/requirements-dev.txt":        "django[argon2]~=4.2 ; python_version >= \"3.9\"\n",
		"locked/requirements.txt":         "django==4.2.1 \\\n    --hash=sha256:abc\n",
		"node_modules/x/requirements.txt": "django==4.2.1\n",
	})
	_, err := Apply(root, Request{Ecosystem: PyPI, Package: "django", Current: "4.2.1", Target: "4.2.11"})
	if !IsNotSupported(err) || !strings.Contains(err.Error(), "--hash") {
		t.Fatalf("hashed requirements must not be edited: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "locked", "requirements.txt")); err != nil {
		t.Fatal(err)
	}
	r, err := Apply(root, Request{Ecosystem: PyPI, Package: "django", Current: "4.2.1", Target: "4.2.11"})
	if err != nil {
		t.Fatal(err)
	}
	got := changes(t, r)
	if got["requirements.txt"] != "# deps\nDjango==4.2.11  # web\nrequests>=2.0\nflask\n" {
		t.Errorf("requirements.txt:\n%s", got["requirements.txt"])
	}
	if got["svc/requirements-dev.txt"] != "django[argon2]==4.2.11 ; python_version >= \"3.9\"\n" {
		t.Errorf("requirements-dev.txt:\n%q", got["svc/requirements-dev.txt"])
	}
	if _, ok := got["node_modules/x/requirements.txt"]; ok {
		t.Error("node_modules must be skipped")
	}
	// Transitive: not declared.
	if _, err := Apply(root, Request{Ecosystem: PyPI, Package: "urllib3", Current: "1.26.0", Target: "1.26.18"}); !IsNotSupported(err) {
		t.Errorf("transitive dependency: want not supported, got %v", err)
	}
}

func TestMaven(t *testing.T) {
	pom := `<project>
  <properties>
    <jackson.version>2.15.0</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-api</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
`
	root := tree(t, map[string]string{"pom.xml": pom})
	r, err := Apply(root, Request{Ecosystem: Maven, Package: "org.apache.logging.log4j:log4j-core", Current: "2.14.1", Target: "2.17.1"})
	if err != nil {
		t.Fatal(err)
	}
	got := changes(t, r)["pom.xml"]
	if strings.Count(got, "2.17.1") != 1 || !strings.Contains(got, "<artifactId>log4j-api</artifactId>\n      <version>2.14.1</version>") {
		t.Errorf("only log4j-core must change:\n%s", got)
	}
	r, err = Apply(root, Request{Ecosystem: Maven, Package: "com.fasterxml.jackson.core:jackson-databind", Current: "2.15.0", Target: "2.15.4"})
	if err != nil {
		t.Fatal(err)
	}
	if got := changes(t, r)["pom.xml"]; !strings.Contains(got, "<jackson.version>2.15.4</jackson.version>") {
		t.Errorf("property not updated:\n%s", got)
	}
}

func TestGradle(t *testing.T) {
	root := tree(t, map[string]string{
		"build.gradle":              "dependencies {\n  implementation 'org.yaml:snakeyaml:1.33'\n  implementation group: 'org.yaml', name: 'snakeyaml', version: '1.33'\n}\n",
		"app/build.gradle.kts":      "dependencies { implementation(\"org.yaml:snakeyaml:1.33\") }\n",
		"gradle/libs.versions.toml": "[versions]\nsnake = \"1.33\"\n[libraries]\nsnakeyaml = { module = \"org.yaml:snakeyaml\", version.ref = \"snake\" }\n",
	})
	r, err := Apply(root, Request{Ecosystem: Maven, Package: "org.yaml:snakeyaml", Current: "1.33", Target: "2.0"})
	if err != nil {
		t.Fatal(err)
	}
	got := changes(t, r)
	if g := got["build.gradle"]; strings.Count(g, "2.0") != 2 || strings.Contains(g, "1.33") {
		t.Errorf("build.gradle:\n%s", g)
	}
	if !strings.Contains(got["app/build.gradle.kts"], `"org.yaml:snakeyaml:2.0"`) {
		t.Errorf("kts:\n%s", got["app/build.gradle.kts"])
	}
	if !strings.Contains(got["gradle/libs.versions.toml"], `snake = "2.0"`) {
		t.Errorf("catalog:\n%s", got["gradle/libs.versions.toml"])
	}
	// Dependency locking: not supported.
	if err := os.WriteFile(filepath.Join(root, "gradle.lockfile"), []byte("org.yaml:snakeyaml:1.33=compileClasspath\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(root, Request{Ecosystem: Maven, Package: "org.yaml:snakeyaml", Current: "1.33", Target: "2.0"}); !IsNotSupported(err) {
		t.Errorf("locked gradle: want not supported, got %v", err)
	}
}

func TestNuGet(t *testing.T) {
	root := tree(t, map[string]string{
		"src/App.csproj":           `<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /><PackageReference Version="1.0.0" Include="Other" /></ItemGroup></Project>`,
		"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>`,
		"lib/Lib.csproj":           "<Project><ItemGroup><PackageReference Include=\"Newtonsoft.Json\">\n  <Version>12.0.1</Version>\n</PackageReference></ItemGroup></Project>",
	})
	r, err := Apply(root, Request{Ecosystem: NuGet, Package: "Newtonsoft.Json", Current: "12.0.1", Target: "13.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	got := changes(t, r)
	if len(got) != 3 {
		t.Fatalf("want 3 files, got %v", got)
	}
	if !strings.Contains(got["src/App.csproj"], `Include="Newtonsoft.Json" Version="13.0.1"`) || !strings.Contains(got["src/App.csproj"], `Version="1.0.0" Include="Other"`) {
		t.Errorf("csproj: %s", got["src/App.csproj"])
	}
	if !strings.Contains(got["lib/Lib.csproj"], "<Version>13.0.1</Version>") {
		t.Errorf("child version: %s", got["lib/Lib.csproj"])
	}
}

func TestNPM(t *testing.T) {
	pkg := `{
  "name": "app",
  "version": "1.0.0",
  "dependencies": { "lodash": "^4.17.20", "left-pad": "1.0.0" },
  "devDependencies": { "lodash": "4.17.20" }
}
`
	root := tree(t, map[string]string{"package.json": pkg})
	r, err := Apply(root, Request{Ecosystem: NPM, Package: "lodash", Current: "4.17.20", Target: "4.17.21"})
	if err != nil {
		t.Fatal(err)
	}
	got := changes(t, r)["package.json"]
	var v map[string]any
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Fatalf("invalid JSON after edit: %v\n%s", err, got)
	}
	if !strings.Contains(got, `"lodash": "^4.17.21"`) || !strings.Contains(got, `"devDependencies": { "lodash": "4.17.21" }`) || !strings.Contains(got, `"version": "1.0.0"`) {
		t.Errorf("package.json:\n%s", got)
	}
	// With a lockfile: honestly not supported.
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(root, Request{Ecosystem: NPM, Package: "lodash", Current: "4.17.20", Target: "4.17.21"}); !IsNotSupported(err) {
		t.Errorf("npm with lockfile: want not supported, got %v", err)
	}
}

func TestUnsupportedAndValidation(t *testing.T) {
	root := tree(t, map[string]string{"go.mod": "module x\n"})
	for _, eco := range []string{Go, Cargo, Composer, RubyGems, "", "hex"} {
		if _, err := Apply(root, Request{Ecosystem: eco, Package: "x", Current: "1", Target: "2"}); !IsNotSupported(err) {
			t.Errorf("%q: want not supported, got %v", eco, err)
		}
	}
	for _, v := range []string{"", "1.0; rm -rf /", "../1", strings.Repeat("1", 101), "-1"} {
		if _, err := Apply(root, Request{Ecosystem: PyPI, Package: "x", Current: "1", Target: v}); err == nil || IsNotSupported(err) {
			t.Errorf("target %q accepted", v)
		}
	}
}

func TestPickTarget(t *testing.T) {
	for _, c := range []struct{ cur, fixed, want string }{
		{"2.14.1", "2.17.1", "2.17.1"},
		{"2.28.0", "2.31.0, 3.0.1", "2.31.0"},
		{"1.2.3", ">= 1.2.5", "1.2.5"},
		{"4.2.1", "3.2.20, 4.1.10, 4.2.11", "4.2.11"},
		{"1.0.0", "2.0.0 || 3.0.0", "2.0.0"},
		{"1.0.0", "", ""},
		{"1.0.0", "0.9.0", ""},
		{"1.0.0", "1.0.1-rc1, 1.0.1", "1.0.1"},
		{"1.0.0", "1.0.1-rc1", "1.0.1-rc1"},
	} {
		if got := PickTarget(c.cur, c.fixed); got != c.want {
			t.Errorf("PickTarget(%q, %q) = %q, want %q", c.cur, c.fixed, got, c.want)
		}
	}
	if Compare("1.10.0", "1.9.0") <= 0 || Compare("1.0.0-rc1", "1.0.0") >= 0 || Compare("1.0", "1.0.0") != 0 {
		t.Error("Compare ordering")
	}
}

func TestEcosystemInference(t *testing.T) {
	for purl, want := range map[string][2]string{
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": {Maven, "org.apache.logging.log4j:log4j-core"},
		"pkg:npm/%40babel/core@7.0.0":                          {NPM, "@babel/core"},
		"pkg:pypi/django@4.2.1":                                {PyPI, "django"},
		"pkg:golang/golang.org/x/net@v0.1.0":                   {Go, "golang.org/x/net"},
		"pkg:nuget/Newtonsoft.Json@12.0.1?x=y":                 {NuGet, "Newtonsoft.Json"},
	} {
		e, n, _ := FromPURL(purl)
		if e != want[0] || n != want[1] {
			t.Errorf("FromPURL(%q) = %q %q, want %v", purl, e, n, want)
		}
	}
	for p, want := range map[string]string{
		"web/package-lock.json": NPM, "requirements-dev.txt": PyPI, "svc/pom.xml": Maven, "go.sum": Go,
		"App.csproj": NuGet, "Cargo.lock": Cargo, "Gemfile.lock": RubyGems, "README.md": "",
	} {
		if got := FromPath(p); got != want {
			t.Errorf("FromPath(%q) = %q, want %q", p, got, want)
		}
	}
}

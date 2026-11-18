package worker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"pathos/internal/scanners"
)

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCollectRuntimes(t *testing.T) {
	src := t.TempDir()
	write(t, src, ".nvmrc", "v18.17.1\n")
	write(t, src, ".python-version", "3.8.10\n")
	write(t, src, ".ruby-version", "ruby-3.0.6\n")
	write(t, src, "runtime.txt", "python-3.11.4\n")
	write(t, src, ".tool-versions", "nodejs 20.11.0\njava temurin-17.0.8+7\n# comment\n")
	write(t, src, "go.mod", "module x\n\ngo 1.19\n\ntoolchain go1.21.5\n")
	write(t, src, "svc/go.mod", "module y\n\ngo 1.20\n") // minimum only: not a runtime
	write(t, src, "global.json", `{"sdk":{"version":"6.0.100"}}`)
	write(t, src, "api/Api.csproj", `<Project><PropertyGroup><TargetFramework>net7.0</TargetFramework></PropertyGroup></Project>`)
	write(t, src, "Gemfile", "source 'https://rubygems.org'\nruby \"2.7.8\"\n")
	write(t, src, "package.json", `{"engines":{"node":">=16"}}`) // a range: ignored
	write(t, src, "web/package.json", `{"engines":{"node":"16.x"}}`)
	write(t, src, "composer.json", `{"require":{"php":"^7.4"}}`)
	write(t, src, "pom.xml", `<project><properties><java.version>1.8</java.version></properties></project>`)
	write(t, src, "build.gradle", "java {\n  toolchain { languageVersion = JavaLanguageVersion.of(11) }\n}\n")
	write(t, src, "Dockerfile", "FROM node:16-alpine AS build\nRUN x\nFROM build AS test\nFROM --platform=linux/amd64 python:3.9-slim\nFROM scratch\nFROM $BASE\n")
	write(t, src, "node_modules/x/.nvmrc", "12\n") // dependencies are not the repository's
	inv := collectRuntimes(src)
	got := map[string]bool{}
	for _, r := range inv.Runtimes {
		got[r.Kind+" "+r.Name+" "+r.Version+" "+r.Path] = true
	}
	for _, want := range []string{
		"runtime node 18.17.1 .nvmrc", "runtime python 3.8.10 .python-version", "runtime ruby 3.0.6 .ruby-version",
		"runtime python 3.11.4 runtime.txt", "runtime node 20.11.0 .tool-versions", "runtime java 17.0.8 .tool-versions",
		"runtime go 1.21.5 go.mod", "runtime dotnet 6.0.100 global.json", "runtime dotnet 7.0 api/Api.csproj",
		"runtime ruby 2.7.8 Gemfile", "runtime node 16 web/package.json", "runtime php 7.4 composer.json",
		"runtime java 8 pom.xml", "runtime java 11 build.gradle", "image node:16-alpine  Dockerfile", "image python:3.9-slim  Dockerfile",
	} {
		if !got[want] {
			t.Errorf("missing %q", want)
		}
	}
	if len(inv.Runtimes) != 16 {
		t.Errorf("%d entries: %v", len(inv.Runtimes), got)
	}
}

func TestParseLinePorcelain(t *testing.T) {
	out := strings.Join([]string{
		"3f6c1d2e9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d 12 14 1",
		"author Dana Developer",
		"author-mail <dana@example.com>",
		"author-time 1700000000",
		"author-tz +0200",
		"committer X",
		"summary add query",
		"filename src/db.py",
		"\tquery = \"SELECT\" + x",
		"9a8b7c6d5e4f3a2b1c0d3f6c1d2e9a8b7c6d5e4f 3 30 1",
		"author Sam",
		"author-time 1600000000",
		"author-tz -0500",
		"filename src/db.py",
		"\tpassword = 'x'",
	}, "\n")
	es := parseLinePorcelain([]byte(out), "src/db.py")
	if len(es) != 2 {
		t.Fatalf("%d entries", len(es))
	}
	e := es[0]
	if e.Line != 14 || e.Author != "Dana Developer" || e.Commit != "3f6c1d2e9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d" || e.Time.Unix() != 1700000000 {
		t.Errorf("%+v", e)
	}
	if _, off := e.Time.Zone(); off != 7200 {
		t.Errorf("zone offset %d", off)
	}
	b, _ := json.Marshal(es)
	if strings.Contains(string(b), "example.com") {
		t.Error("author e-mail collected")
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=Dana Developer", "-c", "user.email=dana@example.com",
		"-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_DATE=2026-01-02T03:04:05+01:00",
		"GIT_COMMITTER_DATE=2026-01-02T03:04:05+01:00")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func TestBlameFullHistory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	src := t.TempDir()
	git(t, src, "init", "-q")
	write(t, src, "app/db.py", "import os\nquery = 'SELECT ' + os.environ['X']\n")
	git(t, src, "add", ".")
	git(t, src, "commit", "-q", "-m", "first")
	write(t, src, "app/db.py", "import os\nquery = 'SELECT ' + os.environ['X']\nsecret = 'abc'\n")
	git(t, src, "commit", "-q", "-am", "second")
	locs := map[string][]int{"app/db.py": {2, 3, 99}, "gone.py": {1}}
	rep := blame(context.Background(), src, locs)
	if rep.Mode != "full" || len(rep.Entries) != 2 {
		t.Fatalf("entries: %+v", rep)
	}
	if rep.Entries[0].Line != 2 || rep.Entries[1].Line != 3 || rep.Entries[0].Commit == rep.Entries[1].Commit {
		t.Errorf("lines attributed to the wrong commits: %+v", rep.Entries)
	}
	if rep.Entries[0].Author != "Dana Developer" || rep.Entries[0].Time.Year() != 2026 {
		t.Errorf("author/time: %+v", rep.Entries[0])
	}
	missing := map[string]bool{}
	for _, m := range rep.Missing {
		missing[m.File] = true
	}
	if !missing["gone.py"] || !missing["app/db.py"] {
		t.Errorf("missing: %+v", rep.Missing)
	}
}

func TestBlameLocations(t *testing.T) {
	out := t.TempDir()
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"opengrep","rules":[{"id":"r1"}]}},"results":[
	  {"ruleId":"r1","message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/work/j/src/app/db.py"},"region":{"startLine":2}}}]},
	  {"ruleId":"r1","message":{"text":"y"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/db.py"},"region":{"startLine":2}}}]},
	  {"ruleId":"r1","message":{"text":"z"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"../etc/passwd"},"region":{"startLine":1}}}]}]}]}`
	write(t, out, "opengrep.out", sarif)
	write(t, out, "trivy-fs.out", sarif) // SCA: no blame
	locs := blameLocations(out, []string{"opengrep", "trivy-fs", "syft"})
	// Paths are confined to the checkout ("../etc/passwd" is etc/passwd in it).
	if len(locs) != 2 || len(locs["app/db.py"]) != 1 || locs["app/db.py"][0] != 2 || locs["etc/passwd"] == nil {
		t.Errorf("locations: %v", locs)
	}
	if categoryOf("plugin-sast-semgrep") != "sast" || categoryOf("gitleaks") != "secrets" || categoryOf("grype") != "sca" {
		t.Error("categoryOf")
	}
}

type fakeCall struct {
	args []string
	env  []string
}

func TestVerifySignature(t *testing.T) {
	dir := t.TempDir()
	pub := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n"
	verified := `[{"critical":{"image":{"docker-manifest-digest":"sha256:9d50"}},"optional":{"Subject":"https://github.com/acme/api/.github/workflows/release.yml@refs/tags/v1","Issuer":"https://token.actions.githubusercontent.com"}}]`
	stmt := base64.StdEncoding.EncodeToString([]byte(`{"predicateType":"https://slsa.dev/provenance/v1","predicate":{"runDetails":{"builder":{"id":"https://github.com/actions/runner"}},"buildDefinition":{"externalParameters":{"workflow":{"repository":"https://github.com/acme/api"}}}}}`))
	var calls []fakeCall
	run := func(results map[string]struct {
		out, stderr string
		err error
	}) runner {
		return func(_ context.Context, env []string, args ...string) ([]byte, string, error) {
			calls = append(calls, fakeCall{args: args, env: env})
			r := results[args[0]]
			return []byte(r.out), r.stderr, r.err
		}
	}
	type res = struct {
		out, stderr string
		err error
	}
	fail := errors.New("cosign exited with 1")
	keyless := &JobTarget{Kind: "image", Reference: "ghcr.io/acme/api:1", AuthType: "basic", Username: "bot", Password: "s3cret",
		Signature: &SignatureConfig{Mode: "keyless", IdentityRegexp: "^https://github.com/acme/", Issuer: "https://token.actions.githubusercontent.com",
			Require: true, Attestation: "slsaprovenance1"}}

	// Verified signature and attestation.
	rep := verifySignature(context.Background(), run(map[string]res{"verify": {out: verified}, "verify-attestation": {out: `{"payload":"` + stmt + `"}`}}),
		false, RunInput{Target: keyless}, dir)
	if rep.Status != "verified" || len(rep.Signatures) != 1 || rep.Signatures[0].Issuer != "https://token.actions.githubusercontent.com" ||
		rep.Attestation == nil || rep.Attestation.Status != "verified" || rep.Attestation.BuilderID != "https://github.com/actions/runner" ||
		rep.Attestation.SourceRepo != "https://github.com/acme/api" {
		t.Fatalf("verified: %+v %+v", rep, rep.Attestation)
	}
	args := strings.Join(calls[0].args, " ")
	if !strings.Contains(args, "--certificate-identity-regexp ^https://github.com/acme/") || !strings.Contains(args, "--certificate-oidc-issuer") ||
		strings.Contains(args, "s3cret") || strings.Contains(args, "insecure-ignore-tlog") {
		t.Errorf("args: %s", args)
	}
	cfgDir := ""
	for _, e := range calls[0].env {
		if v, ok := strings.CutPrefix(e, "DOCKER_CONFIG="); ok {
			cfgDir = v
		}
	}
	if b, err := os.ReadFile(filepath.Join(cfgDir, "config.json")); err != nil || !strings.Contains(string(b), `"ghcr.io"`) {
		t.Errorf("registry credentials: %s %v", b, err)
	}

	// Unsigned, invalid and missing attestation.
	rep = verifySignature(context.Background(), run(map[string]res{"verify": {stderr: "Error: no signatures found\n", err: fail}}), false, RunInput{Target: keyless}, dir)
	if rep.Status != "unsigned" || rep.Detail != "no signatures found" {
		t.Errorf("unsigned: %+v", rep)
	}
	rep = verifySignature(context.Background(), run(map[string]res{"verify": {stderr: "Error: no matching signatures: none of the expected identities matched\n", err: fail}}),
		false, RunInput{Target: keyless}, dir)
	if rep.Status != "invalid" {
		t.Errorf("invalid: %+v", rep)
	}
	rep = verifySignature(context.Background(), run(map[string]res{"verify": {out: verified}, "verify-attestation": {stderr: "Error: no matching attestations: \n", err: fail}}),
		false, RunInput{Target: keyless}, dir)
	if rep.Status != "verified" || rep.Attestation.Status != "missing" {
		t.Errorf("missing attestation: %+v", rep.Attestation)
	}
	rep = verifySignature(context.Background(), run(map[string]res{"verify": {stderr: "Error: GET https://ghcr.io/v2/: dial tcp: i/o timeout\n", err: fail}}),
		false, RunInput{Target: keyless}, dir)
	if rep.Status != "error" {
		t.Errorf("network error: %+v", rep)
	}

	// Offline: keyless is skipped; key-based skips the transparency log.
	calls = nil
	rep = verifySignature(context.Background(), run(nil), true, RunInput{Target: keyless}, dir)
	if rep.Status != "skipped" || len(calls) != 0 || !rep.Offline {
		t.Errorf("offline keyless: %+v", rep)
	}
	keyed := &JobTarget{Kind: "image", Reference: "registry.local/app:2", Signature: &SignatureConfig{Mode: "key", PublicKey: pub}}
	rep = verifySignature(context.Background(), run(map[string]res{"verify": {out: "[]"}}), true, RunInput{Target: keyed}, dir)
	if rep.Status != "verified" || !strings.Contains(strings.Join(calls[0].args, " "), "--key "+filepath.Join(dir, "cosign.pub")+" --insecure-ignore-tlog=true") {
		t.Errorf("offline key: %+v %v", rep, calls[0].args)
	}

	// Artifacts: a bundle or a detached signature.
	scan := filepath.Join(dir, "target", "artifact")
	write(t, scan, "app.jar", "jar")
	art := &JobTarget{Kind: "artifact", FileName: "app.jar", Signature: &SignatureConfig{Mode: "key", PublicKey: pub}, SignatureMaterial: `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`}
	calls = nil
	rep = verifySignature(context.Background(), run(map[string]res{"verify-blob": {}}), false, RunInput{Target: art, TargetFile: scan}, dir)
	a := strings.Join(calls[0].args, " ")
	if rep.Status != "verified" || rep.Subject != "app.jar" || !strings.Contains(a, "--bundle") || !strings.HasSuffix(a, filepath.Join(scan, "app.jar")) {
		t.Errorf("artifact: %+v %s", rep, a)
	}
	art.SignatureMaterial = ""
	rep = verifySignature(context.Background(), run(nil), false, RunInput{Target: art, TargetFile: scan}, dir)
	if rep.Status != "unsigned" {
		t.Errorf("artifact without signature: %+v", rep)
	}

	// The report is accepted by the API parser and creates a finding only
	// when a signature is required.
	b, _ := json.Marshal(scanners.SignatureReport{Version: 1, Subject: "x", Mode: "key", Status: "invalid", Required: true})
	if fs, err := scanners.Parse(scanners.Cosign, b); err != nil || len(fs) != 1 || fs[0].Severity != "high" {
		t.Errorf("required: %v %+v", err, fs)
	}
	b, _ = json.Marshal(scanners.SignatureReport{Version: 1, Subject: "x", Mode: "key", Status: "invalid"})
	if fs, err := scanners.Parse(scanners.Cosign, b); err != nil || len(fs) != 0 {
		t.Errorf("not required: %v %+v", err, fs)
	}
}

package worker

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeTool(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "fake-scanner")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo "fake 1.2.3"; exit 0; fi
out=""; src=""
while [ $# -gt 0 ]; do case "$1" in --out) out="$2"; shift;; *) src="$1";; esac; shift; done
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fake","rules":[{"id":"R1","shortDescription":{"text":"Fake issue"}}]}},"results":[{"ruleId":"R1","level":"error","message":{"text":"found in %s with %s"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":3}}}]}]}]}' "$src" "$FAKE_MODE" > "$out"
exit 1
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPlugins(t *testing.T) {
	dir := t.TempDir()
	bin := fakeTool(t, dir)
	conf := filepath.Join(dir, "conf")
	_ = os.MkdirAll(conf, 0o755)
	write := func(n, body string) { _ = os.WriteFile(filepath.Join(conf, n), []byte(body), 0o644) }
	write("10-good.yaml", `name: fake
display_name: Fake scanner
category: sast
command: `+bin+`
args: ["--out", "{output}", "{source}"]
ok_exit_codes: [0, 1]
env: {FAKE_MODE: strict}
`)
	write("20-bad-placeholder.yaml", "name: bad\ncategory: sast\ncommand: "+bin+"\nargs: [\"{source}\", \"{secret}\", \"{output}\"]\n")
	write("30-relative.yaml", "name: rel\ncategory: sast\ncommand: fake-scanner\nargs: [\"{source}\", \"{output}\"]\n")
	write("40-env.yaml", "name: env\ncategory: sast\ncommand: "+bin+"\nargs: [\"{source}\", \"{output}\"]\nenv: {LD_PRELOAD: /x.so}\n")
	write("50-unknown-field.yaml", "name: unk\ncategory: sast\ncommand: "+bin+"\nargs: [\"{source}\", \"{output}\"]\nshell: true\n")
	write("60-dup.yaml", "name: fake\ncategory: sast\ncommand: "+bin+"\nargs: [\"{source}\", \"--out\", \"{output}\"]\n")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	defs := LoadPlugins(conf, log)
	if len(defs) != 1 || defs[0].Key() != "plugin-sast-fake" {
		t.Fatalf("only the valid, first definition loads: %+v", defs)
	}
	if LoadPlugins(filepath.Join(dir, "missing"), log) != nil {
		t.Error("no directory, no plugins")
	}
	// A writable command is refused.
	_ = os.Chmod(bin, 0o777)
	d := defs[0]
	if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("group/world-writable command: %v", err)
	}
	_ = os.Chmod(bin, 0o755)

	tool := pluginTool{def: defs[0], cacheDir: filepath.Join(dir, "cache")}
	if v, err := tool.Version(context.Background()); err != nil || !strings.Contains(v, "1.2.3") {
		t.Errorf("version: %q %v", v, err)
	}
	src, out := filepath.Join(dir, "src"), filepath.Join(dir, "out")
	_ = os.MkdirAll(src, 0o755)
	_ = os.MkdirAll(out, 0o755)
	report := filepath.Join(out, "plugin.out")
	skipped, err := tool.Run(context.Background(), RunInput{Src: src, Out: report})
	if err != nil || skipped != "" {
		t.Fatalf("run: %q %v", skipped, err)
	}
	b, _ := os.ReadFile(report)
	if !strings.Contains(string(b), "found in "+src+" with strict") {
		t.Errorf("placeholders and env applied: %s", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "cache", "plugins", "fake")); err != nil {
		t.Error("the plugin gets its own cache directory")
	}
	if s, _ := tool.Run(context.Background(), RunInput{Src: src, Out: report, Target: &JobTarget{Kind: "image"}}); s == "" {
		t.Error("plugins do not run for scan targets")
	}
}

// The version command runs with the manifest's env and version_timeout.
// Regression (benchmark 2026-11-19): Semgrep CE's version command waited
// for a version check its manifest disables in env, the worker gave up
// after 20s and stored an empty version on every scan.
func TestPluginVersionEnvAndTimeout(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "slow-version")
	script := `#!/bin/sh
if [ "$NO_VERSION_CHECK" = "1" ]; then echo "slow 4.5.6"; exit 0; fi
sleep 5; echo "slow 4.5.6"
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	spec := "name: slow\ncategory: sast\ncommand: " + bin + "\nargs: [\"{source}\", \"{output}\"]\nversion_timeout: 1s\n"
	d, err := decodeManifest([]byte(spec), false)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := (pluginTool{def: d}).Version(context.Background()); err == nil || v != "" {
		t.Errorf("without the env the version command must hit version_timeout: %q %v", v, err)
	}
	d, err = decodeManifest([]byte(spec+"env: {NO_VERSION_CHECK: \"1\"}\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := (pluginTool{def: d}).Version(context.Background()); err != nil || v != "4.5.6" {
		t.Errorf("version with the manifest env: %q %v", v, err)
	}
	for _, bad := range []string{"500ms", "10m", "x"} {
		if _, err := decodeManifest([]byte(strings.Replace(spec, "1s", bad, 1)), false); err == nil {
			t.Errorf("version_timeout %s accepted", bad)
		}
	}
}

func TestRequiresFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("README.md")
	write("node_modules/lib/index.js") // dependencies do not count
	write(".git/hooks/x.go")
	if hasMatchingFile(dir, []string{"*.js", "*.go"}) {
		t.Fatal("files under node_modules and .git must not count")
	}
	write("src/deep/app.ts")
	if !hasMatchingFile(dir, []string{"*.js", "*.ts"}) || hasMatchingFile(dir, []string{"*.php"}) {
		t.Fatal("pattern match")
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link.php")); err == nil && hasMatchingFile(dir, []string{"*.php"}) {
		t.Fatal("symbolic links must not count")
	}

	def := PluginDef{Name: "gosec-like", Category: "sast", Command: "/bin/true", Args: []string{"{source}", "{output}"},
		RequiresFiles: []string{"*.go"}}
	if err := def.Validate(); err != nil {
		t.Fatal(err)
	}
	tool := pluginTool{def: def}
	msg, err := tool.Run(context.Background(), RunInput{Src: dir, Out: filepath.Join(t.TempDir(), "out")})
	if err != nil || !strings.Contains(msg, "no matching files") {
		t.Fatalf("a repository without Go files skips the tool: %q %v", msg, err)
	}
	for _, bad := range [][]string{{"src/*.go"}, {"["}, {""}} {
		d := PluginDef{Name: "bad", Category: "sast", Command: "/bin/true", Args: []string{"{source}"}, RequiresFiles: bad}
		if d.Validate() == nil {
			t.Errorf("requires_files %q must be rejected", bad)
		}
	}
}

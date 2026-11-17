package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"pathos/internal/scanners"
)

// Declarative scanner adapters: an operator adds a tool to a worker with a
// definition file in PATHOS_SCANNER_PLUGINS_DIR (default
// /etc/pathos/scanners.d), for example:
//
//	name: semgrep-pro
//	display_name: Semgrep Pro
//	category: sast
//	command: /opt/plugins/semgrep
//	args: ["scan", "--sarif", "--output", "{output}", "{source}"]
//	ok_exit_codes: [0, 1]
//
// The tool must write SARIF to {output} (or to stdout with "output:
// stdout"). Definitions live on the worker, never in the API: a PATHOS
// administrator cannot make workers run arbitrary programs. Plugins run
// like the built-in scanners: no shell, the worker's user, its sandbox and
// egress policy, the job's timeout.

// PluginDef is one definition file.
type PluginDef struct {
	Name        string            `yaml:"name" json:"name"`
	DisplayName string            `yaml:"display_name" json:"display_name"`
	Category    string            `yaml:"category" json:"category"`
	Homepage    string            `yaml:"homepage" json:"homepage"`
	Command     string            `yaml:"command" json:"command"`
	VersionArgs []string          `yaml:"version_args" json:"version_args"`
	Args        []string          `yaml:"args" json:"args"`
	OKExitCodes []int             `yaml:"ok_exit_codes" json:"ok_exit_codes"`
	Env         map[string]string `yaml:"env" json:"env"`
	Output      string            `yaml:"output" json:"output"` // file (default) | stdout
}

const maxPlugins = 20

var (
	pluginNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,22}$`)
	envKeyRe      = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	pluginCats    = []string{"sast", "sca", "secrets", "iac", "container", "license", "dast", "other"}
	placeholderRe = regexp.MustCompile(`\{[a-z]+\}`)
)

// Key is the plugin's scanner key.
func (d PluginDef) Key() string { return scanners.PluginKey(d.Category, d.Name) }

// Validate checks a definition. The command must be an existing, executable
// file that the worker's user cannot modify.
func (d *PluginDef) Validate() error {
	if !pluginNameRe.MatchString(d.Name) {
		return errors.New("name: lowercase letters, digits and dashes, at most 23 characters")
	}
	if !slices.Contains(pluginCats, d.Category) {
		return fmt.Errorf("category must be one of %s", strings.Join(pluginCats, ", "))
	}
	if len(d.DisplayName) > 100 || len(d.Homepage) > 300 || (d.Homepage != "" && !strings.HasPrefix(d.Homepage, "https://")) {
		return errors.New("display_name at most 100 characters; homepage an https URL")
	}
	if d.Output == "" {
		d.Output = "file"
	}
	if d.Output != "file" && d.Output != "stdout" {
		return errors.New("output must be file or stdout")
	}
	if !filepath.IsAbs(d.Command) || filepath.Clean(d.Command) != d.Command {
		return errors.New("command must be an absolute, clean path")
	}
	st, err := os.Stat(d.Command)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
		return errors.New("command must be an existing executable file")
	}
	if st.Mode().Perm()&0o022 != 0 {
		return errors.New("command must not be writable by group or others")
	}
	if len(d.Args) == 0 || len(d.Args) > 64 {
		return errors.New("args: 1 to 64 arguments")
	}
	joined := strings.Join(d.Args, " ")
	if !strings.Contains(joined, "{source}") {
		return errors.New("args must contain {source}")
	}
	if d.Output == "file" && !strings.Contains(joined, "{output}") {
		return errors.New("args must contain {output} (or set output: stdout)")
	}
	for _, a := range append(append([]string{}, d.Args...), d.VersionArgs...) {
		for _, ph := range placeholderRe.FindAllString(a, -1) {
			if ph != "{source}" && ph != "{output}" && ph != "{cache}" && ph != "{tmp}" {
				return fmt.Errorf("unknown placeholder %s (use {source}, {output}, {cache}, {tmp})", ph)
			}
		}
	}
	if len(d.Env) > 32 {
		return errors.New("env: at most 32 variables")
	}
	for k := range d.Env {
		u := strings.ToUpper(k)
		if !envKeyRe.MatchString(k) || u == "PATH" || u == "HOME" || strings.HasPrefix(u, "LD_") || strings.HasPrefix(u, "DYLD_") ||
			strings.HasSuffix(u, "_PROXY") || strings.HasPrefix(u, "PATHOS_") {
			return fmt.Errorf("env %s is not allowed", k)
		}
	}
	for _, c := range d.OKExitCodes {
		if c < 0 || c > 255 {
			return errors.New("ok_exit_codes must be 0-255")
		}
	}
	return nil
}

// LoadPlugins reads the definitions in dir. Invalid files are logged and
// skipped; a missing directory means no plugins.
func LoadPlugins(dir string, log *slog.Logger) []PluginDef {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Warn("scanner plugins not loaded", "dir", dir, "err", err)
		}
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var out []PluginDef
	seen := map[string]bool{}
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() || !(strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".json")) {
			continue
		}
		if len(out) >= maxPlugins {
			log.Warn("too many scanner plugins; the rest are ignored", "max", maxPlugins)
			break
		}
		// #nosec G304 -- operator-controlled configuration directory
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil || len(raw) > 64<<10 {
			log.Warn("scanner plugin not loaded", "file", n, "err", err)
			continue
		}
		var d PluginDef
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(&d); err != nil {
			log.Warn("scanner plugin not loaded: invalid file", "file", n, "err", err)
			continue
		}
		if err := d.Validate(); err != nil {
			log.Warn("scanner plugin not loaded", "file", n, "err", err)
			continue
		}
		if seen[d.Key()] {
			log.Warn("scanner plugin defined twice; the first is used", "key", d.Key(), "file", n)
			continue
		}
		seen[d.Key()] = true
		log.Info("scanner plugin loaded", "key", d.Key(), "command", d.Command)
		out = append(out, d)
	}
	return out
}

// pluginTool runs a declarative adapter.
type pluginTool struct {
	def      PluginDef
	cacheDir string
}

func (t pluginTool) Version(ctx context.Context) (string, error) {
	args := t.def.VersionArgs
	if len(args) == 0 {
		args = []string{"--version"}
	}
	return versionOf(ctx, t.def.Command, args...)
}

func (t pluginTool) expand(args []string, in RunInput, tmp string) []string {
	r := strings.NewReplacer("{source}", in.Src, "{output}", in.Out, "{cache}", filepath.Join(t.cacheDir, "plugins", t.def.Name), "{tmp}", tmp)
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = r.Replace(a)
	}
	return out
}

func (t pluginTool) Run(ctx context.Context, in RunInput) (string, error) {
	if in.Target != nil {
		return "plugins scan repository source only", nil
	}
	tmp, err := os.MkdirTemp(filepath.Dir(in.Out), "plugin-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	if err := os.MkdirAll(filepath.Join(t.cacheDir, "plugins", t.def.Name), 0o700); err != nil {
		return "", err
	}
	var env []string
	keys := make([]string, 0, len(t.def.Env))
	for k := range t.def.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+t.def.Env[k])
	}
	codes := t.def.OKExitCodes
	if len(codes) == 0 {
		codes = []int{0}
	}
	args := t.expand(t.def.Args, in, tmp)
	if t.def.Output == "stdout" {
		// #nosec G304 -- report path is created by the worker in its job directory
		f, err := os.OpenFile(in.Out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return "", err
		}
		_, err = commandTo(ctx, f, env, codes, t.def.Command, args...)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return "", err
		}
	} else if _, err := command(ctx, env, codes, t.def.Command, args...); err != nil {
		return "", err
	}
	return "", ensureReport(in.Out, t.def.Key())
}

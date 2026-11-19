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
	"time"

	"go.yaml.in/yaml/v3"

	"pathos/internal/scanners"
)

// Tool manifests ("declarative scanner adapters") describe a scanner as
// data: the command to run, its arguments, and how to parse its output.
// There are two sources:
//
//   - First-party manifests, shipped read-only in the family worker images
//     at /opt/pathos/tools.d (PATHOS_TOOLS_DIR). They are trusted: their
//     name is a catalog key (for example "bandit"), so their findings,
//     catalog entry and scan types are those of the catalog.
//   - Operator plugins in PATHOS_SCANNER_PLUGINS_DIR (default
//     /etc/pathos/scanners.d). Their key is plugin-<category>-<name>.
//
// An operator plugin, for example:
//
//	name: semgrep-pro
//	display_name: Semgrep Pro
//	category: sast
//	command: /opt/plugins/semgrep
//	args: ["scan", "--sarif", "--output", "{output}", "{source}"]
//	ok_exit_codes: [0, 1]
//
// Version 1 files (the fields above plus homepage, version_args, env and
// output) keep working unchanged. Version 2 adds scan_types,
// license_spdx, family, targets, timeout, network, intrusive,
// requires_build, default_enabled, parser and jsonmap (see
// docs/SCANNER_CATALOG.md). Definitions live on the worker, never in the
// API: a PATHOS administrator cannot make workers run arbitrary programs.
// Tools run like the built-in scanners: no shell, the worker's user, its
// sandbox and egress policy, the job's timeout.

// PluginDef is one manifest.
type PluginDef struct {
	Name           string            `yaml:"name" json:"name"`
	DisplayName    string            `yaml:"display_name" json:"display_name"`
	Category       string            `yaml:"category" json:"category"`
	ScanTypes      []string          `yaml:"scan_types" json:"scan_types"`
	LicenseSPDX    string            `yaml:"license_spdx" json:"license_spdx"`
	Homepage       string            `yaml:"homepage" json:"homepage"`
	Family         string            `yaml:"family" json:"family"`
	Targets        []string          `yaml:"targets" json:"targets"`
	Command        string            `yaml:"command" json:"command"`
	VersionArgs    []string          `yaml:"version_args" json:"version_args"`
	Args           []string          `yaml:"args" json:"args"`
	OKExitCodes    []int             `yaml:"ok_exit_codes" json:"ok_exit_codes"`
	Timeout        string            `yaml:"timeout" json:"timeout"`
	Env            map[string]string `yaml:"env" json:"env"`
	Output         string            `yaml:"output" json:"output"` // file (default) | stdout
	Network        string            `yaml:"network" json:"network"`
	Intrusive      bool              `yaml:"intrusive" json:"intrusive"`
	RequiresBuild  bool              `yaml:"requires_build" json:"requires_build"`
	DefaultEnabled bool              `yaml:"default_enabled" json:"default_enabled"`
	Parser         string            `yaml:"parser" json:"parser"`
	JSONMap        *scanners.JSONMap `yaml:"jsonmap" json:"jsonmap,omitempty"`

	// FirstParty marks a manifest from the image's trusted directory.
	FirstParty bool `yaml:"-" json:"first_party"`
	parser     scanners.ToolParser
	timeout    time.Duration
}

const (
	// maxPlugins bounds operator plugins; maxFirstParty the manifests
	// shipped in an image.
	maxPlugins    = 50
	maxFirstParty = 500
)

var (
	pluginNameRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,22}$`)
	firstPartyNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	familyRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	spdxRe           = regexp.MustCompile(`^[A-Za-z0-9.+:() -]{1,100}$`)
	envKeyRe         = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	placeholderRe    = regexp.MustCompile(`\{[a-z_]+\}`)
	// manifestTargets are what a tool can scan; targetPlaceholder is the
	// argument that passes each to the tool.
	manifestTargets   = []string{"repository", "image", "url", "api", "mobile-app", "binary", "model"}
	targetPlaceholder = map[string][]string{"repository": {"{source}"}, "image": {"{image}"}, "url": {"{target_url}"},
		"api": {"{openapi}", "{target_url}"}, "mobile-app": {"{artifact}"}, "binary": {"{artifact}"}, "model": {"{artifact}"}}
	placeholders = []string{"{source}", "{output}", "{target_url}", "{openapi}", "{image}", "{artifact}", "{cache}", "{tmp}"}
)

// Key is the tool's scanner key: the catalog key of a first-party
// manifest, plugin-<category>-<name> for an operator plugin.
func (d PluginDef) Key() string {
	if d.FirstParty {
		return d.Name
	}
	return scanners.PluginKey(d.Category, d.Name)
}

// ToolParser is the validated parser of the tool's output.
func (d PluginDef) ToolParser() scanners.ToolParser { return d.parser }

// RunsOn reports whether the tool scans a job of target kind ("" for a
// repository job).
func (d PluginDef) RunsOn(kind string) bool {
	for _, t := range d.Targets {
		switch {
		case kind == "" && t == "repository",
			kind == "image" && t == "image",
			kind == "url" && t == "url",
			kind == "api" && (t == "api" || t == "url"),
			kind == "artifact" && (t == "binary" || t == "mobile-app" || t == "model"):
			return true
		}
	}
	return false
}

// Validate checks a definition. The command must be an existing, executable
// file that the worker's user cannot modify.
func (d *PluginDef) Validate() error {
	if err := d.validateSpec(); err != nil {
		return err
	}
	st, err := os.Stat(d.Command)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
		return errors.New("command must be an existing executable file")
	}
	if st.Mode().Perm()&0o022 != 0 {
		return errors.New("command must not be writable by group or others")
	}
	return nil
}

// validateSpec checks everything but the command file.
func (d *PluginDef) validateSpec() error {
	if d.FirstParty {
		if !firstPartyNameRe.MatchString(d.Name) {
			return errors.New("name: lowercase letters, digits and dashes, at most 40 characters")
		}
		sc, ok := scanners.Lookup(d.Name)
		if !ok || !scanners.ManifestRouted(d.Name) {
			return errors.New("name: a first-party manifest names a catalog tool that is not built into the core worker")
		}
		if d.Category != sc.Category {
			return fmt.Errorf("category must be the catalog's (%s)", sc.Category)
		}
	} else {
		if !pluginNameRe.MatchString(d.Name) {
			return errors.New("name: lowercase letters, digits and dashes, at most 23 characters")
		}
		if !slices.Contains(scanners.ToolCategories, d.Category) {
			return fmt.Errorf("category must be one of %s", strings.Join(scanners.ToolCategories, ", "))
		}
	}
	if len(d.DisplayName) > 100 || len(d.Homepage) > 300 || (d.Homepage != "" && !strings.HasPrefix(d.Homepage, "https://")) {
		return errors.New("display_name at most 100 characters; homepage an https URL")
	}
	if d.LicenseSPDX != "" && !spdxRe.MatchString(d.LicenseSPDX) {
		return errors.New("license_spdx must be an SPDX licence expression")
	}
	if d.Family != "" && !familyRe.MatchString(d.Family) {
		return errors.New("family: lowercase letters, digits and dashes")
	}
	if len(d.ScanTypes) > 10 {
		return errors.New("scan_types: at most 10")
	}
	for _, t := range d.ScanTypes {
		if _, ok := scanners.LookupScanType(t); !ok {
			return fmt.Errorf("unknown scan type %q", t)
		}
	}
	if len(d.Targets) == 0 {
		d.Targets = []string{"repository"}
	}
	if len(d.Targets) > len(manifestTargets) {
		return errors.New("targets: too many")
	}
	for _, t := range d.Targets {
		if !slices.Contains(manifestTargets, t) {
			return fmt.Errorf("targets must be among %s", strings.Join(manifestTargets, ", "))
		}
	}
	switch d.Network {
	case "", "none", "target", "registry":
	default:
		return errors.New("network must be none, target or registry")
	}
	if d.Network == "target" && !slices.ContainsFunc(d.Targets, func(t string) bool { return t == "url" || t == "api" }) {
		return errors.New("network: target applies to url and api targets")
	}
	if d.Intrusive && d.Network != "target" {
		return errors.New("intrusive tools send traffic to the target: set network: target")
	}
	if d.Timeout != "" {
		to, err := time.ParseDuration(d.Timeout)
		if err != nil || to < 10*time.Second || to > 6*time.Hour {
			return errors.New("timeout must be a duration between 10s and 6h")
		}
		d.timeout = to
	}
	p, err := scanners.ParseToolParserSpec(d.Parser, d.JSONMap)
	if err != nil {
		return err
	}
	d.parser = p
	if d.Output == "" {
		d.Output = "file"
	}
	if d.Output != "file" && d.Output != "stdout" {
		return errors.New("output must be file or stdout")
	}
	if !filepath.IsAbs(d.Command) || filepath.Clean(d.Command) != d.Command {
		return errors.New("command must be an absolute, clean path")
	}
	if len(d.Args) == 0 || len(d.Args) > 64 {
		return errors.New("args: 1 to 64 arguments")
	}
	joined := strings.Join(d.Args, " ")
	for _, t := range d.Targets {
		if !slices.ContainsFunc(targetPlaceholder[t], func(ph string) bool { return strings.Contains(joined, ph) }) {
			return fmt.Errorf("args must contain %s for target %s", strings.Join(targetPlaceholder[t], " or "), t)
		}
	}
	if d.Output == "file" && !strings.Contains(joined, "{output}") {
		return errors.New("args must contain {output} (or set output: stdout)")
	}
	for _, a := range append(append([]string{}, d.Args...), d.VersionArgs...) {
		for _, ph := range placeholderRe.FindAllString(a, -1) {
			if !slices.Contains(placeholders, ph) {
				return fmt.Errorf("unknown placeholder %s (use %s)", ph, strings.Join(placeholders, ", "))
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

// LoadPlugins reads the operator plugins in dir. Invalid files are logged
// and skipped; a missing directory means no plugins.
func LoadPlugins(dir string, log *slog.Logger) []PluginDef {
	return loadManifests(dir, false, maxPlugins, log)
}

// LoadToolManifests reads the first-party manifests shipped in the image.
func LoadToolManifests(dir string, log *slog.Logger) []PluginDef {
	return loadManifests(dir, true, maxFirstParty, log)
}

func loadManifests(dir string, firstParty bool, limit int, log *slog.Logger) []PluginDef {
	if dir == "" {
		return nil
	}
	what := "scanner plugin"
	if firstParty {
		what = "tool manifest"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Warn(what+"s not loaded", "dir", dir, "err", err)
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
		if len(out) >= limit {
			log.Warn("too many "+what+"s; the rest are ignored", "max", limit)
			break
		}
		// #nosec G304 -- operator-controlled configuration directory or the image's read-only manifests
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil || len(raw) > 64<<10 {
			log.Warn(what+" not loaded", "file", n, "err", err)
			continue
		}
		d, err := decodeManifest(raw, firstParty)
		if err != nil {
			log.Warn(what+" not loaded", "file", n, "err", err)
			continue
		}
		if seen[d.Key()] {
			log.Warn(what+" defined twice; the first is used", "key", d.Key(), "file", n)
			continue
		}
		seen[d.Key()] = true
		log.Info(what+" loaded", "key", d.Key(), "command", d.Command, "parser", d.parser.String())
		out = append(out, d)
	}
	return out
}

// decodeManifest parses and validates one manifest file.
func decodeManifest(raw []byte, firstParty bool) (PluginDef, error) {
	d, err := decodeManifestSpec(raw, firstParty)
	if err != nil {
		return d, err
	}
	return d, d.Validate()
}

// decodeManifestSpec parses a manifest file and checks everything but its
// command file.
func decodeManifestSpec(raw []byte, firstParty bool) (PluginDef, error) {
	var d PluginDef
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return d, fmt.Errorf("invalid file: %w", err)
	}
	d.FirstParty = firstParty
	return d, d.validateSpec()
}

// toolAdvert is what a worker tells the API about a manifest tool when it
// registers (never its command or arguments).
type toolAdvert struct {
	Name          string   `json:"name"`
	Category      string   `json:"category"`
	ScanTypes     []string `json:"scan_types"`
	LicenseSPDX   string   `json:"license_spdx"`
	Homepage      string   `json:"homepage"`
	Family        string   `json:"family"`
	Targets       []string `json:"targets"`
	Network       string   `json:"network"`
	Intrusive     bool     `json:"intrusive"`
	RequiresBuild bool     `json:"requires_build"`
	Parser        string   `json:"parser"`
	FirstParty    bool     `json:"first_party"`
}

func (d PluginDef) advert() toolAdvert {
	network := d.Network
	if network == "" {
		network = "none"
	}
	return toolAdvert{Name: firstNonEmptyStr(d.DisplayName, d.Name), Category: d.Category, ScanTypes: d.ScanTypes, LicenseSPDX: d.LicenseSPDX,
		Homepage: d.Homepage, Family: d.Family, Targets: d.Targets, Network: network, Intrusive: d.Intrusive, RequiresBuild: d.RequiresBuild,
		Parser: d.parser.String(), FirstParty: d.FirstParty}
}

// pluginTool runs a manifest tool.
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
	pairs := []string{"{source}", in.Src, "{output}", in.Out, "{cache}", filepath.Join(t.cacheDir, "plugins", t.def.Name), "{tmp}", tmp}
	if tg := in.Target; tg != nil {
		switch tg.Kind {
		case "url", "api":
			pairs = append(pairs, "{target_url}", tg.Reference)
			if tg.Kind == "api" {
				pairs = append(pairs, "{openapi}", in.TargetFile)
			}
		case "image":
			pairs = append(pairs, "{image}", tg.Reference)
		case "artifact":
			pairs = append(pairs, "{artifact}", in.TargetFile)
		}
	}
	r := strings.NewReplacer(pairs...)
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = r.Replace(a)
	}
	return out
}

// noProxyEnv removes the egress proxy from the environment of tools that
// declare network: none (the worker's networks reach nothing else).
var noProxyEnv = []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"}

func (t pluginTool) Run(ctx context.Context, in RunInput) (string, error) {
	kind := ""
	if in.Target != nil {
		kind = in.Target.Kind
	}
	if !t.def.RunsOn(kind) {
		if kind == "" {
			return "this tool scans " + strings.Join(t.def.Targets, ", ") + " targets, not repositories", nil
		}
		return "this tool does not scan " + kind + " targets", nil
	}
	if t.def.Intrusive && (in.Target == nil || !in.Target.IntrusiveAuthorized) {
		return "intrusive testing of this target is not authorized", nil
	}
	if strings.Contains(strings.Join(t.def.Args, " "), "{openapi}") && kind == "api" && in.TargetFile == "" {
		return "", errors.New("the API target has no OpenAPI document")
	}
	if t.def.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.def.timeout)
		defer cancel()
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
	if t.def.Network == "none" {
		env = append(env, noProxyEnv...)
	}
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
	if t.def.parser.Kind == "sarif" {
		return "", ensureReport(in.Out, t.def.Key())
	}
	// Other formats: an empty report stays empty (no findings).
	if _, err := os.Stat(in.Out); errors.Is(err, os.ErrNotExist) {
		return "", os.WriteFile(in.Out, nil, 0o600)
	}
	return "", nil
}

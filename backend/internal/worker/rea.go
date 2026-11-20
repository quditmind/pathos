package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Reverse engineering, static tier (PATHOS 3.0 M10, ADR-009). The
// worker-rea family image contains pathos-rea, which analyses a build
// artifact with radare2, binwalk and the optional Ghidra, Jadx and ILSpy
// and writes normalised facts (pathos.rea/v1: sections, functions,
// imports, strings with secrets redacted, the call graph). Parsing an
// untrusted binary can trigger a parser bug, so pathos-rea never runs in
// the worker container: like repository code it runs only in the sandbox
// runner (no network interface, its own UID, no worker token, read-only
// root filesystem, no capabilities, its own CPU, memory and pids limits).
// The artifact is never executed. Without a runner the analysis fails
// (never runs elsewhere).

// REABinary is pathos-rea in the worker-rea image.
const REABinary = "/opt/pathos/rea/bin/pathos-rea"

// REAKey is the catalog key of the analysis (scanners.PathosREA).
const REAKey = "pathos-rea"

// JobKindREA marks reverse-engineering executions (trigger "rea"): only
// pathos-rea runs, on the raw artifact (no archive extraction).
const JobKindREA = "rea"

// REATools are the analysis tools pathos-rea knows.
var REATools = []string{"radare2", "binwalk", "ghidra", "jadx", "ilspy"}

// REAConfig is the per-analysis configuration sent with the lease (the
// organization's reverse-engineering settings).
type REAConfig struct {
	Tools          []string `json:"tools"`
	MemoryMB       int      `json:"memory_mb"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	MaxFunctions   int      `json:"max_functions"`
	MaxStrings     int      `json:"max_strings"`
	MaxCode        int      `json:"max_code"`
}

func (c *REAConfig) normalise() {
	var tools []string
	for _, t := range c.Tools {
		if slices.Contains(REATools, t) && !slices.Contains(tools, t) {
			tools = append(tools, t)
		}
	}
	if len(tools) == 0 {
		tools = []string{"radare2", "binwalk"}
	}
	c.Tools = tools
	if c.MemoryMB < 256 || c.MemoryMB > 65536 {
		c.MemoryMB = 4096
	}
	if c.TimeoutSeconds < 60 || c.TimeoutSeconds > int(sandboxMaxTimeout/time.Second) {
		c.TimeoutSeconds = 1800
	}
	if c.MaxFunctions <= 0 || c.MaxFunctions > 100000 {
		c.MaxFunctions = 20000
	}
	if c.MaxStrings <= 0 || c.MaxStrings > 100000 {
		c.MaxStrings = 20000
	}
	if c.MaxCode < 0 || c.MaxCode > 1000 {
		c.MaxCode = 200
	}
}

type reaTool struct{ sandbox *Sandbox }

// Version is pathos-rea's whole version line with the tools it contains
// ("pathos-rea 3.0; radare2 6.2.6; binwalk 3.1.0; ilspy 11.2"): the API
// reads the installed tools from it. Tools that are not installed ("-") are
// left out, and the line is kept within the 100 characters a worker may
// advertise per tool.
func (t reaTool) Version(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, REABinary, "version")
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return compactREAVersion(string(out)), nil
}

func compactREAVersion(out string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	var parts []string
	n := 0
	for _, p := range strings.Split(line, ";") {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasSuffix(p, " -") {
			continue
		}
		if n+len(p)+2 > 100 {
			break
		}
		parts = append(parts, p)
		n += len(p) + 2
	}
	return strings.Join(parts, "; ")
}

var reaNameRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// reaInputName is a safe file name for the artifact in the job directory.
func reaInputName(name string) string {
	name = reaNameRe.ReplaceAllString(filepath.Base(strings.ReplaceAll(name, "\\", "/")), "_")
	name = strings.TrimLeft(name, ".")
	if name == "" || name == "_" {
		name = "artifact.bin"
	}
	if len(name) > 120 {
		name = name[len(name)-120:]
	}
	return name
}

func (t reaTool) Run(ctx context.Context, in RunInput) (string, error) {
	tg := in.Target
	if tg == nil || (tg.Kind != "artifact" && tg.Kind != "mobile-app") {
		return "reverse engineering analyses uploaded build artifacts only", nil
	}
	if t.sandbox == nil {
		// Never parse an untrusted binary in the worker container.
		return "", errors.New("reverse engineering needs the sandbox runner (" + SandboxDirEnv + ", worker-rea-sandbox); the artifact was not analysed")
	}
	if in.TargetFile == "" {
		return "", errors.New("the artifact file is not available")
	}
	st, err := os.Stat(in.TargetFile)
	if err != nil || !st.Mode().IsRegular() {
		return "", errors.New("the artifact file is not available")
	}
	var cfg REAConfig
	if len(in.Config) > 0 {
		if err := json.Unmarshal(in.Config, &cfg); err != nil {
			return "", fmt.Errorf("invalid analysis configuration: %w", err)
		}
	}
	cfg.normalise()
	stage, err := os.MkdirTemp(filepath.Dir(in.Out), "rea-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	name := reaInputName(tg.FileName)
	if err := os.MkdirAll(filepath.Join(stage, "input"), 0o700); err != nil {
		return "", err
	}
	if err := copyFile(in.TargetFile, filepath.Join(stage, "input", name)); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(stage, "config.json"), raw, 0o600); err != nil {
		return "", err
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < timeout {
		timeout = time.Until(dl)
	}
	if timeout <= 0 {
		return "", context.DeadlineExceeded
	}
	res, err := t.sandbox.RunUntrusted(ctx, UntrustedJob{Source: stage, Command: REABinary,
		Args:    []string{"analyse", "{source}/config.json", "{source}/input/" + name, "{output}", "{tmp}"},
		Timeout: timeout, Output: in.Out, Dir: "tmp"})
	if err != nil {
		return "", err
	}
	if c := collectorFrom(ctx); c != nil {
		w := c.writer()
		_, _ = w.Write(res.Log)
		w.close()
	}
	switch {
	case res.TimedOut:
		return "", fmt.Errorf("pathos-rea timed out in the sandbox after %s", timeout.Round(time.Second))
	case res.Signal != "":
		return "", fmt.Errorf("pathos-rea was killed by %s in the sandbox (memory limit?): %s", res.Signal, lastLogLine(res.Log))
	case res.ExitCode != 0:
		return "", fmt.Errorf("pathos-rea exited with %d: %s", res.ExitCode, lastLogLine(res.Log))
	case !res.OutputWritten:
		return "", errors.New("pathos-rea wrote no analysis document")
	}
	return "", nil
}

func copyFile(src, dst string) error {
	// #nosec G304 -- src is the artifact the worker downloaded into its job directory
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// #nosec G304 -- dst is in a directory the worker just created
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

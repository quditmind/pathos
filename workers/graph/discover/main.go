// Command pathos-graph builds the CodeGraph of a source tree (PATHOS
// worker-graph family). It reads source files only: repository code is
// never built or executed, and nothing is fetched from the network. The
// helper engines (Opengrep, Syft) run as separate processes with a
// minimal environment (no proxy settings).
//
//	pathos-graph version
//	pathos-graph discover [--rules DIR] [--opengrep BIN] [--syft BIN] <source-dir> <output-file>
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
)

const (
	defaultRules    = "/opt/pathos/graph/rules"
	defaultOpengrep = "/usr/local/bin/opengrep"
	defaultSyft     = "/usr/local/bin/syft"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func executable(p string) string {
	if p == "" {
		return ""
	}
	if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
		return p
	}
	return ""
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: pathos-graph version | discover [--rules DIR] [--opengrep BIN] [--syft BIN] <source-dir> <output-file>")
		return 2
	}
	switch args[0] {
	case "version", "--version":
		ev := engineVersions()
		keys := make([]string, 0, len(ev))
		for k := range ev {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		_, _ = fmt.Fprintf(stdout, "pathos-graph %s\n", Version)
		for _, k := range keys {
			if k != "pathos-graph" {
				_, _ = fmt.Fprintf(stdout, "  %s %s\n", k, ev[k])
			}
		}
		return 0
	case "discover":
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rules := fs.String("rules", defaultRules, "directory of the PATHOS graph rules (Opengrep)")
	og := fs.String("opengrep", defaultOpengrep, "opengrep binary (empty: skip rule-based extraction)")
	syft := fs.String("syft", defaultSyft, "syft binary (empty: skip SBOM components)")
	maxFiles := fs.Int("max-files", 50000, "maximum number of files considered")
	maxNodes := fs.Int("max-nodes", 300000, "maximum number of nodes")
	maxEdges := fs.Int("max-edges", 300000, "maximum number of edges")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		_, _ = fmt.Fprintln(stderr, "discover needs <source-dir> <output-file>")
		return 2
	}
	src, out := fs.Arg(0), fs.Arg(1)
	if st, err := os.Stat(src); err != nil || !st.IsDir() {
		_, _ = fmt.Fprintf(stderr, "source directory %q not found\n", src)
		return 2
	}
	opts := DefaultOptions()
	opts.MaxFiles, opts.MaxNodes, opts.MaxEdges = *maxFiles, *maxNodes, *maxEdges
	opts.Opengrep, opts.Syft = executable(*og), executable(*syft)
	if st, err := os.Stat(*rules); err == nil && st.IsDir() {
		opts.RulesDir = *rules
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, err := Discover(ctx, src, opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "discovery failed: %v\n", err)
		return 1
	}
	if err := writeAtomic(out, res); err != nil {
		_, _ = fmt.Fprintf(stderr, "writing %s: %v\n", out, err)
		return 1
	}
	_, _ = fmt.Fprintf(stderr, "pathos-graph: %d files, %d nodes, %d edges in %d ms (truncated: %v)\n",
		res.Stats.FilesScanned, res.Stats.NodeCount, res.Stats.EdgeCount, res.Stats.DurationMS, res.Stats.Truncated)
	return 0
}

func writeAtomic(out string, res *Output) error {
	dir := filepath.Dir(out)
	tmp, err := os.CreateTemp(dir, ".pathos-graph-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	err = res.Write(tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(name, out)
	}
	if err != nil {
		_ = os.Remove(name)
		return errors.Join(err)
	}
	// The report is read by the worker agent (same user) and by operators
	// running the tool by hand; it holds no secret values.
	return os.Chmod(out, 0o644) // #nosec G302 -- report file, no secrets
}

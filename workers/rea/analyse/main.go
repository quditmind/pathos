// Command pathos-rea is the static reverse-engineering analyser of the
// PATHOS worker-rea image (PATHOS 3.0 M10, ADR-009). It runs only inside
// the sandbox runner (no network, its own UID, read-only root filesystem,
// no capabilities, CPU, memory and pids limits) and never executes the
// artifact it analyses: radare2, binwalk and the optional Ghidra, Jadx and
// ILSpy only read it, each as a separate process with its own time budget
// and memory limit. It writes normalised facts (pathos.rea/v1).
//
//	pathos-rea version
//	pathos-rea analyse <config.json> <input-file> <output.json> <tmpdir>
//	pathos-rea selftest <output.json>
//	pathos-rea limit <memory_mb> -- <tool> [args...]   (internal)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Version is set at build time (-X main.Version=...).
var Version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Println(versionLine(context.Background()))
		return 0
	case "limit":
		return limitMain(args[1:])
	case "selftest":
		if len(args) != 2 {
			usage()
			return 2
		}
		if err := selftest(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "selftest:", err)
			return 1
		}
		return 0
	case "analyse", "analyze":
		if len(args) != 5 {
			usage()
			return 2
		}
		return analyseMain(args[1], args[2], args[3], args[4])
	}
	usage()
	return 2
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pathos-rea version | analyse <config.json> <input> <output.json> <tmpdir> | selftest <output.json>")
}

// versionLine is "pathos-rea <v>; radare2 <v>; binwalk <v>; ghidra <v|->; jadx <v|->; ilspy <v|->".
func versionLine(ctx context.Context) string {
	v := toolVersions(ctx)
	parts := []string{"pathos-rea " + Version}
	for _, t := range []string{"radare2", "binwalk", "ghidra", "jadx", "ilspy"} {
		x := v[t]
		if x == "" {
			x = "-"
		}
		parts = append(parts, t+" "+x)
	}
	return strings.Join(parts, "; ")
}

func analyseMain(cfgPath, input, out, tmp string) int {
	var cfg Config
	// #nosec G304 G703 -- the configuration the worker wrote into the job directory (pathos-rea's argument)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		return 1
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		return 1
	}
	cfg.normalise()
	// #nosec G703 -- the job's temporary directory (pathos-rea's argument)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "tmp:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
	defer cancel()
	d, err := analyse(ctx, cfg, input, tmp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "analysis failed:", err)
		return 1
	}
	if err := writeDoc(d, out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("pathos-rea: %s %s/%s, %d functions, %d imports, %d strings, %d calls\n", d.Artifact.Format, d.Artifact.Arch,
		d.Artifact.Language, len(d.Functions), len(d.Imports), len(d.Strings), len(d.Calls))
	return 0
}

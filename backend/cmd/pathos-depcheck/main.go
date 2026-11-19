// Command pathos-depcheck reports dependency-confusion and typosquatting
// risks in a repository's dependency declarations (package.json, .npmrc,
// requirements*.txt, pyproject.toml), offline. It is shipped in the
// worker-sca image and run by its tool manifest.
//
//	pathos-depcheck [-o report.json] <repository directory>
//	pathos-depcheck --version
//
// The report is JSON ({"tool", "version", "findings": [...]}); the exit
// status is 0 whether or not findings are reported, 2 on usage errors.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"pathos/internal/depcheck"
)

var version = "dev"

func main() {
	out := flag.String("o", "", "write the report to this file (default: standard output)")
	showVersion := flag.Bool("version", false, "print the version")
	flag.Parse()
	if *showVersion {
		fmt.Println("pathos-depcheck " + version)
		return
	}
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pathos-depcheck [-o report.json] <directory>")
		os.Exit(2)
	}
	fs, err := depcheck.Default().Scan(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "pathos-depcheck:", err)
		os.Exit(1)
	}
	if fs == nil {
		fs = []depcheck.Finding{}
	}
	b, _ := json.MarshalIndent(depcheck.Report{Tool: "pathos-depcheck", Version: version, Findings: depcheck.Sorted(fs)}, "", "  ")
	b = append(b, '\n')
	if *out == "" {
		_, err = os.Stdout.Write(b)
	} else {
		err = os.WriteFile(*out, b, 0o600)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pathos-depcheck:", err)
		os.Exit(1)
	}
}

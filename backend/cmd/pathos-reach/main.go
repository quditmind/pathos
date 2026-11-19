// Command pathos-reach reports which members of external modules a
// repository's JavaScript/TypeScript, Python and Java code calls, with call
// sites and caller chains, and the constructs it cannot follow (dynamic
// imports, computed member access, reflection), for function-level
// reachability of dependency vulnerabilities. It also marks Go packages
// that call methods through reflection. It reads source files only
// (nothing is built or run) and needs no network. It is shipped in the
// worker-sca image and run by its tool manifest.
//
//	pathos-reach [-o report.json] <repository directory>
//	pathos-reach --version
//
// The report is JSON (reachscan.Report); the exit status is 0 when it was
// written, 1 on errors and 2 on usage errors.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"pathos/internal/reachscan"
)

var version = "dev"

func main() {
	out := flag.String("o", "", "write the report to this file (default: standard output)")
	showVersion := flag.Bool("version", false, "print the version")
	flag.Parse()
	if *showVersion {
		fmt.Println("pathos-reach " + version)
		return
	}
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pathos-reach [-o report.json] <directory>")
		os.Exit(2)
	}
	r, err := reachscan.Scan(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "pathos-reach:", err)
		os.Exit(1)
	}
	r.Version = version
	b, _ := json.Marshal(r)
	b = append(b, '\n')
	if *out == "" {
		_, err = os.Stdout.Write(b)
	} else {
		err = os.WriteFile(*out, b, 0o600)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pathos-reach:", err)
		os.Exit(1)
	}
}

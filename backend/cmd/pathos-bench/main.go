// Command pathos-bench is the scoring side of the benchmark harness
// (benchmarks/run.sh, docs/BENCHMARKS.md). It never runs scanners itself:
// the worker images do (`pathos-worker run-local`).
//
//	pathos-bench owasp-labels -csv expectedresults.csv -suite NAME -source TEXT -license SPDX -out labels.json
//	pathos-bench gen-secrets -dir DIR [-seed N]       writes DIR/src and DIR/labels.json
//	pathos-bench score -labels labels.json -out result.json [-exclude k1,k2] [-name NAME] [-require-recall F] RUNDIR...
//	pathos-bench report -out results.md result.json...
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"pathos/internal/bench"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "owasp-labels":
		err = owaspLabels(os.Args[2:])
	case "gen-secrets":
		err = genSecrets(os.Args[2:])
	case "score":
		err = score(os.Args[2:])
	case "report":
		err = report(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pathos-bench:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: pathos-bench owasp-labels|gen-secrets|score|report [flags]")
	os.Exit(2)
}

func writeJSON(file string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, append(raw, '\n'), 0o644) // #nosec G306 -- benchmark results, not sensitive
}

func owaspLabels(args []string) error {
	fs := flag.NewFlagSet("owasp-labels", flag.ExitOnError)
	csv := fs.String("csv", "", "expectedresults-*.csv")
	suite := fs.String("suite", "", "suite name")
	source := fs.String("source", "", "where the suite comes from")
	license := fs.String("license", "", "the suite's licence")
	out := fs.String("out", "", "labels file to write")
	_ = fs.Parse(args)
	if *csv == "" || *suite == "" || *out == "" {
		return fmt.Errorf("owasp-labels: -csv, -suite and -out are required")
	}
	l, err := bench.OWASPLabels(*csv, *suite, *source, *license)
	if err != nil {
		return err
	}
	return writeJSON(*out, l)
}

func genSecrets(args []string) error {
	fs := flag.NewFlagSet("gen-secrets", flag.ExitOnError)
	dir := fs.String("dir", "", "output directory")
	seed := fs.Uint64("seed", 20261119, "random seed")
	_ = fs.Parse(args)
	if *dir == "" {
		return fmt.Errorf("gen-secrets: -dir is required")
	}
	if _, err := os.Stat(filepath.Join(*dir, "src")); err == nil {
		return fmt.Errorf("gen-secrets: %s/src exists", *dir)
	}
	l, err := bench.GenerateSecrets(*dir, *seed)
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(*dir, "labels.json"), l)
}

func score(args []string) error {
	fs := flag.NewFlagSet("score", flag.ExitOnError)
	labels := fs.String("labels", "", "labels file")
	out := fs.String("out", "", "result file to write")
	exclude := fs.String("exclude", "", "comma-separated scanners to leave out")
	name := fs.String("name", "", "suite name in the result (default: the labels' suite name)")
	floor := fs.Float64("require-recall", -1, "fail unless every tool that ran and the combined result reach this recall (smoke runs)")
	_ = fs.Parse(args)
	if *labels == "" || *out == "" || fs.NArg() == 0 {
		return fmt.Errorf("score: -labels, -out and at least one run directory are required")
	}
	l, err := bench.LoadLabels(*labels)
	if err != nil {
		return err
	}
	runs, err := bench.LoadRuns(fs.Args()...)
	if err != nil {
		return err
	}
	if len(runs) == 0 {
		return bench.ErrNoRuns
	}
	if *exclude != "" {
		runs = bench.Exclude(runs, strings.Split(*exclude, ","))
	}
	if *name != "" {
		l.Suite = *name
	}
	res := bench.Score(l, runs)
	for _, t := range append(res.Tools, res.Combined) {
		m := t.Overall
		fmt.Printf("%-16s %-10s findings=%-6d TP=%-5d FP=%-5d FN=%-5d TN=%-5d", t.Scanner, t.Status, t.Findings, m.TP, m.FP, m.FN, m.TN)
		if m.Score != nil && m.Recall != nil && m.FPR != nil {
			fmt.Printf(" TPR=%.3f FPR=%.3f score=%+.3f", *m.Recall, *m.FPR, *m.Score)
		}
		if t.Error != "" {
			fmt.Printf(" (%s)", strings.SplitN(t.Error, "\n", 2)[0])
		}
		fmt.Println()
	}
	if err := writeJSON(*out, res); err != nil {
		return err
	}
	if *floor >= 0 {
		for _, t := range append(res.Tools, res.Combined) {
			if t.Status != "succeeded" {
				return fmt.Errorf("%s did not run: %s %s", t.Scanner, t.Status, t.Error)
			}
			if t.Overall.Recall == nil || *t.Overall.Recall < *floor {
				return fmt.Errorf("%s: recall below %.2f", t.Scanner, *floor)
			}
		}
	}
	return nil
}

func report(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	out := fs.String("out", "", "Markdown file to write")
	_ = fs.Parse(args)
	if *out == "" || fs.NArg() == 0 {
		return fmt.Errorf("report: -out and at least one result file are required")
	}
	var results []bench.Result
	for _, f := range fs.Args() {
		// #nosec G304 -- result files chosen by the operator
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var r bench.Result
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		results = append(results, r)
	}
	return os.WriteFile(*out, []byte(bench.Markdown(results)), 0o644) // #nosec G306 -- benchmark report
}

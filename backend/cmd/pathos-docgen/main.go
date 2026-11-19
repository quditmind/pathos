// Command pathos-docgen writes the troubleshooting pages generated from the
// error catalogue (backend/internal/platform/diag):
//
//	pathos-docgen -out ../docs/troubleshooting      (make docs-errors)
//
// Every page of the directory is rewritten and pages of areas that no
// longer have codes are removed, so the directory always matches the
// catalogue (a test in internal/platform/diag checks it).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"pathos/internal/platform/diag"
)

func main() {
	out := flag.String("out", "../docs/troubleshooting", "output directory")
	flag.Parse()
	if err := write(*out); err != nil {
		fmt.Fprintln(os.Stderr, "pathos-docgen:", err)
		os.Exit(1)
	}
}

func write(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	files := diag.DocFiles()
	old, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		return err
	}
	for _, p := range old {
		if _, keep := files[filepath.Base(p)]; !keep {
			if err := os.Remove(p); err != nil {
				return err
			}
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(files[n]), 0o644); err != nil { // #nosec G306 -- public documentation
			return err
		}
	}
	fmt.Printf("wrote %d pages (%d codes) to %s: %s\n", len(names), len(diag.All()), dir, strings.Join(names, ", "))
	return nil
}

// Command pathos-loadgen fills a PATHOS database with synthetic data at
// scale and drives the worker API, for the measurements in
// docs/PERFORMANCE.md. It is a development tool: no image builds it and it
// must never be pointed at a database with real data.
//
//	pathos-loadgen seed      -db <superuser DSN> [-repos 10000] [-findings 1000000] ...
//	pathos-loadgen ingest    -worker-api http://api:8081 -bootstrap-token ... -db ...
//	pathos-loadgen recompute -db <DSN> [-limits 500,2000,5000]
//	pathos-loadgen sizes     -db <DSN>
//	pathos-loadgen cleanup   -db <superuser DSN>
//
// seed writes with SQL (INSERT ... SELECT generate_series), because a million
// findings cannot go through scans in reasonable time; ingest uses the real
// worker protocol (register, lease, upload SARIF, complete), so the ingest
// code path is what gets measured. Every synthetic row belongs to the
// archived SCM connection "loadgen" (repositories are not scan-enabled), so
// schedules, webhooks and SCM sync ignore it, and cleanup removes it.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: pathos-loadgen <seed|ingest|recompute|sizes|cleanup> [flags]
run "pathos-loadgen <command> -h" for the flags of a command`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dsn := fs.String("db", os.Getenv("PATHOS_LOADGEN_DB"), "PostgreSQL DSN (default $PATHOS_LOADGEN_DB)")
	var err error
	switch cmd {
	case "seed":
		var o seedOptions
		fs.IntVar(&o.Repos, "repos", 10000, "repositories")
		fs.IntVar(&o.Findings, "findings", 1000000, "findings")
		fs.IntVar(&o.Chunk, "chunk", 100000, "findings per transaction")
		fs.IntVar(&o.Apps, "apps", 500, "applications")
		fs.IntVar(&o.ComponentsPerRepo, "components", 150, "average SBOM components per repository")
		fs.IntVar(&o.CVEs, "cves", 5000, "distinct CVEs (and OSV records) in the vulnerability pool")
		fs.IntVar(&o.EPSS, "epss", 0, "synthetic EPSS rows to add for CVEs the EPSS feed does not have")
		_ = fs.Parse(args)
		err = seed(ctx, *dsn, o)
	case "ingest":
		var o ingestOptions
		fs.StringVar(&o.WorkerAPI, "worker-api", "http://api:8081", "worker API base URL")
		fs.StringVar(&o.BootstrapToken, "bootstrap-token", os.Getenv("PATHOS_WORKER_BOOTSTRAP_TOKEN"), "worker bootstrap token")
		fs.IntVar(&o.Workers, "workers", 8, "concurrent fake workers")
		fs.IntVar(&o.Jobs, "jobs", 200, "scan jobs to queue and process")
		fs.IntVar(&o.FindingsPerUpload, "findings-per-upload", 50, "SARIF results per upload")
		fs.IntVar(&o.RepoOffset, "repo-offset", 10, "first synthetic repository number to scan (uploaded repositories are multiples of 10)")
		fs.IntVar(&o.Stride, "stride", 1, "use every n-th uploaded repository (to give two runs comparable repositories)")
		fs.StringVar(&o.Out, "out", "", "write a JSON summary to this file")
		_ = fs.Parse(args)
		err = ingest(ctx, *dsn, o)
	case "recompute":
		limits := fs.String("limits", "2000", "comma-separated batch sizes to time")
		n := fs.Int("findings", 200000, "findings to mark dirty and re-score for each batch size")
		_ = fs.Parse(args)
		err = recompute(ctx, *dsn, *limits, *n)
	case "sizes":
		_ = fs.Parse(args)
		err = sizes(ctx, *dsn)
	case "cleanup":
		_ = fs.Parse(args)
		err = cleanup(ctx, *dsn)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// step runs fn and prints how long it took.
func step(name string, fn func() (int64, error)) error {
	t := time.Now()
	n, err := fn()
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	fmt.Printf("%-40s %12d rows %10.1f s\n", name, n, time.Since(t).Seconds())
	return nil
}

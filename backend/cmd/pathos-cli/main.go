// Command pathos is the PATHOS command-line client for CI/CD pipelines:
// import tool results and SBOMs, start scans, evaluate the security gate,
// list findings and export SBOMs through the REST API with an API token.
//
// It is built from backend/cmd/pathos-cli as the binary "pathos" and uses
// the standard library only. See docs/user-guide/ci-cd-integration.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// version is set at build time: -ldflags "-X main.version=1.1.1".
var version = "dev"

// Exit codes.
const (
	exitOK         = 0
	exitGateFailed = 1
	exitUsage      = 2
	exitError      = 3
	exitScanFailed = 4
)

const usageText = `pathos: PATHOS command-line client

Usage:
  pathos [global flags] <command> [flags]

Commands:
  import       upload a results file (or an SBOM with --sbom) to a repository
  scan         start a scan of a repository and follow it
  gate         evaluate the security gate of a scan (exit 1 when it fails)
  findings     list findings
  sbom export  download a repository's SBOM
  version      print the version

Global flags (also accepted after the command):
  --url URL          PATHOS base URL (env PATHOS_URL)
  --token TOKEN      REST API token (env PATHOS_TOKEN); prefer the env variable
  --token-file PATH  read the token from a file (env PATHOS_TOKEN_FILE)
  --ca-cert PATH     PEM CA certificate(s) to trust in addition to the system ones (env PATHOS_CA_CERT)
  --allow-http       allow a plain http:// URL to a host other than localhost
  --timeout DUR      timeout of each HTTP request (default 2m)
  --json             machine-readable JSON output on stdout
  --quiet            no progress output on stderr
  -v, --version      print the version

Exit codes: 0 success, 1 gate failed, 2 usage error,
            3 API, authentication, network or configuration error,
            4 scan failed, was cancelled or timed out.

Run "pathos <command> --help" for the flags of a command.
`

// usageError is a command-line mistake (exit 2).
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// exitErr carries a specific exit code.
type exitErr struct {
	code int
	msg  string
}

func (e exitErr) Error() string { return e.msg }

// config is the global configuration.
type config struct {
	URL       string
	Token     string
	TokenFile string
	CACert    string
	AllowHTTP bool
	Timeout   time.Duration
	JSON      bool
	Quiet     bool
}

// app is one invocation: configuration and output streams.
type app struct {
	cfg    config
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
	client *client
	// pollInterval between scan status requests.
	pollInterval time.Duration
}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// run executes the command line and returns the exit code.
func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	a := &app{stdout: stdout, stderr: stderr, getenv: getenv, pollInterval: 3 * time.Second}
	a.cfg = config{URL: getenv("PATHOS_URL"), Token: getenv("PATHOS_TOKEN"), TokenFile: getenv("PATHOS_TOKEN_FILE"),
		CACert: getenv("PATHOS_CA_CERT"), Timeout: 2 * time.Minute}
	code := a.run(args)
	return code
}

func (a *app) run(args []string) int {
	gfs := flag.NewFlagSet("pathos", flag.ContinueOnError)
	gfs.SetOutput(io.Discard)
	showVersion := false
	a.globalFlags(gfs)
	gfs.BoolVar(&showVersion, "v", false, "")
	gfs.BoolVar(&showVersion, "version", false, "")
	help := false
	gfs.BoolVar(&help, "h", false, "")
	gfs.BoolVar(&help, "help", false, "")
	if err := gfs.Parse(args); err != nil {
		return a.fail(usageError{err.Error()})
	}
	if help {
		fmt.Fprint(a.stdout, usageText)
		return exitOK
	}
	if showVersion {
		fmt.Fprintln(a.stdout, "pathos "+version)
		return exitOK
	}
	rest := gfs.Args()
	if len(rest) == 0 {
		fmt.Fprint(a.stderr, usageText)
		return exitUsage
	}
	cmd, rest := rest[0], rest[1:]
	var err error
	switch cmd {
	case "version":
		fmt.Fprintln(a.stdout, "pathos "+version)
		return exitOK
	case "help":
		fmt.Fprint(a.stdout, usageText)
		return exitOK
	case "import":
		err = a.cmdImport(rest)
	case "scan":
		err = a.cmdScan(rest)
	case "gate":
		err = a.cmdGate(rest)
	case "findings":
		err = a.cmdFindings(rest)
	case "sbom":
		if len(rest) == 0 || rest[0] != "export" {
			err = usagef("usage: pathos sbom export --repo <repository> [--format cyclonedx|spdx] [--output FILE]")
		} else {
			err = a.cmdSBOMExport(rest[1:])
		}
	default:
		err = usagef("unknown command %q (run pathos --help)", cmd)
	}
	return a.fail(err)
}

// fail prints err (with the token redacted) and returns its exit code.
func (a *app) fail(err error) int {
	if err == nil {
		return exitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	msg := a.redact(err.Error())
	var ue usageError
	var ee exitErr
	switch {
	case errors.As(err, &ue):
		fmt.Fprintln(a.stderr, "pathos: "+msg)
		return exitUsage
	case errors.As(err, &ee):
		if msg != "" {
			fmt.Fprintln(a.stderr, "pathos: "+msg)
		}
		return ee.code
	}
	fmt.Fprintln(a.stderr, "pathos: "+msg)
	return exitError
}

// redact removes the token from a message.
func (a *app) redact(s string) string {
	if t := strings.TrimSpace(a.cfg.Token); len(t) >= 4 {
		s = strings.ReplaceAll(s, t, "[REDACTED]")
	}
	return s
}

// globalFlags registers the global flags on fs (with the current values as
// defaults, so flags given before the command are kept).
func (a *app) globalFlags(fs *flag.FlagSet) {
	c := &a.cfg
	fs.StringVar(&c.URL, "url", c.URL, "PATHOS base URL (env PATHOS_URL)")
	fs.StringVar(&c.Token, "token", c.Token, "REST API token (env PATHOS_TOKEN)")
	fs.StringVar(&c.TokenFile, "token-file", c.TokenFile, "read the token from a file (env PATHOS_TOKEN_FILE)")
	fs.StringVar(&c.CACert, "ca-cert", c.CACert, "PEM CA certificate(s) to trust (env PATHOS_CA_CERT)")
	fs.BoolVar(&c.AllowHTTP, "allow-http", c.AllowHTTP, "allow a plain http:// URL to a host other than localhost")
	fs.DurationVar(&c.Timeout, "timeout", c.Timeout, "timeout of each HTTP request")
	fs.BoolVar(&c.JSON, "json", c.JSON, "JSON output")
	fs.BoolVar(&c.Quiet, "quiet", c.Quiet, "no progress output")
}

// commandFlags returns a flag set for a command with the global flags.
func (a *app) commandFlags(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	a.globalFlags(fs)
	fs.Usage = func() {
		fmt.Fprintf(a.stderr, "Usage: %s\n\nFlags:\n", usage)
		fs.PrintDefaults()
	}
	return fs
}

// parse parses command flags; positional arguments are not accepted.
func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err.Error()}
	}
	if fs.NArg() > 0 {
		return usagef("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

// progress prints a progress line on stderr unless --quiet.
func (a *app) progress(format string, args ...any) {
	if !a.cfg.Quiet {
		fmt.Fprintf(a.stderr, format+"\n", args...)
	}
}

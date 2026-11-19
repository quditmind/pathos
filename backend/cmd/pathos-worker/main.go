// Command pathos-worker is the scan worker agent embedded in worker images.
//
//	PATHOS_API_URL                  internal worker API, e.g. http://api:8081
//	PATHOS_WORKER_BOOTSTRAP_TOKEN   registration secret shared with the API
//	PATHOS_WORKER_NAME              stable worker name (default: hostname)
//	PATHOS_WORKER_FAMILY            worker family (default: core)
//	PATHOS_WORK_DIR / PATHOS_CACHE_DIR / PATHOS_RULES_DIRS
//	PATHOS_CLAMAV_ADDRESS           clamd host:port for the clamav scanner (optional)
//	PATHOS_SANDBOX_DIR              volume shared with the sandbox runner (optional;
//	                                tools that run repository code need it)
//
// `pathos-worker sandbox-runner` runs the sandbox runner instead: the
// process of the network-less sibling container that executes repository
// code for the worker (PATHOS_SANDBOX_DIR, default /sandbox). It needs no
// token. See internal/worker/sandbox.go.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"pathos/internal/platform/logging"
	"pathos/internal/worker"
)

var version = "dev"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "sandbox-runner" {
		log := logging.New(os.Stdout, env("PATHOS_LOG_LEVEL", "info")).With("service", "pathos-sandbox-runner")
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := worker.RunSandboxRunner(ctx, env(worker.SandboxDirEnv, "/sandbox"), log); err != nil {
			log.Error("sandbox runner stopped", "err", err)
			os.Exit(1)
		}
		return
	}
	log := logging.New(os.Stdout, env("PATHOS_LOG_LEVEL", "info")).With("service", "pathos-worker")
	token := os.Getenv("PATHOS_WORKER_BOOTSTRAP_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "PATHOS_WORKER_BOOTSTRAP_TOKEN is required")
		os.Exit(2)
	}
	// The registration secret must not leak into scanner processes.
	os.Unsetenv("PATHOS_WORKER_BOOTSTRAP_TOKEN")
	host, _ := os.Hostname()
	cfg := worker.Config{
		APIURL:         env("PATHOS_API_URL", "http://api:8081"),
		BootstrapToken: token,
		Name:           env("PATHOS_WORKER_NAME", host),
		Family:         env("PATHOS_WORKER_FAMILY", "core"),
		WorkDir:        env("PATHOS_WORK_DIR", "/work"),
		CacheDir:       env("PATHOS_CACHE_DIR", "/cache"),
		Offline:        env("PATHOS_OFFLINE", "false") == "true",
		PluginsDir:     env("PATHOS_SCANNER_PLUGINS_DIR", "/etc/pathos/scanners.d"),
		ToolsDir:       env("PATHOS_TOOLS_DIR", "/opt/pathos/tools.d"),
		ClamAVAddress:  strings.TrimSpace(os.Getenv("PATHOS_CLAMAV_ADDRESS")),
		SandboxDir:     strings.TrimSpace(os.Getenv(worker.SandboxDirEnv)),
		RulesDirs:      strings.Split(env("PATHOS_RULES_DIRS", "/opt/pathos/rules:/rules"), ":"),
		Version:        version,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := worker.New(cfg, log).Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("worker stopped", "err", err)
		os.Exit(1)
	}
}

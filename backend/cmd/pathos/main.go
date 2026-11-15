// Command pathos runs the PATHOS platform in one of its roles:
//
//	pathos            # role from PATHOS_ROLE (api | jobs | scheduler)
//	pathos healthcheck [url]  # container health probe (distroless has no curl)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"pathos/internal/auth"
	"pathos/internal/identity"
	"pathos/internal/org"
	"pathos/internal/platform/config"
	"pathos/internal/platform/db"
	"pathos/internal/platform/logging"
	"pathos/internal/server"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(server.Version)
		return
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error:\n%v\n", err)
		os.Exit(2)
	}
	log := logging.New(os.Stdout, cfg.LogLevel).With("service", "pathos", "role", string(cfg.Role), "version", server.Version)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var runErr error
	switch cfg.Role {
	case config.RoleAPI:
		runErr = runAPI(ctx, cfg, log)
	case config.RoleJobs:
		runErr = runJobs(ctx, cfg, log)
	case config.RoleScheduler:
		runErr = errors.New("the scheduler role arrives in Phase 7")
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		log.Error("exiting", "err", runErr)
		os.Exit(1)
	}
}

func runAPI(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	pool, err := db.Connect(ctx, cfg.DatabaseURL, log)
	if err != nil {
		return err
	}
	defer pool.Close()

	ropt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("PATHOS_REDIS_URL: %w", err)
	}
	rdb := redis.NewClient(ropt)
	defer rdb.Close()

	var orgID [16]byte
	if err := pool.QueryRow(ctx, `SELECT id FROM organizations WHERE slug = $1`, cfg.OrgSlug).Scan(&orgID); err != nil {
		return fmt.Errorf("organization %q not found; run `pathosctl migrate` first: %w", cfg.OrgSlug, err)
	}

	authSvc := &auth.Service{
		Cfg: cfg, DB: pool, Log: log, OrgID: orgID,
		Sessions:   &auth.SessionStore{R: rdb, IdleTTL: cfg.SessionIdleTTL, AbsoluteTTL: cfg.SessionAbsoluteTTL},
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}
	var prov identity.Provisioner
	if cfg.OIDC.ProvisionerClientID != "" && cfg.OIDC.ProvisionerClientSecret != "" && cfg.OIDC.AdminBaseURL != "" {
		prov = &identity.KeycloakProvisioner{
			BaseURL: cfg.OIDC.AdminBaseURL, Realm: cfg.OIDC.Realm,
			ClientID: cfg.OIDC.ProvisionerClientID, ClientSecret: cfg.OIDC.ProvisionerClientSecret,
			// Must be registered on the pathos-web client (deploy/keycloak/pathos-realm.json).
			ActionsClientID: cfg.OIDC.ClientID, ActionsRedirectURI: cfg.PublicURL.String() + "/login",
		}
		log.Info("keycloak user provisioning enabled")
	}

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: server.Handler(server.Deps{DB: pool, Redis: rdb, Auth: authSvc, Provisioner: prov, OrgID: orgID, Log: log}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.HTTPAddr)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

// runJobs runs background maintenance. AI review, ingestion and
// notification workers join this role in later phases.
func runJobs(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	pool, err := db.Connect(ctx, cfg.DatabaseURL, log)
	if err != nil {
		return err
	}
	defer pool.Close()
	tick := func() {
		if err := org.EnsureAuditPartitions(ctx, pool); err != nil {
			log.Error("audit partition maintenance failed", "err", err)
		}
	}
	// Minimal health listener for container health checks.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		pctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(pctx); err != nil {
			http.Error(w, "db unreachable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	hs := &http.Server{Addr: cfg.HTTPAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("health listener", "err", err)
		}
	}()
	defer hs.Close()

	tick()
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	log.Info("jobs runner started")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			tick()
		}
	}
}

func healthcheck(args []string) int {
	url := "http://127.0.0.1:8080/healthz"
	if len(args) > 0 {
		url = args[0]
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "status", resp.StatusCode)
		return 1
	}
	return 0
}

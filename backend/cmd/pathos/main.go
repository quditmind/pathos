// Command pathos runs the PATHOS platform in one of its roles:
//
//	pathos            # role from PATHOS_ROLE (api | jobs | scheduler)
//	pathos healthcheck [url]  # container health probe (distroless has no curl)
package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"pathos/internal/platform/sourcestore"
	"pathos/internal/policy"
	"pathos/internal/reporting"
	"pathos/internal/repos"
	"pathos/internal/risk"
	"pathos/internal/tickets"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/mcp"
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/config"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
	"pathos/internal/platform/logging"
	"pathos/internal/platform/objstore"
	"pathos/internal/platform/ratelimit"
	"pathos/internal/platform/telemetry"
	"pathos/internal/scans"
	"pathos/internal/schedule"
	"pathos/internal/scm"
	"pathos/internal/secrets"
	"pathos/internal/server"
	"pathos/internal/vuln"
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

	host, _ := os.Hostname()
	shutdownTelemetry, err := telemetry.Setup(ctx, cfg.OTLPEndpoint, string(cfg.Role), server.Version, host)
	if err != nil {
		log.Error("telemetry setup failed", "err", err)
		os.Exit(1)
	}
	if cfg.OTLPEndpoint != "" {
		log.Info("OpenTelemetry export enabled", "endpoint", cfg.OTLPEndpoint)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTelemetry(sctx)
	}()

	var runErr error
	switch cfg.Role {
	case config.RoleAPI:
		runErr = runAPI(ctx, cfg, log)
	case config.RoleJobs:
		runErr = runJobs(ctx, cfg, log)
	case config.RoleScheduler:
		runErr = runScheduler(ctx, cfg, log)
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		log.Error("exiting", "err", runErr)
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = shutdownTelemetry(sctx)
		cancel()
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
			MFAForNewUsers: cfg.RequireMFA,
		}
		log.Info("keycloak user provisioning enabled")
	}
	if kp, ok := prov.(*identity.KeycloakProvisioner); ok && cfg.RequireMFA {
		// Existing users too: every active/invited account without an
		// authenticator must enrol at its next sign-in. Hourly, idempotent.
		go func() {
			t := time.NewTicker(time.Hour)
			defer t.Stop()
			for {
				if n, err := identity.EnforceMFA(ctx, pool, kp, log); err != nil {
					log.Error("MFA enforcement failed", "err", err)
				} else if n > 0 {
					log.Info("MFA now required for existing users", "count", n)
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
	}

	keys, err := crypto.NewKeyring(cfg.MasterKeys)
	if err != nil {
		return err
	}

	artifacts, err := artifactStore(ctx, cfg, log)
	if err != nil {
		return err
	}
	if err := mcp.EnsureBuiltIn(ctx, pool, orgID, cfg.PublicURL.String()); err != nil {
		return fmt.Errorf("seed MCP registry: %w", err)
	}
	if err := repos.EnsureAssetDefaults(ctx, pool, orgID); err != nil {
		return fmt.Errorf("seed asset classifications: %w", err)
	}
	sources, err := sourceStore(cfg, keys, log)
	if err != nil {
		return err
	}
	handlers := server.Build(server.Deps{DB: pool, Redis: rdb, Auth: authSvc, Provisioner: prov, OrgID: orgID, Log: log, Offline: cfg.Offline,
		Secrets: &secrets.Store{Keys: keys}, SCMNet: scm.NetPolicy{AllowPrivate: cfg.SCMAllowPrivate, AllowHTTP: cfg.SCMAllowHTTP},
		PublicURL: cfg.PublicURL.String(), WorkerBootstrapToken: cfg.WorkerBootstrapToken,
		RateLimiter: rateLimiter(cfg, rdb, log), RateLimitPolicy: scaledPolicy(cfg.RateLimitScale), Artifacts: artifacts,
		Sources: sources, Limits: importLimits(cfg)})
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handlers.Public,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	// Internal worker API on its own listener and network; never proxied.
	workerSrv := &http.Server{
		Addr:              cfg.WorkerAPIAddr,
		Handler:           handlers.Worker,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // large result uploads
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 2)
	go func() {
		log.Info("listening", "addr", cfg.HTTPAddr)
		errc <- srv.ListenAndServe()
	}()
	if cfg.WorkerBootstrapToken != "" {
		go func() {
			log.Info("worker API listening", "addr", cfg.WorkerAPIAddr)
			errc <- workerSrv.ListenAndServe()
		}()
	} else {
		log.Warn("PATHOS_WORKER_BOOTSTRAP_TOKEN not set: worker API disabled, scans will stay queued")
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	defer workerSrv.Close()
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

// runJobs runs background work: maintenance, AI review, notification
// delivery, risk-acceptance expiry and nightly SCM metadata re-sync.
func runJobs(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	pool, err := db.Connect(ctx, cfg.DatabaseURL, log)
	if err != nil {
		return err
	}
	defer pool.Close()
	artifacts, err := artifactStore(ctx, cfg, log)
	if err != nil {
		return err
	}
	tick := func() {
		if err := org.EnsureAuditPartitions(ctx, pool); err != nil {
			log.Error("audit partition maintenance failed", "err", err)
		}
		if n, err := scans.PruneArtifacts(ctx, pool, artifacts); err != nil {
			log.Error("artifact retention failed", "err", err)
		} else if n > 0 {
			log.Info("pruned scan artifacts past retention", "count", n)
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

	// AI review worker (no-op until a provider and configuration exist).
	keys, err := crypto.NewKeyring(cfg.MasterKeys)
	if err != nil {
		return err
	}
	az := &authz.Authorizer{}
	aiSvc := server.NewAIService(server.Deps{DB: pool, Log: log, Secrets: &secrets.Store{Keys: keys},
		SCMNet: scm.NetPolicy{AllowPrivate: cfg.SCMAllowPrivate}}, az)
	go aiSvc.RunWorker(ctx)

	// Notifications: outbox dispatch, email delivery, SLA breach detection.
	store := &secrets.Store{Keys: keys}
	go (&notify.Dispatcher{Pool: pool, Secrets: store, Sender: notify.SMTPSender{}, BaseURL: cfg.PublicURL.String(), Log: log}).Run(ctx)

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM organizations WHERE slug = $1`, cfg.OrgSlug).Scan(&orgID); err != nil {
		return fmt.Errorf("organization %q not found; run `pathosctl migrate` first: %w", cfg.OrgSlug, err)
	}
	sources, err := sourceStore(cfg, keys, log)
	if err != nil {
		return err
	}
	// Repository imports authorize placements against the hierarchy.
	repoAz := &authz.Authorizer{H: &org.Hierarchy{DB: pool, OrgID: orgID}}
	reposSvc := server.NewReposService(server.Deps{DB: pool, Log: log, Secrets: store,
		SCMNet: scm.NetPolicy{AllowPrivate: cfg.SCMAllowPrivate, AllowHTTP: cfg.SCMAllowHTTP}, PublicURL: cfg.PublicURL.String(),
		Sources: sources, Limits: importLimits(cfg)}, repoAz)
	if err := repos.EnsureAssetDefaults(ctx, pool, orgID); err != nil {
		return fmt.Errorf("seed asset classifications: %w", err)
	}
	host, _ := os.Hostname()
	go reposSvc.RunImportWorkers(ctx, cfg.ImportConcurrency, host)
	// SCM inventory for the unmanaged-asset report (daily per connection).
	go reposSvc.RunInventory(ctx)
	log.Info("repository import workers started", "concurrency", cfg.ImportConcurrency)
	// Human Review: automatic queue ingestion, capture of the original
	// scanner output before retention prunes it, overdue notifications.
	reviewSvc := server.NewReviewService(server.Deps{DB: pool, Log: log, Artifacts: artifacts}, repoAz, nil, nil)
	go reviewSvc.RunBackground(ctx)
	// Vulnerability intelligence feeds (EPSS, CISA KEV) and contextual risk
	// scores.
	go server.NewIntelService(server.Deps{DB: pool, Log: log, Offline: cfg.Offline}).RunBackground(ctx)
	go risk.RunBackground(ctx, pool, log)
	go func() {
		// OAuth tokens are refreshed before they expire; expired uploads
		// are removed.
		tk := time.NewTicker(10 * time.Minute)
		defer tk.Stop()
		n := 0
		for {
			reposSvc.RefreshExpiringTokens(ctx, 30*time.Minute)
			if n%6 == 0 {
				reposSvc.CleanupUploads(ctx)
				if _, err := pool.Exec(ctx, `DELETE FROM repository_sync_runs WHERE started_at < now() - interval '180 days'`); err != nil {
					log.Warn("sync history retention failed", "err", err)
				}
				for _, t := range []string{"scan_job_logs", "scan_job_events"} {
					// t is one of two constants.
					if _, err := pool.Exec(ctx, `DELETE FROM `+t+` WHERE at < now() - make_interval(days => $1)`, cfg.ScanLogRetentionDays); err != nil {
						log.Warn("scan log retention failed", "table", t, "err", err)
					}
				}
			}
			n++
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
			}
		}
	}()

	expire := func() {
		if n, err := vuln.ExpireSuppressionRules(ctx, pool); err != nil {
			log.Warn("suppression rule expiry failed", "err", err)
		} else if n > 0 {
			log.Info("suppression rules expired", "rules", n)
		}
		if n, err := vuln.ExpireAcceptances(ctx, pool); err != nil {
			log.Error("risk acceptance expiry failed", "err", err)
		} else if n > 0 {
			log.Info("expired risk acceptances; findings reopened", "count", n)
		}
		if n, err := reporting.RunDue(ctx, pool); err != nil {
			log.Warn("scheduled reports failed", "err", err)
		} else if n > 0 {
			log.Info("scheduled reports sent", "count", n)
		}
		// Ticket statuses (Jira, ServiceNow) for the finding drawer.
		ts := &tickets.Service{DB: pool, Secrets: store, Log: log}
		if n, err := ts.Sync(ctx); err != nil {
			log.Warn("ticket status sync failed", "err", err)
		} else if n > 0 {
			log.Debug("ticket statuses synced", "count", n)
		}
		// Security policies follow changes between scans (risk scores,
		// intelligence, repository context, finding age).
		var orgs []uuid.UUID
		if rows, err := pool.Query(ctx, `SELECT DISTINCT organization_id FROM security_policies WHERE enabled`); err == nil {
			orgs, _ = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		}
		for _, org := range orgs {
			var n int
			err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
				var err error
				n, err = policy.Evaluate(ctx, tx, org, nil)
				return err
			})
			if err != nil {
				log.Warn("security policy evaluation failed", "err", err)
			} else {
				log.Debug("security policies evaluated", "open_violations", n)
			}
		}
	}
	tick()
	expire()
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	te := time.NewTicker(10 * time.Minute)
	defer te.Stop()
	tr := time.NewTicker(24 * time.Hour)
	defer tr.Stop()
	log.Info("jobs runner started")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			tick()
		case <-te.C:
			expire()
		case <-tr.C:
			reposSvc.ResyncAll(ctx)
		}
	}
}

// runScheduler runs the leader-elected scan scheduler. Replicas are safe:
// one holds a Postgres advisory lock, the others wait as standbys.
// artifactStore connects the S3 object store when configured (nil keeps
// artifacts in PostgreSQL). The bucket is created if missing.
func artifactStore(ctx context.Context, cfg *config.Config, log *slog.Logger) (objstore.Store, error) {
	if cfg.S3Bucket == "" {
		return nil, nil
	}
	st, err := objstore.NewS3(objstore.Config{Endpoint: cfg.S3Endpoint, Region: cfg.S3Region, Bucket: cfg.S3Bucket,
		AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey, PathStyle: cfg.S3PathStyle})
	if err != nil {
		return nil, err
	}
	var lastErr error
	for range 30 { // the object store may still be starting
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		lastErr = st.EnsureBucket(cctx)
		cancel()
		if lastErr == nil {
			log.Info("scan artifacts stored in object storage", "endpoint", cfg.S3Endpoint, "bucket", cfg.S3Bucket)
			return st, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, fmt.Errorf("object store %s/%s unavailable: %w", cfg.S3Endpoint, cfg.S3Bucket, lastErr)
}

// sourceStore opens the encrypted store for uploads and snapshots: S3 when
// PATHOS_S3_BUCKET is set, otherwise PATHOS_SOURCE_STORE_DIR.
func sourceStore(cfg *config.Config, keys *crypto.Keyring, log *slog.Logger) (repos.SourceStore, error) {
	if cfg.S3Bucket != "" {
		st, err := sourcestore.NewS3(objstore.Config{Endpoint: cfg.S3Endpoint, Region: cfg.S3Region, Bucket: cfg.S3Bucket,
			AccessKey: cfg.S3AccessKey, SecretKey: cfg.S3SecretKey, PathStyle: cfg.S3PathStyle}, cfg.SourceS3Prefix, keys)
		if err != nil {
			return nil, err
		}
		st.TempDir = cfg.ImportWorkDir
		log.Info("source snapshots stored in object storage", "bucket", cfg.S3Bucket, "prefix", cfg.SourceS3Prefix)
		return st, nil
	}
	if cfg.SourceStoreDir == "" {
		log.Warn("no source store configured: local uploads disabled")
		return nil, nil
	}
	st, err := sourcestore.NewFS(cfg.SourceStoreDir, keys)
	if err != nil {
		return nil, fmt.Errorf("PATHOS_SOURCE_STORE_DIR: %w", err)
	}
	log.Info("source snapshots stored on disk (encrypted)", "dir", cfg.SourceStoreDir)
	return st, nil
}

func importLimits(cfg *config.Config) repos.Limits {
	return repos.Limits{UploadMaxBytes: cfg.UploadMaxBytes, MaxFiles: cfg.ImportMaxFiles, MaxExtractedBytes: cfg.ImportMaxExtractedBytes,
		MaxFileBytes: cfg.ImportMaxFileBytes, ImportTimeout: cfg.ImportTimeout, ClamAVAddress: cfg.ClamAVAddress,
		ClamAVRequired: cfg.ClamAVRequired, WorkDir: cfg.ImportWorkDir}
}

// rateLimiter returns the shared Valkey limiter, or nil when disabled.
func rateLimiter(cfg *config.Config, rdb redis.UniversalClient, log *slog.Logger) ratelimit.Limiter {
	if cfg.RateLimitScale == 0 {
		log.Warn("API rate limiting disabled (PATHOS_RATE_LIMIT_SCALE=0)")
		return nil
	}
	return &ratelimit.Redis{R: rdb, Prefix: "pathos:rl:"}
}

func scaledPolicy(f float64) ratelimit.Policy {
	p := ratelimit.DefaultPolicy()
	for _, r := range []*ratelimit.Rule{&p.Auth, &p.Anonymous, &p.Read, &p.Write, &p.Webhook, &p.MCP} {
		r.PerSecond *= f
		r.Burst = max(1, int(float64(r.Burst)*f))
	}
	return p
}

func runScheduler(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	pool, err := db.Connect(ctx, cfg.DatabaseURL, log)
	if err != nil {
		return err
	}
	defer pool.Close()
	host, _ := os.Hostname()
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
	log.Info("scheduler started", "holder", host)
	sch := &schedule.Scheduler{Pool: pool, Log: log, Holder: host, Interval: 15 * time.Second}
	if err := schedule.RegisterMetrics(pool, sch.IsLeader); err != nil {
		return err
	}
	return sch.Run(ctx)
}

func healthcheck(args []string) int {
	url := "http://127.0.0.1:8080/healthz"
	if len(args) > 0 {
		url = args[0]
	}
	c := &http.Client{Timeout: 3 * time.Second}
	// #nosec G704 -- container health probe; URL comes from the healthcheck command line (localhost)
	resp, err := c.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "status", resp.StatusCode)
		return 1
	}
	return 0
}

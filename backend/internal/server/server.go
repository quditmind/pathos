// Package server assembles the HTTP API.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"pathos/internal/ai"
	"pathos/internal/analyst"
	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/compliance"
	"pathos/internal/connectors"
	"pathos/internal/dashboard"
	"pathos/internal/diagnostics"
	"pathos/internal/eol"
	"pathos/internal/featureflags"
	"pathos/internal/gates"
	"pathos/internal/identity"
	"pathos/internal/insights"
	"pathos/internal/intel"
	"pathos/internal/mcp"
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/buildinfo"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/objstore"
	"pathos/internal/platform/ratelimit"
	"pathos/internal/platform/telemetry"
	"pathos/internal/policy"
	"pathos/internal/posture"
	"pathos/internal/pushprotect"
	"pathos/internal/releases"
	"pathos/internal/remediation"
	"pathos/internal/reporting"
	"pathos/internal/repos"
	"pathos/internal/review"
	"pathos/internal/risk"
	"pathos/internal/runtimectx"
	"pathos/internal/scans"
	"pathos/internal/schedule"
	"pathos/internal/scm"
	"pathos/internal/search"
	"pathos/internal/secrets"
	"pathos/internal/tenancy"
	"pathos/internal/tickets"
	"pathos/internal/vuln"
)

type Deps struct {
	DB          *pgxpool.Pool
	Redis       redis.UniversalClient
	Auth        *auth.Service
	Provisioner identity.Provisioner
	// OrgID is the default organization (PATHOS_ORG_SLUG).
	OrgID uuid.UUID
	// MultiTenant is set when multi-tenancy is enabled
	// (docs/MULTI_TENANCY.md).
	MultiTenant bool
	Log         *slog.Logger
	Secrets     *secrets.Store
	SCMNet      scm.NetPolicy
	PublicURL   string
	// WorkerBootstrapToken enables worker registration.
	WorkerBootstrapToken string
	// Artifacts is the object store for scan artifacts (nil: PostgreSQL).
	Artifacts objstore.Store
	// Sources stores uploads and source snapshots (nil disables uploads).
	Sources repos.SourceStore
	// Limits bounds uploads and imports.
	Limits repos.Limits
	// RateLimiter enables API rate limiting with RateLimitPolicy (nil: off).
	RateLimiter     ratelimit.Limiter
	RateLimitPolicy ratelimit.Policy
	// Offline disables online intelligence downloads (air-gapped).
	Offline bool
	// Connectors hub: the egress proxy URL to check, the check interval and
	// a non-secret description of the object store.
	EgressProxyURL         string
	ConnectorCheckInterval time.Duration
	ObjectStoreMeta        map[string]string
}

// Handlers bundles the public handler and the internal worker handler.
type Handlers struct {
	Public http.Handler
	Worker http.Handler
}

// Handler builds the public handler (kept for tests and simple callers).
func Handler(d Deps) http.Handler { return Build(d).Public }

// Build assembles the public API and the internal worker API.
func Build(d Deps) Handlers {
	// The hierarchy takes the organization from the request context; the
	// default organization is a fallback for single-organization installs
	// only (with multi-tenancy an unscoped lookup finds nothing).
	hierarchyOrg := d.OrgID
	if d.MultiTenant {
		hierarchyOrg = uuid.Nil
	}
	az := &authz.Authorizer{H: &org.Hierarchy{DB: d.DB, OrgID: hierarchyOrg}}

	public := http.NewServeMux()
	public.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": buildinfo.Version})
	})
	public.HandleFunc("GET /readyz", readiness(d))
	public.HandleFunc("GET /api/auth/login", d.Auth.HandleLogin)
	public.HandleFunc("GET /api/auth/callback", d.Auth.HandleCallback)
	// Organization switcher: these two also work while the session's
	// organization is suspended (to switch away), so they check the
	// session themselves instead of RequireAuth.
	public.HandleFunc("GET /api/v1/me/organizations", d.Auth.HandleMyOrganizations)
	public.HandleFunc("POST /api/v1/me/organization", d.Auth.HandleSwitchOrganization)

	repoSvc := NewReposService(d, az)
	scanSvc := &scans.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom,
		CloneCredential: repoSvc.CloneCredential, BootstrapToken: d.WorkerBootstrapToken, OrgID: d.OrgID, Artifacts: d.Artifacts,
		OpenSnapshot: repoSvc.OpenSnapshot, Secrets: d.Secrets}
	pushSvc := &pushprotect.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom, Diff: repoSvc.PushDiffReader}
	repoSvc.OnEvent = func(ctx context.Context, orgID, repoID uuid.UUID, ev scm.WebhookEvent) {
		scanSvc.OnWebhookEvent(ctx, orgID, repoID, ev)
		pushSvc.OnPush(ctx, orgID, repoID, ev) // secret push protection (opt-in per repository)
	}
	repoSvc.RegisterPublic(public)
	aiSvc := NewAIService(d, az)
	// Product metadata (GET /api/v1/meta answers without authentication
	// with product, vendor and version only) and the diagnostic engine.
	// Connectors hub (flag "connectors"). The API runs the checks of kinds
	// it already calls for their test buttons; Kubernetes, registries and
	// the egress proxy are checked by the jobs service only (no runtime
	// checker here).
	connSvc := &connectors.Service{Env: ConnectorEnv(d, "api", repoSvc, aiSvc, nil), Log: d.Log, Principal: auth.PrincipalFrom}
	diagSvc := &diagnostics.Service{DB: d.DB, Log: d.Log, Principal: auth.PrincipalFrom, AI: aiSvc, WorkerOnlineWindow: scans.WorkerOnlineWindow,
		Subjects: map[string]diagnostics.SubjectContext{"connector": connSvc.TroubleshootContext}}
	diagSvc.RegisterPublic(public)
	reviewSvc := NewReviewService(d, az, repoSvc, aiSvc)
	// After a scan: AI auto-review first, then the Human Eye queue picks
	// up findings that need a person.
	scanSvc.StatusWriter, scanSvc.PublicURL = repoSvc.StatusWriter, d.PublicURL
	scanSvc.FixPRTarget = FixPRTarget(repoSvc)
	// Verified AI fixes: the AI service proposes, workers verify.
	scanSvc.AIFix = aiSvc
	scanSvc.ReadSource = func(ctx context.Context, orgID, repoID uuid.UUID, commit, path string) ([]byte, error) {
		b, _, err := repoSvc.ReadSourceFile(ctx, orgID, repoID, repos.SourceRef{Commit: commit}, path)
		return b, err
	}
	scanSvc.ClamAVAddress, scanSvc.ClamAVRequired = d.Limits.ClamAVAddress, d.Limits.ClamAVRequired
	scanSvc.Offline = d.Offline
	scanSvc.OnScanFinished = func(ctx context.Context, orgID, jobID uuid.UUID) {
		// Developer attribution (no-op unless enabled) before the queues.
		if _, _, err := insights.Attribute(ctx, d.DB, orgID, jobID); err != nil {
			d.Log.Warn("developer attribution failed", "job_id", jobID, "err", err)
		}
		// Runtime facts of the new findings (database only; no-op
		// without a connected cluster).
		if err := runtimectx.LinkAfterScan(ctx, d.DB, orgID); err != nil {
			d.Log.Warn("runtime linking failed", "job_id", jobID, "err", err)
		}
		aiSvc.OnScanFinished(ctx, orgID, jobID)
		reviewSvc.OnScanFinished(ctx, orgID, jobID)
	}
	// Remediation workspace and security gates (flag "remediation_workspace",
	// PATHOS 3.0 M8). Fix verification reuses the AI fix machinery: the
	// scanner configuration of the scan profile and the worker API.
	remSvc := NewRemediationService(d, az, scanSvc, repoSvc)
	scanSvc.WorkerRoutes = append(scanSvc.WorkerRoutes, remSvc.RegisterWorker)
	mcpSvc := &mcp.Service{DB: d.DB, Authz: az, AI: aiSvc, Log: d.Log, Principal: auth.PrincipalFrom, PublicURL: d.PublicURL}
	// The MCP endpoint authenticates with personal API tokens, not sessions.
	public.Handle("/mcp", mcpSvc.Handler())

	protected := http.NewServeMux()
	protected.HandleFunc("POST /api/auth/logout", d.Auth.HandleLogout)
	(&identity.Handlers{
		DB: d.DB, Authz: az, Sessions: d.Auth.Sessions, Provisioner: d.Provisioner, Log: d.Log,
		Principal: auth.PrincipalFrom,
		CSRFToken: func(ctx context.Context) string {
			if s := auth.SessionFrom(ctx); s != nil {
				return s.CSRF
			}
			return ""
		},
	}).Register(protected)
	(&org.Handlers{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	installation := &tenancy.Handlers{DB: d.DB, Log: d.Log, DefaultOrgID: d.OrgID,
		Caller: func(ctx context.Context) *tenancy.Caller {
			// Installation administration needs a browser session (never an
			// API token) of a person linked to the identity provider.
			p := auth.PrincipalFrom(ctx)
			if p == nil || p.Subject == "" || auth.SessionFrom(ctx) == nil {
				return nil
			}
			return &tenancy.Caller{Subject: p.Subject, Email: p.Email}
		},
		Seed: func(ctx context.Context, orgID uuid.UUID) error {
			if err := scans.EnsureDefaultProfile(ctx, d.DB, orgID); err != nil {
				return err
			}
			if err := vuln.EnsureDefaults(ctx, d.DB, orgID); err != nil {
				return err
			}
			if err := notify.EnsureDefaults(ctx, d.DB, d.Secrets, orgID); err != nil {
				return err
			}
			if err := mcp.EnsureBuiltIn(ctx, d.DB, orgID, d.PublicURL); err != nil {
				return err
			}
			if err := review.EnsureSettings(ctx, d.DB, orgID); err != nil {
				return err
			}
			return repos.EnsureAssetDefaults(ctx, d.DB, orgID)
		}}
	if d.Artifacts != nil {
		installation.DeleteArtifacts = d.Artifacts.Delete
	}
	if d.Sources != nil {
		installation.DeleteSources = func(ctx context.Context, keys []string) error { return d.Sources.Delete(ctx, keys...) }
	}
	installation.Register(protected)
	(&dashboard.Handlers{DB: d.DB, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	(&search.Handlers{DB: d.DB, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	repoSvc.Register(protected)
	pushSvc.Register(protected)
	scanSvc.Register(protected)
	aiSvc.Register(protected)
	(&vuln.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom, Artifacts: d.Artifacts}).Register(protected)
	(&policy.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	(&releases.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	(&compliance.Service{DB: d.DB, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	(&reporting.Service{DB: d.DB, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	(&tickets.Service{DB: d.DB, Authz: az, Secrets: d.Secrets, Log: d.Log, Principal: auth.PrincipalFrom, PublicURL: d.PublicURL}).Register(protected)
	reviewSvc.Register(protected)
	(&risk.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	NewRuntimeService(d, az).Register(protected)
	postureSvc := &posture.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}
	postureSvc.Register(protected)
	(&insights.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	(&analyst.Service{DB: d.DB, Authz: az, AI: aiSvc, Posture: postureSvc, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	NewIntelService(d).Register(protected)
	(&eol.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	mcpSvc.Register(protected)
	(&schedule.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	(&notify.Service{DB: d.DB, Authz: az, Secrets: d.Secrets, Log: d.Log, Principal: auth.PrincipalFrom, BaseURL: d.PublicURL}).Register(protected)
	diagSvc.Register(protected)
	connSvc.Register(protected)
	remSvc.Register(protected)
	(&gates.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	(&featureflags.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	protected.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, d.Log, httpx.ErrNotFound)
	})

	public.Handle("/api/", d.Auth.RequireAuth(telemetry.RecordRoute(protected)))
	// "/api" without a slash: a JSON 404, not the mux's redirect to "/api/".
	public.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, d.Log, httpx.ErrNotFound)
	})
	publicHandler := telemetry.RecordRoute(public)
	if d.RateLimiter != nil {
		publicHandler = (&ratelimit.Middleware{Limiter: d.RateLimiter, Policy: d.RateLimitPolicy, Log: d.Log,
			UserID: func(ctx context.Context) (uuid.UUID, bool) {
				if p := auth.PrincipalFrom(ctx); p != nil {
					return p.UserID, true
				}
				return uuid.Nil, false
			}}).Wrap(publicHandler)
	}
	return Handlers{
		Public: telemetry.HTTP(httpx.Middleware(d.Log, d.Auth.Authenticate(publicHandler)), "pathos-api"),
		Worker: telemetry.HTTP(httpx.Middleware(d.Log, scanSvc.InternalHandler()), "pathos-worker-api"),
	}
}

func readiness(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		checks := map[string]string{}
		ok := true
		if err := d.DB.Ping(ctx); err != nil {
			checks["postgres"], ok = "unreachable", false
		} else if cur, latest, err := db.MigrationStatus(ctx, d.DB); err != nil || cur < latest {
			checks["postgres"], ok = "migrations pending", false
		} else {
			checks["postgres"] = "ok"
		}
		if err := d.Redis.Ping(ctx).Err(); err != nil {
			checks["redis"], ok = "unreachable", false
		} else {
			checks["redis"] = "ok"
		}
		status := http.StatusOK
		if !ok {
			status = http.StatusServiceUnavailable
		}
		httpx.WriteJSON(w, status, map[string]any{"ready": ok, "checks": checks})
	}
}

// NewAIService builds the AI review service (also used by the jobs role).
// NewReposService builds the repository service for background use (jobs
// role: nightly metadata re-sync).
func NewReposService(d Deps, az *authz.Authorizer) *repos.Service {
	lim := d.Limits
	def := repos.DefaultLimits()
	if lim.UploadMaxBytes == 0 {
		lim.UploadMaxBytes = def.UploadMaxBytes
	}
	if lim.ImportTimeout == 0 {
		lim.ImportTimeout = def.ImportTimeout
	}
	if lim.WorkDir == "" {
		lim.WorkDir = def.WorkDir
	}
	return &repos.Service{DB: d.DB, Authz: az, Secrets: d.Secrets, Net: d.SCMNet, Log: d.Log, Principal: auth.PrincipalFrom,
		PublicURL: d.PublicURL, Sources: d.Sources, Limits: lim,
		EnqueueScan: func(ctx context.Context, orgID, repoID uuid.UUID, trigger string, by *uuid.UUID) error {
			_, err := scans.Enqueue(ctx, d.DB, orgID, repoID, trigger, "", "", by)
			return err
		}}
}

// NewRemediationService builds the remediation service (also used by the
// jobs role for the "fix merged → targeted rescan" feedback loop; scanSvc
// and repoSvc may be nil there).
func NewRemediationService(d Deps, az *authz.Authorizer, scanSvc *scans.Service, repoSvc *repos.Service) *remediation.Service {
	svc := &remediation.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}
	if scanSvc != nil {
		svc.ScannerConfig = scanSvc.ScannerConfigFor
	}
	if repoSvc != nil {
		svc.CloneCredential = repoSvc.CloneCredential
	}
	return svc
}

// FixPRTarget adapts the repository service for fix pull requests.
func FixPRTarget(repoSvc *repos.Service) scans.FixPRTargetFunc {
	return func(ctx context.Context, orgID, repoID uuid.UUID) (scm.PullRequestWriter, scm.RepoRef, string, error) {
		t, err := repoSvc.PullRequestTarget(ctx, orgID, repoID)
		return t.Writer, t.Ref, t.Branch, err
	}
}

// NewIntelService builds the vulnerability intelligence service. Feeds
// are downloaded from public hosts only.
func NewIntelService(d Deps) *intel.Service {
	client := scm.NetPolicy{}.Client()
	client.Timeout = 5 * time.Minute
	if d.Offline {
		// Air-gapped: feeds are imported from files only.
		return &intel.Service{DB: d.DB, Log: d.Log, Principal: auth.PrincipalFrom, Offline: true}
	}
	return &intel.Service{DB: d.DB, Log: d.Log, Principal: auth.PrincipalFrom, HTTP: client}
}

// NewReviewService builds the Human Eye service (also used by the jobs
// role for ingestion and overdue detection).
func NewReviewService(d Deps, az *authz.Authorizer, repoSvc *repos.Service, aiSvc *ai.Service) *review.Service {
	svc := &review.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom, Artifacts: d.Artifacts}
	if repoSvc != nil {
		svc.Source = repoSvc
	}
	if d.Sources != nil {
		svc.Evidence = d.Sources
	}
	if aiSvc != nil {
		svc.AI = aiSvc
	}
	return svc
}

func NewAIService(d Deps, az *authz.Authorizer) *ai.Service {
	client := d.SCMNet.Client()
	client.Timeout = 5 * time.Minute
	// Self-hosted model servers (Ollama, vLLM) live on private networks.
	local := scm.NetPolicy{AllowPrivate: true, AllowHTTP: true}.Client()
	local.Timeout = 10 * time.Minute // CPU inference can be slow
	// Model servers answer a non-streaming request only when the whole
	// response is generated: wait for headers as long as for the request
	// (the shared 30 s header timeout suits SCM APIs, not inference).
	for _, c := range []*http.Client{client, local} {
		if tr, ok := c.Transport.(*http.Transport); ok {
			tr.ResponseHeaderTimeout = c.Timeout
		}
	}
	return &ai.Service{DB: d.DB, Authz: az, Secrets: d.Secrets, Log: d.Log, Principal: auth.PrincipalFrom, HTTP: client, LocalHTTP: local}
}

// NewRuntimeService builds the runtime context service. The API role only
// serves it; synchronisations (outbound calls to clusters and registries)
// run in the jobs role.
func NewRuntimeService(d Deps, az *authz.Authorizer) *runtimectx.Service {
	return &runtimectx.Service{DB: d.DB, Authz: az, Secrets: d.Secrets, Log: d.Log, Principal: auth.PrincipalFrom, AllowHTTP: d.SCMNet.AllowHTTP}
}

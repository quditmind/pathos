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
	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/dashboard"
	"pathos/internal/identity"
	"pathos/internal/intel"
	"pathos/internal/mcp"
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/objstore"
	"pathos/internal/platform/ratelimit"
	"pathos/internal/platform/telemetry"
	"pathos/internal/posture"
	"pathos/internal/repos"
	"pathos/internal/review"
	"pathos/internal/risk"
	"pathos/internal/scans"
	"pathos/internal/schedule"
	"pathos/internal/scm"
	"pathos/internal/search"
	"pathos/internal/secrets"
	"pathos/internal/vuln"
)

// Version is set at build time with -ldflags.
var Version = "dev"

type Deps struct {
	DB          *pgxpool.Pool
	Redis       redis.UniversalClient
	Auth        *auth.Service
	Provisioner identity.Provisioner
	OrgID       uuid.UUID
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
	az := &authz.Authorizer{H: &org.Hierarchy{DB: d.DB, OrgID: d.OrgID}}

	public := http.NewServeMux()
	public.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": Version})
	})
	public.HandleFunc("GET /readyz", readiness(d))
	public.HandleFunc("GET /api/auth/login", d.Auth.HandleLogin)
	public.HandleFunc("GET /api/auth/callback", d.Auth.HandleCallback)

	repoSvc := NewReposService(d, az)
	scanSvc := &scans.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom,
		CloneCredential: repoSvc.CloneCredential, BootstrapToken: d.WorkerBootstrapToken, OrgID: d.OrgID, Artifacts: d.Artifacts,
		OpenSnapshot: repoSvc.OpenSnapshot, Secrets: d.Secrets}
	repoSvc.OnEvent = scanSvc.OnWebhookEvent
	repoSvc.RegisterPublic(public)
	aiSvc := NewAIService(d, az)
	reviewSvc := NewReviewService(d, az, repoSvc, aiSvc)
	// After a scan: AI auto-review first, then the Human Eye queue picks
	// up findings that need a person.
	scanSvc.OnScanFinished = func(ctx context.Context, orgID, jobID uuid.UUID) {
		aiSvc.OnScanFinished(ctx, orgID, jobID)
		reviewSvc.OnScanFinished(ctx, orgID, jobID)
	}
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
	(&dashboard.Handlers{DB: d.DB, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	(&search.Handlers{DB: d.DB, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	repoSvc.Register(protected)
	scanSvc.Register(protected)
	aiSvc.Register(protected)
	(&vuln.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom, Artifacts: d.Artifacts}).Register(protected)
	reviewSvc.Register(protected)
	(&risk.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	(&posture.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	NewIntelService(d).Register(protected)
	mcpSvc.Register(protected)
	(&schedule.Service{DB: d.DB, Authz: az, Log: d.Log, Principal: auth.PrincipalFrom}).Register(protected)
	(&notify.Service{DB: d.DB, Authz: az, Secrets: d.Secrets, Log: d.Log, Principal: auth.PrincipalFrom, BaseURL: d.PublicURL}).Register(protected)
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

// NewIntelService builds the vulnerability intelligence service. Feeds
// are downloaded from public hosts only.
func NewIntelService(d Deps) *intel.Service {
	client := scm.NetPolicy{}.Client()
	client.Timeout = 5 * time.Minute
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
	return &ai.Service{DB: d.DB, Authz: az, Secrets: d.Secrets, Log: d.Log, Principal: auth.PrincipalFrom, HTTP: client, LocalHTTP: local}
}

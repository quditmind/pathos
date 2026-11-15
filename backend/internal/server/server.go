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

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
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
}

// Handler builds the root handler.
func Handler(d Deps) http.Handler {
	az := &authz.Authorizer{H: &org.Hierarchy{DB: d.DB, OrgID: d.OrgID}}

	public := http.NewServeMux()
	public.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": Version})
	})
	public.HandleFunc("GET /readyz", readiness(d))
	public.HandleFunc("GET /api/auth/login", d.Auth.HandleLogin)
	public.HandleFunc("GET /api/auth/callback", d.Auth.HandleCallback)

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
	protected.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, d.Log, httpx.ErrNotFound)
	})

	public.Handle("/api/", d.Auth.RequireAuth(protected))
	return httpx.Middleware(d.Log, d.Auth.Authenticate(public))
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

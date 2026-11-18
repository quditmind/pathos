package eol

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/httpx"
)

// Service serves a repository's end-of-life view.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/repositories/{id}/eol", s.repository)
}

// Item is the end-of-life status of one component, runtime or image.
type Item struct {
	Source       string     `json:"source"` // sbom | runtime | image
	Component    string     `json:"component"`
	Version      string     `json:"version"`
	PURL         string     `json:"purl,omitempty"`
	Path         string     `json:"path,omitempty"`
	TargetID     *uuid.UUID `json:"scan_target_id,omitempty"`
	Product      string     `json:"product"`
	ProductLabel string     `json:"product_label"`
	Cycle        string     `json:"cycle"`
	EOLDate      *time.Time `json:"eol_date"`
	Status       string     `json:"status"` // eol | approaching | supported
	Latest       string     `json:"latest_in_cycle,omitempty"`
}

// RepositoryView is GET /api/v1/repositories/{id}/eol.
type RepositoryView struct {
	// FeedLoaded: end-of-life data is available (the feed was loaded).
	FeedLoaded  bool       `json:"feed_loaded"`
	FeedAsOf    string     `json:"feed_as_of"`
	EOL         int        `json:"eol"`
	Approaching int        `json:"approaching"`
	Supported   int        `json:"supported"`
	ComputedAt  *time.Time `json:"computed_at"`
	Items       []Item     `json:"items"`
}

func (s *Service) repository(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	if err := s.Authz.Require(ctx, p, authz.PermSBOMRead, authz.Scope{Type: authz.ScopeRepository, ID: id}); err != nil {
		if errors.Is(err, org.ErrScopeNotFound) || (errors.Is(err, authz.ErrForbidden) && p.HasAnywhere(authz.PermSBOMRead)) {
			err = httpx.ErrNotFound
		} else if errors.Is(err, authz.ErrForbidden) {
			err = httpx.ErrForbidden
		}
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	out := RepositoryView{Items: []Item{}}
	_ = s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM eol_products), COALESCE((SELECT as_of FROM intel_feed_runs WHERE feed = 'endoflife'
		AND status = 'succeeded' ORDER BY started_at DESC LIMIT 1), '')`).Scan(&out.FeedLoaded, &out.FeedAsOf)
	rows, err := s.DB.Query(ctx, `SELECT source, component, version, purl, source_path, scan_target_id, product, product_label, cycle, eol_date,
		status, latest_version, computed_at FROM component_eol WHERE organization_id = $1 AND repository_id = $2
		ORDER BY array_position(ARRAY['eol','approaching','supported'], status), eol_date NULLS LAST, product, component LIMIT 5000`, p.OrganizationID, id)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Item, error) {
		var it Item
		var at time.Time
		err := row.Scan(&it.Source, &it.Component, &it.Version, &it.PURL, &it.Path, &it.TargetID, &it.Product, &it.ProductLabel, &it.Cycle,
			&it.EOLDate, &it.Status, &it.Latest, &at)
		if out.ComputedAt == nil || at.After(*out.ComputedAt) {
			a := at
			out.ComputedAt = &a
		}
		return it, err
	})
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	for _, it := range items {
		switch it.Status {
		case "eol":
			out.EOL++
		case "approaching":
			out.Approaching++
		default:
			out.Supported++
		}
	}
	if items != nil {
		out.Items = items
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

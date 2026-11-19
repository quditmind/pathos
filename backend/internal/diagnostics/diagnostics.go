// Package diagnostics serves the product metadata endpoint
// (GET /api/v1/meta), the error catalogue (GET /api/v1/diagnostics/codes)
// and troubleshooting (POST /api/v1/diagnostics/troubleshoot) on top of
// the diagnostic engine in internal/platform/diag.
package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/ai"
	"pathos/internal/authz"
	"pathos/internal/featureflags"
	"pathos/internal/platform/buildinfo"
	"pathos/internal/platform/diag"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/logging"
)

// Troubleshooter is the AI part of troubleshooting (ai.Service).
type Troubleshooter interface {
	Troubleshoot(ctx context.Context, orgID uuid.UUID, in ai.TroubleshootInput) (ai.TroubleshootResult, error)
}

// Service serves the endpoints.
type Service struct {
	DB        *pgxpool.Pool
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	// AI answers troubleshooting requests (nil: catalogue only).
	AI Troubleshooter
	// WorkerOnlineWindow is how recent a heartbeat must be for a worker
	// to count as online.
	WorkerOnlineWindow time.Duration
	// Subjects build the troubleshooting context of a subject kind
	// ("connector") on the server: non-secret configuration metadata and
	// the last stored failure, never client-supplied text. ok is false
	// when the caller may not read the subject (answered 404).
	Subjects map[string]SubjectContext
}

// SubjectContext returns the redacted context and stored error message of
// one subject.
type SubjectContext func(ctx context.Context, p *authz.Principal, id uuid.UUID) (ctxMap map[string]string, message string, ok bool, err error)

// RegisterPublic mounts GET /api/v1/meta, which answers without
// authentication (product, vendor and version only).
func (s *Service) RegisterPublic(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/meta", s.meta)
}

// Register mounts the authenticated endpoints.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/diagnostics/codes", s.codes)
	mux.HandleFunc("POST /api/v1/diagnostics/troubleshoot", s.troubleshoot)
}

// PublicMeta is the unauthenticated part of GET /api/v1/meta.
type PublicMeta struct {
	Product string `json:"product"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

// WorkerMeta is one registered worker.
type WorkerMeta struct {
	Name     string            `json:"name"`
	Family   string            `json:"family"`
	Version  string            `json:"version"`
	Scanners map[string]string `json:"scanners"`
	Online   bool              `json:"online"`
}

// PackMeta is the version of one worker family (scanner pack).
type PackMeta struct {
	Family  string `json:"family"`
	Version string `json:"version"`
}

// Meta is the authenticated GET /api/v1/meta.
type Meta struct {
	PublicMeta
	Commit       string          `json:"commit"`
	BuildDate    string          `json:"build_date"`
	APIVersion   string          `json:"api_version"`
	FeatureFlags map[string]bool `json:"feature_flags"`
	Workers      []WorkerMeta    `json:"workers"`
	ScannerPacks []PackMeta      `json:"scanner_packs"`
}

func publicMeta() PublicMeta {
	return PublicMeta{Product: buildinfo.Product, Vendor: buildinfo.Vendor, Version: buildinfo.Version}
}

func (s *Service) meta(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if p == nil {
		httpx.WriteJSON(w, http.StatusOK, publicMeta())
		return
	}
	ctx := r.Context()
	flags, err := featureflags.Load(ctx, s.DB, p.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	workers, packs, err := s.workers(ctx, p.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, Meta{PublicMeta: publicMeta(), Commit: buildinfo.Commit, BuildDate: buildinfo.BuildDate,
		APIVersion: buildinfo.APIVersion, FeatureFlags: flags, Workers: workers, ScannerPacks: packs})
}

// workers reads the live worker registry: every worker that is not
// revoked, and per family the version of the most recently seen worker.
func (s *Service) workers(ctx context.Context, orgID uuid.UUID) ([]WorkerMeta, []PackMeta, error) {
	window := s.WorkerOnlineWindow
	if window == 0 {
		window = 2 * time.Minute
	}
	workers := []WorkerMeta{}
	packs := []PackMeta{}
	seen := map[string]bool{}
	rows, err := s.DB.Query(ctx, `SELECT name, family, version, scanners, last_seen_at FROM workers
		WHERE organization_id = $1 AND revoked_at IS NULL ORDER BY last_seen_at DESC NULLS LAST, name`, orgID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var wm WorkerMeta
		var raw []byte
		var last *time.Time
		if err := rows.Scan(&wm.Name, &wm.Family, &wm.Version, &raw, &last); err != nil {
			return nil, nil, err
		}
		wm.Scanners = map[string]string{}
		_ = json.Unmarshal(raw, &wm.Scanners)
		wm.Online = last != nil && time.Since(*last) < window
		workers = append(workers, wm)
		if !seen[wm.Family] {
			seen[wm.Family] = true
			packs = append(packs, PackMeta{Family: wm.Family, Version: wm.Version})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].Name < workers[j].Name })
	sort.Slice(packs, func(i, j int) bool { return packs[i].Family < packs[j].Family })
	return workers, packs, nil
}

// CodeView is one catalogue entry as served to the UI.
type CodeView struct {
	diag.Entry
	DocsSlug string `json:"docs_slug"`
	DocsURL  string `json:"docs_url"`
}

func (s *Service) codes(w http.ResponseWriter, r *http.Request) {
	if s.Principal(r.Context()) == nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrUnauthenticated)
		return
	}
	all := diag.All()
	items := make([]CodeView, 0, len(all))
	for _, e := range all {
		items = append(items, CodeView{Entry: e, DocsSlug: e.DocsSlug(), DocsURL: e.DocsURL()})
	}
	areas := []diag.Area{}
	for _, a := range diag.Areas {
		if len(diag.EntriesOf(a.Key)) > 0 {
			areas = append(areas, a)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"areas": areas, "items": items})
}

// TroubleshootRequest is the body of POST /api/v1/diagnostics/troubleshoot.
type TroubleshootRequest struct {
	// Code is the PTH-<AREA>-<NNNN> code (error.error_code).
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
	// Message is the error message the user saw (optional).
	Message string `json:"message"`
	// Context is non-secret metadata (route, connection kind, HTTP status,
	// recent log lines). It is redacted before anything is sent. Ignored
	// when Subject is set (the server builds the context).
	Context map[string]string `json:"context"`
	// Subject names a stored subject ({"kind": "connector", "id": ...});
	// the server then builds the context from its configuration metadata
	// and last failure.
	Subject *Subject `json:"subject,omitempty"`
}

// Subject is the thing being troubleshot.
type Subject struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// TroubleshootResponse has the diagnostic fields of the error envelope plus
// where the answer came from.
type TroubleshootResponse struct {
	diag.Detail
	Message string `json:"message"`
	// Source is "ai" (AI-inferred, never confirmed) or "catalogue".
	Source string `json:"source"`
	// Model is the AI model that answered (source "ai").
	Model string `json:"model,omitempty"`
	// AIUnavailable says why the catalogue answered (AI off or failed).
	AIUnavailable string `json:"ai_unavailable,omitempty"`
}

var (
	codeBlockRe = regexp.MustCompile("(?s)```.*?```")
	ctxKeyRe    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,40}$`)
)

// sanitize strips code blocks and secrets and bounds sizes. The result is
// redacted again by the AI service with the organization's patterns.
func sanitize(s string, n int) string {
	s = codeBlockRe.ReplaceAllString(s, "[code removed]")
	s = logging.RedactString(ai.Redact(s, nil))
	if len(s) > n {
		s = s[:n]
	}
	return strings.TrimSpace(s)
}

func (s *Service) troubleshoot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if p == nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrUnauthenticated)
		return
	}
	var in TroubleshootRequest
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	entry, ok := diag.Lookup(strings.TrimSpace(in.Code))
	if !ok {
		httpx.WriteError(w, r, s.Log, &httpx.Error{Status: http.StatusUnprocessableEntity, Code: "validation_failed",
			Message: "code must be a PATHOS error code (PTH-<AREA>-<NNNN>) from the catalogue", Fields: map[string]string{"code": "unknown error code"}})
		return
	}
	if len(in.RequestID) > 64 || len(in.Context) > 20 {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("request_id is at most 64 characters and context at most 20 entries"))
		return
	}
	msg := sanitize(in.Message, 1000)
	cleanCtx := map[string]string{}
	for k, v := range in.Context {
		if !ctxKeyRe.MatchString(k) {
			continue
		}
		cleanCtx[k] = sanitize(v, 2000)
	}
	if in.Subject != nil {
		build, known := s.Subjects[in.Subject.Kind]
		id, perr := uuid.Parse(in.Subject.ID)
		if !known || perr != nil {
			httpx.WriteError(w, r, s.Log, &httpx.Error{Status: http.StatusUnprocessableEntity, Code: "validation_failed",
				Message: "subject must name a known subject kind and id", Fields: map[string]string{"subject": "unknown subject"}})
			return
		}
		sctx, smsg, ok, err := build(ctx, p, id)
		if err != nil {
			httpx.WriteError(w, r, s.Log, err)
			return
		}
		if !ok {
			httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
			return
		}
		// Only the server-built context goes to the model.
		cleanCtx = map[string]string{}
		for k, v := range sctx {
			if ctxKeyRe.MatchString(k) && len(cleanCtx) < 40 {
				cleanCtx[k] = sanitize(v, 500)
			}
		}
		msg = sanitize(smsg, 1000)
	}
	reqID := in.RequestID
	if reqID == "" {
		reqID = httpx.RequestID(r)
	}
	out := TroubleshootResponse{Detail: diag.DetailFor(entry.Code, "", reqID), Message: msg, Source: "catalogue"}
	switch {
	case s.AI == nil:
		out.AIUnavailable = "AI troubleshooting is not available on this server"
	case !entry.AIHelp:
		out.AIUnavailable = "AI help is not offered for this code; the catalogue steps apply"
	default:
		res, err := s.AI.Troubleshoot(ctx, p.OrganizationID, ai.TroubleshootInput{Code: entry.Code, Title: entry.Title, Description: entry.Description,
			Message: msg, ProbableCauses: entry.ProbableCauses, Actions: entry.Actions, Verify: entry.Verify, Context: cleanCtx})
		if err != nil {
			code := ai.DiagCode(err)
			s.Log.Info("AI troubleshooting unavailable; catalogue answer", "code", entry.Code, "request_id", httpx.RequestID(r), "error_code", code, "err", err)
			out.AIUnavailable = "AI did not answer (" + code + "); the catalogue steps apply"
			if errors.Is(err, ai.ErrNotConfigured) {
				out.AIUnavailable = "no AI provider is configured (" + code + "); the catalogue steps apply"
			}
			break
		}
		o := res.Output
		out.Source, out.Model = "ai", res.Model
		// AI conclusions are AI-inferred, never confirmed.
		out.Cause = diag.Cause{Confirmed: false, Text: o.LikelyCause}
		if len(o.ProbableCauses) > 0 {
			out.ProbableCauses = o.ProbableCauses
		}
		out.Actions = o.Actions
		if len(o.Verify) > 0 {
			out.Verify = o.Verify
		}
		s.Log.Info("AI troubleshooting answered", "code", entry.Code, "request_id", httpx.RequestID(r), "provider", res.Provider, "model", res.Model, "prompt_sha256", res.SHA256)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

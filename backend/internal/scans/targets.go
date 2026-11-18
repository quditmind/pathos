package scans

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.yaml.in/yaml/v3"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/ingest"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scanners"
	"pathos/internal/vuln"
)

// Scan targets: what PATHOS scans besides source code. Each target belongs
// to a repository (and so to its application, owners and scope).
//
//	image  container image in a registry      → Trivy (image)
//	url    running web application (DAST)     → Nuclei, non-intrusive templates
//	api    API described by an OpenAPI file   → Nuclei DAST templates
//	sbom   imported SBOM                      → Grype vulnerability matching
//
// Testing a running application (url, api) requires a recorded statement
// that the person adding it is authorized to test it.

const secretKindTarget = "scan_target"

var targetKinds = []string{"image", "url", "api", "sbom", "artifact"}

func (s *Service) registerTargets(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/scan-targets", s.listTargets)
	mux.HandleFunc("GET /api/v1/scan-targets/{id}", s.getTarget)
	mux.HandleFunc("POST /api/v1/scan-targets", s.createTarget)
	mux.HandleFunc("POST /api/v1/scan-targets/sbom", s.createSBOMTarget)
	mux.HandleFunc("POST /api/v1/scan-targets/artifact", s.createArtifactTarget)
	mux.HandleFunc("PUT /api/v1/scan-targets/{id}", s.updateTarget)
	mux.HandleFunc("DELETE /api/v1/scan-targets/{id}", s.deleteTarget)
	mux.HandleFunc("POST /api/v1/scan-targets/{id}/scan", s.scanTarget)
}

// TargetConfig tunes target scans.
type TargetConfig struct {
	// RateLimit is the DAST request rate per second (1-100, default 20).
	RateLimit int `json:"rate_limit,omitempty"`
	// MinSeverity limits DAST templates to this severity and above.
	MinSeverity string `json:"min_severity,omitempty"`
	// Nuclei runs the non-intrusive exposure templates against declared
	// endpoints (endpoints targets).
	Nuclei bool `json:"nuclei,omitempty"`
	// Signature verification of image and artifact targets (cosign).
	Signature *SignatureConfig `json:"signature,omitempty"`
}

// ScanTarget is the API representation (secrets are never returned).
type ScanTarget struct {
	ID                uuid.UUID    `json:"id"`
	RepositoryID      uuid.UUID    `json:"repository_id"`
	RepositoryName    string       `json:"repository_name"`
	Kind              string       `json:"kind"`
	Name              string       `json:"name"`
	Reference         string       `json:"reference"`
	EgressHost        string       `json:"egress_host"`
	Config            TargetConfig `json:"config"`
	APISpec           *string      `json:"api_spec,omitempty"`
	SBOMFormat        string       `json:"sbom_format"`
	SBOMComponents    int          `json:"sbom_components"`
	SBOMSize          int64        `json:"sbom_size"`
	AuthType          string       `json:"auth_type"`
	AuthUsername      string       `json:"auth_username"`
	AuthHeaderName    string       `json:"auth_header_name"`
	HasSecret         bool         `json:"has_secret"`
	AuthorizedBy      *string      `json:"authorized_by"`
	AuthorizedAt      *time.Time   `json:"authorized_at"`
	AuthorizationNote string       `json:"authorization_note"`
	Enabled           bool         `json:"enabled"`
	Scanners          []string     `json:"scanners"`
	// HasSignature: an artifact's signature or Sigstore bundle was uploaded.
	HasSignature bool `json:"has_signature"`
	// LastVerification is the latest signature verification evidence.
	LastVerification *SignatureVerification `json:"last_verification"`
	CreatedBy        *string                `json:"created_by"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	OpenFindings     int                    `json:"open_findings"`
	LastScan         *struct {
		ID         uuid.UUID  `json:"id"`
		ScanKey    string     `json:"scan_key"`
		Status     string     `json:"status"`
		QueuedAt   time.Time  `json:"queued_at"`
		FinishedAt *time.Time `json:"finished_at"`
		Error      string     `json:"error"`
	} `json:"last_scan"`
}

const targetSelect = `
	SELECT t.id, t.repository_id, COALESCE(NULLIF(r.display_name, ''), r.full_name), t.kind, t.name, t.reference, t.egress_host, t.config,
	       t.sbom_format, t.sbom_components, t.sbom_size, t.auth_type, t.auth_username, t.auth_header_name, t.secret_id IS NOT NULL,
	       COALESCE(NULLIF(au.display_name, ''), au.email), t.authorized_at, t.authorization_note, t.enabled,
	       COALESCE(NULLIF(cu.display_name, ''), cu.email), t.created_at, t.updated_at,
	       (SELECT count(*) FROM findings f WHERE f.scan_target_id = t.id AND f.status IN ('open', 'in_progress', 'needs_review')),
	       (SELECT jsonb_build_object('id', j.id, 'scan_key', j.scan_key, 'status', j.status, 'queued_at', j.queued_at,
	                                  'finished_at', j.finished_at, 'error', j.error)
	          FROM scan_jobs j WHERE j.target_id = t.id ORDER BY j.queued_at DESC LIMIT 1),
	       t.signature_material IS NOT NULL,
	       (SELECT jsonb_build_object('status', sv.status, 'mode', sv.mode, 'required', sv.required, 'attestation_status', sv.attestation_status,
	                                  'details', sv.details, 'scan_job_id', sv.scan_job_id, 'verified_at', sv.created_at)
	          FROM signature_verifications sv WHERE sv.scan_target_id = t.id ORDER BY sv.created_at DESC LIMIT 1)
	FROM scan_targets t
	JOIN repositories r ON r.id = t.repository_id
	LEFT JOIN users au ON au.id = t.authorized_by
	LEFT JOIN users cu ON cu.id = t.created_by`

func scanTarget(row pgx.Row) (ScanTarget, error) {
	var t ScanTarget
	var cfg, last, verification []byte
	err := row.Scan(&t.ID, &t.RepositoryID, &t.RepositoryName, &t.Kind, &t.Name, &t.Reference, &t.EgressHost, &cfg,
		&t.SBOMFormat, &t.SBOMComponents, &t.SBOMSize, &t.AuthType, &t.AuthUsername, &t.AuthHeaderName, &t.HasSecret,
		&t.AuthorizedBy, &t.AuthorizedAt, &t.AuthorizationNote, &t.Enabled, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
		&t.OpenFindings, &last, &t.HasSignature, &verification)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, errNotFound
	}
	if err != nil {
		return t, err
	}
	_ = json.Unmarshal(cfg, &t.Config)
	if len(last) > 0 {
		_ = json.Unmarshal(last, &t.LastScan)
	}
	if len(verification) > 0 {
		_ = json.Unmarshal(verification, &t.LastVerification)
	}
	t.Scanners = targetScannerKeys(t.Kind, t.Config)
	return t, nil
}

// --- validation (pure; unit-tested) ---

var (
	imageComponent = `[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*`
	imageRefRe     = regexp.MustCompile(`^(?:((?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+(?::\d{1,5})?|[a-zA-Z0-9-]+:\d{1,5}|localhost(?::\d{1,5})?)/)?` +
		`(` + imageComponent + `(?:/` + imageComponent + `)*)` + `(?::([\w][\w.-]{0,127}))?(?:@(sha256:[a-f0-9]{64}))?$`)
)

// ValidateImageRef checks a container image reference and returns the
// registry host the worker must reach.
func ValidateImageRef(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || len(ref) > 500 {
		return "", errors.New("enter an image reference such as ghcr.io/acme/api:1.4.2")
	}
	m := imageRefRe.FindStringSubmatch(ref)
	if m == nil {
		return "", errors.New("not a valid image reference (registry/repository:tag or @sha256:digest)")
	}
	host := m[1]
	if host == "" || host == "docker.io" || host == "index.docker.io" {
		host = "registry-1.docker.io"
	}
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}
	return strings.ToLower(host), nil
}

// ValidateTargetURL checks the base URL of a web application or API and
// returns its host.
func ValidateTargetURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Opaque != "" {
		return "", errors.New("enter an http:// or https:// URL")
	}
	if u.User != nil {
		return "", errors.New("do not put credentials in the URL; use the authentication fields")
	}
	if u.Fragment != "" || len(raw) > 1000 {
		return "", errors.New("the URL must not contain a fragment and is limited to 1000 characters")
	}
	return strings.ToLower(u.Hostname()), nil
}

// ValidateAPISpec checks an OpenAPI 3 or Swagger 2 document and that every
// server it declares is on the authorized host, so a scan cannot be pointed
// at a host nobody authorized.
func ValidateAPISpec(spec, host string) error {
	if strings.TrimSpace(spec) == "" {
		return errors.New("an OpenAPI document is required")
	}
	if len(spec) > 2<<20 {
		return errors.New("the OpenAPI document is limited to 2 MiB")
	}
	var doc struct {
		OpenAPI string `yaml:"openapi"`
		Swagger string `yaml:"swagger"`
		Host    string `yaml:"host"`
		Servers []struct {
			URL string `yaml:"url"`
		} `yaml:"servers"`
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(spec), &doc); err != nil {
		return fmt.Errorf("the OpenAPI document is not valid YAML or JSON: %s", firstLine(err.Error()))
	}
	switch {
	case strings.HasPrefix(doc.OpenAPI, "3."):
		if len(doc.Servers) == 0 {
			return errors.New("the OpenAPI document must declare servers (absolute URLs on the target host)")
		}
		for _, sv := range doc.Servers {
			h, err := ValidateTargetURL(sv.URL)
			if err != nil {
				return fmt.Errorf("server %q: use an absolute URL", sv.URL)
			}
			if h != host {
				return fmt.Errorf("server %q is not on the authorized host %s", sv.URL, host)
			}
		}
	case strings.HasPrefix(doc.Swagger, "2."):
		h := strings.ToLower(doc.Host)
		if i := strings.LastIndex(h, ":"); i > 0 {
			h = h[:i]
		}
		if h != host {
			return fmt.Errorf("the Swagger host %q is not the authorized host %s", doc.Host, host)
		}
	default:
		return errors.New("not an OpenAPI 3 or Swagger 2 document")
	}
	if len(doc.Paths) == 0 {
		return errors.New("the OpenAPI document declares no paths")
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func validConfig(c TargetConfig) error {
	if c.RateLimit < 0 || c.RateLimit > 100 {
		return errors.New("the request rate must be between 1 and 100 per second")
	}
	if c.MinSeverity != "" && !slices.Contains([]string{"low", "medium", "high", "critical"}, c.MinSeverity) {
		return errors.New("min_severity must be low, medium, high or critical")
	}
	return validSignatureConfig(c.Signature)
}

// targetSecret is the encrypted credential of a target.
type targetSecret struct {
	Value string `json:"value"` // registry/HTTP password or header value
}

// --- handlers ---

func (s *Service) listTargets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermScansRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	scope, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 2)
	args := append([]any{p.OrganizationID}, sargs...)
	where := []string{"t.organization_id = $1", scope}
	q := r.URL.Query()
	if v := q.Get("repository_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid repository_id"))
			return
		}
		args = append(args, id)
		where = append(where, fmt.Sprintf("t.repository_id = $%d", len(args)))
	}
	if v := q.Get("kind"); v != "" {
		if !slices.Contains(targetKinds, v) {
			s.fail(w, r, httpx.BadRequest("kind must be image, url, api, sbom or artifact"))
			return
		}
		args = append(args, v)
		where = append(where, fmt.Sprintf("t.kind = $%d", len(args)))
	}
	rows, err := s.DB.Query(ctx, targetSelect+` WHERE `+strings.Join(where, " AND ")+` ORDER BY t.kind, lower(t.name) LIMIT 1000`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ScanTarget, error) { return scanTarget(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []ScanTarget{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "scanners": scanners.TargetScanners})
}

// loadTarget loads a target the caller may act on with perm.
func (s *Service) loadTarget(ctx context.Context, p *authz.Principal, perm authz.Permission, id uuid.UUID) (ScanTarget, error) {
	t, err := scanTarget(s.DB.QueryRow(ctx, targetSelect+` WHERE t.organization_id = $1 AND t.id = $2`, p.OrganizationID, id))
	if err != nil {
		return t, err
	}
	if err := s.requireRepo(ctx, p, perm, t.RepositoryID); err != nil {
		return ScanTarget{}, err
	}
	return t, nil
}

func (s *Service) getTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.loadTarget(ctx, p, authz.PermScansRead, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if t.Kind == "api" {
		var spec string
		if err := s.DB.QueryRow(ctx, `SELECT COALESCE(api_spec, '') FROM scan_targets WHERE id = $1`, id).Scan(&spec); err == nil {
			t.APISpec = &spec
		}
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

type targetRequest struct {
	RepositoryID   uuid.UUID     `json:"repository_id"`
	Kind           string        `json:"kind"`
	Name           *string       `json:"name"`
	Reference      *string       `json:"reference"`
	Config         *TargetConfig `json:"config"`
	APISpec        *string       `json:"api_spec"`
	AuthType       *string       `json:"auth_type"`
	AuthUsername   *string       `json:"auth_username"`
	AuthHeaderName *string       `json:"auth_header_name"`
	// AuthSecret: nil keeps the stored value, "" removes it.
	AuthSecret *string `json:"auth_secret"`
	// Authorized records that the caller is authorized to test the target
	// (required for url and api, and again when their address changes).
	Authorized        bool    `json:"authorized"`
	AuthorizationNote *string `json:"authorization_note"`
	Enabled           *bool   `json:"enabled"`
	// SignatureMaterial is an artifact's detached signature (base64) or
	// Sigstore bundle (JSON); "" removes it.
	SignatureMaterial *string `json:"signature_material"`
}

var headerNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`)

// targetFields is the validated, normalized state of a target.
type targetFields struct {
	kind, name, reference, egress, authType, authUser, authHeader, note string
	spec                                                                *string
	config                                                              TargetConfig
	enabled                                                             bool
}

func (f *targetFields) apply(req targetRequest) error {
	if req.Name != nil {
		f.name = strings.TrimSpace(*req.Name)
	}
	if req.Reference != nil {
		f.reference = strings.TrimSpace(*req.Reference)
	}
	if req.Config != nil {
		f.config = *req.Config
	}
	if req.APISpec != nil {
		spec := *req.APISpec
		f.spec = &spec
	}
	if req.AuthType != nil {
		f.authType = *req.AuthType
	}
	if req.AuthUsername != nil {
		f.authUser = strings.TrimSpace(*req.AuthUsername)
	}
	if req.AuthHeaderName != nil {
		f.authHeader = strings.TrimSpace(*req.AuthHeaderName)
	}
	if req.AuthorizationNote != nil {
		f.note = strings.TrimSpace(*req.AuthorizationNote)
	}
	if req.Enabled != nil {
		f.enabled = *req.Enabled
	}
	if f.name == "" || len(f.name) > 200 {
		return httpx.BadRequest("a name of at most 200 characters is required")
	}
	if len(f.note) > 2000 {
		return httpx.BadRequest("the authorization note is limited to 2000 characters")
	}
	if err := validConfig(f.config); err != nil {
		return httpx.BadRequest(err.Error())
	}
	var err error
	switch f.kind {
	case "image":
		f.egress, err = ValidateImageRef(f.reference)
		if f.authType == "header" {
			return httpx.BadRequest("container registries use basic authentication (username and password or token)")
		}
	case "url", "api":
		f.egress, err = ValidateTargetURL(f.reference)
		if err == nil && f.kind == "api" {
			if f.spec == nil {
				return httpx.BadRequest("an OpenAPI document is required")
			}
			err = ValidateAPISpec(*f.spec, f.egress)
		}
	case "sbom", "artifact":
		f.egress = ""
	case "endpoints":
		return httpx.BadRequest("declared endpoints are verified from the repository's endpoint verification settings")
	default:
		return httpx.BadRequest("kind must be image, url, api, sbom or artifact")
	}
	if f.config.Signature != nil && f.config.Signature.Mode != "" && f.kind != "image" && f.kind != "artifact" {
		return httpx.BadRequest("signature verification applies to container image and artifact targets")
	}
	if f.config.Signature != nil && f.config.Signature.Attestation != "" && f.kind != "image" {
		return httpx.BadRequest("attestations are verified for container image targets")
	}
	if f.config.Nuclei {
		return httpx.BadRequest("nuclei applies to declared endpoint verification only")
	}
	if err != nil {
		return httpx.BadRequest(err.Error())
	}
	switch f.authType {
	case "", "none":
		f.authType, f.authUser, f.authHeader = "none", "", ""
	case "basic":
		if f.authUser == "" || len(f.authUser) > 300 {
			return httpx.BadRequest("basic authentication needs a username")
		}
		if strings.ContainsAny(f.authUser, ":\r\n\x00") {
			return httpx.BadRequest("the username must not contain colons or line breaks")
		}
		f.authHeader = ""
	case "header":
		if !headerNameRe.MatchString(f.authHeader) {
			return httpx.BadRequest("enter a header name such as Authorization or X-API-Key")
		}
		f.authUser = ""
	default:
		return httpx.BadRequest("auth_type must be none, basic or header")
	}
	if (f.kind == "sbom" || f.kind == "artifact") && f.authType != "none" {
		return httpx.BadRequest("uploaded targets have no authentication")
	}
	return nil
}

func (s *Service) createTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req targetRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Kind == "sbom" || req.Kind == "artifact" {
		s.fail(w, r, httpx.BadRequest("upload SBOM and artifact targets with POST /api/v1/scan-targets/"+req.Kind))
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermReposManage, req.RepositoryID); err != nil {
		s.fail(w, r, err)
		return
	}
	f := targetFields{kind: req.Kind, enabled: true}
	if err := f.apply(req); err != nil {
		s.fail(w, r, err)
		return
	}
	if (f.kind == "url" || f.kind == "api") && !req.Authorized {
		s.fail(w, r, httpx.BadRequest("confirm that you are authorized to test this application"))
		return
	}
	id := uuid.Must(uuid.NewV7())
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		secretID, err := s.storeTargetSecret(ctx, tx, p, nil, f.authType, req.AuthSecret, f.name)
		if err != nil {
			return err
		}
		cfg, _ := json.Marshal(f.config)
		var authBy *uuid.UUID
		var authAt *time.Time
		if f.kind == "url" || f.kind == "api" {
			now := time.Now()
			authBy, authAt = &p.UserID, &now
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scan_targets (id, organization_id, repository_id, kind, name, reference, egress_host, config,
			api_spec, auth_type, auth_username, auth_header_name, secret_id, authorized_by, authorized_at, authorization_note, enabled, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
			id, p.OrganizationID, req.RepositoryID, f.kind, f.name, f.reference, f.egress, cfg, f.spec, f.authType, f.authUser,
			f.authHeader, secretID, authBy, authAt, f.note, f.enabled, p.UserID); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("this repository already has a " + f.kind + " target with this address")
			}
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan_target.create", TargetType: "scan_target", TargetID: id.String(),
			Metadata: map[string]any{"kind": f.kind, "name": f.name, "reference": f.reference, "repository_id": req.RepositoryID,
				"authorized": authAt != nil, "authorization_note": f.note}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.loadTarget(ctx, p, authz.PermScansRead, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, t)
}

// storeTargetSecret creates, updates or removes a target credential and
// returns the secret id to store.
func (s *Service) storeTargetSecret(ctx context.Context, tx pgx.Tx, p *authz.Principal, current *uuid.UUID, authType string, value *string, name string) (*uuid.UUID, error) {
	if authType == "none" || (value != nil && *value == "") {
		if current != nil && s.Secrets != nil {
			if err := s.Secrets.Delete(ctx, tx, p.OrganizationID, *current); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	if value == nil {
		return current, nil
	}
	if len(*value) > 8192 {
		return nil, httpx.BadRequest("the credential is limited to 8192 characters")
	}
	if strings.ContainsAny(*value, "\r\n\x00") {
		// A line break in a header value would inject further headers.
		return nil, httpx.BadRequest("the credential must not contain line breaks")
	}
	if s.Secrets == nil {
		return nil, httpx.Conflict("credential storage is not configured")
	}
	plain, _ := json.Marshal(targetSecret{Value: *value})
	if current != nil {
		return current, s.Secrets.Update(ctx, tx, p.OrganizationID, *current, secretKindTarget, plain)
	}
	id, err := s.Secrets.Create(ctx, tx, p.OrganizationID, secretKindTarget, truncate("scan target "+name, 200), plain, &p.UserID)
	return &id, err
}

func (s *Service) updateTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cur, err := s.loadTarget(ctx, p, authz.PermReposManage, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req targetRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Kind != "" && req.Kind != cur.Kind {
		s.fail(w, r, httpx.BadRequest("the kind of a target cannot change"))
		return
	}
	f := targetFields{kind: cur.Kind, name: cur.Name, reference: cur.Reference, authType: cur.AuthType, authUser: cur.AuthUsername,
		authHeader: cur.AuthHeaderName, note: cur.AuthorizationNote, config: cur.Config, enabled: cur.Enabled}
	if cur.Kind == "api" {
		var spec string
		if err := s.DB.QueryRow(ctx, `SELECT COALESCE(api_spec, '') FROM scan_targets WHERE id = $1`, id).Scan(&spec); err != nil {
			s.fail(w, r, err)
			return
		}
		f.spec = &spec
	}
	if (cur.Kind == "sbom" || cur.Kind == "artifact") && req.Reference != nil {
		s.fail(w, r, httpx.BadRequest("upload a new target to change the file"))
		return
	}
	if cur.Kind == "endpoints" {
		s.fail(w, r, httpx.BadRequest("manage declared endpoint verification from the repository (PUT /api/v1/repositories/{id}/endpoint-verification)"))
		return
	}
	if req.SignatureMaterial != nil && cur.Kind != "artifact" {
		s.fail(w, r, httpx.BadRequest("a signature or Sigstore bundle can be attached to artifact targets only"))
		return
	}
	if req.SignatureMaterial != nil {
		if err := validSignatureMaterial(*req.SignatureMaterial); err != nil {
			s.fail(w, r, httpx.BadRequest(err.Error()))
			return
		}
	}
	if err := f.apply(req); err != nil {
		s.fail(w, r, err)
		return
	}
	// A different address is a different system: it needs its own
	// authorization statement.
	live := cur.Kind == "url" || cur.Kind == "api"
	if live && f.reference != cur.Reference && !req.Authorized {
		s.fail(w, r, httpx.BadRequest("the address changed: confirm that you are authorized to test it"))
		return
	}
	reauth := live && req.Authorized
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var curSecret *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT secret_id FROM scan_targets WHERE id = $1 FOR UPDATE`, id).Scan(&curSecret); err != nil {
			return err
		}
		secretID, err := s.storeTargetSecret(ctx, tx, p, curSecret, f.authType, req.AuthSecret, f.name)
		if err != nil {
			return err
		}
		cfg, _ := json.Marshal(f.config)
		if req.SignatureMaterial != nil {
			var mat *string
			if v := strings.TrimSpace(*req.SignatureMaterial); v != "" {
				mat = &v
			}
			if _, err := tx.Exec(ctx, `UPDATE scan_targets SET signature_material = $2 WHERE id = $1`, id, mat); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE scan_targets SET name = $2, reference = $3, egress_host = $4, config = $5, api_spec = $6,
			auth_type = $7, auth_username = $8, auth_header_name = $9, secret_id = $10, authorization_note = $11, enabled = $12,
			authorized_by = CASE WHEN $13 THEN $14::uuid ELSE authorized_by END,
			authorized_at = CASE WHEN $13 THEN now() ELSE authorized_at END, updated_at = now() WHERE id = $1`,
			id, f.name, f.reference, f.egress, cfg, f.spec, f.authType, f.authUser, f.authHeader, secretID, f.note, f.enabled,
			reauth, p.UserID); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("this repository already has a " + f.kind + " target with this address")
			}
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan_target.update", TargetType: "scan_target", TargetID: id.String(),
			Metadata: map[string]any{"name": f.name, "reference": f.reference, "enabled": f.enabled, "reauthorized": reauth,
				"credential_changed": req.AuthSecret != nil, "signature": signatureAudit(f.config.Signature),
				"signature_material_changed": req.SignatureMaterial != nil}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.loadTarget(ctx, p, authz.PermScansRead, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

func (s *Service) deleteTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.loadTarget(ctx, p, authz.PermReposManage, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var findings int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE scan_target_id = $1`, id).Scan(&findings); err != nil {
			return err
		}
		if findings > 0 {
			// Findings keep their evidence and history; disable the target instead.
			return httpx.Conflict(fmt.Sprintf("the target has %d findings; disable it instead of deleting it", findings))
		}
		var running bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scan_jobs WHERE target_id = $1 AND status IN ('queued', 'running'))`, id).Scan(&running); err != nil {
			return err
		}
		if running {
			return httpx.Conflict("a scan of this target is queued or running")
		}
		var secretID *uuid.UUID
		if err := tx.QueryRow(ctx, `DELETE FROM scan_targets WHERE id = $1 RETURNING secret_id`, id).Scan(&secretID); err != nil {
			return err
		}
		if secretID != nil && s.Secrets != nil {
			if err := s.Secrets.Delete(ctx, tx, p.OrganizationID, *secretID); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan_target.delete", TargetType: "scan_target", TargetID: id.String(),
			Metadata: map[string]any{"kind": t.Kind, "name": t.Name, "reference": t.Reference}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// createSBOMTarget stores an uploaded SBOM as a target; scanning it matches
// its components against vulnerability databases on a worker.
func (s *Service) createSBOMTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	data, fileName, form, err := readUpload(w, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	repoID, err := uuid.Parse(form["repository_id"])
	if err != nil {
		s.fail(w, r, httpx.BadRequest("repository_id is required"))
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermReposManage, repoID); err != nil {
		s.fail(w, r, err)
		return
	}
	format, comps, perr := vuln.ParseSBOM(data)
	if perr != nil || len(comps) == 0 {
		msg := "the SBOM contains no components"
		if perr != nil {
			msg = safeErr(perr)
		}
		httpx.WriteError(w, r, s.Log, httpx.E(http.StatusUnprocessableEntity, "invalid_sbom", msg))
		return
	}
	if format != "cyclonedx" && format != "spdx" {
		s.fail(w, r, httpx.BadRequest("unsupported SBOM format"))
		return
	}
	name := strings.TrimSpace(form["name"])
	if name == "" {
		name = fileName
	}
	if name == "" {
		name = "SBOM"
	}
	name = truncate(name, 200)
	ref := truncate(firstNonEmpty(fileName, name), 1000)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(data)
	_ = zw.Close()
	id := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO scan_targets (id, organization_id, repository_id, kind, name, reference, sbom_gzip,
			sbom_format, sbom_sha256, sbom_size, sbom_components, created_by)
			VALUES ($1, $2, $3, 'sbom', $4, $5, $6, $7, $8, $9, $10, $11)`,
			id, p.OrganizationID, repoID, name, ref, gz.Bytes(), format, sum256(data), len(data), len(comps), p.UserID); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("this repository already has an SBOM target named " + ref + "; delete or rename it first")
			}
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan_target.create", TargetType: "scan_target", TargetID: id.String(),
			Metadata: map[string]any{"kind": "sbom", "name": name, "format": format, "components": len(comps), "sha256": sum256(data),
				"repository_id": repoID}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.loadTarget(ctx, p, authz.PermScansRead, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, t)
}

func (s *Service) scanTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.loadTarget(ctx, p, authz.PermScansRun, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if t.Kind == "endpoints" && s.Offline {
		s.fail(w, r, httpx.Conflict(errOfflineEndpoints))
		return
	}
	var res EnqueueResult
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		if res, err = EnqueueTarget(ctx, tx, p.OrganizationID, id, "manual", &p.UserID); err != nil {
			return err
		}
		if res.Coalesced {
			return nil
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan.request", TargetType: "scan_target", TargetID: id.String(),
			Metadata: map[string]any{"job_id": res.JobID, "trigger": "manual", "kind": t.Kind, "repository_id": t.RepositoryID}})
	})
	if errors.Is(err, ErrNotScannable) || errors.Is(err, ErrScanPrerequisite) {
		err = httpx.Conflict(err.Error())
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, res)
}

// EnqueueTarget queues a scan of a target with its repository's profile
// (timeout, severity threshold, exclusions); the scanners follow from the
// target kind.
func EnqueueTarget(ctx context.Context, q db.Querier, orgID, targetID uuid.UUID, trigger string, by *uuid.UUID) (EnqueueResult, error) {
	var res EnqueueResult
	var repoID uuid.UUID
	var kind, name, reference, repoName string
	var enabled, repoEnabled bool
	var archived, authorizedAt *time.Time
	var profileVersion *uuid.UUID
	err := q.QueryRow(ctx, `
		SELECT t.repository_id, t.kind, t.name, t.reference, t.enabled, t.authorized_at, r.scan_enabled, r.archived_at,
		       COALESCE(NULLIF(r.display_name, ''), r.full_name),
		       COALESCE((SELECT current_version_id FROM scan_profiles WHERE id = r.scan_profile_id AND archived_at IS NULL),
		                (SELECT current_version_id FROM scan_profiles WHERE organization_id = r.organization_id AND is_default AND archived_at IS NULL))
		FROM scan_targets t JOIN repositories r ON r.id = t.repository_id
		WHERE t.organization_id = $1 AND t.id = $2`, orgID, targetID).
		Scan(&repoID, &kind, &name, &reference, &enabled, &authorizedAt, &repoEnabled, &archived, &repoName, &profileVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return res, errNotFound
	}
	if err != nil {
		return res, err
	}
	if archived != nil || !enabled {
		return res, fmt.Errorf("%w: the target is disabled or its repository is archived", ErrNotScannable)
	}
	if (kind == "url" || kind == "api" || kind == "endpoints") && authorizedAt == nil {
		return res, fmt.Errorf("%w: testing this application has not been authorized", ErrScanPrerequisite)
	}
	if profileVersion == nil {
		return res, fmt.Errorf("%w: no scan profile available; create a default profile", ErrScanPrerequisite)
	}
	prio := priorities[trigger]
	err = q.QueryRow(ctx, `UPDATE scan_jobs SET priority = GREATEST(priority, $3)
		WHERE organization_id = $1 AND target_id = $2 AND status = 'queued' RETURNING id`, orgID, targetID, prio).Scan(&res.JobID)
	if err == nil {
		res.Coalesced = true
		return res, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return res, err
	}
	snap, profileName, err := configSnapshot(ctx, q, *profileVersion)
	if err != nil {
		return res, err
	}
	// The snapshot records what actually runs: the target and its scanners.
	var m map[string]any
	if err := json.Unmarshal(snap, &m); err != nil {
		return res, err
	}
	var tcfgRaw []byte
	if err := q.QueryRow(ctx, `SELECT config FROM scan_targets WHERE id = $1`, targetID).Scan(&tcfgRaw); err != nil {
		return res, err
	}
	var tcfg TargetConfig
	_ = json.Unmarshal(tcfgRaw, &tcfg)
	keys := targetScannerKeys(kind, tcfg)
	sc := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		sc = append(sc, map[string]any{"key": k})
	}
	m["scanners"] = sc
	delete(m, "custom_rules")
	m["target"] = map[string]any{"id": targetID, "kind": kind, "name": name, "reference": reference}
	if snap, err = json.Marshal(m); err != nil {
		return res, err
	}
	res.JobID = uuid.Must(uuid.NewV7())
	jobName := truncate(repoName+" · "+name+" · "+profileName, 200)
	if _, err := q.Exec(ctx, `
		INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, priority, ref, commit_sha, requested_by,
		  name, config_snapshot, target_id, target_kind)
		VALUES ($1, $2, $3, $4, $5, $6, $7, '', $8, $9, $10, $11, $12)`,
		res.JobID, orgID, repoID, *profileVersion, trigger, prio, kind, by, jobName, snap, targetID, kind); err != nil {
		if db.IsUniqueViolation(err) {
			if err := q.QueryRow(ctx, `SELECT id FROM scan_jobs WHERE target_id = $1 AND status = 'queued' LIMIT 1`, targetID).Scan(&res.JobID); err != nil {
				return res, err
			}
			res.Coalesced = true
			return res, nil
		}
		return res, err
	}
	return res, AddEvent(ctx, q, orgID, res.JobID, "queued", "", "info", "queued by "+trigger+" ("+kind+" target "+name+")")
}

// LeasedTarget is the target part of a leased job.
type LeasedTarget struct {
	Kind        string `json:"kind"`
	Reference   string `json:"reference"`
	Spec        string `json:"spec,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Size        int64  `json:"size,omitempty"`
	AuthType    string `json:"auth_type,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	HeaderName  string `json:"header_name,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`
	RateLimit   int    `json:"rate_limit,omitempty"`
	MinSeverity string `json:"min_severity,omitempty"`
	// FileName of an artifact target.
	FileName string `json:"file_name,omitempty"`
	// Endpoints of an endpoints target.
	Endpoints []LeasedEndpoint `json:"endpoints,omitempty"`
	// Signature verification policy and an artifact's signature material.
	Signature         *SignatureConfig `json:"signature,omitempty"`
	SignatureMaterial string           `json:"signature_material,omitempty"`
}

// leaseTarget fills a leased job's target (with its decrypted credential)
// and its scanners.
func (s *Service) leaseTarget(ctx context.Context, tx pgx.Tx, orgID, targetID uuid.UUID, job *LeasedJob) error {
	var t LeasedTarget
	var cfgRaw []byte
	var spec, material *string
	var secretID *uuid.UUID
	var repoID uuid.UUID
	var scope []string
	if err := tx.QueryRow(ctx, `SELECT kind, reference, api_spec, sbom_sha256, sbom_size, auth_type, auth_username, auth_header_name,
		secret_id, config, artifact_name, signature_material, repository_id, authorized_scope FROM scan_targets WHERE organization_id = $1 AND id = $2`, orgID, targetID).
		Scan(&t.Kind, &t.Reference, &spec, &t.SHA256, &t.Size, &t.AuthType, &t.Username, &t.HeaderName, &secretID, &cfgRaw, &t.FileName,
			&material, &repoID, &scope); err != nil {
		return err
	}
	if spec != nil {
		t.Spec = *spec
	}
	var cfg TargetConfig
	_ = json.Unmarshal(cfgRaw, &cfg)
	t.RateLimit, t.MinSeverity = cfg.RateLimit, cfg.MinSeverity
	if cfg.Signature != nil && cfg.Signature.Mode != "" && (t.Kind == "image" || t.Kind == "artifact") {
		t.Signature = cfg.Signature
		if material != nil {
			t.SignatureMaterial = *material
		}
	}
	if t.Kind == "endpoints" {
		eps, err := leaseEndpoints(ctx, tx, repoID, scope)
		if err != nil {
			return err
		}
		t.Endpoints = eps
	}
	if secretID != nil && t.AuthType != "none" {
		if s.Secrets == nil {
			return errors.New("credential storage is not configured")
		}
		plain, err := s.Secrets.Reveal(ctx, tx, orgID, *secretID, secretKindTarget)
		if err != nil {
			return err
		}
		var sec targetSecret
		if err := json.Unmarshal(plain, &sec); err != nil {
			return err
		}
		if t.AuthType == "header" {
			t.HeaderValue = sec.Value
		} else {
			t.Password = sec.Value
		}
	}
	if t.AuthType == "none" {
		t.AuthType, t.Username, t.HeaderName = "", "", ""
	}
	// Scanners follow the target kind; a profile's settings for the same
	// scanner (if any) are kept.
	byKey := map[string]ProfileScanner{}
	for _, ps := range job.Scanners {
		byKey[ps.Key] = ps
	}
	job.Scanners = nil
	for _, k := range targetScannerKeys(t.Kind, cfg) {
		ps, ok := byKey[k]
		if !ok {
			ps = ProfileScanner{Key: k}
		}
		job.Scanners = append(job.Scanners, ps)
	}
	job.Target = &t
	job.Source, job.CloneURL, job.FullHistory, job.Credential = nil, "", false, nil
	return nil
}

// maxArtifactBytes bounds an uploaded build artifact.
const maxArtifactBytes = 200 << 20

// createArtifactTarget stores an uploaded build artifact (archive, Java
// archive, binary) as a target; its scan extracts archives on a worker and
// looks for vulnerable components.
func (s *Service) createArtifactTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "multipart/form-data" {
		s.fail(w, r, httpx.E(http.StatusUnsupportedMediaType, "unsupported_media_type", "upload the artifact as multipart/form-data (field \"file\")"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxArtifactBytes+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		s.fail(w, r, httpx.BadRequest("invalid multipart body"))
		return
	}
	form := map[string]string{}
	var gz bytes.Buffer
	var size int64
	var fileName string
	h := sha256.New()
	tooLarge := httpx.E(http.StatusRequestEntityTooLarge, "too_large", "artifacts are limited to 200 MiB")
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				s.fail(w, r, tooLarge)
				return
			}
			s.fail(w, r, httpx.BadRequest("invalid multipart body"))
			return
		}
		if part.FormName() != "file" {
			limit := int64(4096)
			if part.FormName() == "signature" {
				limit = maxSignatureMaterial + 1
			}
			b, _ := io.ReadAll(io.LimitReader(part, limit))
			form[part.FormName()] = strings.TrimSpace(string(b))
			continue
		}
		fileName = path.Base(strings.ReplaceAll(part.FileName(), "\\", "/"))
		zw := gzip.NewWriter(&gz)
		n, err := io.Copy(io.MultiWriter(zw, h), io.LimitReader(part, maxArtifactBytes+1))
		_ = zw.Close()
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				s.fail(w, r, tooLarge)
				return
			}
			s.fail(w, r, httpx.BadRequest("could not read the file"))
			return
		}
		if n > maxArtifactBytes {
			s.fail(w, r, tooLarge)
			return
		}
		size = n
	}
	if size == 0 {
		s.fail(w, r, httpx.BadRequest("an artifact file is required (field \"file\")"))
		return
	}
	repoID, err := uuid.Parse(form["repository_id"])
	if err != nil {
		s.fail(w, r, httpx.BadRequest("repository_id is required"))
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermReposManage, repoID); err != nil {
		s.fail(w, r, err)
		return
	}
	if fileName == "" || fileName == "." || fileName == "/" {
		fileName = "artifact.bin"
	}
	var material *string
	if v := form["signature"]; v != "" {
		if err := validSignatureMaterial(v); err != nil {
			s.fail(w, r, httpx.BadRequest(err.Error()))
			return
		}
		material = &v
	}
	// Malware scan (clamd) of the uploaded file, when configured.
	malware := "not_configured"
	if s.ClamAVAddress != "" {
		zr, err := gzip.NewReader(bytes.NewReader(gz.Bytes()))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		v, err := ingest.ClamAV{Address: s.ClamAVAddress, Timeout: 10 * time.Minute}.Scan(ctx, zr)
		switch {
		case err != nil && s.ClamAVRequired:
			s.fail(w, r, httpx.E(http.StatusServiceUnavailable, "malware_scanner_unavailable", "the malware scanner is unavailable; try again later"))
			return
		case err != nil:
			malware = "unavailable"
			s.Log.Warn("artifact malware scan unavailable; continuing (PATHOS_CLAMAV_REQUIRED=false)", "err", err)
		case !v.Clean:
			_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
				Action: "scan_target.malware_detected", Outcome: "failure", TargetType: "repository", TargetID: repoID.String(),
				Metadata: map[string]any{"file_name": fileName, "signature": v.Signature, "engine": v.Engine}})
			s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "malware_detected", "the artifact was rejected by the malware scanner ("+v.Signature+")"))
			return
		default:
			malware = "clean"
		}
	}
	fileName = truncate(fileName, 255)
	name := truncate(firstNonEmpty(strings.TrimSpace(form["name"]), fileName), 200)
	id := uuid.Must(uuid.NewV7())
	key, inline, err := putArtifact(ctx, s.Artifacts, p.OrganizationID, id, gz.Bytes())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	digest := hex.EncodeToString(h.Sum(nil))
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO scan_targets (id, organization_id, repository_id, kind, name, reference, artifact_name, artifact_key,
			artifact_gzip, sbom_sha256, sbom_size, created_by, signature_material) VALUES ($1, $2, $3, 'artifact', $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			id, p.OrganizationID, repoID, name, fileName+" ("+digest[:12]+")", fileName, key, inline, digest, size, p.UserID, material); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan_target.create", TargetType: "scan_target", TargetID: id.String(),
			Metadata: map[string]any{"kind": "artifact", "name": name, "file_name": fileName, "sha256": digest, "size": size, "repository_id": repoID,
				"malware_scan": malware, "signature_attached": material != nil}})
	})
	if err != nil {
		if key != nil && s.Artifacts != nil {
			_ = s.Artifacts.Delete(context.WithoutCancel(ctx), []string{*key})
		}
		if db.IsUniqueViolation(err) {
			err = httpx.Conflict("this repository already has this artifact as a target")
		}
		s.fail(w, r, err)
		return
	}
	t, err := s.loadTarget(ctx, p, authz.PermScansRead, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, t)
}

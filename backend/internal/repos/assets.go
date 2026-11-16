package repos

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Classification kinds (asset_classifications.kind).
const (
	KindCriticality        = "criticality"
	KindDataClassification = "data_classification"
	KindEnvironment        = "environment"
	KindApplicationType    = "application_type"
	KindInternetExposure   = "internet_exposure"
	KindCompliance         = "compliance"
	KindHostingRegion      = "hosting_region"
	KindLifecycleStatus    = "lifecycle_status"
)

var classificationKinds = []string{KindCriticality, KindDataClassification, KindEnvironment, KindApplicationType,
	KindInternetExposure, KindCompliance, KindHostingRegion, KindLifecycleStatus}

// Classification is one catalog entry.
type Classification struct {
	ID          uuid.UUID `json:"id"`
	Kind        string    `json:"kind"`
	Key         string    `json:"key"`
	Label       string    `json:"label"`
	Description string    `json:"description"`
	Color       string    `json:"color"`
	SortOrder   int       `json:"sort_order"`
	IsSystem    bool      `json:"is_system"`
	Archived    bool      `json:"archived"`
}

type classificationSeed struct {
	key, label, description, color string
}

// defaultClassifications seeds each organization's catalogs. They are
// ordinary, editable rows; is_system rows cannot be archived because code
// relies on their keys (criticality levels, "unknown" exposure, "active"
// lifecycle, environments used by legacy data).
var defaultClassifications = map[string][]classificationSeed{
	KindCriticality: {
		{"critical", "Critical", "Outage or compromise causes severe business, financial, legal or safety impact", "#cf222e"},
		{"high", "High", "Significant business impact; important customer-facing or financial system", "#e16f24"},
		{"medium", "Medium", "Moderate impact; supporting business system", "#d4a72c"},
		{"low", "Low", "Limited impact; internal tooling, experiments", "#2da44e"},
	},
	KindDataClassification: {
		{"public", "Public", "Approved for public release", "#2da44e"},
		{"internal", "Internal", "For employees and contractors; low harm if disclosed", "#1f6feb"},
		{"confidential", "Confidential", "Business-sensitive or personal data; disclosure causes harm", "#e16f24"},
		{"restricted", "Restricted", "Highest sensitivity: regulated, secret or special-category data", "#cf222e"},
	},
	KindEnvironment: {
		{"production", "Production", "", ""},
		{"staging", "Staging", "", ""},
		{"test", "Testing", "", ""},
		{"development", "Development", "", ""},
		{"disaster_recovery", "Disaster Recovery", "", ""},
		{"sandbox", "Sandbox", "", ""},
		{"other", "Other", "", ""},
	},
	KindApplicationType: {
		{"web_application", "Web application", "", ""},
		{"mobile_application", "Mobile application", "", ""},
		{"backend_service", "Backend service", "", ""},
		{"api", "API", "", ""},
		{"microservice", "Microservice", "", ""},
		{"library", "Library / package", "", ""},
		{"infrastructure_as_code", "Infrastructure as Code", "", ""},
		{"database_project", "Database project", "", ""},
		{"desktop_application", "Desktop application", "", ""},
		{"other", "Other", "", ""},
	},
	KindInternetExposure: {
		{"public", "Publicly accessible", "Reachable from the internet", "#cf222e"},
		{"internal", "Internally accessible", "Reachable from the corporate network", "#d4a72c"},
		{"private", "Private", "Not network-reachable or restricted to a closed segment", "#2da44e"},
		{"unknown", "Unknown", "Exposure not yet assessed", "#6e7781"},
	},
	KindCompliance: {
		{"gdpr", "GDPR", "", ""},
		{"pci_dss", "PCI DSS", "", ""},
		{"iso_27001", "ISO 27001", "", ""},
		{"soc_2", "SOC 2", "", ""},
		{"hipaa", "HIPAA", "", ""},
		{"internal_security_policy", "Internal Security Policy", "", ""},
		{"other", "Other", "", ""},
	},
	KindHostingRegion: {
		{"on_premises", "On-premises", "Organization-operated data centre", ""},
		{"europe", "Europe", "", ""},
		{"north_america", "North America", "", ""},
		{"south_america", "South America", "", ""},
		{"asia_pacific", "Asia Pacific", "", ""},
		{"middle_east_africa", "Middle East and Africa", "", ""},
		{"multi_region", "Multi-region / global", "", ""},
	},
	KindLifecycleStatus: {
		{"planned", "Planned", "", "#8250df"},
		{"development", "In development", "", "#1f6feb"},
		{"active", "Active", "", "#2da44e"},
		{"maintenance", "Maintenance only", "", "#d4a72c"},
		{"deprecated", "Deprecated", "", "#e16f24"},
		{"retired", "Retired", "", "#6e7781"},
	},
}

// systemKeys cannot be archived.
var systemKeys = map[string][]string{
	KindCriticality:      {"critical", "high", "medium", "low"},
	KindEnvironment:      {"production", "staging", "test", "development", "other"},
	KindInternetExposure: {"unknown"},
	KindLifecycleStatus:  {"active", "retired"},
}

// suggestedColors are the colour picker defaults (spec section 5.9).
var suggestedColors = []map[string]string{
	{"key": "critical", "label": "Critical", "color": "#cf222e"},
	{"key": "high", "label": "High", "color": "#e16f24"},
	{"key": "medium", "label": "Medium", "color": "#d4a72c"},
	{"key": "low", "label": "Low", "color": "#2da44e"},
	{"key": "general", "label": "Internal / general", "color": "#1f6feb"},
	{"key": "inactive", "label": "Archived / inactive", "color": "#6e7781"},
}

// Asset fields usable in required_fields.
var assetFields = []string{
	"description", "application", "application_type", "business_purpose",
	"business_owner", "technical_owner", "application_owner", "business_unit", "department",
	"responsible_team", "supporting_team", "cost_centre",
	"business_region", "country", "hosting_region", "data_residency_region", "operational_location",
	"criticality", "data_classification", "environment", "internet_exposure", "compliance_scopes",
	"tags", "lifecycle_status", "staging_url", "production_url", "public_exposure",
}

// alwaysRequired are mandatory regardless of policy (spec 5.2, 5.3).
var alwaysRequired = []string{"business_owner", "business_unit", "business_region", "public_exposure"}

// EnsureAssetDefaults seeds missing catalog entries and the settings row.
// Idempotent; run at startup.
func EnsureAssetDefaults(ctx context.Context, q db.Querier, orgID uuid.UUID) error {
	for kind, seeds := range defaultClassifications {
		for i, s := range seeds {
			if _, err := q.Exec(ctx, `
				INSERT INTO asset_classifications (id, organization_id, kind, key, label, description, color, sort_order, is_system)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
				ON CONFLICT (organization_id, kind, key) DO UPDATE SET is_system = EXCLUDED.is_system
				  WHERE asset_classifications.is_system <> EXCLUDED.is_system`,
				uuid.Must(uuid.NewV7()), orgID, kind, s.key, s.label, s.description, s.color, (i+1)*10,
				slices.Contains(systemKeys[kind], s.key)); err != nil {
				return err
			}
		}
	}
	_, err := q.Exec(ctx, `INSERT INTO asset_settings (organization_id) VALUES ($1) ON CONFLICT DO NOTHING`, orgID)
	return err
}

func (s *Service) registerAssets(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/asset-settings", s.getAssetSettings)
	mux.HandleFunc("PATCH /api/v1/asset-settings", s.updateAssetSettings)
	mux.HandleFunc("POST /api/v1/asset-classifications", s.createClassification)
	mux.HandleFunc("PATCH /api/v1/asset-classifications/{id}", s.updateClassification)
}

// assetPolicy is the organization's settings plus catalogs, loaded once per
// request that validates metadata.
type assetPolicy struct {
	Required     []string
	ScanOnImport bool
	KeyPrefix    string
	Catalog      map[string][]Classification
}

func (ap *assetPolicy) required(field string) bool {
	return slices.Contains(alwaysRequired, field) || slices.Contains(ap.Required, field)
}

// active reports whether key is a non-archived entry of kind.
func (ap *assetPolicy) active(kind, key string) bool {
	for _, c := range ap.Catalog[kind] {
		if c.Key == key {
			return !c.Archived
		}
	}
	return false
}

// known reports whether key exists (archived entries remain valid on
// existing assets so unrelated edits do not fail).
func (ap *assetPolicy) known(kind, key string) bool {
	for _, c := range ap.Catalog[kind] {
		if c.Key == key {
			return true
		}
	}
	return false
}

func (ap *assetPolicy) label(kind, key string) (string, string) {
	for _, c := range ap.Catalog[kind] {
		if c.Key == key {
			return c.Label, c.Color
		}
	}
	return key, ""
}

func (s *Service) loadPolicy(ctx context.Context, q db.Querier, orgID uuid.UUID) (*assetPolicy, error) {
	ap := &assetPolicy{Catalog: map[string][]Classification{}}
	const sel = `SELECT required_fields, scan_on_import, repository_key_prefix FROM asset_settings WHERE organization_id = $1`
	err := q.QueryRow(ctx, sel, orgID).Scan(&ap.Required, &ap.ScanOnImport, &ap.KeyPrefix)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := EnsureAssetDefaults(ctx, q, orgID); err != nil {
			return nil, err
		}
		err = q.QueryRow(ctx, sel, orgID).Scan(&ap.Required, &ap.ScanOnImport, &ap.KeyPrefix)
	}
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT id, kind, key, label, description, color, sort_order, is_system, archived_at IS NOT NULL
		FROM asset_classifications WHERE organization_id = $1 ORDER BY kind, sort_order, lower(label)`, orgID)
	if err != nil {
		return nil, err
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Classification, error) {
		var c Classification
		err := r.Scan(&c.ID, &c.Kind, &c.Key, &c.Label, &c.Description, &c.Color, &c.SortOrder, &c.IsSystem, &c.Archived)
		return c, err
	})
	if err != nil {
		return nil, err
	}
	for _, k := range classificationKinds {
		ap.Catalog[k] = []Classification{}
	}
	for _, c := range all {
		ap.Catalog[c.Kind] = append(ap.Catalog[c.Kind], c)
	}
	return ap, nil
}

func (s *Service) getAssetSettings(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermReposRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	ap, err := s.loadPolicy(r.Context(), s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"required_fields": ap.Required,
		"always_required": alwaysRequired,
		"scan_on_import":  ap.ScanOnImport,
		// Applies to Repository IDs generated from now on; existing IDs never change.
		"repository_key_prefix": ap.KeyPrefix,
		"classifications":       ap.Catalog,
		"suggested_colors":      suggestedColors,
		"upload": map[string]any{"max_bytes": s.Limits.UploadMaxBytes, "chunk_size": uploadChunkSize,
			"formats": []string{"zip", "tar", "tar.gz"}},
	})
}

type assetSettingsPatch struct {
	RequiredFields      *[]string `json:"required_fields"`
	ScanOnImport        *bool     `json:"scan_on_import"`
	RepositoryKeyPrefix *string   `json:"repository_key_prefix"`
}

var keyPrefixRe = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$`)

func (s *Service) updateAssetSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermAssetsConfigure)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req assetSettingsPatch
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	var fields []string
	if req.RequiredFields != nil {
		for _, f := range *req.RequiredFields {
			if !slices.Contains(assetFields, f) {
				s.fail(w, r, httpx.BadRequest("unknown field "+f))
				return
			}
			if !slices.Contains(fields, f) && !slices.Contains(alwaysRequired, f) {
				fields = append(fields, f)
			}
		}
		if fields == nil {
			fields = []string{}
		}
	}
	if req.RepositoryKeyPrefix != nil {
		v := strings.ToUpper(strings.TrimSpace(*req.RepositoryKeyPrefix))
		if len(v) > 20 || !keyPrefixRe.MatchString(v) {
			s.fail(w, r, httpx.BadRequest("repository_key_prefix must be upper-case letters, digits and single hyphens (max 20), e.g. QD-REPO"))
			return
		}
		req.RepositoryKeyPrefix = &v
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := EnsureAssetDefaults(ctx, tx, p.OrganizationID); err != nil {
			return err
		}
		var oldPrefix string
		if err := tx.QueryRow(ctx, `SELECT repository_key_prefix FROM asset_settings WHERE organization_id = $1`, p.OrganizationID).Scan(&oldPrefix); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE asset_settings SET repository_key_prefix = COALESCE($2, repository_key_prefix) WHERE organization_id = $1`,
			p.OrganizationID, req.RepositoryKeyPrefix); err != nil {
			return err
		}
		var oldFields []string
		var oldScan bool
		if err := tx.QueryRow(ctx, `SELECT required_fields, scan_on_import FROM asset_settings WHERE organization_id = $1 FOR UPDATE`,
			p.OrganizationID).Scan(&oldFields, &oldScan); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE asset_settings SET required_fields = COALESCE($2, required_fields),
			scan_on_import = COALESCE($3, scan_on_import), updated_by = $4, updated_at = now() WHERE organization_id = $1`,
			p.OrganizationID, fields, req.ScanOnImport, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "asset_settings.update", TargetType: "asset_settings", TargetID: p.OrganizationID.String(),
			Metadata: map[string]any{"old": map[string]any{"required_fields": oldFields, "scan_on_import": oldScan, "repository_key_prefix": oldPrefix},
				"new": map[string]any{"required_fields": fields, "scan_on_import": req.ScanOnImport, "repository_key_prefix": req.RepositoryKeyPrefix}}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.getAssetSettings(w, r)
}

var (
	classificationKeyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,62}$`)
	hexColorRe          = regexp.MustCompile(`^#[0-9a-f]{6}$`)
)

type classificationRequest struct {
	Kind        string  `json:"kind"`
	Key         string  `json:"key"`
	Label       *string `json:"label"`
	Description *string `json:"description"`
	Color       *string `json:"color"`
	SortOrder   *int    `json:"sort_order"`
	Archived    *bool   `json:"archived"`
}

func (c *classificationRequest) validate() error {
	if c.Label != nil {
		if l := strings.TrimSpace(*c.Label); l == "" || len(l) > 100 {
			return httpx.BadRequest("label must be 1-100 characters")
		}
	}
	if c.Description != nil && len(*c.Description) > 1000 {
		return httpx.BadRequest("description must be at most 1000 characters")
	}
	if c.Color != nil {
		v := strings.ToLower(strings.TrimSpace(*c.Color))
		if v != "" && !hexColorRe.MatchString(v) {
			return httpx.BadRequest("color must be empty or #rrggbb")
		}
		c.Color = &v
	}
	if c.SortOrder != nil && (*c.SortOrder < -100000 || *c.SortOrder > 100000) {
		return httpx.BadRequest("sort_order out of range")
	}
	return nil
}

func (s *Service) createClassification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermAssetsConfigure)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req classificationRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !slices.Contains(classificationKinds, req.Kind) {
		s.fail(w, r, httpx.BadRequest("kind must be one of "+strings.Join(classificationKinds, ", ")))
		return
	}
	if req.Kind == KindCriticality {
		s.fail(w, r, httpx.BadRequest("criticality has four fixed levels; edit their labels and colours instead"))
		return
	}
	if !classificationKeyRe.MatchString(req.Key) {
		s.fail(w, r, httpx.BadRequest("key must be lower-case letters, digits and underscores (max 63)"))
		return
	}
	if req.Label == nil {
		s.fail(w, r, httpx.BadRequest("label is required"))
		return
	}
	if err := req.validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	id := uuid.Must(uuid.NewV7())
	var out Classification
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := EnsureAssetDefaults(ctx, tx, p.OrganizationID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO asset_classifications (id, organization_id, kind, key, label, description, color, sort_order)
			VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, (SELECT COALESCE(max(sort_order), 0) + 10 FROM asset_classifications
			  WHERE organization_id = $2 AND kind = $3)))`,
			id, p.OrganizationID, req.Kind, req.Key, strings.TrimSpace(*req.Label), deref(req.Description), deref(req.Color), req.SortOrder); err != nil {
			return err
		}
		out, err = getClassification(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "asset_classification.create", TargetType: "asset_classification", TargetID: id.String(),
			Metadata: map[string]any{"new": out}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func getClassification(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (Classification, error) {
	var c Classification
	err := q.QueryRow(ctx, `SELECT id, kind, key, label, description, color, sort_order, is_system, archived_at IS NOT NULL
		FROM asset_classifications WHERE organization_id = $1 AND id = $2`, orgID, id).
		Scan(&c.ID, &c.Kind, &c.Key, &c.Label, &c.Description, &c.Color, &c.SortOrder, &c.IsSystem, &c.Archived)
	return c, err
}

func (s *Service) updateClassification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermAssetsConfigure)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req classificationRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Kind != "" || req.Key != "" {
		s.fail(w, r, httpx.BadRequest("kind and key cannot be changed"))
		return
	}
	if err := req.validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	var out Classification
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		old, err := getClassification(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if req.Archived != nil && *req.Archived && old.IsSystem {
			return httpx.Conflict("built-in entries cannot be archived; rename them instead")
		}
		var archivedAt *time.Time
		if req.Archived != nil && *req.Archived {
			now := time.Now()
			archivedAt = &now
		}
		var label *string
		if req.Label != nil {
			l := strings.TrimSpace(*req.Label)
			label = &l
		}
		if _, err := tx.Exec(ctx, `UPDATE asset_classifications SET label = COALESCE($3, label), description = COALESCE($4, description),
			color = COALESCE($5, color), sort_order = COALESCE($6, sort_order),
			archived_at = CASE WHEN $7::boolean IS NULL THEN archived_at WHEN $7 THEN COALESCE(archived_at, $8) ELSE NULL END,
			updated_at = now() WHERE organization_id = $1 AND id = $2`,
			p.OrganizationID, id, label, req.Description, req.Color, req.SortOrder, req.Archived, archivedAt); err != nil {
			return err
		}
		out, err = getClassification(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "asset_classification.update", TargetType: "asset_classification", TargetID: id.String(),
			Metadata: map[string]any{"old": old, "new": out}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

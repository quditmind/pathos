package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

// Ref is a compact reference.
type Ref struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// UserRef is a compact user reference.
type UserRef struct {
	ID    uuid.UUID `json:"id"`
	Name  string    `json:"name"`
	Email string    `json:"email"`
}

// Detection says where an automatically filled value came from.
type Detection struct {
	// Source: "repository" (repository metadata), "sbom" (components of a
	// linked repository's SBOM) or "scm" (provider discovery).
	Source string `json:"source"`
	Detail string `json:"detail"`
}

// AppTag is a tag on an application.
type AppTag struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Color         string    `json:"color"`
	CategoryID    uuid.UUID `json:"category_id"`
	CategoryName  string    `json:"category_name"`
	CategoryColor string    `json:"category_color"`
	// Source: manual, rule, bulk or onboarding.
	Source string `json:"source"`
}

// Progress is the onboarding completeness of an application.
type Progress struct {
	Filled   int      `json:"filled"`
	Required int      `json:"required"`
	Missing  []string `json:"missing"`
	// MissingTagCategories are mandatory tag categories (for the
	// application's type) without a tag.
	MissingTagCategories []Ref `json:"missing_tag_categories"`
	// Label is the inventory status, e.g. "Onboarding: 6 of 9 fields".
	Label string `json:"label"`
}

// Application is the application profile (GET /api/v1/applications/{id}).
type Application struct {
	ID                  uuid.UUID            `json:"id"`
	Key                 string               `json:"application_key"`
	Name                string               `json:"name"`
	Description         string               `json:"description"`
	ExternalRef         string               `json:"external_ref"`
	BusinessUnit        *Ref                 `json:"business_unit"`
	Owner               *UserRef             `json:"owner"`
	SecurityOwner       *UserRef             `json:"security_owner"`
	TechnicalOwner      *UserRef             `json:"technical_owner"`
	Criticality         string               `json:"criticality"`
	Lifecycle           string               `json:"lifecycle"`
	Environment         string               `json:"environment"`
	ApplicationType     string               `json:"application_type"`
	Languages           []string             `json:"languages"`
	Frameworks          []string             `json:"frameworks"`
	Runtimes            []string             `json:"runtimes"`
	DataClassification  string               `json:"data_classification"`
	InternetExposure    string               `json:"internet_exposure"`
	ComplianceScopes    []string             `json:"compliance_scopes"`
	AuthenticationModel string               `json:"authentication_model"`
	HostingRegion       string               `json:"hosting_region"`
	DataResidencyRegion *Ref                 `json:"data_residency_region"`
	OnboardingStatus    string               `json:"onboarding_status"`
	Detected            map[string]Detection `json:"detected"`
	Progress            Progress             `json:"progress"`
	Tags                []AppTag             `json:"tags"`
	RepositoryCount     int                  `json:"repository_count"`
	CanManage           bool                 `json:"can_manage"`
	ArchivedAt          *time.Time           `json:"archived_at"`
	CreatedAt           time.Time            `json:"created_at"`
	UpdatedAt           time.Time            `json:"updated_at"`
}

// ApplicationFields are the application fields that can be made mandatory
// (asset_settings.application_required_fields).
var ApplicationFields = []string{
	"description", "owner", "security_owner", "technical_owner", "business_unit", "criticality", "external_ref",
	"application_type", "languages", "frameworks", "runtimes",
	"data_classification", "internet_exposure", "compliance_scopes", "authentication_model",
	"hosting_region", "data_residency", "environment", "lifecycle",
}

// FieldLabels are the display names of ApplicationFields.
var FieldLabels = map[string]string{
	"description": "Description", "owner": "Business owner", "security_owner": "Security owner", "technical_owner": "Technical owner",
	"business_unit": "Business unit", "criticality": "Criticality", "external_ref": "External ID", "application_type": "Application type",
	"languages": "Languages", "frameworks": "Frameworks", "runtimes": "Runtime", "data_classification": "Data classification",
	"internet_exposure": "Internet exposure", "compliance_scopes": "Compliance scope", "authentication_model": "Authentication model",
	"hosting_region": "Hosting region", "data_residency": "Data residency", "environment": "Environment", "lifecycle": "Lifecycle",
}

// empty reports whether a field has no value. "unknown" exposure and
// authentication model count as not assessed.
func (a *Application) empty(field string) bool {
	switch field {
	case "description":
		return strings.TrimSpace(a.Description) == ""
	case "owner":
		return a.Owner == nil
	case "security_owner":
		return a.SecurityOwner == nil
	case "technical_owner":
		return a.TechnicalOwner == nil
	case "business_unit":
		return a.BusinessUnit == nil
	case "criticality":
		return a.Criticality == ""
	case "external_ref":
		return a.ExternalRef == ""
	case "application_type":
		return a.ApplicationType == ""
	case "languages":
		return len(a.Languages) == 0
	case "frameworks":
		return len(a.Frameworks) == 0
	case "runtimes":
		return len(a.Runtimes) == 0
	case "data_classification":
		return a.DataClassification == ""
	case "internet_exposure":
		return a.InternetExposure == "" || a.InternetExposure == "unknown"
	case "compliance_scopes":
		return len(a.ComplianceScopes) == 0
	case "authentication_model":
		return a.AuthenticationModel == "" || a.AuthenticationModel == "unknown"
	case "hosting_region":
		return a.HostingRegion == ""
	case "data_residency":
		return a.DataResidencyRegion == nil
	case "environment":
		return a.Environment == ""
	case "lifecycle":
		return a.Lifecycle == ""
	}
	return true
}

// ComputeProgress fills a.Progress from the required fields and the
// mandatory tag categories that apply to the application.
func (a *Application) ComputeProgress(required []string, mandatory []mandatoryCategory) {
	p := Progress{Missing: []string{}, MissingTagCategories: []Ref{}}
	for _, f := range ApplicationFields {
		if !slices.Contains(required, f) {
			continue
		}
		p.Required++
		if a.empty(f) {
			p.Missing = append(p.Missing, f)
		} else {
			p.Filled++
		}
	}
	have := map[uuid.UUID]bool{}
	for _, t := range a.Tags {
		have[t.CategoryID] = true
	}
	for _, c := range mandatory {
		if c.appliesTo(a.ApplicationType) && !have[c.ID] {
			p.MissingTagCategories = append(p.MissingTagCategories, Ref{ID: c.ID, Name: c.Name})
		}
	}
	if a.OnboardingStatus == "draft" {
		p.Label = fmt.Sprintf("Onboarding: %d of %d fields", p.Filled, p.Required)
	} else {
		p.Label = "Registered"
	}
	a.Progress = p
}

// mandatoryCategory is a tag category with mandatory application types.
type mandatoryCategory struct {
	ID    uuid.UUID
	Name  string
	Types []string
}

func (c mandatoryCategory) appliesTo(appType string) bool {
	return slices.Contains(c.Types, "all") || (appType != "" && slices.Contains(c.Types, appType))
}

func loadMandatoryCategories(ctx context.Context, q db.Querier, orgID uuid.UUID) ([]mandatoryCategory, error) {
	rows, err := q.Query(ctx, `SELECT id, name, mandatory_asset_types FROM tag_categories
		WHERE organization_id = $1 AND cardinality(mandatory_asset_types) > 0 ORDER BY lower(name)`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (mandatoryCategory, error) {
		var c mandatoryCategory
		return c, r.Scan(&c.ID, &c.Name, &c.Types)
	})
}

// requiredFields returns the organization's mandatory application fields.
func requiredFields(ctx context.Context, q db.Querier, orgID uuid.UUID) ([]string, error) {
	var req []string
	err := q.QueryRow(ctx, `SELECT application_required_fields FROM asset_settings WHERE organization_id = $1`, orgID).Scan(&req)
	if errors.Is(err, pgx.ErrNoRows) {
		// Not seeded yet: the column default.
		return []string{"owner", "business_unit", "criticality", "languages", "frameworks", "data_classification",
			"internet_exposure", "hosting_region", "environment"}, nil
	}
	return req, err
}

const appDetailSelect = `
	SELECT a.id, a.application_key, a.name, a.description, a.external_ref, b.id, b.name,
	       o.id, COALESCE(NULLIF(o.display_name, ''), o.email), o.email,
	       so.id, COALESCE(NULLIF(so.display_name, ''), so.email), so.email,
	       t.id, COALESCE(NULLIF(t.display_name, ''), t.email), t.email,
	       a.criticality, a.lifecycle, a.environment, a.application_type, a.languages, a.frameworks, a.runtimes,
	       a.data_classification, a.internet_exposure, a.compliance_scopes, a.authentication_model, a.hosting_region,
	       rg.id, rg.name, a.onboarding_status, a.detected_fields,
	       (SELECT count(*) FROM repositories r WHERE r.application_id = a.id AND r.archived_at IS NULL),
	       a.archived_at, a.created_at, a.updated_at
	FROM applications a
	LEFT JOIN business_units b ON b.id = a.business_unit_id
	LEFT JOIN users o ON o.id = a.owner_user_id
	LEFT JOIN users so ON so.id = a.security_owner_user_id
	LEFT JOIN users t ON t.id = a.technical_owner_user_id
	LEFT JOIN regions rg ON rg.id = a.data_residency_region_id`

func userRef(id *uuid.UUID, name, email *string) *UserRef {
	if id == nil {
		return nil
	}
	return &UserRef{ID: *id, Name: *name, Email: *email}
}

func ref(id *uuid.UUID, name *string) *Ref {
	if id == nil {
		return nil
	}
	return &Ref{ID: *id, Name: *name}
}

func scanApp(row pgx.Row) (Application, error) {
	var a Application
	var buID, oID, soID, tID, rgID *uuid.UUID
	var buName, oName, oEmail, soName, soEmail, tName, tEmail, rgName *string
	var detected []byte
	err := row.Scan(&a.ID, &a.Key, &a.Name, &a.Description, &a.ExternalRef, &buID, &buName, &oID, &oName, &oEmail,
		&soID, &soName, &soEmail, &tID, &tName, &tEmail, &a.Criticality, &a.Lifecycle, &a.Environment, &a.ApplicationType,
		&a.Languages, &a.Frameworks, &a.Runtimes, &a.DataClassification, &a.InternetExposure, &a.ComplianceScopes,
		&a.AuthenticationModel, &a.HostingRegion, &rgID, &rgName, &a.OnboardingStatus, &detected, &a.RepositoryCount,
		&a.ArchivedAt, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, errNotFound
	}
	if err != nil {
		return a, err
	}
	a.BusinessUnit, a.DataResidencyRegion = ref(buID, buName), ref(rgID, rgName)
	a.Owner, a.SecurityOwner, a.TechnicalOwner = userRef(oID, oName, oEmail), userRef(soID, soName, soEmail), userRef(tID, tName, tEmail)
	a.Detected = map[string]Detection{}
	if len(detected) > 0 {
		if err := json.Unmarshal(detected, &a.Detected); err != nil {
			return a, err
		}
	}
	return a, nil
}

func appTags(ctx context.Context, q db.Querier, appID uuid.UUID) ([]AppTag, error) {
	rows, err := q.Query(ctx, `SELECT t.id, t.name, t.color, tc.id, tc.name, tc.color, at.source
		FROM application_tags at JOIN tags t ON t.id = at.tag_id JOIN tag_categories tc ON tc.id = t.category_id
		WHERE at.application_id = $1 ORDER BY lower(tc.name), lower(t.name)`, appID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[AppTag])
	if out == nil {
		out = []AppTag{}
	}
	return out, err
}

// loadApp reads the full profile (no authorization check).
func (s *Service) loadApp(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (Application, error) {
	a, err := scanApp(q.QueryRow(ctx, appDetailSelect+` WHERE a.organization_id = $1 AND a.id = $2`, orgID, id))
	if err != nil {
		return a, err
	}
	if a.Tags, err = appTags(ctx, q, a.ID); err != nil {
		return a, err
	}
	req, err := requiredFields(ctx, q, orgID)
	if err != nil {
		return a, err
	}
	mand, err := loadMandatoryCategories(ctx, q, orgID)
	if err != nil {
		return a, err
	}
	a.ComputeProgress(req, mand)
	return a, nil
}

// getApplication: GET /api/v1/applications/{id}.
func (s *Service) getApplication(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	row, err := s.loadVisibleApp(ctx, s.DB, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.loadApp(ctx, s.DB, p.OrganizationID, row.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a.CanManage, _ = s.Authz.Can(ctx, p, authz.PermReposManage, appScope(p, row.BU))
	a.CanManage = a.CanManage && a.ArchivedAt == nil
	httpx.WriteJSON(w, http.StatusOK, a)
}

// optUUID distinguishes an absent field from an explicit null.
type optUUID struct {
	Set bool
	Val *uuid.UUID
}

func (o *optUUID) UnmarshalJSON(b []byte) error {
	o.Set = true
	if bytes.Equal(b, []byte("null")) {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return errors.New("invalid id")
	}
	o.Val = &id
	return nil
}

// ClassificationPatch is the body of PATCH
// /api/v1/applications/{id}/classification (absent fields are unchanged).
type ClassificationPatch struct {
	Description           *string      `json:"description"`
	BusinessUnitID        optUUID      `json:"business_unit_id"`
	OwnerUserID           optUUID      `json:"owner_user_id"`
	SecurityOwnerID       optUUID      `json:"security_owner_user_id"`
	TechnicalOwnerID      optUUID      `json:"technical_owner_user_id"`
	Criticality           *string      `json:"criticality"`
	Environment           *string      `json:"environment"`
	Lifecycle             *string      `json:"lifecycle"`
	ExternalRef           *string      `json:"external_ref"`
	ApplicationType       *string      `json:"application_type"`
	Languages             *[]string    `json:"languages"`
	Frameworks            *[]string    `json:"frameworks"`
	Runtimes              *[]string    `json:"runtimes"`
	DataClassification    *string      `json:"data_classification"`
	InternetExposure      *string      `json:"internet_exposure"`
	ComplianceScopes      *[]string    `json:"compliance_scopes"`
	AuthenticationModel   *string      `json:"authentication_model"`
	HostingRegion         *string      `json:"hosting_region"`
	DataResidencyRegionID optUUID      `json:"data_residency_region_id"`
	TagIDs                *[]uuid.UUID `json:"tag_ids"`
}

var (
	criticalities = []string{"critical", "high", "medium", "low"}
	lifecycles    = []string{"planned", "development", "active", "maintenance", "deprecated", "retired"}
	environments  = []string{"production", "staging", "development", "test", "other"}
)

// catalogKinds maps classification fields to their catalogue kind.
var catalogKinds = map[string]string{
	"application_type": "application_type", "data_classification": "data_classification",
	"internet_exposure": "internet_exposure", "compliance_scopes": "compliance",
	"authentication_model": "authentication_model", "hosting_region": "hosting_region",
}

func cleanList(field string, in []string, maxItems int) ([]string, error) {
	out := mergeUnique(nil, in)
	if len(out) > maxItems {
		return nil, fmt.Errorf("%s: at most %d values", field, maxItems)
	}
	for _, v := range out {
		if len(v) > 60 || strings.ContainsAny(v, "\x00\r\n") {
			return nil, fmt.Errorf("%s: each value must be at most 60 characters", field)
		}
	}
	return out, nil
}

// validate checks values against the fixed lists and the organization's
// classification catalogues; it returns per-field messages.
func (c *ClassificationPatch) validate(ctx context.Context, q db.Querier, orgID uuid.UUID) (map[string]string, error) {
	fe := map[string]string{}
	if c.Description != nil && len(*c.Description) > 2000 {
		fe["description"] = "at most 2000 characters"
	}
	if c.ExternalRef != nil {
		v := strings.TrimSpace(*c.ExternalRef)
		if len(v) > 100 || strings.ContainsAny(v, "\x00\r\n") {
			fe["external_ref"] = "at most 100 characters"
		}
		c.ExternalRef = &v
	}
	if c.Criticality != nil && !slices.Contains(criticalities, *c.Criticality) {
		fe["criticality"] = "must be one of " + strings.Join(criticalities, ", ")
	}
	if c.Environment != nil && !slices.Contains(environments, *c.Environment) {
		fe["environment"] = "must be one of " + strings.Join(environments, ", ")
	}
	if c.Lifecycle != nil && !slices.Contains(lifecycles, *c.Lifecycle) {
		fe["lifecycle"] = "must be one of " + strings.Join(lifecycles, ", ")
	}
	for field, ptr := range map[string]**[]string{"languages": &c.Languages, "frameworks": &c.Frameworks, "runtimes": &c.Runtimes} {
		if *ptr == nil {
			continue
		}
		limit := 50
		if field == "runtimes" {
			limit = 20
		}
		v, err := cleanList(field, **ptr, limit)
		if err != nil {
			fe[field] = err.Error()
			continue
		}
		*ptr = &v
	}
	// Catalogue values: active keys of the organization's catalogues.
	check := func(field, value string) {
		if value == "" {
			return
		}
		var ok bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM asset_classifications WHERE organization_id = $1 AND kind = $2
			AND key = $3 AND archived_at IS NULL)`, orgID, catalogKinds[field], value).Scan(&ok); err == nil && !ok {
			fe[field] = "unknown value " + fmt.Sprintf("%q", value) + " (see Configurations › Asset settings)"
		}
	}
	for field, v := range map[string]*string{"application_type": c.ApplicationType, "data_classification": c.DataClassification,
		"internet_exposure": c.InternetExposure, "authentication_model": c.AuthenticationModel, "hosting_region": c.HostingRegion} {
		if v != nil {
			check(field, *v)
		}
	}
	if c.ComplianceScopes != nil {
		v, err := cleanList("compliance_scopes", *c.ComplianceScopes, 30)
		if err != nil {
			fe["compliance_scopes"] = err.Error()
		} else {
			c.ComplianceScopes = &v
			for _, k := range v {
				check("compliance_scopes", k)
			}
		}
	}
	if c.TagIDs != nil && len(*c.TagIDs) > 50 {
		fe["tags"] = "at most 50 tags"
	}
	return fe, nil
}

// changedFields lists the classification fields a patch sets.
func (c *ClassificationPatch) changedFields() []string {
	var out []string
	add := func(set bool, f string) {
		if set {
			out = append(out, f)
		}
	}
	add(c.Description != nil, "description")
	add(c.BusinessUnitID.Set, "business_unit")
	add(c.OwnerUserID.Set, "owner")
	add(c.SecurityOwnerID.Set, "security_owner")
	add(c.TechnicalOwnerID.Set, "technical_owner")
	add(c.Criticality != nil, "criticality")
	add(c.Environment != nil, "environment")
	add(c.Lifecycle != nil, "lifecycle")
	add(c.ExternalRef != nil, "external_ref")
	add(c.ApplicationType != nil, "application_type")
	add(c.Languages != nil, "languages")
	add(c.Frameworks != nil, "frameworks")
	add(c.Runtimes != nil, "runtimes")
	add(c.DataClassification != nil, "data_classification")
	add(c.InternetExposure != nil, "internet_exposure")
	add(c.ComplianceScopes != nil, "compliance_scopes")
	add(c.AuthenticationModel != nil, "authentication_model")
	add(c.HostingRegion != nil, "hosting_region")
	add(c.DataResidencyRegionID.Set, "data_residency")
	return out
}

// writeClassification applies the patch inside tx. Fields a person sets
// lose their "detected" mark.
func writeClassification(ctx context.Context, tx pgx.Tx, appID uuid.UUID, c *ClassificationPatch) error {
	_, err := tx.Exec(ctx, `UPDATE applications SET
		description = COALESCE($2, description),
		business_unit_id = CASE WHEN $3 THEN $4 ELSE business_unit_id END,
		owner_user_id = CASE WHEN $5 THEN $6 ELSE owner_user_id END,
		security_owner_user_id = CASE WHEN $7 THEN $8 ELSE security_owner_user_id END,
		technical_owner_user_id = CASE WHEN $9 THEN $10 ELSE technical_owner_user_id END,
		criticality = COALESCE($11, criticality), environment = COALESCE($12, environment), lifecycle = COALESCE($13, lifecycle),
		external_ref = COALESCE($14, external_ref), application_type = COALESCE($15, application_type),
		languages = COALESCE($16, languages), frameworks = COALESCE($17, frameworks), runtimes = COALESCE($18, runtimes),
		data_classification = COALESCE($19, data_classification), internet_exposure = COALESCE($20, internet_exposure),
		compliance_scopes = COALESCE($21, compliance_scopes), authentication_model = COALESCE($22, authentication_model),
		hosting_region = COALESCE($23, hosting_region),
		data_residency_region_id = CASE WHEN $24 THEN $25 ELSE data_residency_region_id END,
		detected_fields = detected_fields - $26::text[],
		updated_at = now()
		WHERE id = $1`, appID, c.Description,
		c.BusinessUnitID.Set, c.BusinessUnitID.Val, c.OwnerUserID.Set, c.OwnerUserID.Val,
		c.SecurityOwnerID.Set, c.SecurityOwnerID.Val, c.TechnicalOwnerID.Set, c.TechnicalOwnerID.Val,
		c.Criticality, c.Environment, c.Lifecycle, c.ExternalRef, c.ApplicationType,
		c.Languages, c.Frameworks, c.Runtimes, c.DataClassification, c.InternetExposure, c.ComplianceScopes,
		c.AuthenticationModel, c.HostingRegion, c.DataResidencyRegionID.Set, c.DataResidencyRegionID.Val,
		nonNilStrings(c.changedFields()))
	return err
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// updateClassification: PATCH /api/v1/applications/{id}/classification.
// Saves whatever is given (drafts may stay incomplete), then applies the
// automatic tagging rules.
func (s *Service) updateClassification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req ClassificationPatch
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	row, err := s.loadManagedApp(ctx, s.DB, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	fe, err := req.validate(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(fe) > 0 {
		s.fail(w, r, errFields(http.StatusBadRequest, "validation_failed", "PTH-PLAT-0003", "some fields are invalid", fe))
		return
	}
	if req.BusinessUnitID.Set {
		if err := s.Authz.Require(ctx, p, authz.PermReposManage, appScope(p, req.BusinessUnitID.Val)); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	var out Application
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := writeClassification(ctx, tx, row.ID, &req); err != nil {
			return err
		}
		if req.TagIDs != nil {
			if err := setAppTags(ctx, tx, p, row.ID, row.Name, *req.TagIDs, "manual"); err != nil {
				return err
			}
		}
		if _, err := applyAppRules(ctx, tx, p, row.ID); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "application.classify", TargetType: "application", TargetID: row.ID.String(),
			Metadata: map[string]any{"name": row.Name, "fields": req.changedFields(), "tags_changed": req.TagIDs != nil}}); err != nil {
			return err
		}
		var err error
		out, err = s.loadApp(ctx, tx, p.OrganizationID, row.ID)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out.CanManage = true
	httpx.WriteJSON(w, http.StatusOK, out)
}

// Settings is the application part of Asset settings.
type Settings struct {
	RequiredFields []string          `json:"required_fields"`
	Fields         []string          `json:"fields"`
	Labels         map[string]string `json:"labels"`
}

func (s *Service) getSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReposRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	req, err := requiredFields(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, Settings{RequiredFields: req, Fields: ApplicationFields, Labels: FieldLabels})
}

func (s *Service) updateSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if err := s.Authz.Require(ctx, p, authz.PermAssetsConfigure, orgScope(p)); err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		RequiredFields []string `json:"required_fields"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.RequiredFields == nil {
		s.fail(w, r, httpx.BadRequest("required_fields is required"))
		return
	}
	fields := mergeUnique(nil, req.RequiredFields)
	for _, f := range fields {
		if !slices.Contains(ApplicationFields, f) {
			s.fail(w, r, httpx.BadRequest("unknown field "+f+"; fields: "+strings.Join(ApplicationFields, ", ")))
			return
		}
	}
	var old []string
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO asset_settings (organization_id) VALUES ($1) ON CONFLICT DO NOTHING`, p.OrganizationID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT application_required_fields FROM asset_settings WHERE organization_id = $1 FOR UPDATE`, p.OrganizationID).Scan(&old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE asset_settings SET application_required_fields = $2, updated_by = $3, updated_at = now()
			WHERE organization_id = $1`, p.OrganizationID, fields, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "asset_settings.application_fields", TargetType: "asset_settings", TargetID: p.OrganizationID.String(),
			Metadata: map[string]any{"old": old, "new": fields}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, Settings{RequiredFields: fields, Fields: ApplicationFields, Labels: FieldLabels})
}

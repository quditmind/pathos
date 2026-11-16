package repos

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

	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// AssetMetadata is the registration payload shared by every import method
// and by PATCH /repositories/{id} (frontend type AssetMetadata). Absent
// fields are left unchanged; explicit null or "" clears optional values.
type AssetMetadata struct {
	DisplayName           *string      `json:"display_name"`
	AssetName             *string      `json:"asset_name"`
	Description           *string      `json:"description"`
	ApplicationID         optUUID      `json:"application_id"`
	NewApplication        *NewApp      `json:"new_application"`
	ApplicationType       *string      `json:"application_type"`
	BusinessPurpose       *string      `json:"business_purpose"`
	BusinessOwnerID       optUUID      `json:"business_owner_id"`
	TechnicalOwnerID      optUUID      `json:"technical_owner_id"`
	ApplicationOwnerID    optUUID      `json:"application_owner_id"`
	BusinessUnitID        optUUID      `json:"business_unit_id"`
	DepartmentID          optUUID      `json:"department_id"`
	ResponsibleTeamID     optUUID      `json:"responsible_team_id"`
	SupportingTeamID      optUUID      `json:"supporting_team_id"`
	CostCentre            *string      `json:"cost_centre"`
	BusinessRegionID      optUUID      `json:"business_region_id"`
	CountryID             optUUID      `json:"country_id"`
	HostingRegion         *string      `json:"hosting_region"`
	DataResidencyRegionID optUUID      `json:"data_residency_region_id"`
	OperationalLocation   *string      `json:"operational_location"`
	Criticality           *string      `json:"criticality"`
	DataClassification    *string      `json:"data_classification"`
	Environment           *string      `json:"environment"`
	InternetExposure      *string      `json:"internet_exposure"`
	ComplianceScopes      *[]string    `json:"compliance_scopes"`
	TagIDs                *[]uuid.UUID `json:"tag_ids"`
	Color                 *string      `json:"color"`
	LifecycleStatus       *string      `json:"lifecycle_status"`
	GoLiveDate            optDate      `json:"go_live_date"`
	RetirementDate        optDate      `json:"retirement_date"`
}

// NewApp creates an application during registration.
type NewApp struct {
	Name        string `json:"name"`
	ExternalRef string `json:"external_ref"`
}

// optDate is a nullable YYYY-MM-DD that distinguishes absent from null.
type optDate struct {
	Set bool
	Val *string
}

func (o *optDate) UnmarshalJSON(b []byte) error {
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
	if _, err := time.Parse(time.DateOnly, s); err != nil {
		return errors.New("dates must be YYYY-MM-DD")
	}
	o.Val = &s
	return nil
}

// AssetValues is the complete, normalized metadata of one asset. It is what
// import items store (JSON) and what registration writes.
type AssetValues struct {
	DisplayName           string      `json:"display_name"`
	AssetName             string      `json:"asset_name"`
	Description           string      `json:"description"`
	ApplicationID         *uuid.UUID  `json:"application_id"`
	NewApplication        *NewApp     `json:"new_application,omitempty"`
	ApplicationType       string      `json:"application_type"`
	BusinessPurpose       string      `json:"business_purpose"`
	BusinessOwnerID       *uuid.UUID  `json:"business_owner_id"`
	TechnicalOwnerID      *uuid.UUID  `json:"technical_owner_id"`
	ApplicationOwnerID    *uuid.UUID  `json:"application_owner_id"`
	BusinessUnitID        *uuid.UUID  `json:"business_unit_id"`
	DepartmentID          *uuid.UUID  `json:"department_id"`
	ResponsibleTeamID     *uuid.UUID  `json:"responsible_team_id"`
	SupportingTeamID      *uuid.UUID  `json:"supporting_team_id"`
	CostCentre            string      `json:"cost_centre"`
	BusinessRegionID      *uuid.UUID  `json:"business_region_id"`
	CountryID             *uuid.UUID  `json:"country_id"`
	HostingRegion         string      `json:"hosting_region"`
	DataResidencyRegionID *uuid.UUID  `json:"data_residency_region_id"`
	OperationalLocation   string      `json:"operational_location"`
	Criticality           string      `json:"criticality"`
	DataClassification    string      `json:"data_classification"`
	Environment           string      `json:"environment"`
	InternetExposure      string      `json:"internet_exposure"`
	ComplianceScopes      []string    `json:"compliance_scopes"`
	TagIDs                []uuid.UUID `json:"tag_ids"`
	Color                 string      `json:"color"`
	LifecycleStatus       string      `json:"lifecycle_status"`
	GoLiveDate            *string     `json:"go_live_date"`
	RetirementDate        *string     `json:"retirement_date"`
}

// defaultValues are used for fields an import does not set.
func defaultValues() AssetValues {
	return AssetValues{Criticality: "medium", Environment: "production", InternetExposure: "unknown",
		LifecycleStatus: "active", ComplianceScopes: []string{}, TagIDs: []uuid.UUID{}}
}

func setStr(dst *string, src *string) {
	if src != nil {
		*dst = strings.TrimSpace(*src)
	}
}

func setID(dst **uuid.UUID, src optUUID) {
	if src.Set {
		*dst = src.Val
	}
}

// Apply overlays the set fields of m onto v and returns the AssetValues
// field names (JSON) that were present in the request.
func (m AssetMetadata) Apply(v *AssetValues) []string {
	var changed []string
	str := func(name string, dst *string, src *string) {
		if src != nil {
			setStr(dst, src)
			changed = append(changed, name)
		}
	}
	id := func(name string, dst **uuid.UUID, src optUUID) {
		if src.Set {
			setID(dst, src)
			changed = append(changed, name)
		}
	}
	str("display_name", &v.DisplayName, m.DisplayName)
	str("asset_name", &v.AssetName, m.AssetName)
	if m.Description != nil { // keep internal whitespace and newlines
		v.Description = strings.TrimSpace(*m.Description)
		changed = append(changed, "description")
	}
	id("application_id", &v.ApplicationID, m.ApplicationID)
	if m.NewApplication != nil {
		v.NewApplication = &NewApp{Name: strings.TrimSpace(m.NewApplication.Name), ExternalRef: strings.TrimSpace(m.NewApplication.ExternalRef)}
		v.ApplicationID = nil
		changed = append(changed, "new_application")
	}
	str("application_type", &v.ApplicationType, m.ApplicationType)
	if m.BusinessPurpose != nil {
		v.BusinessPurpose = strings.TrimSpace(*m.BusinessPurpose)
		changed = append(changed, "business_purpose")
	}
	id("business_owner_id", &v.BusinessOwnerID, m.BusinessOwnerID)
	id("technical_owner_id", &v.TechnicalOwnerID, m.TechnicalOwnerID)
	id("application_owner_id", &v.ApplicationOwnerID, m.ApplicationOwnerID)
	id("business_unit_id", &v.BusinessUnitID, m.BusinessUnitID)
	id("department_id", &v.DepartmentID, m.DepartmentID)
	id("responsible_team_id", &v.ResponsibleTeamID, m.ResponsibleTeamID)
	id("supporting_team_id", &v.SupportingTeamID, m.SupportingTeamID)
	str("cost_centre", &v.CostCentre, m.CostCentre)
	id("business_region_id", &v.BusinessRegionID, m.BusinessRegionID)
	id("country_id", &v.CountryID, m.CountryID)
	str("hosting_region", &v.HostingRegion, m.HostingRegion)
	id("data_residency_region_id", &v.DataResidencyRegionID, m.DataResidencyRegionID)
	str("operational_location", &v.OperationalLocation, m.OperationalLocation)
	str("criticality", &v.Criticality, m.Criticality)
	str("data_classification", &v.DataClassification, m.DataClassification)
	str("environment", &v.Environment, m.Environment)
	str("internet_exposure", &v.InternetExposure, m.InternetExposure)
	if m.ComplianceScopes != nil {
		v.ComplianceScopes = dedupe(*m.ComplianceScopes)
		changed = append(changed, "compliance_scopes")
	}
	if m.TagIDs != nil {
		v.TagIDs = slices.Clone(*m.TagIDs)
		if v.TagIDs == nil {
			v.TagIDs = []uuid.UUID{}
		}
		changed = append(changed, "tag_ids")
	}
	if m.Color != nil {
		v.Color = strings.ToLower(strings.TrimSpace(*m.Color))
		changed = append(changed, "color")
	}
	str("lifecycle_status", &v.LifecycleStatus, m.LifecycleStatus)
	if m.GoLiveDate.Set {
		v.GoLiveDate = m.GoLiveDate.Val
		changed = append(changed, "go_live_date")
	}
	if m.RetirementDate.Set {
		v.RetirementDate = m.RetirementDate.Val
		changed = append(changed, "retirement_date")
	}
	return changed
}

func dedupe(in []string) []string {
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// requiredKey maps a policy field (assetFields) to its AssetValues key.
var requiredKey = map[string]string{
	"description": "description", "application": "application_id", "application_type": "application_type",
	"business_purpose": "business_purpose", "business_owner": "business_owner_id", "technical_owner": "technical_owner_id",
	"application_owner": "application_owner_id", "business_unit": "business_unit_id", "department": "department_id",
	"responsible_team": "responsible_team_id", "supporting_team": "supporting_team_id", "cost_centre": "cost_centre",
	"business_region": "business_region_id", "country": "country_id", "hosting_region": "hosting_region",
	"data_residency_region": "data_residency_region_id", "operational_location": "operational_location",
	"criticality": "criticality", "data_classification": "data_classification", "environment": "environment",
	"internet_exposure": "internet_exposure", "compliance_scopes": "compliance_scopes", "tags": "tag_ids",
	"lifecycle_status": "lifecycle_status",
}

func (v AssetValues) empty(key string) bool {
	switch key {
	case "description":
		return v.Description == ""
	case "application_id":
		return v.ApplicationID == nil && (v.NewApplication == nil || v.NewApplication.Name == "")
	case "application_type":
		return v.ApplicationType == ""
	case "business_purpose":
		return v.BusinessPurpose == ""
	case "business_owner_id":
		return v.BusinessOwnerID == nil
	case "technical_owner_id":
		return v.TechnicalOwnerID == nil
	case "application_owner_id":
		return v.ApplicationOwnerID == nil
	case "business_unit_id":
		return v.BusinessUnitID == nil
	case "department_id":
		return v.DepartmentID == nil
	case "responsible_team_id":
		return v.ResponsibleTeamID == nil
	case "supporting_team_id":
		return v.SupportingTeamID == nil
	case "cost_centre":
		return v.CostCentre == ""
	case "business_region_id":
		return v.BusinessRegionID == nil
	case "country_id":
		return v.CountryID == nil
	case "hosting_region":
		return v.HostingRegion == ""
	case "data_residency_region_id":
		return v.DataResidencyRegionID == nil
	case "operational_location":
		return v.OperationalLocation == ""
	case "criticality":
		return v.Criticality == ""
	case "data_classification":
		return v.DataClassification == ""
	case "environment":
		return v.Environment == ""
	case "internet_exposure":
		return v.InternetExposure == "" || v.InternetExposure == "unknown"
	case "compliance_scopes":
		return len(v.ComplianceScopes) == 0
	case "tag_ids":
		return len(v.TagIDs) == 0
	case "lifecycle_status":
		return v.LifecycleStatus == ""
	}
	return false
}

// FieldErrors maps AssetValues keys to messages.
type FieldErrors map[string]string

func (fe FieldErrors) add(field, msg string) {
	if _, ok := fe[field]; !ok {
		fe[field] = msg
	}
}

// Err returns a 422 validation error, or nil.
func (fe FieldErrors) Err() error {
	if len(fe) == 0 {
		return nil
	}
	keys := make([]string, 0, len(fe))
	for k := range fe {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	e := httpx.E(http.StatusUnprocessableEntity, "validation_failed", "check the highlighted fields: "+strings.Join(keys, ", "))
	e.Fields = fe
	return e
}

// validateOpts controls which checks apply.
type validateOpts struct {
	// Creating: every policy-required field must be present. Updating:
	// required fields may not be cleared, but legacy gaps in untouched
	// fields do not block unrelated edits.
	Creating bool
	Changed  []string
	// Previous values (updates): archived catalog entries and deactivated
	// users that were already set remain acceptable.
	Previous *AssetValues
	// ExcludeRepo skips this repository in the asset name uniqueness check.
	ExcludeRepo *uuid.UUID
}

// validateValues checks v against the organization's policy and data.
func validateValues(ctx context.Context, q db.Querier, orgID uuid.UUID, ap *assetPolicy, v *AssetValues, o validateOpts) FieldErrors {
	fe := FieldErrors{}
	changed := func(k string) bool { return o.Creating || slices.Contains(o.Changed, k) }

	for field, key := range requiredKey {
		if ap.required(field) && v.empty(key) && changed(key) {
			fe.add(key, "required")
		}
	}

	for _, c := range []struct {
		key string
		val string
		max int
	}{
		{"display_name", v.DisplayName, 200}, {"asset_name", v.AssetName, 200}, {"description", v.Description, 2000},
		{"business_purpose", v.BusinessPurpose, 2000}, {"cost_centre", v.CostCentre, 100}, {"operational_location", v.OperationalLocation, 200},
	} {
		if len(c.val) > c.max {
			fe.add(c.key, fmt.Sprintf("at most %d characters", c.max))
		}
	}
	if v.Color != "" && !hexColorRe.MatchString(v.Color) {
		fe.add("color", "must be a colour like #1f6feb")
	}

	// Catalog values: new values must be active; unchanged archived values stay valid.
	catalog := func(key, kind, val string, allowEmpty bool) {
		if val == "" {
			if !allowEmpty {
				fe.add(key, "required")
			}
			return
		}
		if ap.active(kind, val) || (!changed(key) && ap.known(kind, val)) {
			return
		}
		if o.Previous != nil && ap.known(kind, val) && previousString(o.Previous, key) == val {
			return
		}
		fe.add(key, "unknown or archived value "+val)
	}
	catalog("criticality", KindCriticality, v.Criticality, false)
	catalog("environment", KindEnvironment, v.Environment, false)
	catalog("internet_exposure", KindInternetExposure, v.InternetExposure, false)
	catalog("lifecycle_status", KindLifecycleStatus, v.LifecycleStatus, false)
	catalog("data_classification", KindDataClassification, v.DataClassification, true)
	catalog("application_type", KindApplicationType, v.ApplicationType, true)
	catalog("hosting_region", KindHostingRegion, v.HostingRegion, true)
	for _, sc := range v.ComplianceScopes {
		if !ap.active(KindCompliance, sc) && !(o.Previous != nil && slices.Contains(o.Previous.ComplianceScopes, sc) && ap.known(KindCompliance, sc)) {
			fe.add("compliance_scopes", "unknown or archived compliance scope "+sc)
		}
	}
	if len(v.ComplianceScopes) > 30 {
		fe.add("compliance_scopes", "at most 30 compliance scopes")
	}

	if v.GoLiveDate != nil && v.RetirementDate != nil && *v.RetirementDate < *v.GoLiveDate {
		fe.add("retirement_date", "must not be before the go-live date")
	}

	// References.
	exists := func(key, sql string, id *uuid.UUID, msg string) {
		if id == nil {
			return
		}
		var ok bool
		if err := q.QueryRow(ctx, sql, orgID, *id).Scan(&ok); err != nil || !ok {
			fe.add(key, msg)
		}
	}
	activeUser := `SELECT EXISTS (SELECT 1 FROM users WHERE organization_id = $1 AND id = $2 AND status <> 'deactivated')`
	anyUser := `SELECT EXISTS (SELECT 1 FROM users WHERE organization_id = $1 AND id = $2)`
	for _, u := range []struct {
		key  string
		id   *uuid.UUID
		prev *uuid.UUID
	}{
		{"business_owner_id", v.BusinessOwnerID, prevID(o.Previous, func(p *AssetValues) *uuid.UUID { return p.BusinessOwnerID })},
		{"technical_owner_id", v.TechnicalOwnerID, prevID(o.Previous, func(p *AssetValues) *uuid.UUID { return p.TechnicalOwnerID })},
		{"application_owner_id", v.ApplicationOwnerID, prevID(o.Previous, func(p *AssetValues) *uuid.UUID { return p.ApplicationOwnerID })},
	} {
		if u.id != nil && u.prev != nil && *u.id == *u.prev {
			exists(u.key, anyUser, u.id, "user does not exist")
		} else {
			exists(u.key, activeUser, u.id, "user does not exist or is deactivated")
		}
	}
	team := `SELECT EXISTS (SELECT 1 FROM teams WHERE organization_id = $1 AND id = $2)`
	exists("responsible_team_id", team, v.ResponsibleTeamID, "team does not exist")
	exists("supporting_team_id", team, v.SupportingTeamID, "team does not exist")
	bu := `SELECT EXISTS (SELECT 1 FROM business_units WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL)`
	exists("business_unit_id", bu, v.BusinessUnitID, "business unit does not exist or is archived")
	region := `SELECT EXISTS (SELECT 1 FROM regions WHERE organization_id = $1 AND id = $2)`
	exists("business_region_id", region, v.BusinessRegionID, "region does not exist")
	exists("data_residency_region_id", region, v.DataResidencyRegionID, "region does not exist")
	exists("country_id", `SELECT EXISTS (SELECT 1 FROM countries WHERE organization_id = $1 AND id = $2)`, v.CountryID, "country does not exist")
	exists("application_id", `SELECT EXISTS (SELECT 1 FROM applications WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL)`,
		v.ApplicationID, "application does not exist or is archived")
	if v.DepartmentID != nil {
		if v.BusinessUnitID == nil {
			fe.add("department_id", "select a business unit first")
		} else if *v.DepartmentID == *v.BusinessUnitID {
			fe.add("department_id", "the department must be a unit below the business unit")
		} else {
			var ok bool
			err := q.QueryRow(ctx, `WITH RECURSIVE d AS (
				SELECT id FROM business_units WHERE organization_id = $1 AND parent_id = $2 AND archived_at IS NULL
				UNION ALL SELECT b.id FROM business_units b JOIN d ON b.parent_id = d.id WHERE b.archived_at IS NULL)
				SELECT EXISTS (SELECT 1 FROM d WHERE id = $3)`, orgID, *v.BusinessUnitID, *v.DepartmentID).Scan(&ok)
			if err != nil || !ok {
				fe.add("department_id", "the department must be a unit below the selected business unit")
			}
		}
	}
	if na := v.NewApplication; na != nil {
		switch {
		case na.Name == "" || len(na.Name) > 200:
			fe.add("new_application", "application name must be 1-200 characters")
		case len(na.ExternalRef) > 100:
			fe.add("new_application", "application ID must be at most 100 characters")
		default:
			var clash bool
			_ = q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM applications WHERE organization_id = $1 AND lower(name) = lower($2) AND archived_at IS NULL)`,
				orgID, na.Name).Scan(&clash)
			if clash {
				fe.add("new_application", "an application with this name already exists; select it instead")
			}
		}
	}
	if v.AssetName != "" && changed("asset_name") {
		var clash bool
		_ = q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM repositories WHERE organization_id = $1 AND lower(asset_name) = lower($2)
			AND archived_at IS NULL AND ($3::uuid IS NULL OR id <> $3))`, orgID, v.AssetName, o.ExcludeRepo).Scan(&clash)
		if clash {
			fe.add("asset_name", "another asset already uses this name")
		}
	}
	if changed("tag_ids") {
		if err := validateTagSet(ctx, q, orgID, v.TagIDs); err != nil {
			var he *httpx.Error
			if errors.As(err, &he) {
				fe.add("tag_ids", he.Message)
			} else {
				fe.add("tag_ids", "invalid tags")
			}
		}
	}
	return fe
}

func prevID(p *AssetValues, f func(*AssetValues) *uuid.UUID) *uuid.UUID {
	if p == nil {
		return nil
	}
	return f(p)
}

func previousString(p *AssetValues, key string) string {
	switch key {
	case "criticality":
		return p.Criticality
	case "environment":
		return p.Environment
	case "internet_exposure":
		return p.InternetExposure
	case "lifecycle_status":
		return p.LifecycleStatus
	case "data_classification":
		return p.DataClassification
	case "application_type":
		return p.ApplicationType
	case "hosting_region":
		return p.HostingRegion
	}
	return ""
}

// currentValues loads a repository's metadata as AssetValues.
func currentValues(ctx context.Context, q db.Querier, orgID, repoID uuid.UUID) (AssetValues, error) {
	var v AssetValues
	var golive, retire *time.Time
	err := q.QueryRow(ctx, `
		SELECT display_name, asset_name, description, application_id, application_type, business_purpose,
		       business_owner_id, technical_owner_id, application_owner_id, business_unit_id, department_id,
		       responsible_team_id, supporting_team_id, cost_centre, business_region_id, country_id, hosting_region,
		       data_residency_region_id, operational_location, criticality, data_classification, environment,
		       internet_exposure, color, lifecycle_status, go_live_date, retirement_date,
		       COALESCE((SELECT array_agg(scope_key ORDER BY scope_key) FROM repository_compliance_scopes s WHERE s.repository_id = r.id), '{}'),
		       COALESCE((SELECT array_agg(tag_id) FROM repository_tags t WHERE t.repository_id = r.id), '{}')
		FROM repositories r WHERE organization_id = $1 AND id = $2`, orgID, repoID).Scan(
		&v.DisplayName, &v.AssetName, &v.Description, &v.ApplicationID, &v.ApplicationType, &v.BusinessPurpose,
		&v.BusinessOwnerID, &v.TechnicalOwnerID, &v.ApplicationOwnerID, &v.BusinessUnitID, &v.DepartmentID,
		&v.ResponsibleTeamID, &v.SupportingTeamID, &v.CostCentre, &v.BusinessRegionID, &v.CountryID, &v.HostingRegion,
		&v.DataResidencyRegionID, &v.OperationalLocation, &v.Criticality, &v.DataClassification, &v.Environment,
		&v.InternetExposure, &v.Color, &v.LifecycleStatus, &golive, &retire, &v.ComplianceScopes, &v.TagIDs)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, errNotFound
	}
	v.GoLiveDate, v.RetirementDate = dateString(golive), dateString(retire)
	return v, err
}

func dateString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.DateOnly)
	return &s
}

// writeValues persists v on an existing repository row (inside tx),
// creating a new application first if requested.
func writeValues(ctx context.Context, tx pgx.Tx, orgID, repoID, actor uuid.UUID, v *AssetValues) error {
	if na := v.NewApplication; na != nil && na.Name != "" {
		appID := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO applications (id, organization_id, name, external_ref, business_unit_id, owner_user_id, criticality)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			appID, orgID, na.Name, na.ExternalRef, v.BusinessUnitID, v.ApplicationOwnerID, v.Criticality); err != nil {
			if db.IsUniqueViolation(err) {
				// Created concurrently by another import of the same batch.
				if err := tx.QueryRow(ctx, `SELECT id FROM applications WHERE organization_id = $1 AND lower(name) = lower($2) AND archived_at IS NULL`,
					orgID, na.Name).Scan(&appID); err != nil {
					return err
				}
			} else {
				return err
			}
		}
		v.ApplicationID, v.NewApplication = &appID, nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE repositories SET display_name = $3, asset_name = $4, description = $5, application_id = $6, application_type = $7,
		       business_purpose = $8, business_owner_id = $9, technical_owner_id = $10, application_owner_id = $11,
		       business_unit_id = $12, department_id = $13, responsible_team_id = $14, supporting_team_id = $15, cost_centre = $16,
		       business_region_id = $17, country_id = $18, hosting_region = $19, data_residency_region_id = $20,
		       operational_location = $21, criticality = $22, data_classification = $23, environment = $24,
		       internet_exposure = $25, color = $26, lifecycle_status = $27, go_live_date = $28::date, retirement_date = $29::date,
		       updated_by = $30, updated_at = now()
		WHERE organization_id = $1 AND id = $2`,
		orgID, repoID, v.DisplayName, v.AssetName, truncate(v.Description, 2000), v.ApplicationID, v.ApplicationType,
		v.BusinessPurpose, v.BusinessOwnerID, v.TechnicalOwnerID, v.ApplicationOwnerID,
		v.BusinessUnitID, v.DepartmentID, v.ResponsibleTeamID, v.SupportingTeamID, v.CostCentre,
		v.BusinessRegionID, v.CountryID, v.HostingRegion, v.DataResidencyRegionID,
		v.OperationalLocation, v.Criticality, v.DataClassification, v.Environment,
		v.InternetExposure, v.Color, v.LifecycleStatus, v.GoLiveDate, v.RetirementDate, actor); err != nil {
		return err
	}
	scopes := v.ComplianceScopes
	if scopes == nil {
		scopes = []string{}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM repository_compliance_scopes WHERE repository_id = $1 AND scope_key <> ALL($2::text[])`, repoID, scopes); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO repository_compliance_scopes (organization_id, repository_id, scope_key)
		SELECT $1, $2, unnest($3::text[]) ON CONFLICT DO NOTHING`, orgID, repoID, scopes); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM repository_tags WHERE repository_id = $1 AND tag_id <> ALL($2::uuid[])`, repoID, nonNil(v.TagIDs)); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO repository_tags (organization_id, repository_id, tag_id)
		SELECT $1, $2, unnest($3::uuid[]) ON CONFLICT DO NOTHING`, orgID, repoID, nonNil(v.TagIDs))
	return err
}

// diffValues returns old/new pairs of changed fields for the audit log.
func diffValues(old, cur AssetValues) map[string]any {
	ob, _ := json.Marshal(old)
	nb, _ := json.Marshal(cur)
	var om, nm map[string]any
	_ = json.Unmarshal(ob, &om)
	_ = json.Unmarshal(nb, &nm)
	out := map[string]any{}
	for k, nv := range nm {
		ov := om[k]
		oj, _ := json.Marshal(ov)
		nj, _ := json.Marshal(nv)
		if !bytes.Equal(oj, nj) {
			out[k] = map[string]any{"old": ov, "new": nv}
		}
	}
	return out
}

// mustBeEmpty rejects metadata on requests that do not create an asset.
func (m AssetMetadata) mustBeEmpty() error {
	var v AssetValues
	if changed := m.Apply(&v); len(changed) > 0 {
		return httpx.BadRequest("metadata cannot be changed when uploading a new version; edit the repository instead")
	}
	return nil
}

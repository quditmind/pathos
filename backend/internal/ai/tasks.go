package ai

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/featureflags"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// FlagIntelligence gates the M7 API and pages (evidence log, model per
// task, correlation, threat suggestions). Evidence records are written
// whatever the flag: they are the audit trail of every AI call.
const FlagIntelligence = "ai_intelligence"

// resolved is the configuration, provider and client an AI call uses.
type resolved struct {
	CV              ConfigVersion
	ConfigurationID uuid.UUID
	PV              ProviderView
	Prov            Provider
	Location        string
	// Source: assignment, local_default, default, troubleshooting_local
	// or queued (the version stored with a queued review).
	Source string
}

// taskConfig picks the configuration version of a task. With the
// ai_intelligence flag on: the task's assignment, else for code-bearing
// tasks a self-hosted configuration (the default one first), else the
// organization default. With the flag off: the behaviour before M7 (the
// default configuration; troubleshooting prefers a self-hosted one).
func taskConfig(ctx context.Context, q db.Querier, orgID uuid.UUID, task string) (ConfigVersion, uuid.UUID, string, error) {
	on, _ := featureflags.Enabled(ctx, q, orgID, FlagIntelligence)
	info, _ := TaskByKey(task)
	type pick struct {
		where, order, source string
		args                 []any
	}
	var picks []pick
	if on {
		picks = append(picks, pick{`EXISTS (SELECT 1 FROM ai_task_assignments a WHERE a.organization_id = c.organization_id AND a.configuration_id = c.id AND a.task = $2)`,
			`c.created_at`, "assignment", []any{task}})
	}
	if (on && info.CodeBearing) || task == TaskTroubleshooting {
		src := "local_default"
		if !on {
			src = "troubleshooting_local"
		}
		picks = append(picks, pick{`p.kind = 'self_hosted'`, `c.is_default DESC, c.created_at`, src, nil})
	}
	picks = append(picks, pick{`c.is_default`, `c.created_at`, "default", nil})
	for _, pk := range picks {
		var cid uuid.UUID
		args := append([]any{orgID}, pk.args...)
		// #nosec G202 -- where and order are constants of this function
		cv, err := scanCVWith(q.QueryRow(ctx, cvSelectWithConfig+` JOIN ai_configurations c ON c.current_version_id = v.id
			JOIN ai_providers p ON p.id = v.provider_id AND p.organization_id = c.organization_id
			WHERE c.organization_id = $1 AND c.archived_at IS NULL AND p.archived_at IS NULL AND `+pk.where+`
			ORDER BY `+pk.order+` LIMIT 1`, args...), &cid)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return cv, cid, "", err
		}
		return cv, cid, pk.source, nil
	}
	return ConfigVersion{}, uuid.Nil, "", ErrNotConfigured
}

const cvSelectWithConfig = `SELECT v.id, v.version, v.provider_id, v.model, v.effort, v.instructions, v.auto_review, v.categories, v.min_severity,
	v.approval_policy, v.daily_limit, v.send_code_context, v.redaction_patterns, v.change_note, v.created_at, v.allow_self_approval, v.configuration_id
	FROM ai_configuration_versions v`

func scanCVWith(r pgx.Row, cid *uuid.UUID) (ConfigVersion, error) {
	var v ConfigVersion
	err := r.Scan(&v.ID, &v.Version, &v.ProviderID, &v.Model, &v.Effort, &v.Instructions, &v.AutoReview, &v.Categories,
		&v.MinSeverity, &v.ApprovalPolicy, &v.DailyLimit, &v.SendCodeContext, &v.RedactionPatterns, &v.ChangeNote, &v.CreatedAt, &v.AllowSelfApproval, cid)
	return v, err
}

// resolve returns the configuration, provider and client of a task.
func (s *Service) resolve(ctx context.Context, orgID uuid.UUID, task string) (resolved, error) {
	cv, cid, src, err := taskConfig(ctx, s.DB, orgID, task)
	if err != nil {
		return resolved{}, err
	}
	return s.resolveVersion(ctx, orgID, cv, cid, src)
}

// resolveVersion loads the provider of a known configuration version.
func (s *Service) resolveVersion(ctx context.Context, orgID uuid.UUID, cv ConfigVersion, cid uuid.UUID, src string) (resolved, error) {
	pvs, err := s.loadProviders(ctx, orgID, &cv.ProviderID)
	if err != nil || len(pvs) == 0 {
		return resolved{}, ErrNotConfigured
	}
	prov, err := s.provider(ctx, orgID, pvs[0])
	if err != nil {
		return resolved{}, err
	}
	if cid == uuid.Nil {
		_ = s.DB.QueryRow(ctx, `SELECT configuration_id FROM ai_configuration_versions WHERE id = $1`, cv.ID).Scan(&cid)
	}
	return resolved{CV: cv, ConfigurationID: cid, PV: pvs[0], Prov: prov, Location: Location(pvs[0].Kind), Source: src}, nil
}

// --- evidence settings (retention) -------------------------------------------

// EvidenceSettings is the organization's retention of AI evidence.
type EvidenceSettings struct {
	RetentionDays int        `json:"retention_days"`
	StorePayloads bool       `json:"store_payloads"`
	UpdatedAt     *time.Time `json:"updated_at"`
}

// DefaultRetentionDays keeps the redacted prompt and response for 180
// days (assessment §8.6).
const DefaultRetentionDays = 180

// LoadEvidenceSettings returns the organization's settings (defaults
// without a row).
func LoadEvidenceSettings(ctx context.Context, q db.Querier, orgID uuid.UUID) EvidenceSettings {
	st := EvidenceSettings{RetentionDays: DefaultRetentionDays, StorePayloads: true}
	var at time.Time
	if err := q.QueryRow(ctx, `SELECT retention_days, store_payloads, updated_at FROM ai_evidence_settings WHERE organization_id = $1`, orgID).
		Scan(&st.RetentionDays, &st.StorePayloads, &at); err == nil {
		st.UpdatedAt = &at
	}
	return st
}

// --- HTTP: model per task and settings ----------------------------------------

// flagged checks the caller's organization has the M7 flag on.
func (s *Service) flagged(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil {
		return nil, httpx.ErrUnauthenticated
	}
	if err := featureflags.Require(r.Context(), s.DB, p.OrganizationID, FlagIntelligence); err != nil {
		return nil, err
	}
	return p, nil
}

// TaskAssignment is one task's effective configuration.
type TaskAssignment struct {
	TaskInfo
	// ConfigurationID is the explicit assignment (nil: automatic).
	ConfigurationID *uuid.UUID `json:"configuration_id"`
	// Effective is what a call would use now.
	Effective *EffectiveConfig `json:"effective"`
	Warning   string           `json:"warning,omitempty"`
}

// EffectiveConfig describes the configuration a task resolves to.
type EffectiveConfig struct {
	ConfigurationID   uuid.UUID `json:"configuration_id"`
	ConfigurationName string    `json:"configuration_name"`
	ProviderKind      string    `json:"provider_kind"`
	Location          string    `json:"location"`
	Model             string    `json:"model"`
	SendsCode         bool      `json:"send_code_context"`
	Source            string    `json:"source"`
}

func (s *Service) taskAssignments(ctx context.Context, orgID uuid.UUID) ([]TaskAssignment, error) {
	assigned := map[string]uuid.UUID{}
	rows, err := s.DB.Query(ctx, `SELECT task, configuration_id FROM ai_task_assignments WHERE organization_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t string
		var c uuid.UUID
		if err := rows.Scan(&t, &c); err != nil {
			rows.Close()
			return nil, err
		}
		assigned[t] = c
	}
	rows.Close()
	out := []TaskAssignment{}
	for _, t := range Tasks {
		ta := TaskAssignment{TaskInfo: t}
		if c, ok := assigned[t.Key]; ok {
			ta.ConfigurationID = &c
		}
		cv, cid, src, err := taskConfig(ctx, s.DB, orgID, t.Key)
		if err == nil {
			e := EffectiveConfig{ConfigurationID: cid, Model: cv.Model, SendsCode: cv.SendCodeContext, Source: src}
			_ = s.DB.QueryRow(ctx, `SELECT c.name, p.kind FROM ai_configurations c JOIN ai_providers p ON p.id = $2 WHERE c.id = $1`, cid, cv.ProviderID).
				Scan(&e.ConfigurationName, &e.ProviderKind)
			e.Location = Location(e.ProviderKind)
			ta.Effective = &e
			if t.CodeBearing && e.Location == LocationCloud {
				if e.SendsCode {
					ta.Warning = "Source code is sent to a cloud model: the configuration allows it."
				} else {
					ta.Warning = "Cloud model without permission to receive code: code is left out, and requests that need code (fix proposals) are refused."
				}
			}
		}
		out = append(out, ta)
	}
	return out, nil
}

func (s *Service) getTaskAssignments(w http.ResponseWriter, r *http.Request) {
	p, err := s.flagged(r)
	if err == nil {
		p, err = s.requireOrg(r, authz.PermAIConfigure)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.taskAssignments(r.Context(), p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "evidence": LoadEvidenceSettings(r.Context(), s.DB, p.OrganizationID)})
}

// putTaskAssignments sets assignments: {"assignments": {task: configuration_id or null}}.
func (s *Service) putTaskAssignments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.flagged(r)
	if err == nil {
		p, err = s.requireOrg(r, authz.PermAIConfigure)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Assignments map[string]*uuid.UUID `json:"assignments"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	for task := range req.Assignments {
		if _, ok := TaskByKey(task); !ok {
			s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "ai_task_invalid", "unknown task "+task).WithDiag("PTH-AI-1102"))
			return
		}
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		for task, cid := range req.Assignments {
			if cid == nil {
				if _, err := tx.Exec(ctx, `DELETE FROM ai_task_assignments WHERE organization_id = $1 AND task = $2`, p.OrganizationID, task); err != nil {
					return err
				}
				continue
			}
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ai_configurations WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL)`,
				p.OrganizationID, *cid).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return httpx.E(http.StatusUnprocessableEntity, "ai_task_invalid", "configuration "+cid.String()+" does not exist or is archived").WithDiag("PTH-AI-1102")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO ai_task_assignments (organization_id, task, configuration_id, updated_by) VALUES ($1, $2, $3, $4)
				ON CONFLICT (organization_id, task) DO UPDATE SET configuration_id = EXCLUDED.configuration_id, updated_by = EXCLUDED.updated_by, updated_at = now()`,
				p.OrganizationID, task, *cid, p.UserID); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ai_task_assignment.update", TargetType: "organization", TargetID: p.OrganizationID.String(),
			Metadata: map[string]any{"assignments": req.Assignments}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.taskAssignments(ctx, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "evidence": LoadEvidenceSettings(ctx, s.DB, p.OrganizationID)})
}

func (s *Service) putEvidenceSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.flagged(r)
	if err == nil {
		p, err = s.requireOrg(r, authz.PermAIConfigure)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		RetentionDays int   `json:"retention_days"`
		StorePayloads *bool `json:"store_payloads"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.RetentionDays < 1 || req.RetentionDays > 3650 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "ai_evidence_settings_invalid", "retention_days must be between 1 and 3650").WithDiag("PTH-AI-1102"))
		return
	}
	store := true
	if req.StorePayloads != nil {
		store = *req.StorePayloads
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ai_evidence_settings (organization_id, retention_days, store_payloads, updated_by) VALUES ($1, $2, $3, $4)
			ON CONFLICT (organization_id) DO UPDATE SET retention_days = EXCLUDED.retention_days, store_payloads = EXCLUDED.store_payloads,
			updated_by = EXCLUDED.updated_by, updated_at = now()`, p.OrganizationID, req.RetentionDays, store, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ai_evidence_settings.update", TargetType: "organization", TargetID: p.OrganizationID.String(),
			Metadata: map[string]any{"retention_days": req.RetentionDays, "store_payloads": store}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, LoadEvidenceSettings(ctx, s.DB, p.OrganizationID))
}

// Retain purges AI evidence payloads past their organization's retention
// (measured from the record's creation, so a shorter retention applies to
// records already stored) and returns how many were purged. The record
// rows stay (hashes, conclusion, model, review) until their finding is
// deleted; a purged record can no longer be replayed (PTH-AI-1202).
func Retain(ctx context.Context, q db.Querier) (int64, error) {
	tag, err := q.Exec(ctx, `WITH due AS (
		SELECT r.id FROM ai_evidence_records r
		LEFT JOIN ai_evidence_settings st ON st.organization_id = r.organization_id
		WHERE r.payload_purged_at IS NULL AND r.payload_expires_at IS NOT NULL
		  AND (r.payload_expires_at < now() OR r.created_at < now() - make_interval(days => COALESCE(st.retention_days, 180))
		       OR NOT COALESCE(st.store_payloads, true))
		LIMIT 5000),
	del AS (DELETE FROM ai_evidence_payloads p USING due WHERE p.record_id = due.id RETURNING p.record_id)
	UPDATE ai_evidence_records r SET payload_purged_at = now() FROM due WHERE r.id = due.id`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RewrapPayloads re-wraps the data keys of AI evidence payloads that are
// not under the current master key (pathosctl rotate-keys). It returns the
// number of payloads updated.
func RewrapPayloads(ctx context.Context, tx pgx.Tx, keys *crypto.Keyring) (int, error) {
	rows, err := tx.Query(ctx, `SELECT record_id, ciphertext, wrapped_dek, key_version FROM ai_evidence_payloads WHERE key_version <> $1 FOR UPDATE`,
		keys.CurrentVersion())
	if err != nil {
		return 0, err
	}
	type row struct {
		id uuid.UUID
		s  crypto.Sealed
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.id, &x.s.Ciphertext, &x.s.WrappedDEK, &x.s.KeyVersion)
		return x, err
	})
	if err != nil {
		return 0, err
	}
	for _, r := range all {
		ns, err := keys.Rewrap(r.s, payloadAAD(r.id))
		if err != nil {
			return 0, errors.Join(errors.New("AI evidence payload "+r.id.String()+": is its key version listed in PATHOS_MASTER_KEYS_PREVIOUS?"), err)
		}
		if _, err := tx.Exec(ctx, `UPDATE ai_evidence_payloads SET wrapped_dek = $2, key_version = $3 WHERE record_id = $1`, r.id, ns.WrappedDEK, ns.KeyVersion); err != nil {
			return 0, err
		}
	}
	return len(all), nil
}

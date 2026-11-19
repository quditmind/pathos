package scans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.yaml.in/yaml/v3"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Custom detection rules are Opengrep rule files managed in PATHOS. Each
// scan records the enabled rule versions in its configuration snapshot and
// the worker receives exactly those versions with the job.

func (s *Service) registerRules(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/custom-rules", s.listRules)
	mux.HandleFunc("POST /api/v1/custom-rules", s.createRule)
	mux.HandleFunc("POST /api/v1/custom-rules/validate", s.validateRuleHandler)
	mux.HandleFunc("GET /api/v1/custom-rules/{id}", s.getRule)
	mux.HandleFunc("PUT /api/v1/custom-rules/{id}", s.updateRule)
	mux.HandleFunc("DELETE /api/v1/custom-rules/{id}", s.deleteRule)
	mux.HandleFunc("GET /api/v1/custom-rules/{id}/versions", s.ruleVersions)
}

// CustomRule is a rule file.
type CustomRule struct {
	ID          uuid.UUID `json:"id"`
	Engine      string    `json:"engine"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Content     string    `json:"content,omitempty"`
	RuleIDs     []string  `json:"rule_ids"`
	Enabled     bool      `json:"enabled"`
	Version     int       `json:"version"`
	UpdatedBy   *string   `json:"updated_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var (
	ruleIDRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	ruleSeverities = []string{"ERROR", "WARNING", "INFO", "CRITICAL", "HIGH", "MEDIUM", "LOW"}
	patternKeys    = []string{"pattern", "patterns", "pattern-either", "pattern-regex", "pattern-sources", "match"}
)

// ValidateRules checks an Opengrep rule file without running it and
// returns its rule IDs. Rule IDs must not use the reserved "pathos." prefix
// of the built-in rules.
func ValidateRules(content string) ([]string, error) {
	if strings.TrimSpace(content) == "" {
		return nil, errors.New("the rule file is empty")
	}
	if len(content) > 256<<10 {
		return nil, errors.New("rule files are limited to 256 KiB")
	}
	var doc struct {
		Rules []map[string]any `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, fmt.Errorf("invalid YAML: %v", err)
	}
	if len(doc.Rules) == 0 {
		return nil, errors.New(`the file must contain a "rules:" list`)
	}
	if len(doc.Rules) > 200 {
		return nil, errors.New("at most 200 rules per file")
	}
	var ids []string
	for i, r := range doc.Rules {
		where := fmt.Sprintf("rule %d", i+1)
		id, _ := r["id"].(string)
		if !ruleIDRe.MatchString(id) {
			return nil, fmt.Errorf("%s: id is required (letters, digits, '.', '_' and '-')", where)
		}
		where = fmt.Sprintf("rule %q", id)
		if strings.HasPrefix(strings.ToLower(id), "pathos.") {
			return nil, fmt.Errorf("%s: the \"pathos.\" prefix is reserved for built-in rules", where)
		}
		if slices.Contains(ids, id) {
			return nil, fmt.Errorf("%s: duplicate id", where)
		}
		if msg, _ := r["message"].(string); strings.TrimSpace(msg) == "" {
			return nil, fmt.Errorf("%s: message is required", where)
		}
		if sev, _ := r["severity"].(string); !slices.Contains(ruleSeverities, strings.ToUpper(sev)) {
			return nil, fmt.Errorf("%s: severity must be ERROR, WARNING or INFO", where)
		}
		langs, ok := r["languages"].([]any)
		if !ok || len(langs) == 0 {
			return nil, fmt.Errorf("%s: languages must be a non-empty list", where)
		}
		hasPattern := false
		for _, k := range patternKeys {
			if _, ok := r[k]; ok {
				hasPattern = true
			}
		}
		if !hasPattern {
			return nil, fmt.Errorf("%s: a pattern is required (pattern, patterns, pattern-either, pattern-regex or taint mode)", where)
		}
		if mode, _ := r["mode"].(string); mode == "taint" {
			if _, ok := r["pattern-sinks"]; !ok {
				return nil, fmt.Errorf("%s: taint rules need pattern-sinks", where)
			}
		}
		ids = append(ids, id)
	}
	return ids, nil
}

const ruleCols = `r.id, r.engine, r.name, r.description, r.content, r.rule_ids, r.enabled, r.version,
	COALESCE(NULLIF(u.display_name, ''), u.email), r.created_at, r.updated_at`

func scanRule(row pgx.Row) (CustomRule, error) {
	var c CustomRule
	err := row.Scan(&c.ID, &c.Engine, &c.Name, &c.Description, &c.Content, &c.RuleIDs, &c.Enabled, &c.Version, &c.UpdatedBy, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, errNotFound
	}
	return c, err
}

func (s *Service) readRules(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermScannersRead) {
		return p, authz.ErrForbidden
	}
	return p, nil
}

func (s *Service) manageRules(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if !p.HasOrgWide(authz.PermProfilesManage) {
		return p, authz.ErrForbidden
	}
	return p, nil
}

func (s *Service) listRules(w http.ResponseWriter, r *http.Request) {
	p, err := s.readRules(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT `+ruleCols+` FROM custom_rules r LEFT JOIN users u ON u.id = r.updated_by
		WHERE r.organization_id = $1 ORDER BY lower(r.name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (CustomRule, error) {
		c, err := scanRule(row)
		c.Content = ""
		return c, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []CustomRule{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) getRule(w http.ResponseWriter, r *http.Request) {
	p, err := s.readRules(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := scanRule(s.DB.QueryRow(r.Context(), `SELECT `+ruleCols+` FROM custom_rules r LEFT JOIN users u ON u.id = r.updated_by
		WHERE r.organization_id = $1 AND r.id = $2`, p.OrganizationID, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

type ruleRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Content     *string `json:"content"`
	Enabled     *bool   `json:"enabled"`
	ChangeNote  string  `json:"change_note"`
}

func ruleError(err error) error {
	return &httpx.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_rules", Message: err.Error(), Fields: map[string]string{"content": err.Error()}}
}

func (s *Service) validateRuleHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := s.manageRules(r); err != nil {
		s.fail(w, r, err)
		return
	}
	var req ruleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := ValidateRules(str(req.Content))
	if err != nil {
		s.fail(w, r, ruleError(err))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"valid": true, "rule_ids": ids})
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// conflictingIDs reports rule IDs already used by another enabled file.
func conflictingIDs(ctx context.Context, q db.Querier, orgID uuid.UUID, self *uuid.UUID, ids []string) error {
	var dup *string
	_ = q.QueryRow(ctx, `SELECT x FROM custom_rules r, unnest(r.rule_ids) x WHERE r.organization_id = $1 AND r.enabled
		AND ($2::uuid IS NULL OR r.id <> $2) AND x = ANY($3) LIMIT 1`, orgID, self, ids).Scan(&dup)
	if dup != nil {
		return ruleError(fmt.Errorf("rule id %q is already used by another enabled rule file", *dup))
	}
	return nil
}

func (s *Service) createRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.manageRules(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req ruleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	name := strings.TrimSpace(str(req.Name))
	if name == "" || len(name) > 200 || len(str(req.Description)) > 2000 {
		s.fail(w, r, httpx.BadRequest("a name (1-200 characters) is required; description at most 2000"))
		return
	}
	ids, err := ValidateRules(str(req.Content))
	if err != nil {
		s.fail(w, r, ruleError(err))
		return
	}
	enabled := req.Enabled == nil || *req.Enabled
	id := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if enabled {
			if err := conflictingIDs(ctx, tx, p.OrganizationID, nil, ids); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO custom_rules (id, organization_id, name, description, content, rule_ids, enabled, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`, id, p.OrganizationID, name, str(req.Description), *req.Content, ids, enabled, p.UserID); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("a rule file with this name already exists")
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO custom_rule_versions (rule_id, version, content, enabled, change_note, created_by) VALUES ($1, 1, $2, $3, $4, $5)`,
			id, *req.Content, enabled, truncate(req.ChangeNote, 2000), p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email, Action: "custom_rule.create",
			TargetType: "custom_rule", TargetID: id.String(), Metadata: map[string]any{"name": name, "rule_ids": ids, "enabled": enabled}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	r.SetPathValue("id", id.String())
	w.WriteHeader(http.StatusCreated)
	s.getRule(w, r)
}

func (s *Service) updateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.manageRules(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req ruleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		cur, err := scanRule(tx.QueryRow(ctx, `SELECT `+ruleCols+` FROM custom_rules r LEFT JOIN users u ON u.id = r.updated_by
			WHERE r.organization_id = $1 AND r.id = $2 FOR UPDATE OF r`, p.OrganizationID, id))
		if err != nil {
			return err
		}
		name, desc, content, enabled := cur.Name, cur.Description, cur.Content, cur.Enabled
		if req.Name != nil {
			name = strings.TrimSpace(*req.Name)
		}
		if req.Description != nil {
			desc = *req.Description
		}
		if req.Content != nil {
			content = *req.Content
		}
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		if name == "" || len(name) > 200 || len(desc) > 2000 {
			return httpx.BadRequest("a name (1-200 characters) is required; description at most 2000")
		}
		ids, err := ValidateRules(content)
		if err != nil {
			return ruleError(err)
		}
		if enabled {
			if err := conflictingIDs(ctx, tx, p.OrganizationID, &id, ids); err != nil {
				return err
			}
		}
		version := cur.Version
		if content != cur.Content || enabled != cur.Enabled {
			version++
			if _, err := tx.Exec(ctx, `INSERT INTO custom_rule_versions (rule_id, version, content, enabled, change_note, created_by) VALUES ($1, $2, $3, $4, $5, $6)`,
				id, version, content, enabled, truncate(req.ChangeNote, 2000), p.UserID); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE custom_rules SET name = $2, description = $3, content = $4, rule_ids = $5, enabled = $6, version = $7,
			updated_by = $8, updated_at = now() WHERE id = $1`, id, name, desc, content, ids, enabled, version, p.UserID); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("a rule file with this name already exists")
			}
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email, Action: "custom_rule.update",
			TargetType: "custom_rule", TargetID: id.String(), Metadata: map[string]any{"name": name, "version": version, "enabled": enabled, "change_note": req.ChangeNote}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.getRule(w, r)
}

func (s *Service) deleteRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.manageRules(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var name string
		if err := tx.QueryRow(ctx, `DELETE FROM custom_rules WHERE organization_id = $1 AND id = $2 RETURNING name`, p.OrganizationID, id).Scan(&name); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email, Action: "custom_rule.delete",
			TargetType: "custom_rule", TargetID: id.String(), Metadata: map[string]any{"name": name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RuleVersion is one saved version.
type RuleVersion struct {
	Version    int       `json:"version"`
	Content    string    `json:"content"`
	Enabled    bool      `json:"enabled"`
	ChangeNote string    `json:"change_note"`
	CreatedBy  *string   `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
}

func (s *Service) ruleVersions(w http.ResponseWriter, r *http.Request) {
	p, err := s.readRules(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var found bool
	if err := s.DB.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM custom_rules WHERE organization_id = $1 AND id = $2)`, p.OrganizationID, id).Scan(&found); err != nil || !found {
		s.fail(w, r, errNotFound)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT v.version, v.content, v.enabled, v.change_note, COALESCE(NULLIF(u.display_name, ''), u.email), v.created_at
		FROM custom_rule_versions v JOIN custom_rules r ON r.id = v.rule_id LEFT JOIN users u ON u.id = v.created_by
		WHERE r.organization_id = $1 AND v.rule_id = $2 ORDER BY v.version DESC LIMIT 100`, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[RuleVersion])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []RuleVersion{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// ruleRef pins a rule file version in a configuration snapshot.
type ruleRef struct {
	ID      uuid.UUID `json:"id"`
	Name    string    `json:"name"`
	Version int       `json:"version"`
}

// enabledRuleRefs lists the organization's enabled rule files.
func enabledRuleRefs(ctx context.Context, q db.Querier, profileVersion uuid.UUID) ([]ruleRef, error) {
	rows, err := q.Query(ctx, `SELECT r.id, r.name, r.version FROM custom_rules r
		JOIN scan_profile_versions v ON v.organization_id = r.organization_id WHERE v.id = $1 AND r.enabled ORDER BY r.name`, profileVersion)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ruleRef])
	if out == nil {
		out = []ruleRef{}
	}
	return out, err
}

// customRulesFor returns the rule file contents pinned in a job's
// configuration snapshot, for the worker.
func customRulesFor(ctx context.Context, q db.Querier, jobID string) ([]map[string]string, error) {
	var snap []byte
	if err := q.QueryRow(ctx, `SELECT config_snapshot FROM scan_jobs WHERE id = $1`, jobID).Scan(&snap); err != nil {
		return nil, err
	}
	var cfg struct {
		CustomRules []ruleRef `json:"custom_rules"`
	}
	_ = json.Unmarshal(snap, &cfg)
	var out []map[string]string
	for _, ref := range cfg.CustomRules {
		var content string
		if err := q.QueryRow(ctx, `SELECT content FROM custom_rule_versions WHERE rule_id = $1 AND version = $2`, ref.ID, ref.Version).Scan(&content); err != nil {
			continue // deleted since the scan was queued
		}
		out = append(out, map[string]string{"name": fmt.Sprintf("%s-v%d", ref.ID, ref.Version), "content": content})
	}
	return out, nil
}

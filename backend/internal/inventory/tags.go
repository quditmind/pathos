package inventory

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// target is an asset whose tags change.
type target struct {
	Type string // application | repository
	ID   uuid.UUID
	Name string
}

func (t target) table() (string, string) {
	if t.Type == "repository" {
		return "repository_tags", "repository_id"
	}
	return "application_tags", "application_id"
}

type tagInfo struct {
	ID            uuid.UUID
	Name          string
	CategoryID    uuid.UUID
	CategoryName  string
	AllowMultiple bool
	RepoMandatory bool
}

func loadTagInfo(ctx context.Context, q db.Querier, orgID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]tagInfo, error) {
	rows, err := q.Query(ctx, `SELECT t.id, t.name, tc.id, tc.name, tc.allow_multiple, tc.is_mandatory
		FROM tags t JOIN tag_categories tc ON tc.id = t.category_id
		WHERE t.organization_id = $1 AND t.id = ANY($2::uuid[])`, orgID, nonNilIDs(ids))
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[tagInfo])
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]tagInfo, len(list))
	for _, t := range list {
		out[t.ID] = t
	}
	return out, nil
}

func nonNilIDs(ids []uuid.UUID) []uuid.UUID {
	if ids == nil {
		return []uuid.UUID{}
	}
	return ids
}

func currentTagIDs(ctx context.Context, q db.Querier, t target) ([]uuid.UUID, error) {
	table, col := t.table()
	// table and col are constants chosen by t.Type.
	rows, err := q.Query(ctx, `SELECT tag_id FROM `+table+` WHERE `+col+` = $1`, t.ID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

var errUnknownTag = httpx.BadRequest("unknown tag")

// changeTags makes next the tag set of t: it validates the set (tags of
// the organization, one tag at most in single-value categories, and for
// repositories no mandatory category left empty that was covered), writes
// the difference and records the history per changed category.
func changeTags(ctx context.Context, tx pgx.Tx, p *authz.Principal, t target, next []uuid.UUID, source string, ruleID *uuid.UUID) (bool, error) {
	next = slices.Compact(slices.SortedFunc(slices.Values(next), func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) }))
	cur, err := currentTagIDs(ctx, tx, t)
	if err != nil {
		return false, err
	}
	all := append(slices.Clone(cur), next...)
	info, err := loadTagInfo(ctx, tx, p.OrganizationID, all)
	if err != nil {
		return false, err
	}
	perCat := map[uuid.UUID]int{}
	for _, id := range next {
		ti, ok := info[id]
		if !ok {
			return false, errUnknownTag
		}
		perCat[ti.CategoryID]++
		if perCat[ti.CategoryID] > 1 && !ti.AllowMultiple {
			return false, httpx.BadRequest("only one tag allowed in: " + ti.CategoryName)
		}
	}
	if len(next) > 50 {
		return false, httpx.BadRequest("at most 50 tags per asset")
	}
	added, removed := diffIDs(cur, next)
	if len(added) == 0 && len(removed) == 0 {
		return false, nil
	}
	if t.Type == "repository" {
		for _, id := range removed {
			ti := info[id]
			if ti.RepoMandatory && perCat[ti.CategoryID] == 0 {
				return false, httpx.E(http.StatusUnprocessableEntity, "mandatory_tags_missing",
					"a tag is required in: "+ti.CategoryName).WithDiag("PTH-ONB-1006")
			}
		}
	}
	table, col := t.table()
	if len(removed) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE `+col+` = $1 AND tag_id = ANY($2::uuid[])`, t.ID, removed); err != nil {
			return false, err
		}
	}
	if len(added) > 0 {
		if t.Type == "repository" {
			_, err = tx.Exec(ctx, `INSERT INTO repository_tags (organization_id, repository_id, tag_id)
				SELECT $1, $2, unnest($3::uuid[]) ON CONFLICT DO NOTHING`, p.OrganizationID, t.ID, added)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO application_tags (organization_id, application_id, tag_id, source, rule_id, created_by)
				SELECT $1, $2, unnest($3::uuid[]), $4, $5, $6 ON CONFLICT DO NOTHING`, p.OrganizationID, t.ID, added, source, ruleID, p.UserID)
		}
		if err != nil {
			return false, err
		}
	}
	// History: one row per category whose tags changed.
	type catChange struct {
		name     string
		old, new []string
	}
	changes := map[uuid.UUID]*catChange{}
	get := func(ti tagInfo) *catChange {
		c := changes[ti.CategoryID]
		if c == nil {
			c = &catChange{name: ti.CategoryName, old: []string{}, new: []string{}}
			changes[ti.CategoryID] = c
		}
		return c
	}
	for _, id := range append(slices.Clone(added), removed...) {
		get(info[id])
	}
	for _, id := range cur {
		if c, ok := changes[info[id].CategoryID]; ok {
			c.old = append(c.old, info[id].Name)
		}
	}
	for _, id := range next {
		if c, ok := changes[info[id].CategoryID]; ok {
			c.new = append(c.new, info[id].Name)
		}
	}
	for catID, c := range changes {
		slices.Sort(c.old)
		slices.Sort(c.new)
		if _, err := tx.Exec(ctx, `INSERT INTO tag_assignment_history (id, organization_id, target_type, target_id, target_name,
			category_id, category_name, old_tags, new_tags, source, rule_id, actor_id, actor_email)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			uuid.Must(uuid.NewV7()), p.OrganizationID, t.Type, t.ID, truncate(t.Name, 500), catID, c.name, c.old, c.new,
			source, ruleID, p.UserID, p.Email); err != nil {
			return false, err
		}
	}
	if t.Type == "application" {
		if _, err := tx.Exec(ctx, `UPDATE applications SET updated_at = now() WHERE id = $1`, t.ID); err != nil {
			return false, err
		}
	}
	return true, nil
}

func diffIDs(cur, next []uuid.UUID) (added, removed []uuid.UUID) {
	for _, id := range next {
		if !slices.Contains(cur, id) {
			added = append(added, id)
		}
	}
	for _, id := range cur {
		if !slices.Contains(next, id) {
			removed = append(removed, id)
		}
	}
	return added, removed
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// setAppTags replaces the tags of an application.
func setAppTags(ctx context.Context, tx pgx.Tx, p *authz.Principal, appID uuid.UUID, name string, tagIDs []uuid.UUID, source string) error {
	_, err := changeTags(ctx, tx, p, target{"application", appID, name}, tagIDs, source, nil)
	return err
}

// ---------------------------------------------------------------------------
// Automatic tagging rules
// ---------------------------------------------------------------------------

// Rule is an automatic tagging rule.
type Rule struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	TagID        uuid.UUID `json:"tag_id"`
	TagName      string    `json:"tag_name"`
	TagColor     string    `json:"tag_color"`
	CategoryName string    `json:"category_name"`
	TargetType   string    `json:"target_type"`
	Condition    string    `json:"condition"`
	Field        string    `json:"field"`
	Value        string    `json:"value"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
}

// RuleFields are the application fields a classification rule can test.
var RuleFields = []string{"application_type", "data_classification", "internet_exposure", "compliance_scopes",
	"authentication_model", "hosting_region", "environment", "criticality", "lifecycle", "languages", "frameworks", "runtimes"}

const ruleSelect = `SELECT tr.id, tr.name, t.id, t.name, t.color, tc.name, tr.target_type, tr.condition, tr.field, tr.value,
	tr.enabled, tr.created_at FROM tag_rules tr JOIN tags t ON t.id = tr.tag_id JOIN tag_categories tc ON tc.id = t.category_id`

func loadRules(ctx context.Context, q db.Querier, orgID uuid.UUID, onlyEnabled bool) ([]Rule, error) {
	cond := ""
	if onlyEnabled {
		cond = " AND tr.enabled"
	}
	rows, err := q.Query(ctx, ruleSelect+` WHERE tr.organization_id = $1`+cond+` ORDER BY lower(tr.name)`, orgID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Rule])
	if out == nil {
		out = []Rule{}
	}
	return out, err
}

// GlobRegexp compiles a path pattern: "**" matches across "/", "*" and "?"
// within one path segment; matching is case-insensitive and anchored.
func GlobRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?i)^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '*' && i+1 < len(pattern) && pattern[i+1] == '*':
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// appValues are the classification values a rule compares.
func appValues(ctx context.Context, q db.Querier, appID uuid.UUID) (map[string][]string, error) {
	var typ, dc, ie, am, hr, env, crit, life string
	var cs, langs, fws, rts []string
	err := q.QueryRow(ctx, `SELECT application_type, data_classification, internet_exposure, authentication_model, hosting_region,
		environment, criticality, lifecycle, compliance_scopes, languages, frameworks, runtimes FROM applications WHERE id = $1`, appID).
		Scan(&typ, &dc, &ie, &am, &hr, &env, &crit, &life, &cs, &langs, &fws, &rts)
	if err != nil {
		return nil, err
	}
	return map[string][]string{"application_type": {typ}, "data_classification": {dc}, "internet_exposure": {ie},
		"authentication_model": {am}, "hosting_region": {hr}, "environment": {env}, "criticality": {crit}, "lifecycle": {life},
		"compliance_scopes": cs, "languages": langs, "frameworks": fws, "runtimes": rts}, nil
}

type repoFacts struct {
	ID         uuid.UUID
	FullName   string
	Topics     []string
	AppID      *uuid.UUID
	Name       string
	Archived   bool
	Visibility string
}

func repoMatches(rule Rule, re *regexp.Regexp, r repoFacts) bool {
	switch rule.Condition {
	case "repository_topic":
		return slices.ContainsFunc(r.Topics, func(t string) bool { return strings.EqualFold(strings.TrimSpace(t), rule.Value) })
	case "path_pattern":
		return re != nil && re.MatchString(r.FullName)
	}
	return false
}

func appMatchesClassification(rule Rule, vals map[string][]string) bool {
	return slices.ContainsFunc(vals[rule.Field], func(v string) bool { return v != "" && strings.EqualFold(v, rule.Value) })
}

// addTag adds one tag to t unless t already has it or it would be a second
// tag of a single-value category (rules never replace a person's choice).
func addTag(ctx context.Context, tx pgx.Tx, p *authz.Principal, t target, tagID uuid.UUID, source string, ruleID *uuid.UUID) (bool, error) {
	cur, err := currentTagIDs(ctx, tx, t)
	if err != nil {
		return false, err
	}
	if slices.Contains(cur, tagID) {
		return false, nil
	}
	info, err := loadTagInfo(ctx, tx, p.OrganizationID, append(slices.Clone(cur), tagID))
	if err != nil {
		return false, err
	}
	ti, ok := info[tagID]
	if !ok {
		return false, nil
	}
	if !ti.AllowMultiple {
		for _, id := range cur {
			if info[id].CategoryID == ti.CategoryID {
				return false, nil
			}
		}
	}
	return changeTags(ctx, tx, p, t, append(cur, tagID), source, ruleID)
}

func appRepoFacts(ctx context.Context, q db.Querier, appID uuid.UUID) ([]repoFacts, error) {
	rows, err := q.Query(ctx, `SELECT id, full_name, technologies, application_id, COALESCE(NULLIF(display_name, ''), full_name),
		archived_at IS NOT NULL, visibility FROM repositories WHERE application_id = $1 AND archived_at IS NULL`, appID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[repoFacts])
}

// applyAppRules runs the enabled application rules on one application and
// returns the number of tags added.
func applyAppRules(ctx context.Context, tx pgx.Tx, p *authz.Principal, appID uuid.UUID) (int, error) {
	rules, err := loadRules(ctx, tx, p.OrganizationID, true)
	if err != nil {
		return 0, err
	}
	var vals map[string][]string
	var repos []repoFacts
	var name string
	if err := tx.QueryRow(ctx, `SELECT name FROM applications WHERE id = $1`, appID).Scan(&name); err != nil {
		return 0, err
	}
	n := 0
	for _, rule := range rules {
		if rule.TargetType != "application" {
			continue
		}
		match := false
		if rule.Condition == "classification" {
			if vals == nil {
				if vals, err = appValues(ctx, tx, appID); err != nil {
					return n, err
				}
			}
			match = appMatchesClassification(rule, vals)
		} else {
			if repos == nil {
				if repos, err = appRepoFacts(ctx, tx, appID); err != nil {
					return n, err
				}
			}
			re, _ := GlobRegexp(rule.Value)
			match = slices.ContainsFunc(repos, func(r repoFacts) bool { return repoMatches(rule, re, r) })
		}
		if !match {
			continue
		}
		ruleID := rule.ID
		added, err := addTag(ctx, tx, p, target{"application", appID, name}, rule.TagID, "rule", &ruleID)
		if err != nil {
			return n, err
		}
		if added {
			n++
		}
	}
	return n, nil
}

// applyRuleEverywhere runs one rule on every active asset of the
// organization (at most 5000) and returns the number of assets tagged.
func applyRuleEverywhere(ctx context.Context, tx pgx.Tx, p *authz.Principal, rule Rule) (int, error) {
	ruleID := rule.ID
	n := 0
	if rule.TargetType == "repository" {
		rows, err := tx.Query(ctx, `SELECT id, full_name, technologies, application_id, COALESCE(NULLIF(display_name, ''), full_name),
			archived_at IS NOT NULL, visibility FROM repositories WHERE organization_id = $1 AND archived_at IS NULL ORDER BY id LIMIT 5000`, p.OrganizationID)
		if err != nil {
			return 0, err
		}
		repos, err := pgx.CollectRows(rows, pgx.RowToStructByPos[repoFacts])
		if err != nil {
			return 0, err
		}
		re, _ := GlobRegexp(rule.Value)
		for _, r := range repos {
			if !repoMatches(rule, re, r) {
				continue
			}
			added, err := addTag(ctx, tx, p, target{"repository", r.ID, r.Name}, rule.TagID, "rule", &ruleID)
			if err != nil {
				return n, err
			}
			if added {
				n++
			}
		}
		return n, nil
	}
	rows, err := tx.Query(ctx, `SELECT id, name FROM applications WHERE organization_id = $1 AND archived_at IS NULL ORDER BY id LIMIT 5000`, p.OrganizationID)
	if err != nil {
		return 0, err
	}
	type app struct {
		ID   uuid.UUID
		Name string
	}
	apps, err := pgx.CollectRows(rows, pgx.RowToStructByPos[app])
	if err != nil {
		return 0, err
	}
	re, _ := GlobRegexp(rule.Value)
	for _, a := range apps {
		match := false
		if rule.Condition == "classification" {
			vals, err := appValues(ctx, tx, a.ID)
			if err != nil {
				return n, err
			}
			match = appMatchesClassification(rule, vals)
		} else {
			repos, err := appRepoFacts(ctx, tx, a.ID)
			if err != nil {
				return n, err
			}
			match = slices.ContainsFunc(repos, func(r repoFacts) bool { return repoMatches(rule, re, r) })
		}
		if !match {
			continue
		}
		added, err := addTag(ctx, tx, p, target{"application", a.ID, a.Name}, rule.TagID, "rule", &ruleID)
		if err != nil {
			return n, err
		}
		if added {
			n++
		}
	}
	return n, nil
}

type ruleRequest struct {
	Name       *string    `json:"name"`
	TagID      *uuid.UUID `json:"tag_id"`
	TargetType *string    `json:"target_type"`
	Condition  *string    `json:"condition"`
	Field      *string    `json:"field"`
	Value      *string    `json:"value"`
	Enabled    *bool      `json:"enabled"`
	// Apply runs the rule on existing assets after saving.
	Apply bool `json:"apply"`
}

func validateRule(r Rule) error {
	if n := strings.TrimSpace(r.Name); n == "" || len(n) > 100 {
		return httpx.BadRequest("name must be 1-100 characters")
	}
	if r.TargetType != "application" && r.TargetType != "repository" {
		return httpx.BadRequest("target_type must be application or repository")
	}
	switch r.Condition {
	case "classification":
		if r.TargetType != "application" {
			return httpx.BadRequest("classification rules apply to applications")
		}
		if !slices.Contains(RuleFields, r.Field) {
			return httpx.BadRequest("field must be one of " + strings.Join(RuleFields, ", "))
		}
	case "repository_topic", "path_pattern":
		if r.Field != "" {
			return httpx.BadRequest("field is only used by classification rules")
		}
	default:
		return httpx.BadRequest("condition must be classification, repository_topic or path_pattern")
	}
	if v := strings.TrimSpace(r.Value); v == "" || len(v) > 200 || strings.ContainsAny(v, "\x00\r\n") {
		return httpx.BadRequest("value must be 1-200 characters")
	}
	if r.Condition == "path_pattern" {
		if _, err := GlobRegexp(r.Value); err != nil {
			return httpx.BadRequest("invalid path pattern")
		}
	}
	return nil
}

func (s *Service) requireTagsManage(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	return p, s.Authz.Require(r.Context(), p, authz.PermTagsManage, orgScope(p))
}

func (s *Service) createRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireTagsManage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req ruleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.TagID == nil {
		s.fail(w, r, httpx.BadRequest("tag_id is required"))
		return
	}
	rule := Rule{ID: uuid.Must(uuid.NewV7()), Name: strings.TrimSpace(deref(req.Name)), TagID: *req.TagID, TargetType: deref(req.TargetType),
		Condition: deref(req.Condition), Field: deref(req.Field), Value: strings.TrimSpace(deref(req.Value)), Enabled: req.Enabled == nil || *req.Enabled}
	if err := validateRule(rule); err != nil {
		s.fail(w, r, err)
		return
	}
	var out Rule
	applied := 0
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tag_rules (id, organization_id, name, tag_id, target_type, condition, field, value, enabled, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, rule.ID, p.OrganizationID, rule.Name, rule.TagID, rule.TargetType,
			rule.Condition, rule.Field, rule.Value, rule.Enabled, p.UserID); err != nil {
			if db.IsForeignKeyViolation(err) {
				return errUnknownTag
			}
			return err
		}
		if err := tx.QueryRow(ctx, ruleSelect+` WHERE tr.id = $1`, rule.ID).Scan(&out.ID, &out.Name, &out.TagID, &out.TagName, &out.TagColor,
			&out.CategoryName, &out.TargetType, &out.Condition, &out.Field, &out.Value, &out.Enabled, &out.CreatedAt); err != nil {
			return err
		}
		if req.Apply && out.Enabled {
			var err error
			if applied, err = applyRuleEverywhere(ctx, tx, p, out); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "tag_rule.create", TargetType: "tag_rule", TargetID: rule.ID.String(),
			Metadata: map[string]any{"name": rule.Name, "tag_id": rule.TagID, "condition": rule.Condition, "field": rule.Field,
				"value": rule.Value, "target_type": rule.TargetType, "applied": applied}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"rule": out, "applied": applied})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (s *Service) updateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireTagsManage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req ruleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	var out Rule
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var cur Rule
		if err := tx.QueryRow(ctx, ruleSelect+` WHERE tr.organization_id = $1 AND tr.id = $2 FOR UPDATE OF tr`, p.OrganizationID, id).
			Scan(&cur.ID, &cur.Name, &cur.TagID, &cur.TagName, &cur.TagColor, &cur.CategoryName, &cur.TargetType, &cur.Condition,
				&cur.Field, &cur.Value, &cur.Enabled, &cur.CreatedAt); err != nil {
			return err
		}
		next := cur
		if req.Name != nil {
			next.Name = strings.TrimSpace(*req.Name)
		}
		if req.TagID != nil {
			next.TagID = *req.TagID
		}
		if req.TargetType != nil {
			next.TargetType = *req.TargetType
		}
		if req.Condition != nil {
			next.Condition = *req.Condition
		}
		if req.Field != nil {
			next.Field = *req.Field
		}
		if req.Value != nil {
			next.Value = strings.TrimSpace(*req.Value)
		}
		if req.Enabled != nil {
			next.Enabled = *req.Enabled
		}
		if err := validateRule(next); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE tag_rules SET name = $3, tag_id = $4, target_type = $5, condition = $6, field = $7, value = $8,
			enabled = $9, updated_at = now() WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id, next.Name, next.TagID,
			next.TargetType, next.Condition, next.Field, next.Value, next.Enabled); err != nil {
			if db.IsForeignKeyViolation(err) {
				return errUnknownTag
			}
			return err
		}
		if err := tx.QueryRow(ctx, ruleSelect+` WHERE tr.id = $1`, id).Scan(&out.ID, &out.Name, &out.TagID, &out.TagName, &out.TagColor,
			&out.CategoryName, &out.TargetType, &out.Condition, &out.Field, &out.Value, &out.Enabled, &out.CreatedAt); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "tag_rule.update", TargetType: "tag_rule", TargetID: id.String(),
			Metadata: map[string]any{"old": cur, "new": out}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) deleteRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireTagsManage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var name string
		if err := tx.QueryRow(ctx, `DELETE FROM tag_rules WHERE organization_id = $1 AND id = $2 RETURNING name`, p.OrganizationID, id).Scan(&name); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "tag_rule.delete", TargetType: "tag_rule", TargetID: id.String(), Metadata: map[string]any{"name": name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// applyRule: POST /api/v1/tag-rules/{id}/apply runs a rule on every
// existing asset. Tags are only added, never removed.
func (s *Service) applyRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireTagsManage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	n := 0
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var rule Rule
		if err := tx.QueryRow(ctx, ruleSelect+` WHERE tr.organization_id = $1 AND tr.id = $2`, p.OrganizationID, id).
			Scan(&rule.ID, &rule.Name, &rule.TagID, &rule.TagName, &rule.TagColor, &rule.CategoryName, &rule.TargetType, &rule.Condition,
				&rule.Field, &rule.Value, &rule.Enabled, &rule.CreatedAt); err != nil {
			return err
		}
		if !rule.Enabled {
			return httpx.Conflict("the rule is disabled; enable it first")
		}
		var err error
		if n, err = applyRuleEverywhere(ctx, tx, p, rule); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "tag_rule.apply", TargetType: "tag_rule", TargetID: id.String(), Metadata: map[string]any{"name": rule.Name, "tagged": n}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"tagged": n})
}

// ---------------------------------------------------------------------------
// Framework view and category settings
// ---------------------------------------------------------------------------

// FrameworkTag is a tag with its usage.
type FrameworkTag struct {
	ID               uuid.UUID `json:"id"`
	Name             string    `json:"name"`
	Color            string    `json:"color"`
	RepositoryCount  int       `json:"repository_count"`
	ApplicationCount int       `json:"application_count"`
}

// FrameworkCategory is a tag category with the framework settings.
type FrameworkCategory struct {
	ID                  uuid.UUID      `json:"id"`
	Name                string         `json:"name"`
	Color               string         `json:"color"`
	IsMandatory         bool           `json:"is_mandatory"`
	AllowMultiple       bool           `json:"allow_multiple"`
	MandatoryAssetTypes []string       `json:"mandatory_asset_types"`
	Tags                []FrameworkTag `json:"tags"`
	// NonCompliantApplications counts active applications of a mandatory
	// type without a tag of the category.
	NonCompliantApplications int `json:"noncompliant_applications"`
}

func (s *Service) tagFramework(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReposRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(ctx, `
		SELECT tc.id, tc.name, tc.color, tc.is_mandatory, tc.allow_multiple, tc.mandatory_asset_types,
		       COALESCE((SELECT json_agg(json_build_object('id', t.id, 'name', t.name, 'color', t.color,
		                   'repository_count', (SELECT count(*) FROM repository_tags rt WHERE rt.tag_id = t.id),
		                   'application_count', (SELECT count(*) FROM application_tags at WHERE at.tag_id = t.id)) ORDER BY lower(t.name))
		                 FROM tags t WHERE t.category_id = tc.id), '[]'),
		       CASE WHEN cardinality(tc.mandatory_asset_types) > 0 THEN (SELECT count(*) FROM applications a
		            WHERE a.organization_id = tc.organization_id AND a.archived_at IS NULL
		              AND ('all' = ANY(tc.mandatory_asset_types) OR a.application_type = ANY(tc.mandatory_asset_types))
		              AND NOT EXISTS (SELECT 1 FROM application_tags at JOIN tags t ON t.id = at.tag_id
		                              WHERE at.application_id = a.id AND t.category_id = tc.id)) ELSE 0 END
		FROM tag_categories tc WHERE tc.organization_id = $1 ORDER BY lower(tc.name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cats, err := pgx.CollectRows(rows, pgx.RowToStructByPos[FrameworkCategory])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if cats == nil {
		cats = []FrameworkCategory{}
	}
	rules, err := loadRules(ctx, s.DB, p.OrganizationID, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"categories": cats, "rules": rules, "rule_fields": RuleFields})
}

var hexColor = regexp.MustCompile(`^#[0-9a-f]{6}$`)

func (s *Service) updateCategoryFramework(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireTagsManage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Color               *string   `json:"color"`
		MandatoryAssetTypes *[]string `json:"mandatory_asset_types"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Color != nil {
		c := strings.ToLower(strings.TrimSpace(*req.Color))
		if c != "" && !hexColor.MatchString(c) {
			s.fail(w, r, httpx.BadRequest("color must be #rrggbb or empty"))
			return
		}
		req.Color = &c
	}
	if req.MandatoryAssetTypes != nil {
		types := mergeUnique(nil, *req.MandatoryAssetTypes)
		if len(types) > 30 {
			s.fail(w, r, httpx.BadRequest("at most 30 application types"))
			return
		}
		for _, t := range types {
			if t == "all" {
				continue
			}
			var ok bool
			if err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM asset_classifications WHERE organization_id = $1
				AND kind = 'application_type' AND key = $2)`, p.OrganizationID, t).Scan(&ok); err != nil {
				s.fail(w, r, err)
				return
			}
			if !ok {
				s.fail(w, r, httpx.BadRequest("unknown application type "+strconv.Quote(t)))
				return
			}
		}
		req.MandatoryAssetTypes = &types
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var oldColor string
		var oldTypes []string
		if err := tx.QueryRow(ctx, `SELECT color, mandatory_asset_types FROM tag_categories WHERE organization_id = $1 AND id = $2 FOR UPDATE`,
			p.OrganizationID, id).Scan(&oldColor, &oldTypes); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE tag_categories SET color = COALESCE($3, color),
			mandatory_asset_types = COALESCE($4, mandatory_asset_types), updated_at = now() WHERE organization_id = $1 AND id = $2`,
			p.OrganizationID, id, req.Color, req.MandatoryAssetTypes); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "tag_category.framework", TargetType: "tag_category", TargetID: id.String(),
			Metadata: map[string]any{"old": map[string]any{"color": oldColor, "mandatory_asset_types": oldTypes},
				"new": map[string]any{"color": req.Color, "mandatory_asset_types": req.MandatoryAssetTypes}}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Bulk tagging and history
// ---------------------------------------------------------------------------

type bulkRequest struct {
	TargetType string      `json:"target_type"`
	IDs        []uuid.UUID `json:"ids"`
	Add        []uuid.UUID `json:"add_tag_ids"`
	Remove     []uuid.UUID `json:"remove_tag_ids"`
}

type bulkResult struct {
	ID     uuid.UUID `json:"id"`
	Status string    `json:"status"` // updated | unchanged | error
	Error  string    `json:"error,omitempty"`
}

// bulkAssign: POST /api/v1/tag-assignments/bulk adds and removes tags on
// many applications or repositories. A tag added to a single-value
// category replaces the asset's other tag in that category. Each asset is
// authorized and changed on its own; failures are reported per asset.
func (s *Service) bulkAssign(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req bulkRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.TargetType != "application" && req.TargetType != "repository" {
		s.fail(w, r, httpx.BadRequest("target_type must be application or repository"))
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 500 {
		s.fail(w, r, httpx.BadRequest("ids must list 1-500 assets"))
		return
	}
	if len(req.Add)+len(req.Remove) == 0 || len(req.Add)+len(req.Remove) > 50 {
		s.fail(w, r, httpx.BadRequest("add_tag_ids and remove_tag_ids must list 1-50 tags"))
		return
	}
	info, err := loadTagInfo(ctx, s.DB, p.OrganizationID, append(slices.Clone(req.Add), req.Remove...))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, id := range append(slices.Clone(req.Add), req.Remove...) {
		if _, ok := info[id]; !ok {
			s.fail(w, r, errUnknownTag)
			return
		}
	}
	results := make([]bulkResult, 0, len(req.IDs))
	updated := 0
	for _, id := range slices.Compact(slices.SortedFunc(slices.Values(req.IDs), func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })) {
		res := bulkResult{ID: id, Status: "unchanged"}
		err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
			t, err := s.bulkTarget(ctx, tx, p, req.TargetType, id)
			if err != nil {
				return err
			}
			cur, err := currentTagIDs(ctx, tx, t)
			if err != nil {
				return err
			}
			curInfo, err := loadTagInfo(ctx, tx, p.OrganizationID, cur)
			if err != nil {
				return err
			}
			next := []uuid.UUID{}
			for _, c := range cur {
				if slices.Contains(req.Remove, c) {
					continue
				}
				// A single-value category takes the added tag instead.
				replaced := slices.ContainsFunc(req.Add, func(a uuid.UUID) bool {
					return a != c && info[a].CategoryID == curInfo[c].CategoryID && !info[a].AllowMultiple
				})
				if !replaced {
					next = append(next, c)
				}
			}
			next = append(next, req.Add...)
			changed, err := changeTags(ctx, tx, p, t, next, "bulk", nil)
			if err != nil || !changed {
				return err
			}
			res.Status = "updated"
			return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
				Action: t.Type + ".bulk_tags", TargetType: t.Type, TargetID: t.ID.String(),
				Metadata: map[string]any{"add": req.Add, "remove": req.Remove}})
		})
		if err != nil {
			res.Status = "error"
			var he *httpx.Error
			switch {
			case errors.As(err, &he):
				res.Error = he.Message
			case errors.Is(err, errNotFound), errors.Is(err, authz.ErrForbidden), errors.Is(err, pgx.ErrNoRows):
				res.Error = "not found or not permitted"
			default:
				s.Log.Error("bulk tagging failed", "err", err, "target_id", id)
				res.Error = "could not update"
			}
		}
		if res.Status == "updated" {
			updated++
		}
		results = append(results, res)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": results, "updated": updated})
}

func (s *Service) bulkTarget(ctx context.Context, q db.Querier, p *authz.Principal, typ string, id uuid.UUID) (target, error) {
	if typ == "application" {
		a, err := s.loadManagedApp(ctx, q, p, id)
		return target{"application", a.ID, a.Name}, err
	}
	var name string
	if err := q.QueryRow(ctx, `SELECT COALESCE(NULLIF(display_name, ''), full_name) FROM repositories
		WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL`, p.OrganizationID, id).Scan(&name); err != nil {
		return target{}, errNotFound
	}
	if err := s.Authz.Require(ctx, p, authz.PermReposManage, authz.Scope{Type: authz.ScopeRepository, ID: id}); err != nil {
		return target{}, err
	}
	return target{"repository", id, name}, nil
}

// HistoryEntry is one tag change.
type HistoryEntry struct {
	ID           uuid.UUID  `json:"id"`
	TargetType   string     `json:"target_type"`
	TargetID     uuid.UUID  `json:"target_id"`
	TargetName   string     `json:"target_name"`
	CategoryID   *uuid.UUID `json:"category_id"`
	CategoryName string     `json:"category_name"`
	OldTags      []string   `json:"old_tags"`
	NewTags      []string   `json:"new_tags"`
	Source       string     `json:"source"`
	RuleID       *uuid.UUID `json:"rule_id"`
	ActorEmail   string     `json:"actor_email"`
	CreatedAt    time.Time  `json:"created_at"`
}

// tagHistory: GET /api/v1/tag-history?target_type=&target_id= (anyone who
// can see the asset) or without a target, the organization's latest
// changes (tags.manage or audit.read organization-wide).
func (s *Service) tagHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	q := r.URL.Query()
	typ, tid := q.Get("target_type"), q.Get("target_id")
	args := []any{p.OrganizationID}
	where := "h.organization_id = $1"
	if tid != "" {
		id, err := uuid.Parse(tid)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid target_id"))
			return
		}
		switch typ {
		case "application":
			if _, err := s.loadVisibleApp(ctx, s.DB, p, id); err != nil {
				s.fail(w, r, err)
				return
			}
		case "repository":
			if ok, _ := s.Authz.Can(ctx, p, authz.PermReposRead, authz.Scope{Type: authz.ScopeRepository, ID: id}); !ok {
				s.fail(w, r, errNotFound)
				return
			}
		default:
			s.fail(w, r, httpx.BadRequest("target_type must be application or repository"))
			return
		}
		args = append(args, typ, id)
		where += " AND h.target_type = $2 AND h.target_id = $3"
	} else if !p.HasOrgWide(authz.PermTagsManage) && !p.HasOrgWide(authz.PermAuditRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT h.id, h.target_type, h.target_id, h.target_name, h.category_id, h.category_name,
		h.old_tags, h.new_tags, h.source, h.rule_id, h.actor_email, h.created_at
		FROM tag_assignment_history h WHERE `+where+` ORDER BY h.created_at DESC, h.id DESC LIMIT 200`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[HistoryEntry])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []HistoryEntry{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/secrets"
)

// Service exposes notification settings, history and the inbox.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Secrets   *secrets.Store
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	BaseURL   string
}

// Register mounts the routes.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/notifications/events", s.events)
	mux.HandleFunc("GET /api/v1/notifications/smtp", s.getSMTP)
	mux.HandleFunc("PUT /api/v1/notifications/smtp", s.putSMTP)
	mux.HandleFunc("POST /api/v1/notifications/smtp/test", s.testSMTP)
	mux.HandleFunc("GET /api/v1/notifications/rules", s.listRules)
	mux.HandleFunc("POST /api/v1/notifications/rules", s.createRule)
	mux.HandleFunc("PUT /api/v1/notifications/rules/{id}", s.updateRule)
	mux.HandleFunc("DELETE /api/v1/notifications/rules/{id}", s.deleteRule)
	mux.HandleFunc("GET /api/v1/notifications/templates", s.listTemplates)
	mux.HandleFunc("PUT /api/v1/notifications/templates/{event}", s.putTemplate)
	mux.HandleFunc("DELETE /api/v1/notifications/templates/{event}", s.resetTemplate)
	mux.HandleFunc("POST /api/v1/notifications/templates/{event}/preview", s.previewTemplate)
	mux.HandleFunc("GET /api/v1/notifications/deliveries", s.listDeliveries)
	mux.HandleFunc("GET /api/v1/notifications/deliveries/{id}", s.getDelivery)
	mux.HandleFunc("POST /api/v1/notifications/deliveries/{id}/retry", s.retryDelivery)
	s.registerWebhooks(mux)
	mux.HandleFunc("GET /api/v1/me/notifications", s.inbox)
	mux.HandleFunc("POST /api/v1/me/notifications/read", s.markRead)
}

var errNotFound = errors.New("not found")

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	}
	httpx.WriteError(w, r, s.Log, err)
}

// admin requires notifications.manage at organization scope.
func (s *Service) admin(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if !p.HasOrgWide(authz.PermNotificationsManage) {
		return p, authz.ErrForbidden
	}
	return p, nil
}

func (s *Service) auditWrite(ctx context.Context, q db.Querier, p *authz.Principal, action, typ, id string, meta map[string]any) error {
	return audit.Write(ctx, q, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: action, TargetType: typ, TargetID: id, Metadata: meta})
}

func (s *Service) events(w http.ResponseWriter, r *http.Request) {
	if _, err := s.admin(r); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": Events, "dynamic": DynamicLabels})
}

// ------------------------------------------------------------------ SMTP

type smtpView struct {
	Enabled     bool       `json:"enabled"`
	Host        string     `json:"host"`
	Port        int        `json:"port"`
	TLSMode     string     `json:"tls_mode"`
	Username    string     `json:"username"`
	HasPassword bool       `json:"has_password"`
	FromAddress string     `json:"from_address"`
	FromName    string     `json:"from_name"`
	UpdatedAt   *time.Time `json:"updated_at"`
}

func (s *Service) getSMTP(w http.ResponseWriter, r *http.Request) {
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v := smtpView{Port: 587, TLSMode: "starttls", FromName: "PATHOS"}
	err = s.DB.QueryRow(r.Context(), `SELECT enabled, host, port, tls_mode, username, secret_id IS NOT NULL, from_address, from_name, updated_at
		FROM smtp_settings WHERE organization_id = $1`, p.OrganizationID).
		Scan(&v.Enabled, &v.Host, &v.Port, &v.TLSMode, &v.Username, &v.HasPassword, &v.FromAddress, &v.FromName, &v.UpdatedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

type smtpRequest struct {
	Enabled     bool    `json:"enabled"`
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	TLSMode     string  `json:"tls_mode"`
	Username    string  `json:"username"`
	Password    *string `json:"password"` // nil keeps, "" clears
	FromAddress string  `json:"from_address"`
	FromName    string  `json:"from_name"`
}

func (req *smtpRequest) validate() error {
	req.Host, req.Username, req.FromAddress = strings.TrimSpace(req.Host), strings.TrimSpace(req.Username), strings.TrimSpace(req.FromAddress)
	req.FromName = SanitizeHeader(req.FromName, 100)
	if req.FromName == "" {
		req.FromName = "PATHOS"
	}
	if !slices.Contains([]string{"starttls", "tls", "none"}, req.TLSMode) {
		return httpx.BadRequest("tls_mode must be starttls, tls or none")
	}
	if req.Port < 1 || req.Port > 65535 {
		return httpx.BadRequest("port must be between 1 and 65535")
	}
	if !req.Enabled && req.Host == "" {
		return nil
	}
	if err := ValidateHost(req.Host); err != nil {
		return httpx.BadRequest("host: " + err.Error())
	}
	if err := ValidateAddress(req.FromAddress); err != nil {
		return httpx.BadRequest("from address: " + err.Error())
	}
	if req.Username != "" && req.TLSMode == "none" {
		return httpx.BadRequest("authentication requires TLS (starttls or tls)")
	}
	return nil
}

func (s *Service) putSMTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req smtpRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := req.validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var secretID *uuid.UUID
		err := tx.QueryRow(ctx, `SELECT secret_id FROM smtp_settings WHERE organization_id = $1 FOR UPDATE`, p.OrganizationID).Scan(&secretID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if req.Password != nil {
			switch {
			case *req.Password == "" && secretID != nil:
				old := *secretID
				secretID = nil
				defer func() { _ = s.Secrets.Delete(ctx, tx, p.OrganizationID, old) }()
			case *req.Password != "" && secretID != nil:
				if err := s.Secrets.Update(ctx, tx, p.OrganizationID, *secretID, secrets.KindSMTP, []byte(*req.Password)); err != nil {
					return err
				}
			case *req.Password != "":
				id, err := s.Secrets.Create(ctx, tx, p.OrganizationID, secrets.KindSMTP, "smtp", []byte(*req.Password), &p.UserID)
				if err != nil {
					return err
				}
				secretID = &id
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO smtp_settings (organization_id, enabled, host, port, tls_mode, username, secret_id, from_address, from_name, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
			ON CONFLICT (organization_id) DO UPDATE SET enabled = $2, host = $3, port = $4, tls_mode = $5, username = $6,
			  secret_id = $7, from_address = $8, from_name = $9, updated_by = $10, updated_at = now()`,
			p.OrganizationID, req.Enabled, req.Host, req.Port, req.TLSMode, req.Username, secretID, req.FromAddress, req.FromName, p.UserID); err != nil {
			return err
		}
		return s.auditWrite(ctx, tx, p, "notifications.smtp_update", "smtp_settings", p.OrganizationID.String(),
			map[string]any{"enabled": req.Enabled, "host": req.Host, "port": req.Port, "tls_mode": req.TLSMode, "password_changed": req.Password != nil})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.getSMTP(w, r)
}

// testSMTP queues a test email to the caller (or a given address). The jobs
// role sends it, so the result reflects the real delivery path.
func (s *Service) testSMTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		To string `json:"to"`
	}
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, &req); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	to := strings.TrimSpace(req.To)
	if to == "" {
		to = p.Email
	}
	if err := ValidateAddress(to); err != nil {
		s.fail(w, r, httpx.BadRequest(err.Error()))
		return
	}
	d := Sample(testEvent.Key, s.BaseURL)
	_ = s.DB.QueryRow(ctx, `SELECT name FROM organizations WHERE id = $1`, p.OrganizationID).Scan(&d.Org)
	subject, body, err := Render(testEvent.Subject, testEvent.Body, d)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var id uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO notifications (organization_id, event_key, channel, user_id, email, subject, body)
			VALUES ($1, 'smtp.test', 'email', $2, lower($3), $4, $5) RETURNING id`, p.OrganizationID, p.UserID, to, subject, body).Scan(&id); err != nil {
			return err
		}
		return s.auditWrite(ctx, tx, p, "notifications.smtp_test", "notification", id.String(), map[string]any{"to": to})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"id": id, "to": to})
}

// ----------------------------------------------------------------- rules

// Rule is the API representation.
type Rule struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Enabled     bool       `json:"enabled"`
	EventKey    string     `json:"event_key"`
	MinSeverity *string    `json:"min_severity"`
	ScopeType   string     `json:"scope_type"`
	ScopeID     *uuid.UUID `json:"scope_id"`
	ScopeName   string     `json:"scope_name"`
	Recipients  Recipients `json:"recipients"`
	Email       bool       `json:"email"`
	InApp       bool       `json:"in_app"`
	System      bool       `json:"system"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

const selectRules = `
	SELECT r.id, r.name, r.enabled, r.event_key, r.min_severity, r.scope_type, r.scope_id,
	       COALESCE(CASE r.scope_type WHEN 'organization' THEN 'Organization'
	         WHEN 'region' THEN (SELECT name FROM regions WHERE id = r.scope_id)
	         WHEN 'business_unit' THEN (SELECT name FROM business_units WHERE id = r.scope_id)
	         WHEN 'repository' THEN (SELECT full_name FROM repositories WHERE id = r.scope_id) END, '(deleted)'),
	       r.recipients, r.email, r.in_app, r.system_key IS NOT NULL, r.updated_at
	FROM notification_rules r`

func scanRule(row pgx.Row) (Rule, error) {
	var rl Rule
	var rec []byte
	err := row.Scan(&rl.ID, &rl.Name, &rl.Enabled, &rl.EventKey, &rl.MinSeverity, &rl.ScopeType, &rl.ScopeID, &rl.ScopeName,
		&rec, &rl.Email, &rl.InApp, &rl.System, &rl.UpdatedAt)
	if err == nil {
		_ = json.Unmarshal(rec, &rl.Recipients)
		rl.Recipients = rl.Recipients.normalized()
	}
	return rl, err
}

func (s *Service) listRules(w http.ResponseWriter, r *http.Request) {
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), selectRules+` WHERE r.organization_id = $1 ORDER BY r.system_key IS NULL, r.event_key, r.name`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Rule, error) { return scanRule(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

type ruleRequest struct {
	Name        string     `json:"name"`
	Enabled     *bool      `json:"enabled"`
	EventKey    string     `json:"event_key"`
	MinSeverity *string    `json:"min_severity"`
	ScopeType   string     `json:"scope_type"`
	ScopeID     *uuid.UUID `json:"scope_id"`
	Recipients  Recipients `json:"recipients"`
	Email       bool       `json:"email"`
	InApp       bool       `json:"in_app"`
}

func (s *Service) validateRule(ctx context.Context, q db.Querier, orgID uuid.UUID, req *ruleRequest) error {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 120 {
		return httpx.BadRequest("name is required (at most 120 characters)")
	}
	def, ok := LookupEvent(req.EventKey)
	if !ok || req.EventKey == testEvent.Key {
		return httpx.BadRequest("unknown event")
	}
	if req.MinSeverity != nil && *req.MinSeverity == "" {
		req.MinSeverity = nil
	}
	if req.MinSeverity != nil {
		if _, ok := severityRank[*req.MinSeverity]; !ok || !def.Severity {
			return httpx.BadRequest("min_severity is not valid for this event")
		}
	}
	if req.ScopeType == "" {
		req.ScopeType = "organization"
	}
	table := map[string]string{"region": "regions", "business_unit": "business_units", "repository": "repositories"}
	switch req.ScopeType {
	case "organization":
		req.ScopeID = nil
	case "region", "business_unit", "repository":
		if !def.Repository {
			return httpx.BadRequest("this event is not tied to a repository; use organization scope")
		}
		if req.ScopeID == nil {
			return httpx.BadRequest("scope_id is required")
		}
		var exists bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+table[req.ScopeType]+` WHERE organization_id = $1 AND id = $2)`, orgID, *req.ScopeID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return httpx.BadRequest("scope not found")
		}
	default:
		return httpx.BadRequest("invalid scope_type")
	}
	if !req.Email && !req.InApp {
		return httpx.BadRequest("choose at least one channel")
	}
	rc := &req.Recipients
	rc.Roles, rc.Dynamic = nonNil(rc.Roles), nonNil(rc.Dynamic)
	if rc.Users == nil {
		rc.Users = []uuid.UUID{}
	}
	if len(rc.Roles) > 20 || len(rc.Users) > 100 || len(rc.Emails) > 50 {
		return httpx.BadRequest("too many recipients")
	}
	for _, d := range rc.Dynamic {
		if !slices.Contains(def.Dynamic, d) {
			return httpx.BadRequest("dynamic recipient " + strconv.Quote(d) + " does not apply to this event")
		}
	}
	emails := []string{}
	for _, e := range rc.Emails {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if err := ValidateAddress(e); err != nil {
			return httpx.BadRequest(err.Error())
		}
		emails = append(emails, e)
	}
	rc.Emails = emails
	if len(rc.Roles) > 0 {
		var n int
		if err := q.QueryRow(ctx, `SELECT count(DISTINCT key) FROM roles WHERE key = ANY($1) AND (organization_id IS NULL OR organization_id = $2)`, rc.Roles, orgID).Scan(&n); err != nil {
			return err
		}
		if n != len(slices.Compact(slices.Sorted(slices.Values(rc.Roles)))) {
			return httpx.BadRequest("unknown role")
		}
	}
	if len(rc.Users) > 0 {
		var n int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM users WHERE organization_id = $1 AND id = ANY($2)`, orgID, rc.Users).Scan(&n); err != nil {
			return err
		}
		if n != len(slices.Compact(slices.SortedFunc(slices.Values(rc.Users), func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) }))) {
			return httpx.BadRequest("unknown user")
		}
	}
	if len(rc.Roles)+len(rc.Users)+len(rc.Emails)+len(rc.Dynamic) == 0 {
		return httpx.BadRequest("add at least one recipient")
	}
	if len(rc.Emails) > 0 && !req.Email {
		return httpx.BadRequest("email addresses need the email channel")
	}
	return nil
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func (s *Service) createRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req ruleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.validateRule(ctx, s.DB, p.OrganizationID, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	id := uuid.Must(uuid.NewV7())
	rec, _ := json.Marshal(req.Recipients.normalized())
	var out Rule
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_rules (id, organization_id, name, enabled, event_key, min_severity, scope_type, scope_id, recipients, email, in_app, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			id, p.OrganizationID, req.Name, req.Enabled == nil || *req.Enabled, req.EventKey, req.MinSeverity, req.ScopeType, req.ScopeID, rec, req.Email, req.InApp, p.UserID); err != nil {
			return err
		}
		if err := s.auditWrite(ctx, tx, p, "notifications.rule_create", "notification_rule", id.String(), map[string]any{"name": req.Name, "event": req.EventKey}); err != nil {
			return err
		}
		out, err = scanRule(tx.QueryRow(ctx, selectRules+` WHERE r.id = $1`, id))
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (s *Service) updateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	var req ruleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	var out Rule
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var system bool
		var event string
		if err := tx.QueryRow(ctx, `SELECT system_key IS NOT NULL, event_key FROM notification_rules WHERE organization_id = $1 AND id = $2 FOR UPDATE`,
			p.OrganizationID, id).Scan(&system, &event); err != nil {
			return errNotFound
		}
		if system && req.EventKey != event {
			return httpx.Conflict("the event of a built-in rule cannot change; create a new rule instead")
		}
		if err := s.validateRule(ctx, tx, p.OrganizationID, &req); err != nil {
			return err
		}
		rec, _ := json.Marshal(req.Recipients.normalized())
		if _, err := tx.Exec(ctx, `UPDATE notification_rules SET name = $3, enabled = $4, event_key = $5, min_severity = $6, scope_type = $7,
			scope_id = $8, recipients = $9, email = $10, in_app = $11, updated_at = now() WHERE organization_id = $1 AND id = $2`,
			p.OrganizationID, id, req.Name, req.Enabled == nil || *req.Enabled, req.EventKey, req.MinSeverity, req.ScopeType, req.ScopeID, rec, req.Email, req.InApp); err != nil {
			return err
		}
		if err := s.auditWrite(ctx, tx, p, "notifications.rule_update", "notification_rule", id.String(),
			map[string]any{"name": req.Name, "event": req.EventKey, "enabled": req.Enabled == nil || *req.Enabled}); err != nil {
			return err
		}
		var err error
		out, err = scanRule(tx.QueryRow(ctx, selectRules+` WHERE r.id = $1`, id))
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) deleteRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var system bool
		var name string
		if err := tx.QueryRow(ctx, `SELECT system_key IS NOT NULL, name FROM notification_rules WHERE organization_id = $1 AND id = $2 FOR UPDATE`,
			p.OrganizationID, id).Scan(&system, &name); err != nil {
			return errNotFound
		}
		if system {
			return httpx.Conflict("built-in rules cannot be deleted; disable them instead")
		}
		if _, err := tx.Exec(ctx, `DELETE FROM notification_rules WHERE id = $1`, id); err != nil {
			return err
		}
		return s.auditWrite(ctx, tx, p, "notifications.rule_delete", "notification_rule", id.String(), map[string]any{"name": name})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ------------------------------------------------------------- templates

type templateView struct {
	EventKey       string `json:"event_key"`
	Label          string `json:"label"`
	Subject        string `json:"subject"`
	Body           string `json:"body"`
	DefaultSubject string `json:"default_subject"`
	DefaultBody    string `json:"default_body"`
	Customized     bool   `json:"customized"`
}

func (s *Service) listTemplates(w http.ResponseWriter, r *http.Request) {
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	custom := map[string][2]string{}
	rows, err := s.DB.Query(r.Context(), `SELECT event_key, subject, body FROM notification_templates WHERE organization_id = $1`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for rows.Next() {
		var k, sub, body string
		if err := rows.Scan(&k, &sub, &body); err == nil {
			custom[k] = [2]string{sub, body}
		}
	}
	rows.Close()
	out := []templateView{}
	for _, e := range append(slices.Clone(Events), testEvent) {
		v := templateView{EventKey: e.Key, Label: e.Label, Subject: e.Subject, Body: e.Body, DefaultSubject: e.Subject, DefaultBody: e.Body}
		if c, ok := custom[e.Key]; ok {
			v.Subject, v.Body, v.Customized = c[0], c[1], true
		}
		out = append(out, v)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type templateRequest struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// checkTemplate parses and test-renders against sample data so broken
// templates are rejected at save time.
func (s *Service) checkTemplate(event string, req templateRequest) (string, string, error) {
	if _, ok := LookupEvent(event); !ok {
		return "", "", errNotFound
	}
	if strings.TrimSpace(req.Subject) == "" || strings.TrimSpace(req.Body) == "" || len(req.Subject) > 300 || len(req.Body) > 20000 {
		return "", "", httpx.BadRequest("subject (≤ 300) and body (≤ 20000 characters) are required")
	}
	sub, body, err := Render(req.Subject, req.Body, Sample(event, s.BaseURL))
	if err != nil {
		return "", "", httpx.BadRequest("template error: " + err.Error())
	}
	return sub, body, nil
}

func (s *Service) putTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	event := r.PathValue("event")
	var req templateRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if _, _, err := s.checkTemplate(event, req); err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_templates (organization_id, event_key, subject, body, updated_by)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT (organization_id, event_key) DO UPDATE SET subject = $3, body = $4, updated_by = $5, updated_at = now()`,
			p.OrganizationID, event, req.Subject, req.Body, p.UserID); err != nil {
			return err
		}
		return s.auditWrite(ctx, tx, p, "notifications.template_update", "notification_template", event, nil)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) resetTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	event := r.PathValue("event")
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM notification_templates WHERE organization_id = $1 AND event_key = $2`, p.OrganizationID, event); err != nil {
			return err
		}
		return s.auditWrite(ctx, tx, p, "notifications.template_reset", "notification_template", event, nil)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) previewTemplate(w http.ResponseWriter, r *http.Request) {
	if _, err := s.admin(r); err != nil {
		s.fail(w, r, err)
		return
	}
	var req templateRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	sub, body, err := s.checkTemplate(r.PathValue("event"), req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"subject": sub, "body": body})
}

// ------------------------------------------------------------ deliveries

// Delivery is one notification as shown in the history.
type Delivery struct {
	ID        uuid.UUID  `json:"id"`
	EventKey  string     `json:"event_key"`
	Channel   string     `json:"channel"`
	Recipient string     `json:"recipient"`
	Subject   string     `json:"subject"`
	Body      string     `json:"body,omitempty"`
	Link      string     `json:"link"`
	Status    string     `json:"status"`
	Attempts  int        `json:"attempts"`
	LastError string     `json:"last_error"`
	RuleName  *string    `json:"rule_name"`
	SentAt    *time.Time `json:"sent_at"`
	ReadAt    *time.Time `json:"read_at"`
	CreatedAt time.Time  `json:"created_at"`
}

const selectDeliveries = `
	SELECT n.id, n.event_key, n.channel, COALESCE(NULLIF(n.email, ''), u.email, ''), n.subject, n.link, n.status, n.attempts,
	       n.last_error, r.name, n.sent_at, n.read_at, n.created_at
	FROM notifications n LEFT JOIN users u ON u.id = n.user_id LEFT JOIN notification_rules r ON r.id = n.rule_id`

func scanDelivery(row pgx.Row) (Delivery, error) {
	var d Delivery
	err := row.Scan(&d.ID, &d.EventKey, &d.Channel, &d.Recipient, &d.Subject, &d.Link, &d.Status, &d.Attempts, &d.LastError,
		&d.RuleName, &d.SentAt, &d.ReadAt, &d.CreatedAt)
	return d, err
}

func (s *Service) listDeliveries(w http.ResponseWriter, r *http.Request) {
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	where := []string{"n.organization_id = $1"}
	args := []any{p.OrganizationID}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if v := q.Get("status"); v != "" {
		add("n.status = ?", v)
	}
	if v := q.Get("channel"); v != "" {
		add("n.channel = ?", v)
	}
	if v := q.Get("event_key"); v != "" {
		add("n.event_key = ?", v)
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		add("(n.subject ILIKE '%' || ? || '%' OR n.email ILIKE '%' || ? || '%' OR u.email ILIKE '%' || ? || '%')", v)
	}
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid before"))
			return
		}
		add("n.created_at < ?", t)
	}
	rows, err := s.DB.Query(r.Context(), selectDeliveries+` WHERE `+strings.Join(where, " AND ")+` ORDER BY n.created_at DESC LIMIT 101`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Delivery, error) { return scanDelivery(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	next := ""
	if len(items) > 100 {
		items = items[:100]
		next = items[99].CreatedAt.Format(time.RFC3339Nano)
	}
	var stats struct {
		Sent, Pending, Failed, Suppressed int
	}
	_ = s.DB.QueryRow(r.Context(), `SELECT count(*) FILTER (WHERE status = 'sent'), count(*) FILTER (WHERE status = 'pending'),
		count(*) FILTER (WHERE status = 'failed'), count(*) FILTER (WHERE status = 'suppressed')
		FROM notifications WHERE organization_id = $1 AND channel = 'email' AND created_at > now() - interval '7 days'`, p.OrganizationID).
		Scan(&stats.Sent, &stats.Pending, &stats.Failed, &stats.Suppressed)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next,
		"email_last_7_days": map[string]int{"sent": stats.Sent, "pending": stats.Pending, "failed": stats.Failed, "suppressed": stats.Suppressed}})
}

func (s *Service) getDelivery(w http.ResponseWriter, r *http.Request) {
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	d, err := scanDelivery(s.DB.QueryRow(r.Context(), selectDeliveries+` WHERE n.organization_id = $1 AND n.id = $2`, p.OrganizationID, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.DB.QueryRow(r.Context(), `SELECT body FROM notifications WHERE id = $1`, id).Scan(&d.Body)
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (s *Service) retryDelivery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE notifications SET status = 'pending', attempts = 0, next_attempt_at = now(), last_error = ''
			WHERE organization_id = $1 AND id = $2 AND channel = 'email' AND status IN ('failed', 'suppressed')`, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var found bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notifications WHERE organization_id = $1 AND id = $2)`, p.OrganizationID, id).Scan(&found); err != nil || !found {
				return errNotFound
			}
			return httpx.Conflict("only failed or suppressed emails can be retried")
		}
		return s.auditWrite(ctx, tx, p, "notifications.retry", "notification", id.String(), nil)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ----------------------------------------------------------------- inbox

func (s *Service) inbox(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	cond := ""
	if r.URL.Query().Get("unread") == "1" {
		cond = " AND n.read_at IS NULL"
	}
	rows, err := s.DB.Query(ctx, selectDeliveries+` WHERE n.organization_id = $1 AND n.user_id = $2 AND n.channel = 'in_app'`+cond+`
		ORDER BY n.created_at DESC LIMIT 50`, p.OrganizationID, p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Delivery, error) { return scanDelivery(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var unread int
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE user_id = $1 AND channel = 'in_app' AND read_at IS NULL`, p.UserID).Scan(&unread)
	for i := range items {
		items[i].Recipient = "" // the caller's own address; no need to repeat it
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "unread": unread})
}

func (s *Service) markRead(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req struct {
		IDs []uuid.UUID `json:"ids"`
		All bool        `json:"all"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !req.All && len(req.IDs) == 0 {
		s.fail(w, r, httpx.BadRequest("ids or all is required"))
		return
	}
	if len(req.IDs) > 500 {
		s.fail(w, r, httpx.BadRequest("at most 500 ids"))
		return
	}
	_, err := s.DB.Exec(ctx, `UPDATE notifications SET read_at = now()
		WHERE user_id = $1 AND channel = 'in_app' AND read_at IS NULL AND ($2 OR id = ANY($3))`, p.UserID, req.All, req.IDs)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

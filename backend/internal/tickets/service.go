package tickets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
	"pathos/internal/platform/logging"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

// Service serves the ticketing API.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Secrets   *secrets.Store
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	PublicURL string
	// HTTP overrides the network-policy client (tests only).
	HTTP *http.Client
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/ticket-connections", s.list)
	mux.HandleFunc("POST /api/v1/ticket-connections", s.create)
	mux.HandleFunc("PUT /api/v1/ticket-connections/{id}", s.update)
	mux.HandleFunc("DELETE /api/v1/ticket-connections/{id}", s.remove)
	mux.HandleFunc("POST /api/v1/ticket-connections/{id}/test", s.test)
	mux.HandleFunc("GET /api/v1/findings/{id}/tickets", s.findingTickets)
	mux.HandleFunc("POST /api/v1/findings/{id}/tickets", s.createTicket)
}

// Connection as returned by the API (never the credential).
type Connection struct {
	ID           uuid.UUID `json:"id"`
	Kind         string    `json:"kind"`
	Name         string    `json:"name"`
	BaseURL      string    `json:"base_url"`
	AuthType     string    `json:"auth_type"`
	Username     string    `json:"username"`
	Config       Config    `json:"config"`
	AllowPrivate bool      `json:"allow_private"`
	Enabled      bool      `json:"enabled"`
	// CABundlePEM is the private CA bundle added to the system trust store
	// for this connection ("" = system trust store only).
	CABundlePEM    string       `json:"ca_bundle_pem"`
	CACertificates []scm.CACert `json:"ca_certificates"`
	Tickets        int          `json:"tickets"`
	CreatedAt      time.Time    `json:"created_at"`
}

const connSelect = `SELECT c.id, c.kind, c.name, c.base_url, c.auth_type, c.username, c.config, c.allow_private, c.enabled, c.ca_bundle_pem,
	(SELECT count(*) FROM finding_tickets t WHERE t.connection_id = c.id), c.created_at FROM ticket_connections c`

func scanConn(r pgx.Row) (Connection, error) {
	var c Connection
	var cfg []byte
	if err := r.Scan(&c.ID, &c.Kind, &c.Name, &c.BaseURL, &c.AuthType, &c.Username, &cfg, &c.AllowPrivate, &c.Enabled, &c.CABundlePEM, &c.Tickets, &c.CreatedAt); err != nil {
		return c, err
	}
	_, c.CACertificates, _ = scm.ParseCABundle(c.CABundlePEM, time.Now())
	if c.CACertificates == nil {
		c.CACertificates = []scm.CACert{}
	}
	return c, json.Unmarshal(cfg, &c.Config)
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, pgx.ErrNoRows):
		err = httpx.ErrNotFound
	case db.IsUniqueViolation(err):
		err = httpx.Conflict("a connection with this name already exists")
	}
	httpx.WriteError(w, r, s.Log, err)
}

func (s *Service) manage(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil {
		return nil, authz.ErrForbidden
	}
	return p, s.Authz.Require(r.Context(), p, authz.PermSettingsManage, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID})
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if p == nil || !p.HasAnywhere(authz.PermFindingsTriage) && !p.HasOrgWide(authz.PermSettingsManage) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(r.Context(), connSelect+` WHERE c.organization_id = $1 ORDER BY lower(c.name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Connection, error) { return scanConn(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasOrgWide(authz.PermSettingsManage) {
		// Triage users see only what they need to pick a connection.
		for i := range items {
			items[i] = Connection{ID: items[i].ID, Kind: items[i].Kind, Name: items[i].Name, Enabled: items[i].Enabled}
		}
	}
	if items == nil {
		items = []Connection{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

type input struct {
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	BaseURL      string `json:"base_url"`
	AuthType     string `json:"auth_type"`
	Username     string `json:"username"`
	Secret       string `json:"secret"`
	Config       Config `json:"config"`
	AllowPrivate bool   `json:"allow_private"`
	Enabled      *bool  `json:"enabled"`
	// CABundlePEM: private CA bundle (PEM certificates). On update, absent
	// keeps the stored bundle and "" removes it.
	CABundlePEM *string `json:"ca_bundle_pem"`
}

func (in *input) validate(update bool) error {
	in.Name, in.BaseURL, in.Username = strings.TrimSpace(in.Name), strings.TrimRight(strings.TrimSpace(in.BaseURL), "/"), strings.TrimSpace(in.Username)
	if _, ok := registry[in.Kind]; !ok {
		return httpx.BadRequest("kind must be one of: " + strings.Join(Kinds(), ", "))
	}
	if in.Name == "" || len(in.Name) > 120 {
		return httpx.BadRequest("name is required (at most 120 characters)")
	}
	if _, err := (scm.NetPolicy{AllowPrivate: in.AllowPrivate, OrgChosen: true}).ValidateBaseURL(in.BaseURL); err != nil {
		return httpx.BadRequest("base_url: " + err.Error())
	}
	if in.AuthType != "basic" && in.AuthType != "bearer" {
		return httpx.BadRequest("auth_type must be basic or bearer")
	}
	if in.AuthType == "basic" && in.Username == "" {
		return httpx.BadRequest("username is required for basic authentication")
	}
	if !update && in.Secret == "" {
		return httpx.BadRequest("secret (API token, personal access token or password) is required")
	}
	if len(in.Secret) > 4000 || len(in.Username) > 200 {
		return httpx.BadRequest("credential too long")
	}
	switch in.Kind {
	case "jira":
		in.Config.ProjectKey = strings.ToUpper(strings.TrimSpace(in.Config.ProjectKey))
		if in.Config.ProjectKey == "" || len(in.Config.ProjectKey) > 30 {
			return httpx.BadRequest("config.project_key is required for Jira")
		}
		in.Config.Table, in.Config.AssignmentGroup, in.Config.CallerID = "", "", ""
		in.Config.CloudID = strings.ToLower(strings.TrimSpace(in.Config.CloudID))
		switch in.Config.TokenType {
		case "", TokenUnscoped:
			in.Config.TokenType, in.Config.CloudID = "", ""
		case TokenScoped:
			if in.AuthType != "basic" {
				return httpx.BadRequest("a scoped Jira API token uses basic authentication (e-mail and token)")
			}
			if in.Config.CloudID != "" && !cloudIDRe.MatchString(in.Config.CloudID) {
				return httpx.BadRequest("config.cloud_id must be the site's cloud ID (a UUID); leave it empty to look it up")
			}
		default:
			return httpx.BadRequest("config.token_type must be unscoped or scoped")
		}
	case "servicenow":
		if in.Config.Table == "" {
			in.Config.Table = "incident"
		}
		for _, c := range in.Config.Table {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				return httpx.BadRequest("config.table must be a ServiceNow table name")
			}
		}
		in.Config.ProjectKey, in.Config.IssueType, in.Config.Labels = "", "", nil
		in.Config.TokenType, in.Config.CloudID = "", ""
	}
	if len(in.Config.Labels) > 10 {
		return httpx.BadRequest("at most 10 labels")
	}
	if in.CABundlePEM != nil {
		b := strings.TrimSpace(*in.CABundlePEM)
		if _, _, err := scm.ParseCABundle(b, time.Now()); err != nil {
			return httpx.BadRequest("ca_bundle_pem: " + err.Error()).WithDiag(scm.DiagCABundleInvalid)
		}
		in.CABundlePEM = &b
	}
	return nil
}

func (in *input) caBundle() string {
	if in.CABundlePEM == nil {
		return ""
	}
	return *in.CABundlePEM
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	p, err := s.manage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in input
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := in.validate(false); err != nil {
		s.fail(w, r, err)
		return
	}
	id := uuid.Must(uuid.NewV7())
	cfg, _ := json.Marshal(in.Config)
	enabled := in.Enabled == nil || *in.Enabled
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		sid, err := s.Secrets.Create(r.Context(), tx, p.OrganizationID, secrets.KindIntegration, in.Kind+": "+in.Name, []byte(in.Secret), &p.UserID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `INSERT INTO ticket_connections (id, organization_id, kind, name, base_url, auth_type, username, secret_id, config,
			allow_private, enabled, created_by, ca_bundle_pem) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			id, p.OrganizationID, in.Kind, in.Name, in.BaseURL, in.AuthType, in.Username, sid, cfg, in.AllowPrivate, enabled, p.UserID, in.caBundle()); err != nil {
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ticket_connection.create", TargetType: "ticket_connection", TargetID: id.String(),
			Metadata: map[string]any{"kind": in.Kind, "name": in.Name, "base_url": in.BaseURL, "auth_type": in.AuthType}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := scanConn(s.DB.QueryRow(r.Context(), connSelect+` WHERE c.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, c)
}

func (s *Service) update(w http.ResponseWriter, r *http.Request) {
	p, err := s.manage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	var in input
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := in.validate(true); err != nil {
		s.fail(w, r, err)
		return
	}
	cfg, _ := json.Marshal(in.Config)
	enabled := in.Enabled == nil || *in.Enabled
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		var sid uuid.UUID
		var kind string
		if err := tx.QueryRow(r.Context(), `SELECT secret_id, kind FROM ticket_connections WHERE organization_id = $1 AND id = $2 FOR UPDATE`,
			p.OrganizationID, id).Scan(&sid, &kind); err != nil {
			return err
		}
		if kind != in.Kind {
			return httpx.BadRequest("the kind of a connection cannot change")
		}
		if in.Secret != "" {
			if err := s.Secrets.Update(r.Context(), tx, p.OrganizationID, sid, secrets.KindIntegration, []byte(in.Secret)); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(r.Context(), `UPDATE ticket_connections SET name = $3, base_url = $4, auth_type = $5, username = $6, config = $7,
			allow_private = $8, enabled = $9, ca_bundle_pem = CASE WHEN $10 THEN $11 ELSE ca_bundle_pem END, updated_at = now()
			WHERE organization_id = $1 AND id = $2`,
			p.OrganizationID, id, in.Name, in.BaseURL, in.AuthType, in.Username, cfg, in.AllowPrivate, enabled, in.CABundlePEM != nil, in.caBundle()); err != nil {
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ticket_connection.update", TargetType: "ticket_connection", TargetID: id.String(),
			Metadata: map[string]any{"name": in.Name, "base_url": in.BaseURL, "secret_changed": in.Secret != "", "enabled": enabled}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := scanConn(s.DB.QueryRow(r.Context(), connSelect+` WHERE c.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (s *Service) remove(w http.ResponseWriter, r *http.Request) {
	p, err := s.manage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		var name string
		var sid uuid.UUID
		if err := tx.QueryRow(r.Context(), `DELETE FROM ticket_connections WHERE organization_id = $1 AND id = $2 RETURNING name, secret_id`,
			p.OrganizationID, id).Scan(&name, &sid); err != nil {
			return err
		}
		if err := s.Secrets.Delete(r.Context(), tx, p.OrganizationID, sid); err != nil {
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ticket_connection.delete", TargetType: "ticket_connection", TargetID: id.String(), Metadata: map[string]any{"name": name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// conn loads a connection with its decrypted credential.
func (s *Service) conn(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (Conn, string, bool, error) {
	var c Conn
	var sid uuid.UUID
	var cfg []byte
	var name string
	var allowPrivate, enabled bool
	var caBundle string
	if err := q.QueryRow(ctx, `SELECT kind, name, base_url, auth_type, username, secret_id, config, allow_private, enabled, ca_bundle_pem
		FROM ticket_connections WHERE organization_id = $1 AND id = $2`, orgID, id).
		Scan(&c.Kind, &name, &c.BaseURL, &c.AuthType, &c.Username, &sid, &cfg, &allowPrivate, &enabled, &caBundle); err != nil {
		return c, "", false, err
	}
	_ = json.Unmarshal(cfg, &c.Config)
	sec, err := s.Secrets.Reveal(ctx, q, orgID, sid, secrets.KindIntegration)
	if err != nil {
		return c, "", false, err
	}
	c.Secret = string(sec)
	c.HTTP = s.HTTP
	if c.HTTP == nil {
		c.HTTP = connClient(allowPrivate, caBundle)
	}
	return c, name, enabled, nil
}

// CheckConnection runs the connection's read-only check (the Test button:
// who PATHOS acts as, and the configured project or table) for the
// Connectors health check. It returns the identity.
func (s *Service) CheckConnection(ctx context.Context, orgID, id uuid.UUID) (string, error) {
	c, _, _, err := s.conn(ctx, s.DB, orgID, id)
	if err != nil {
		return "", err
	}
	return c.Check(ctx)
}

func (s *Service) test(w http.ResponseWriter, r *http.Request) {
	p, err := s.manage(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	c, _, _, err := s.conn(r.Context(), s.DB, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	who, cerr := c.Check(r.Context())
	out := map[string]any{"ok": cerr == nil, "identity": who}
	if cerr != nil {
		out["error"] = logging.RedactString(cerr.Error())
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// FindingTicket is a ticket linked to a finding.
type FindingTicket struct {
	ID             uuid.UUID  `json:"id"`
	ConnectionID   uuid.UUID  `json:"connection_id"`
	ConnectionName string     `json:"connection_name"`
	Kind           string     `json:"kind"`
	Key            string     `json:"key"`
	URL            string     `json:"url"`
	Status         string     `json:"status"`
	Done           bool       `json:"done"`
	SyncError      string     `json:"sync_error"`
	SyncedAt       *time.Time `json:"synced_at"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
}

const ticketSelect = `SELECT t.id, t.connection_id, c.name, c.kind, t.external_key, t.url, t.remote_status, t.remote_done, t.sync_error, t.synced_at,
	COALESCE(u.email, ''), t.created_at FROM finding_tickets t JOIN ticket_connections c ON c.id = t.connection_id LEFT JOIN users u ON u.id = t.created_by`

// visibleFinding checks the caller may act on the finding with perm.
func (s *Service) visibleFinding(ctx context.Context, p *authz.Principal, id uuid.UUID, perm authz.Permission) error {
	f := authz.FilterFor(p, perm)
	if f.None() {
		return authz.ErrForbidden
	}
	scope, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 3)
	args = append([]any{p.OrganizationID, id}, args...)
	var ok bool
	if err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM findings fi JOIN repositories r ON r.id = fi.repository_id
		WHERE fi.organization_id = $1 AND fi.id = $2 AND `+scope+`)`, args...).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Service) findingTickets(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || p == nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	if err := s.visibleFinding(r.Context(), p, id, authz.PermFindingsRead); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), ticketSelect+` WHERE t.finding_id = $1 ORDER BY t.created_at`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[FindingTicket])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []FindingTicket{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// issueFor describes a finding for an issue tracker: its facts and a link
// back, never code snippets, and with secrets redacted.
func (s *Service) issueFor(ctx context.Context, findingID uuid.UUID) (Issue, error) {
	var title, severity, category, repo, path, cve, pkg, ver, fixed, desc string
	var line *int
	var cwe []string
	var risk *int
	err := s.DB.QueryRow(ctx, `SELECT f.title, f.severity, f.category, COALESCE(NULLIF(r.display_name, ''), r.full_name), f.file_path, COALESCE(f.cve, ''),
		  f.package_name, f.package_version, f.fixed_version, f.description, f.start_line, f.cwe, f.risk_score
		FROM findings f JOIN repositories r ON r.id = f.repository_id WHERE f.id = $1`, findingID).
		Scan(&title, &severity, &category, &repo, &path, &cve, &pkg, &ver, &fixed, &desc, &line, &cwe, &risk)
	if err != nil {
		return Issue{}, err
	}
	loc := path
	if line != nil {
		loc = fmt.Sprintf("%s:%d", path, *line)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Severity: %s\nType: %s\nRepository: %s\n", severity, category, repo)
	if loc != "" {
		fmt.Fprintf(&b, "Location: %s\n", loc)
	}
	if pkg != "" {
		fmt.Fprintf(&b, "Package: %s %s", pkg, ver)
		if fixed != "" {
			fmt.Fprintf(&b, " (fixed in %s)", fixed)
		}
		b.WriteString("\n")
	}
	if cve != "" {
		fmt.Fprintf(&b, "Vulnerability: %s\n", cve)
	}
	if len(cwe) > 0 {
		fmt.Fprintf(&b, "CWE: %s\n", strings.Join(cwe, ", "))
	}
	if risk != nil {
		fmt.Fprintf(&b, "PATHOS contextual risk: %d/100\n", *risk)
	}
	if d := strings.TrimSpace(desc); d != "" {
		if len(d) > 4000 {
			d = d[:4000] + "…"
		}
		b.WriteString("\n" + d + "\n")
	}
	if s.PublicURL != "" {
		fmt.Fprintf(&b, "\nPATHOS: %s/findings?finding=%s\n", strings.TrimRight(s.PublicURL, "/"), findingID)
	}
	label := severity
	if label != "" {
		label = strings.ToUpper(label[:1]) + label[1:]
	}
	summary := fmt.Sprintf("[PATHOS] %s: %s", label, title)
	if len(summary) > 250 {
		summary = summary[:250]
	}
	return Issue{Summary: logging.RedactString(summary), Description: logging.RedactString(b.String()), Severity: severity}, nil
}

func (s *Service) createTicket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || p == nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	if err := s.visibleFinding(ctx, p, id, authz.PermFindingsTriage); err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		ConnectionID uuid.UUID `json:"connection_id"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	c, name, enabled, err := s.conn(ctx, s.DB, p.OrganizationID, req.ConnectionID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !enabled {
		s.fail(w, r, httpx.Conflict("this connection is disabled"))
		return
	}
	var existing string
	if err := s.DB.QueryRow(ctx, `SELECT external_key FROM finding_tickets WHERE finding_id = $1 AND connection_id = $2`, id, req.ConnectionID).Scan(&existing); err == nil {
		s.fail(w, r, httpx.Conflict("this finding already has ticket "+existing+" in "+name))
		return
	}
	is, err := s.issueFor(ctx, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := c.Create(ctx, is)
	if err != nil {
		s.Log.Warn("ticket not created", "connection_id", req.ConnectionID, "err", err, "request_id", httpx.RequestID(r), "error_code", "PTH-CONN-1250")
		s.fail(w, r, httpx.E(http.StatusBadGateway, "ticket_failed", "could not create the ticket: "+logging.RedactString(err.Error())))
		return
	}
	tid := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO finding_tickets (id, organization_id, finding_id, connection_id, external_key, external_id, url, remote_status, synced_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), $9)`, tid, p.OrganizationID, id, req.ConnectionID, t.Key, t.ID, t.URL, t.Status, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "finding.ticket_create", TargetType: "finding", TargetID: id.String(),
			Metadata: map[string]any{"connection": name, "kind": c.Kind, "key": t.Key}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, ticketSelect+` WHERE t.id = $1`, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ft, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[FindingTicket])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, ft)
}

// Sync refreshes the status of open tickets (up to 100 per call, each at
// most every 15 minutes). The finding itself is not changed: it is fixed
// when a scan no longer reports it.
func (s *Service) Sync(ctx context.Context) (int, error) {
	rows, err := s.DB.Query(ctx, `SELECT t.id, t.organization_id, t.connection_id, t.external_key, t.external_id FROM finding_tickets t
		JOIN ticket_connections c ON c.id = t.connection_id AND c.enabled
		WHERE NOT t.remote_done AND (t.synced_at IS NULL OR t.synced_at < now() - interval '15 minutes')
		ORDER BY t.synced_at NULLS FIRST LIMIT 100`)
	if err != nil {
		return 0, err
	}
	type due struct {
		id, org, conn uuid.UUID
		key, ext      string
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (due, error) {
		var d due
		return d, r.Scan(&d.id, &d.org, &d.conn, &d.key, &d.ext)
	})
	if err != nil {
		return 0, err
	}
	conns := map[uuid.UUID]Conn{}
	n := 0
	for _, d := range list {
		c, ok := conns[d.conn]
		if !ok {
			if c, _, _, err = s.conn(ctx, s.DB, d.org, d.conn); err != nil {
				continue
			}
			conns[d.conn] = c
		}
		t, err := c.Status(ctx, Ticket{Key: d.key, ID: d.ext})
		msg := ""
		if err != nil {
			msg = logging.RedactString(err.Error())
			if len(msg) > 500 {
				msg = msg[:500]
			}
		}
		if _, err := s.DB.Exec(ctx, `UPDATE finding_tickets SET remote_status = CASE WHEN $2 = '' THEN remote_status ELSE $2 END,
			remote_done = $3, sync_error = $4, synced_at = now() WHERE id = $1`, d.id, t.Status, t.Done, msg); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// connClient applies the network policy and the connection's private CA
// bundle (added to the system trust store; verification stays on, TLS 1.2
// minimum). A stored bundle was validated on save; if it no longer parses,
// the system trust store is used, never an unverified connection.
func connClient(allowPrivate bool, caBundle string) *http.Client {
	pol := scm.NetPolicy{AllowPrivate: allowPrivate, OrgChosen: true}
	c, err := pol.ClientWithCA(caBundle)
	if err != nil {
		return pol.Client()
	}
	return c
}

package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/logging"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

// Outbound webhooks: every notification event can also be POSTed to
// administrator-configured endpoints, as signed JSON or as a Slack or
// Microsoft Teams message. Deliveries are queued with the event and retried
// with back-off. Nothing is sent until an endpoint is configured.

// WebhookFormats are the payload formats.
var WebhookFormats = []string{"json", "slack", "teams"}

// webhookBackoff is the wait before each retry (6 attempts in total).
var webhookBackoff = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour}

// Webhook is an endpoint as returned by the API (the URL is never shown
// again after creation; only its host).
type Webhook struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	Format       string    `json:"format"`
	Host         string    `json:"host"`
	Signed       bool      `json:"signed"`
	Events       []string  `json:"events"`
	MinSeverity  *string   `json:"min_severity"`
	AllowPrivate bool      `json:"allow_private"`
	Enabled      bool      `json:"enabled"`
	// CABundlePEM is the private CA bundle added to the system trust store
	// for this endpoint ("" = system trust store only).
	CABundlePEM    string       `json:"ca_bundle_pem"`
	CACertificates []scm.CACert `json:"ca_certificates"`
	CreatedAt      time.Time    `json:"created_at"`
	LastStatus     *string      `json:"last_status"`
	LastAt         *time.Time   `json:"last_delivery_at"`
	Failed24h      int          `json:"failed_24h"`
	// TriggerAuth (Teams): the Microsoft Entra app used for Workflows
	// triggers restricted to the tenant (the client secret is never
	// returned); null when the trigger is open to anyone.
	TriggerAuth *TriggerAuth `json:"trigger_auth"`
}

const webhookSelect = `SELECT w.id, w.name, w.format, w.url_host, w.signing_secret_id IS NOT NULL, w.events, w.min_severity, w.allow_private,
	w.enabled, w.ca_bundle_pem, w.created_at,
	(SELECT d.status FROM outbound_webhook_deliveries d WHERE d.endpoint_id = w.id AND d.status <> 'pending' ORDER BY d.created_at DESC LIMIT 1),
	(SELECT max(d.delivered_at) FROM outbound_webhook_deliveries d WHERE d.endpoint_id = w.id),
	(SELECT count(*) FROM outbound_webhook_deliveries d WHERE d.endpoint_id = w.id AND d.status = 'failed' AND d.created_at > now() - interval '24 hours'),
	CASE WHEN w.trigger_auth_secret_id IS NOT NULL THEN w.trigger_auth END
	FROM outbound_webhooks w`

func scanWebhook(r pgx.Row) (Webhook, error) {
	var w Webhook
	var ta []byte
	err := r.Scan(&w.ID, &w.Name, &w.Format, &w.Host, &w.Signed, &w.Events, &w.MinSeverity, &w.AllowPrivate, &w.Enabled, &w.CABundlePEM, &w.CreatedAt,
		&w.LastStatus, &w.LastAt, &w.Failed24h, &ta)
	if err == nil && len(ta) > 0 {
		var t TriggerAuth
		if json.Unmarshal(ta, &t) == nil && t.ClientID != "" {
			w.TriggerAuth = &t
		}
	}
	_, w.CACertificates, _ = scm.ParseCABundle(w.CABundlePEM, time.Now())
	if w.CACertificates == nil {
		w.CACertificates = []scm.CACert{}
	}
	return w, err
}

func (s *Service) registerWebhooks(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/notifications/webhooks", s.listWebhooks)
	mux.HandleFunc("POST /api/v1/notifications/webhooks", s.createWebhook)
	mux.HandleFunc("PUT /api/v1/notifications/webhooks/{id}", s.updateWebhook)
	mux.HandleFunc("DELETE /api/v1/notifications/webhooks/{id}", s.deleteWebhook)
	mux.HandleFunc("POST /api/v1/notifications/webhooks/{id}/test", s.testWebhook)
	mux.HandleFunc("GET /api/v1/notifications/webhooks/{id}/deliveries", s.webhookDeliveries)
}

type webhookInput struct {
	Name         string   `json:"name"`
	Format       string   `json:"format"`
	URL          string   `json:"url"`
	Events       []string `json:"events"`
	MinSeverity  *string  `json:"min_severity"`
	AllowPrivate bool     `json:"allow_private"`
	Enabled      *bool    `json:"enabled"`
	// Sign (json format): generate a signing secret, returned once. Slack
	// and Teams cannot verify signatures: the request is accepted with a
	// warning and the deliveries are not signed.
	Sign bool `json:"sign"`
	// TriggerAuth (teams format): authenticate to a Workflows trigger
	// restricted to the tenant. Omitted: unchanged; tenant_id "": removed.
	TriggerAuth *TriggerAuthInput `json:"trigger_auth"`
	// CABundlePEM: private CA bundle (PEM certificates). On update, absent
	// keeps the stored bundle and "" removes it.
	CABundlePEM *string `json:"ca_bundle_pem"`
}

// caBundleInput validates an optional CA bundle field.
func caBundleInput(v *string) (string, error) {
	if v == nil {
		return "", nil
	}
	b := strings.TrimSpace(*v)
	if _, _, err := scm.ParseCABundle(b, time.Now()); err != nil {
		return "", httpx.BadRequest("ca_bundle_pem: " + err.Error()).WithDiag(scm.DiagCABundleInvalid)
	}
	return b, nil
}

// signingWarning explains why a requested signature is not applied.
func signingWarning(in webhookInput) []string {
	if in.Sign && in.Format != "json" {
		return []string{"Signing is available only for the JSON format: Slack and Teams incoming webhooks cannot verify a signature, " +
			"so deliveries to this endpoint are not signed. Keep the webhook URL secret instead."}
	}
	return []string{}
}

func (in *webhookInput) validate(update bool) (*url.URL, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 120 {
		return nil, httpx.BadRequest("name is required (at most 120 characters)")
	}
	if !slices.Contains(WebhookFormats, in.Format) {
		return nil, httpx.BadRequest("format must be json, slack or teams")
	}
	if len(in.Events) == 0 || len(in.Events) > 50 {
		return nil, httpx.BadRequest("choose at least one event")
	}
	for _, e := range in.Events {
		if _, ok := LookupEvent(e); !ok || e == "smtp.test" {
			return nil, httpx.BadRequest("unknown event " + e)
		}
	}
	if in.MinSeverity != nil && !slices.Contains([]string{"critical", "high", "medium", "low", "info"}, *in.MinSeverity) {
		return nil, httpx.BadRequest("invalid min_severity")
	}
	if in.TriggerAuth != nil && strings.TrimSpace(in.TriggerAuth.TenantID) != "" && !triggerAuthAllowed(in.Format) {
		return nil, httpx.BadRequest("trigger_auth is only for the teams format")
	}
	if update && in.URL == "" {
		return nil, nil
	}
	u, err := url.Parse(strings.TrimSpace(in.URL))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(in.URL) > 2000 {
		return nil, httpx.BadRequest("url must be an https URL without credentials")
	}
	if in.Format == "teams" && RetiredTeamsHost(u.Hostname()) {
		return nil, httpx.BadRequest("Office 365 connector webhooks (webhook.office.com) were retired in May 2026: create a Workflows flow with " +
			"the trigger \"When a Teams webhook request is received\" and use its URL").WithDiag("PTH-CONN-1310")
	}
	if _, err := (scm.NetPolicy{AllowPrivate: in.AllowPrivate, OrgChosen: true}).ValidateBaseURL(u.Scheme + "://" + u.Host); err != nil {
		return nil, httpx.BadRequest("url: " + err.Error())
	}
	return u, nil
}

func (s *Service) listWebhooks(w http.ResponseWriter, r *http.Request) {
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), webhookSelect+` WHERE w.organization_id = $1 ORDER BY lower(w.name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Webhook, error) { return scanWebhook(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []Webhook{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func newSigningSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "whsec_" + base64.RawURLEncoding.EncodeToString(b)
}

func (s *Service) createWebhook(w http.ResponseWriter, r *http.Request) {
	p, err := s.admin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in webhookInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := in.validate(false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	caBundle, err := caBundleInput(in.CABundlePEM)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.Secrets == nil {
		s.fail(w, r, httpx.E(http.StatusConflict, "secrets_unavailable", "the secrets store is not configured"))
		return
	}
	id := uuid.Must(uuid.NewV7())
	enabled := in.Enabled == nil || *in.Enabled
	var signing string
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		urlID, err := s.Secrets.Create(r.Context(), tx, p.OrganizationID, secrets.KindIntegration, "webhook url: "+in.Name, []byte(u.String()), &p.UserID)
		if err != nil {
			return err
		}
		var signID *uuid.UUID
		if in.Sign && in.Format == "json" {
			signing = newSigningSecret()
			sid, err := s.Secrets.Create(r.Context(), tx, p.OrganizationID, secrets.KindIntegration, "webhook signing: "+in.Name, []byte(signing), &p.UserID)
			if err != nil {
				return err
			}
			signID = &sid
		}
		if _, err := tx.Exec(r.Context(), `INSERT INTO outbound_webhooks (id, organization_id, name, format, url_secret_id, url_host, signing_secret_id,
			events, min_severity, allow_private, enabled, created_by, ca_bundle_pem) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			id, p.OrganizationID, in.Name, in.Format, urlID, u.Host, signID, in.Events, in.MinSeverity, in.AllowPrivate, enabled, p.UserID, caBundle); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("a webhook with this name already exists")
			}
			return err
		}
		auth, err := s.saveTriggerAuth(r.Context(), tx, p.OrganizationID, id, p.UserID, in.Format, in.Name, in.TriggerAuth)
		if err != nil {
			return err
		}
		return s.auditWrite(r.Context(), tx, p, "webhook.create", "webhook", id.String(),
			map[string]any{"name": in.Name, "format": in.Format, "host": u.Host, "events": in.Events, "signed": signing != "", "allow_private": in.AllowPrivate,
				"trigger_auth": auth, "sign_requested": in.Sign, "ca_bundle": caBundle != ""})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	wh, err := scanWebhook(s.DB.QueryRow(r.Context(), webhookSelect+` WHERE w.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]any{"webhook": wh, "warnings": signingWarning(in)}
	if signing != "" {
		out["signing_secret"] = signing // shown once
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (s *Service) updateWebhook(w http.ResponseWriter, r *http.Request) {
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
	var in webhookInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := in.validate(true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	caBundle, err := caBundleInput(in.CABundlePEM)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		var urlID uuid.UUID
		var host string
		if err := tx.QueryRow(r.Context(), `SELECT url_secret_id, url_host FROM outbound_webhooks WHERE organization_id = $1 AND id = $2 FOR UPDATE`,
			p.OrganizationID, id).Scan(&urlID, &host); err != nil {
			return err
		}
		if u != nil {
			if err := s.Secrets.Update(r.Context(), tx, p.OrganizationID, urlID, secrets.KindIntegration, []byte(u.String())); err != nil {
				return err
			}
			host = u.Host
		} else if !in.AllowPrivate {
			// The stored URL must still pass with the (possibly stricter)
			// network policy.
			if _, err := (scm.NetPolicy{}).ValidateBaseURL("https://" + host); err != nil {
				return httpx.BadRequest("url: " + err.Error())
			}
		}
		enabled := in.Enabled == nil || *in.Enabled
		if _, err := tx.Exec(r.Context(), `UPDATE outbound_webhooks SET name = $3, format = $4, url_host = $5, events = $6, min_severity = $7,
			allow_private = $8, enabled = $9, ca_bundle_pem = CASE WHEN $10 THEN $11 ELSE ca_bundle_pem END, updated_at = now()
			WHERE organization_id = $1 AND id = $2`,
			p.OrganizationID, id, in.Name, in.Format, host, in.Events, in.MinSeverity, in.AllowPrivate, enabled, in.CABundlePEM != nil, caBundle); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("a webhook with this name already exists")
			}
			return err
		}
		auth, err := s.saveTriggerAuth(r.Context(), tx, p.OrganizationID, id, p.UserID, in.Format, in.Name, in.TriggerAuth)
		if err != nil {
			return err
		}
		return s.auditWrite(r.Context(), tx, p, "webhook.update", "webhook", id.String(),
			map[string]any{"name": in.Name, "format": in.Format, "host": host, "events": in.Events, "url_changed": u != nil, "enabled": enabled,
				"trigger_auth": auth, "ca_bundle_changed": in.CABundlePEM != nil})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	wh, err := scanWebhook(s.DB.QueryRow(r.Context(), webhookSelect+` WHERE w.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, wh)
}

func (s *Service) deleteWebhook(w http.ResponseWriter, r *http.Request) {
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
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		var name string
		var urlID uuid.UUID
		var signID, authID *uuid.UUID
		if err := tx.QueryRow(r.Context(), `DELETE FROM outbound_webhooks WHERE organization_id = $1 AND id = $2
			RETURNING name, url_secret_id, signing_secret_id, trigger_auth_secret_id`, p.OrganizationID, id).Scan(&name, &urlID, &signID, &authID); err != nil {
			return err
		}
		for _, sid := range []*uuid.UUID{&urlID, signID, authID} {
			if sid != nil {
				if err := s.Secrets.Delete(r.Context(), tx, p.OrganizationID, *sid); err != nil {
					return err
				}
			}
		}
		return s.auditWrite(r.Context(), tx, p, "webhook.delete", "webhook", id.String(), map[string]any{"name": name})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// WebhookDelivery is one delivery attempt record.
type WebhookDelivery struct {
	ID             uuid.UUID  `json:"id"`
	EventKey       string     `json:"event_key"`
	Status         string     `json:"status"`
	Attempts       int        `json:"attempts"`
	ResponseStatus *int       `json:"response_status"`
	Error          string     `json:"error"`
	CreatedAt      time.Time  `json:"created_at"`
	DeliveredAt    *time.Time `json:"delivered_at"`
	NextAttemptAt  time.Time  `json:"next_attempt_at"`
}

func (s *Service) webhookDeliveries(w http.ResponseWriter, r *http.Request) {
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
	var exists bool
	if err := s.DB.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM outbound_webhooks WHERE organization_id = $1 AND id = $2)`, p.OrganizationID, id).Scan(&exists); err != nil || !exists {
		s.fail(w, r, errNotFound)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT d.id, d.event_key, d.status, d.attempts, d.response_status, d.error, d.created_at, d.delivered_at, d.next_attempt_at
		FROM outbound_webhook_deliveries d WHERE d.organization_id = $1 AND d.endpoint_id = $2 ORDER BY d.created_at DESC LIMIT 100`, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[WebhookDelivery])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []WebhookDelivery{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// testWebhook sends a sample message now and reports the outcome.
func (s *Service) testWebhook(w http.ResponseWriter, r *http.Request) {
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
	ep, err := loadEndpoint(r.Context(), s.DB, s.Secrets, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := Sample("findings.new", s.BaseURL)
	d.Org = "PATHOS test"
	status, sendErr := sendWebhook(r.Context(), s.webhookClient(ep), ep, uuid.New(), "webhook.test", time.Now(), d)
	_ = s.auditWrite(r.Context(), s.DB, p, "webhook.test", "webhook", id.String(), map[string]any{"status": status, "ok": sendErr == nil})
	out := map[string]any{"ok": sendErr == nil, "status": status}
	if sendErr != nil {
		out["error"] = logging.RedactString(sendErr.Error())
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// HTTPOverride replaces the network-policy client (tests only).
var HTTPOverride *http.Client

func (s *Service) webhookClient(ep endpoint) *http.Client { return endpointClient(ep) }

// endpointClient applies the network policy and the endpoint's private CA
// bundle (added to the system trust store; verification stays on, TLS 1.2
// minimum).
func endpointClient(ep endpoint) *http.Client {
	if HTTPOverride != nil {
		return HTTPOverride
	}
	pol := scm.NetPolicy{AllowPrivate: ep.allowPrivate, OrgChosen: true}
	c, err := pol.ClientWithCA(ep.caBundle)
	if err != nil {
		// A stored bundle was validated on save; fall back to the system
		// trust store (never to an unverified connection).
		return pol.Client()
	}
	return c
}

type endpoint struct {
	id                   uuid.UUID
	format, url, signing string
	allowPrivate         bool
	caBundle             string
	// Teams trigger authentication (nil: open trigger, no header).
	trigger                   *TriggerAuth
	triggerSecret, triggerKey string
}

func loadEndpoint(ctx context.Context, q db.Querier, store *secrets.Store, orgID, id uuid.UUID) (endpoint, error) {
	ep := endpoint{id: id}
	var urlID uuid.UUID
	var signID *uuid.UUID
	if err := q.QueryRow(ctx, `SELECT format, url_secret_id, signing_secret_id, allow_private, ca_bundle_pem FROM outbound_webhooks WHERE organization_id = $1 AND id = $2`,
		orgID, id).Scan(&ep.format, &urlID, &signID, &ep.allowPrivate, &ep.caBundle); err != nil {
		return ep, err
	}
	if store == nil {
		return ep, errors.New("secrets store not configured")
	}
	u, err := store.Reveal(ctx, q, orgID, urlID, secrets.KindIntegration)
	if err != nil {
		return ep, err
	}
	ep.url = string(u)
	if signID != nil {
		sig, err := store.Reveal(ctx, q, orgID, *signID, secrets.KindIntegration)
		if err != nil {
			return ep, err
		}
		ep.signing = string(sig)
	}
	if ep.format == "teams" {
		if err := loadTriggerAuth(ctx, q, store, orgID, id, &ep); err != nil {
			return ep, err
		}
	}
	return ep, nil
}

// enqueueWebhooks queues deliveries of an event to the subscribed
// endpoints (same transaction as the event's processing).
func enqueueWebhooks(ctx context.Context, tx pgx.Tx, ev eventRow) error {
	_, err := tx.Exec(ctx, `INSERT INTO outbound_webhook_deliveries (organization_id, endpoint_id, event_id, event_key)
		SELECT w.organization_id, w.id, $3, $2 FROM outbound_webhooks w
		WHERE w.organization_id = $1 AND w.enabled AND $2 = ANY(w.events)
		  AND (w.min_severity IS NULL OR $4::text IS NULL OR
		       array_position(ARRAY['critical','high','medium','low','info'], $4::text) <= array_position(ARRAY['critical','high','medium','low','info'], w.min_severity))
		ON CONFLICT (endpoint_id, event_id) DO NOTHING`, ev.OrgID, ev.Key, ev.ID, ev.Severity)
	return err
}

// webhookPayload builds the body for a format.
func webhookPayload(format string, deliveryID uuid.UUID, key string, at time.Time, d *Data) ([]byte, error) {
	label := d.EventLabel
	if label == "" {
		label = key
	}
	subject := label
	if def, ok := LookupEvent(key); ok && def.Subject != "" {
		if s, _, err := Render(def.Subject, "", d); err == nil && s != "" {
			subject = strings.TrimPrefix(s, "[PATHOS] ")
		}
	}
	type item struct {
		ID       string `json:"id,omitempty"`
		Title    string `json:"title"`
		Severity string `json:"severity,omitempty"`
		Location string `json:"location,omitempty"`
	}
	var items []item
	for _, f := range d.Findings {
		items = append(items, item{ID: f.ID, Title: f.Title, Severity: f.Severity, Location: f.Location})
	}
	switch format {
	case "slack":
		text := "*" + slackEscape(subject) + "*"
		for _, it := range items {
			text += "\n• [" + it.Severity + "] " + slackEscape(it.Title)
		}
		if d.More > 0 {
			text += "\n…and " + strconv.Itoa(d.More) + " more"
		}
		if d.Link != "" {
			text += "\n<" + d.Link + "|Open in PATHOS>"
		}
		return json.Marshal(map[string]any{"text": text, "unfurl_links": false})
	case "teams":
		body := []map[string]any{{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": true, "text": subject}}
		for _, it := range items {
			body = append(body, map[string]any{"type": "TextBlock", "wrap": true, "spacing": "Small", "text": "[" + it.Severity + "] " + it.Title})
		}
		card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body}
		if d.Link != "" {
			card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Open in PATHOS", "url": d.Link}}
		}
		return json.Marshal(map[string]any{"type": "message", "attachments": []map[string]any{
			{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}}})
	}
	out := map[string]any{"id": deliveryID, "event": key, "event_label": label, "occurred_at": at.UTC().Format(time.RFC3339),
		"summary": subject, "organization": d.Org, "link": d.Link, "count": d.Count, "findings": items}
	if d.Repository != "" {
		out["repository"] = d.Repository
	}
	if d.Severity != "" {
		out["severity"] = d.Severity
	}
	if d.Policy != "" {
		out["policy"] = d.Policy
	}
	if d.Scan.ID != "" {
		scan := map[string]any{"id": d.Scan.ID, "trigger": d.Scan.Trigger, "new": d.Scan.New, "fixed": d.Scan.Fixed, "gate_failed": d.Scan.GateFailed}
		if c := d.Scan.Changes; c != nil {
			scan["changes"] = map[string]any{"base_commit": c.BaseCommit, "head_commit": c.HeadCommit, "new": c.New, "fixed": c.Fixed,
				"new_total": c.NewTotal, "fixed_total": c.FixedTotal}
		}
		out["scan"] = scan
	}
	return json.Marshal(out)
}

func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// Signature computes the X-PATHOS-Signature value: HMAC-SHA256 of
// "<timestamp>.<body>" with the endpoint's signing secret.
func Signature(secret, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(timestamp + "."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func sendWebhook(ctx context.Context, c *http.Client, ep endpoint, deliveryID uuid.UUID, key string, at time.Time, d *Data) (int, error) {
	body, err := webhookPayload(ep.format, deliveryID, key, at, d)
	if err != nil {
		return 0, err
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, ep.url, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("invalid webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PATHOS-Webhooks")
	if ep.trigger != nil {
		tok, err := entraToken(ctx, c, *ep.trigger, ep.triggerSecret, ep.triggerKey)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if ep.format == "json" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("X-PATHOS-Event", key)
		req.Header.Set("X-PATHOS-Delivery", deliveryID.String())
		req.Header.Set("X-PATHOS-Timestamp", ts)
		if ep.signing != "" {
			req.Header.Set("X-PATHOS-Signature", Signature(ep.signing, ts, body))
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		// Never echo the URL (it can carry a token).
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, scm.WithCAHint(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if ep.format == "teams" && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			if ep.trigger == nil {
				return resp.StatusCode, fmt.Errorf("HTTP %d: the Workflows trigger requires authentication; configure trigger authentication (Microsoft Entra app)", resp.StatusCode)
			}
			return resp.StatusCode, fmt.Errorf("HTTP %d: the Workflows trigger refused the Entra token (check the allowed users and the audience)", resp.StatusCode)
		}
		return resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

// SendWebhooks delivers due webhook deliveries (up to 50 per call).
func (d *Dispatcher) SendWebhooks(ctx context.Context) (sent, failed int, err error) {
	for range 50 {
		done, ok, err := d.sendOneWebhook(ctx)
		if err != nil || !done {
			return sent, failed, err
		}
		if ok {
			sent++
		} else {
			failed++
		}
	}
	return sent, failed, nil
}

func (d *Dispatcher) sendOneWebhook(ctx context.Context) (done, ok bool, err error) {
	err = db.InTx(ctx, d.Pool, func(tx pgx.Tx) error {
		var id, orgID, endpointID uuid.UUID
		var eventID *uuid.UUID
		var key string
		var attempts int
		var created time.Time
		err := tx.QueryRow(ctx, `SELECT id, organization_id, endpoint_id, event_id, event_key, attempts, created_at FROM outbound_webhook_deliveries
			WHERE status = 'pending' AND next_attempt_at <= now() ORDER BY next_attempt_at LIMIT 1 FOR UPDATE SKIP LOCKED`).
			Scan(&id, &orgID, &endpointID, &eventID, &key, &attempts, &created)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		done = true
		ep, err := loadEndpoint(ctx, tx, d.Secrets, orgID, endpointID)
		var status int
		var sendErr error
		if err != nil {
			sendErr = err
		} else {
			var data *Data
			if eventID != nil {
				ev := eventRow{ID: *eventID}
				var payload []byte
				if qerr := tx.QueryRow(ctx, `SELECT organization_id, event_key, repository_id, severity, subject_id, payload, created_at
					FROM notification_events WHERE id = $1`, *eventID).Scan(&ev.OrgID, &ev.Key, &ev.Repository, &ev.Severity, &ev.SubjectID, &payload, &ev.CreatedAt); qerr == nil {
					_ = json.Unmarshal(payload, &ev.Payload)
					var lerr error
					if data, lerr = load(ctx, tx, ev, d.BaseURL); lerr != nil {
						// The event is still delivered, with what is known.
						d.Log.Warn("webhook event details unavailable", "event_id", ev.ID, "err", lerr)
						data = nil
					}
				}
			}
			if data == nil {
				data = &Data{BaseURL: d.BaseURL, Event: key}
				if def, ok := LookupEvent(key); ok {
					data.EventLabel = def.Label
				}
			}
			status, sendErr = sendWebhook(ctx, endpointClient(ep), ep, id, key, created, data)
		}
		attempts++
		var st *int
		if status > 0 {
			st = &status
		}
		if sendErr == nil {
			ok = true
			_, err = tx.Exec(ctx, `UPDATE outbound_webhook_deliveries SET status = 'succeeded', attempts = $2, response_status = $3, error = '', delivered_at = now()
				WHERE id = $1`, id, attempts, st)
			return err
		}
		msg := logging.RedactString(sendErr.Error())
		if len(msg) > 1000 {
			msg = msg[:1000]
		}
		if attempts > len(webhookBackoff) || (status >= 400 && status < 500 && status != 408 && status != 429) {
			// Exhausted, or a client error retrying will not fix.
			d.Log.Warn("outbound webhook delivery failed", "delivery_id", id, "response_status", status, "err", msg, "error_code", "PTH-SYNC-1005")
			_, err = tx.Exec(ctx, `UPDATE outbound_webhook_deliveries SET status = 'failed', attempts = $2, response_status = $3, error = $4 WHERE id = $1`,
				id, attempts, st, msg)
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE outbound_webhook_deliveries SET attempts = $2, response_status = $3, error = $4, next_attempt_at = now() + $5::interval
			WHERE id = $1`, id, attempts, st, msg, webhookBackoff[attempts-1].String())
		return err
	})
	return done, ok, err
}

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/secrets"
)

// Microsoft Teams Workflows trigger authentication.
//
// Office 365 connector webhooks were retired in May 2026; Teams messages
// now go to a Power Automate Workflows flow with the trigger "When a Teams
// webhook request is received". Its "Who can trigger the flow" setting is
// Anyone (no authentication header may be sent), Any user in my tenant, or
// Specific users in my tenant (object IDs of service principals allowed).
// The two restricted modes need an OAuth bearer token from Microsoft Entra
// whose aud claim is the flow service ("https://service.flow.microsoft.com/"
// in the public cloud, matched exactly including the trailing slash) and
// whose tid (and, for specific users, oid) identify the caller. Microsoft
// documents no signature or shared-secret header for this trigger.
//
// PATHOS obtains that token with the client credentials grant of a
// Microsoft Entra app registration (tenant ID, client ID, client secret)
// and sends it as "Authorization: Bearer". Sources (checked 2026-11-20):
// https://learn.microsoft.com/en-us/connectors/teams/ (trigger
// TeamsIncomingWebhookTrigger, triggerAuthenticationType) and
// https://learn.microsoft.com/en-us/power-automate/oauth-authentication
// (required claims and audience values).

// TeamsAudiences are the flow service audiences per cloud, with the Entra
// authority host of each cloud.
var TeamsAudiences = map[string]string{
	"https://service.flow.microsoft.com/":     "https://login.microsoftonline.com", // public cloud
	"https://gov.service.flow.microsoft.us/":  "https://login.microsoftonline.com", // GCC
	"https://high.service.flow.microsoft.us/": "https://login.microsoftonline.us",  // GCC High
	"https://service.flow.appsplatform.us/":   "https://login.microsoftonline.us",  // DoD
	"https://service.powerautomate.cn/":       "https://login.chinacloudapi.cn",    // China
}

// DefaultTeamsAudience is the public cloud audience.
const DefaultTeamsAudience = "https://service.flow.microsoft.com/"

// EntraAuthorityOverride replaces the Entra authority host (tests only).
var EntraAuthorityOverride string

// TriggerAuth is the non-secret part of a Teams trigger authentication.
type TriggerAuth struct {
	TenantID string `json:"tenant_id"`
	ClientID string `json:"client_id"`
	Audience string `json:"audience"`
}

// TriggerAuthInput is the API input (the client secret is write-only).
type TriggerAuthInput struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
}

var (
	guidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	tenantRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`) // GUID or verified domain
)

func (in *TriggerAuthInput) validate(hadSecret bool) error {
	in.TenantID, in.ClientID, in.Audience = strings.TrimSpace(in.TenantID), strings.TrimSpace(in.ClientID), strings.TrimSpace(in.Audience)
	if in.Audience == "" {
		in.Audience = DefaultTeamsAudience
	}
	switch {
	case !tenantRe.MatchString(in.TenantID):
		return httpx.BadRequest("trigger_auth.tenant_id must be the Microsoft Entra tenant ID or domain")
	case !guidRe.MatchString(in.ClientID):
		return httpx.BadRequest("trigger_auth.client_id must be the application (client) ID of the Entra app registration")
	case TeamsAudiences[in.Audience] == "":
		return httpx.BadRequest("trigger_auth.audience must be one of the flow service audiences (for example " + DefaultTeamsAudience + ")")
	case in.ClientSecret == "" && !hadSecret:
		return httpx.BadRequest("trigger_auth.client_secret is required")
	case len(in.ClientSecret) > 1000:
		return httpx.BadRequest("trigger_auth.client_secret is too long")
	}
	return nil
}

// ErrTriggerToken means the Entra token for a Teams trigger could not be
// obtained (wrong tenant, client ID or secret, or an expired secret).
var ErrTriggerToken = errors.New("microsoft entra token request failed")

type cachedToken struct {
	token   string
	expires time.Time
}

var (
	tokenMu    sync.Mutex
	tokenCache = map[string]cachedToken{}
)

// entraToken returns a bearer token for the Workflows trigger (client
// credentials grant), cached until shortly before it expires. The cache key
// includes a hash-free identity of the app and the secret's row id, so a
// rotated secret gets a new token.
func entraToken(ctx context.Context, c *http.Client, ta TriggerAuth, secret, cacheKey string) (string, error) {
	tokenMu.Lock()
	if t, ok := tokenCache[cacheKey]; ok && time.Until(t.expires) > 2*time.Minute {
		tokenMu.Unlock()
		return t.token, nil
	}
	tokenMu.Unlock()
	authority := TeamsAudiences[ta.Audience]
	if EntraAuthorityOverride != "" {
		authority = EntraAuthorityOverride
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {ta.ClientID},
		"client_secret": {secret},
		// v2 scope of a resource whose ID ends in "/": "<resource>/.default"
		// (hence the double slash).
		"scope": {ta.Audience + "/.default"},
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, authority+"/"+url.PathEscape(ta.TenantID)+"/oauth2/v2.0/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", ErrTriggerToken
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("%w: %w", ErrTriggerToken, err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Codes       []int  `json:"error_codes"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		// Only the OAuth error code and AADSTS numbers: never the
		// description (it can echo the client ID and tenant details).
		msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if out.Error != "" {
			msg += " " + out.Error
		}
		if len(out.Codes) > 0 {
			msg += fmt.Sprintf(" (AADSTS%d)", out.Codes[0])
		}
		return "", fmt.Errorf("%w: %s", ErrTriggerToken, msg)
	}
	exp := time.Now().Add(time.Duration(max(out.ExpiresIn, 60)) * time.Second)
	tokenMu.Lock()
	tokenCache[cacheKey] = cachedToken{token: out.AccessToken, expires: exp}
	tokenMu.Unlock()
	return out.AccessToken, nil
}

// loadTriggerAuth reads a Teams endpoint's trigger authentication.
func loadTriggerAuth(ctx context.Context, q db.Querier, store *secrets.Store, orgID, id uuid.UUID, ep *endpoint) error {
	var raw []byte
	var sid *uuid.UUID
	if err := q.QueryRow(ctx, `SELECT trigger_auth, trigger_auth_secret_id FROM outbound_webhooks WHERE organization_id = $1 AND id = $2`,
		orgID, id).Scan(&raw, &sid); err != nil {
		return err
	}
	if sid == nil {
		return nil
	}
	var ta TriggerAuth
	if err := json.Unmarshal(raw, &ta); err != nil || ta.ClientID == "" {
		return nil
	}
	sec, err := store.Reveal(ctx, q, orgID, *sid, secrets.KindIntegration)
	if err != nil {
		return err
	}
	ep.trigger, ep.triggerSecret, ep.triggerKey = &ta, string(sec), sid.String()+":"+ta.TenantID+":"+ta.ClientID+":"+ta.Audience
	return nil
}

// saveTriggerAuth applies trigger_auth of a create or update (Teams only):
// nil keeps the current setting, an empty tenant_id removes it.
func (s *Service) saveTriggerAuth(ctx context.Context, tx pgx.Tx, orgID, id uuid.UUID, by uuid.UUID, format, name string, in *TriggerAuthInput) (bool, error) {
	var sid *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT trigger_auth_secret_id FROM outbound_webhooks WHERE organization_id = $1 AND id = $2`, orgID, id).Scan(&sid); err != nil {
		return false, err
	}
	remove := format != "teams" || (in != nil && strings.TrimSpace(in.TenantID) == "")
	if in == nil && !remove {
		return sid != nil, nil
	}
	if remove {
		if sid == nil {
			return false, nil
		}
		if _, err := tx.Exec(ctx, `UPDATE outbound_webhooks SET trigger_auth = '{}', trigger_auth_secret_id = NULL WHERE id = $1`, id); err != nil {
			return false, err
		}
		return false, s.Secrets.Delete(ctx, tx, orgID, *sid)
	}
	if err := in.validate(sid != nil); err != nil {
		return false, err
	}
	if in.ClientSecret != "" {
		if sid != nil {
			if err := s.Secrets.Update(ctx, tx, orgID, *sid, secrets.KindIntegration, []byte(in.ClientSecret)); err != nil {
				return false, err
			}
		} else {
			n, err := s.Secrets.Create(ctx, tx, orgID, secrets.KindIntegration, "teams trigger auth: "+name, []byte(in.ClientSecret), &by)
			if err != nil {
				return false, err
			}
			sid = &n
		}
	}
	raw, _ := json.Marshal(TriggerAuth{TenantID: in.TenantID, ClientID: in.ClientID, Audience: in.Audience})
	_, err := tx.Exec(ctx, `UPDATE outbound_webhooks SET trigger_auth = $2, trigger_auth_secret_id = $3 WHERE id = $1`, id, raw, sid)
	return true, err
}

// WebhookHealth is the health view of an outbound webhook. Nothing is
// posted: a webhook has no read-only endpoint, so the state comes from the
// recorded deliveries, plus, for a Teams trigger with authentication, a
// real token request to Microsoft Entra.
type WebhookHealth struct {
	Format       string
	Host         string
	Enabled      bool
	LastStatus   string // succeeded | failed | "" (nothing delivered yet)
	LastAt       *time.Time
	LastResponse int
	Failed24h    int
	TriggerAuth  bool
	// TriggerAuthErr is the token request's error (nil when it worked or
	// is not configured).
	TriggerAuthErr error
}

// CheckWebhook reports a webhook's health without sending a message.
func (s *Service) CheckWebhook(ctx context.Context, orgID, id uuid.UUID) (WebhookHealth, error) {
	var h WebhookHealth
	var resp *int
	if err := s.DB.QueryRow(ctx, `SELECT w.format, w.url_host, w.enabled,
		  COALESCE((SELECT d.status FROM outbound_webhook_deliveries d WHERE d.endpoint_id = w.id AND d.status IN ('succeeded', 'failed')
		    ORDER BY COALESCE(d.delivered_at, d.created_at) DESC LIMIT 1), ''),
		  (SELECT COALESCE(d.delivered_at, d.created_at) FROM outbound_webhook_deliveries d WHERE d.endpoint_id = w.id AND d.status IN ('succeeded', 'failed')
		    ORDER BY COALESCE(d.delivered_at, d.created_at) DESC LIMIT 1),
		  (SELECT d.response_status FROM outbound_webhook_deliveries d WHERE d.endpoint_id = w.id AND d.status IN ('succeeded', 'failed')
		    ORDER BY COALESCE(d.delivered_at, d.created_at) DESC LIMIT 1),
		  (SELECT count(*) FROM outbound_webhook_deliveries d WHERE d.endpoint_id = w.id AND d.status = 'failed' AND d.created_at > now() - interval '24 hours')
		FROM outbound_webhooks w WHERE w.organization_id = $1 AND w.id = $2`, orgID, id).
		Scan(&h.Format, &h.Host, &h.Enabled, &h.LastStatus, &h.LastAt, &resp, &h.Failed24h); err != nil {
		return h, err
	}
	if resp != nil {
		h.LastResponse = *resp
	}
	if h.Format != "teams" {
		return h, nil
	}
	var ep endpoint
	if err := loadTriggerAuth(ctx, s.DB, s.Secrets, orgID, id, &ep); err != nil {
		return h, err
	}
	if ep.trigger != nil {
		h.TriggerAuth = true
		_, h.TriggerAuthErr = entraToken(ctx, s.webhookClient(endpoint{allowPrivate: false}), *ep.trigger, ep.triggerSecret, ep.triggerKey)
	}
	return h, nil
}

// RetiredTeamsHost reports a host of the retired Office 365 connector
// webhooks (they no longer accept messages since May 2026).
func RetiredTeamsHost(host string) bool {
	h := strings.ToLower(host)
	return h == "outlook.office.com" || h == "outlook.office365.com" || strings.HasSuffix(h, ".webhook.office.com") || h == "webhook.office.com"
}

// webhookFormatsWithAuth are the formats that accept trigger_auth.
var webhookFormatsWithAuth = []string{"teams"}

func triggerAuthAllowed(format string) bool { return slices.Contains(webhookFormatsWithAuth, format) }

// SMTPHealth is what the SMTP probe reports.
type SMTPHealth struct {
	Configured bool // a host is set
	Enabled    bool
	TLSMode    string
	Host       string
	Port       int
	Auth       bool // credentials are set (and AUTH succeeded when err is nil)
}

// SMTPProbe overrides the SMTP sender of ProbeSMTP (tests).
var SMTPProbe SMTPSender

// ProbeSMTP checks the organization's mail relay without sending a message
// (connect, EHLO, STARTTLS or TLS, AUTH, QUIT).
func (s *Service) ProbeSMTP(ctx context.Context, orgID uuid.UUID) (SMTPHealth, error) {
	var h SMTPHealth
	var cfg SMTPConfig
	var secretID *uuid.UUID
	err := s.DB.QueryRow(ctx, `SELECT enabled, host, port, tls_mode, username, secret_id FROM smtp_settings WHERE organization_id = $1`, orgID).
		Scan(&h.Enabled, &cfg.Host, &cfg.Port, &cfg.TLSMode, &cfg.Username, &secretID)
	if errors.Is(err, pgx.ErrNoRows) {
		return h, nil
	}
	if err != nil {
		return h, err
	}
	h.Configured, h.TLSMode, h.Host, h.Port, h.Auth = cfg.Host != "", cfg.TLSMode, cfg.Host, cfg.Port, cfg.Username != ""
	if !h.Configured || !h.Enabled {
		return h, nil
	}
	if secretID != nil {
		pw, err := s.Secrets.Reveal(ctx, s.DB, orgID, *secretID, secrets.KindSMTP)
		if err != nil {
			return h, err
		}
		cfg.Password = string(pw)
	}
	return h, SMTPProbe.Probe(ctx, cfg)
}

package connectors

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
)

// sourceRow is one live connection of a legacy table, with non-secret
// metadata only. Nothing here is copied into the registry except the key.
type sourceRow struct {
	Kind       string
	Table      string
	Key        string
	Name       string
	Enabled    bool
	LastSyncAt *time.Time
	Meta       map[string]string
}

// Singleton keys and source tables that are not database tables.
const (
	tableObjectStore = "installation_object_store"
	tableEgressProxy = "installation_egress_proxy"
)

// legacyTables are the tables reconciled into the registry.
var legacyTables = []string{"scm_connections", "ticket_connections", "outbound_webhooks", "runtime_clusters", "registry_connections",
	"ai_providers", "smtp_settings", "intel_feeds", "secret_validation_settings", tableObjectStore, tableEgressProxy}

// SCM API versions PATHOS uses (shown as metadata).
var scmAPIVersion = map[string]string{
	"github": "REST 2022-11-28", "github_enterprise": "REST 2022-11-28", "gitlab": "REST v4", "bitbucket": "REST 2.0",
	"azure_devops": "REST 7.1", "azure_devops_server": "REST 7.1",
}

var feedNames = map[string]string{"epss": "EPSS (FIRST)", "kev": "CISA KEV", "osv": "OSV.dev records", "endoflife": "endoflife.date"}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// listSources reads every legacy connection of the organization.
func listSources(ctx context.Context, q db.Querier, env *Env, orgID uuid.UUID) ([]sourceRow, error) {
	var out []sourceRow
	collect := func(sql string, scan func(pgx.Rows) (sourceRow, error), args ...any) error {
		rows, err := q.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scan(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	}

	if err := collect(`SELECT id, name, provider, base_url, auth_type, last_synced_at, webhook_signing_secret_id IS NOT NULL, token_expires_at,
		COALESCE(ca_bundle_pem, '') <> ''
		FROM scm_connections WHERE organization_id = $1 AND archived_at IS NULL`, func(r pgx.Rows) (sourceRow, error) {
		var id uuid.UUID
		var name, provider, base, auth string
		var synced, expires *time.Time
		var signed, ca bool
		err := r.Scan(&id, &name, &provider, &base, &auth, &synced, &signed, &expires, &ca)
		// ca_bundle_set: whether the connection has a private CA bundle (the
		// PEM and its certificates stay on the SCM connection).
		meta := map[string]string{"host": HostOf(base), "auth_method": auth, "api_version": scmAPIVersion[provider], "ca_bundle_set": yesNo(ca)}
		if provider == "gitlab" {
			meta["webhook_verification"] = map[bool]string{true: "signature", false: "token (legacy)"}[signed]
		}
		if expires != nil {
			meta["credential_expires_at"] = expires.UTC().Format(time.RFC3339)
		}
		return sourceRow{Kind: provider, Table: "scm_connections", Key: id.String(), Name: name, Enabled: true, LastSyncAt: synced, Meta: meta}, err
	}, orgID); err != nil {
		return nil, err
	}

	if err := collect(`SELECT c.id, c.kind, c.name, c.base_url, c.auth_type, c.allow_private, c.enabled, c.config,
		(SELECT max(t.synced_at) FROM finding_tickets t WHERE t.connection_id = c.id)
		FROM ticket_connections c WHERE c.organization_id = $1`, func(r pgx.Rows) (sourceRow, error) {
		var id uuid.UUID
		var kind, name, base, auth string
		var private, enabled bool
		var cfg []byte
		var synced *time.Time
		err := r.Scan(&id, &kind, &name, &base, &auth, &private, &enabled, &cfg, &synced)
		meta := map[string]string{"host": HostOf(base), "auth_method": auth, "allow_private": yesNo(private)}
		var c struct {
			TokenType string `json:"token_type"`
			Table     string `json:"table"`
		}
		_ = json.Unmarshal(cfg, &c)
		if kind == "jira" {
			meta["api_version"] = "REST v2"
			meta["token_type"] = map[bool]string{true: "scoped (Atlassian API gateway)", false: "unscoped (site URL)"}[c.TokenType == "scoped"]
		} else {
			meta["api_version"] = "Table API"
			meta["table"] = c.Table
		}
		return sourceRow{Kind: kind, Table: "ticket_connections", Key: id.String(), Name: name, Enabled: enabled, LastSyncAt: synced, Meta: meta}, err
	}, orgID); err != nil {
		return nil, err
	}

	if err := collect(`SELECT w.id, w.format, w.name, w.url_host, w.signing_secret_id IS NOT NULL, w.trigger_auth_secret_id IS NOT NULL, w.allow_private, w.enabled,
		(SELECT max(d.delivered_at) FROM outbound_webhook_deliveries d WHERE d.endpoint_id = w.id)
		FROM outbound_webhooks w WHERE w.organization_id = $1`, func(r pgx.Rows) (sourceRow, error) {
		var id uuid.UUID
		var format, name, host string
		var signed, auth, private, enabled bool
		var last *time.Time
		err := r.Scan(&id, &format, &name, &host, &signed, &auth, &private, &enabled, &last)
		kind := map[string]string{"json": "webhook", "slack": "slack", "teams": "teams"}[format]
		meta := map[string]string{"host": "https://" + host, "format": format, "allow_private": yesNo(private)}
		switch format {
		case "json":
			meta["signed"] = yesNo(signed)
		case "teams":
			meta["trigger_auth"] = map[bool]string{true: "Microsoft Entra app", false: "none (trigger open to anyone)"}[auth]
		}
		return sourceRow{Kind: kind, Table: "outbound_webhooks", Key: id.String(), Name: name, Enabled: enabled, LastSyncAt: last, Meta: meta}, err
	}, orgID); err != nil {
		return nil, err
	}

	if err := collect(`SELECT id, name, api_server, auth_type, allow_private, enabled, last_sync_at, cardinality(namespaces), ca_cert <> ''
		FROM runtime_clusters WHERE organization_id = $1`, func(r pgx.Rows) (sourceRow, error) {
		var id uuid.UUID
		var name, server, auth string
		var private, enabled, ca bool
		var last *time.Time
		var ns int
		err := r.Scan(&id, &name, &server, &auth, &private, &enabled, &last, &ns, &ca)
		meta := map[string]string{"host": HostOf(server), "auth_method": auth, "allow_private": yesNo(private), "namespaces": "all"}
		if ns > 0 {
			meta["namespaces"] = strconv.Itoa(ns)
		}
		if auth == "token" {
			meta["ca_bundle"] = yesNo(ca)
		}
		return sourceRow{Kind: "kubernetes", Table: "runtime_clusters", Key: id.String(), Name: name, Enabled: enabled, LastSyncAt: last, Meta: meta}, err
	}, orgID); err != nil {
		return nil, err
	}

	if err := collect(`SELECT id, name, base_url, auth_type, allow_private, enabled, last_sync_at, cardinality(repositories)
		FROM registry_connections WHERE organization_id = $1`, func(r pgx.Rows) (sourceRow, error) {
		var id uuid.UUID
		var name, base, auth string
		var private, enabled bool
		var last *time.Time
		var repos int
		err := r.Scan(&id, &name, &base, &auth, &private, &enabled, &last, &repos)
		meta := map[string]string{"host": HostOf(base), "auth_method": auth, "allow_private": yesNo(private), "repositories": strconv.Itoa(repos),
			"api_version": "OCI Distribution v2"}
		return sourceRow{Kind: "container_registry", Table: "registry_connections", Key: id.String(), Name: name, Enabled: enabled, LastSyncAt: last, Meta: meta}, err
	}, orgID); err != nil {
		return nil, err
	}

	if err := collect(`SELECT id, name, kind, base_url FROM ai_providers WHERE organization_id = $1 AND archived_at IS NULL`, func(r pgx.Rows) (sourceRow, error) {
		var id uuid.UUID
		var name, kind, base string
		err := r.Scan(&id, &name, &kind, &base)
		host := HostOf(base)
		if host == "" {
			host = map[string]string{"anthropic": "https://api.anthropic.com", "openai": "https://api.openai.com", "xai": "https://api.x.ai"}[kind]
		}
		meta := map[string]string{"provider": kind, "host": host}
		return sourceRow{Kind: "ai_provider", Table: "ai_providers", Key: id.String(), Name: name, Enabled: true, Meta: meta}, err
	}, orgID); err != nil {
		return nil, err
	}

	// One mail relay per organization (a row exists only once configured).
	smtp := sourceRow{Kind: "smtp", Table: "smtp_settings", Key: "", Name: "E-mail (SMTP relay)", Meta: map[string]string{}}
	var host, tlsMode, user string
	var port int
	var enabled bool
	switch err := q.QueryRow(ctx, `SELECT enabled, host, port, tls_mode, username FROM smtp_settings WHERE organization_id = $1`, orgID).
		Scan(&enabled, &host, &port, &tlsMode, &user); {
	case err == nil:
		smtp.Enabled = enabled && host != ""
		smtp.Meta = map[string]string{"host": host, "port": strconv.Itoa(port), "tls_mode": tlsMode, "auth": yesNo(user != "")}
	case err != pgx.ErrNoRows:
		return nil, err
	}
	smtp.LastSyncAt = nil
	var lastMail *time.Time
	if err := q.QueryRow(ctx, `SELECT max(sent_at) FROM notifications WHERE organization_id = $1 AND channel = 'email' AND status = 'sent'`, orgID).Scan(&lastMail); err == nil {
		smtp.LastSyncAt = lastMail
	}
	out = append(out, smtp)

	// Vulnerability feeds are installation-wide data; every organization
	// sees their state.
	if err := collect(`SELECT f.feed, f.enabled, f.interval_hours, f.url,
		(SELECT max(r.finished_at) FROM intel_feed_runs r WHERE r.feed = f.feed AND r.status = 'succeeded')
		FROM intel_feeds f ORDER BY f.feed`, func(r pgx.Rows) (sourceRow, error) {
		var feed, u string
		var enabled bool
		var interval int
		var last *time.Time
		err := r.Scan(&feed, &enabled, &interval, &u, &last)
		name := feedNames[feed]
		if name == "" {
			name = feed
		}
		meta := map[string]string{"feed": feed, "host": HostOf(u), "interval_hours": strconv.Itoa(interval)}
		return sourceRow{Kind: "vulnerability_feed", Table: "intel_feeds", Key: feed, Name: name, Enabled: enabled, LastSyncAt: last, Meta: meta}, err
	}); err != nil {
		return nil, err
	}

	sv := sourceRow{Kind: "secret_validation", Table: "secret_validation_settings", Key: "", Name: "Live secret validation", Meta: map[string]string{"providers": "none"}}
	var providers []string
	switch err := q.QueryRow(ctx, `SELECT providers FROM secret_validation_settings WHERE organization_id = $1`, orgID).Scan(&providers); {
	case err == nil:
		sv.Enabled = len(providers) > 0
		if len(providers) > 0 {
			sv.Meta["providers"] = strings.Join(providers, ", ")
		}
	case err != pgx.ErrNoRows:
		return nil, err
	}
	out = append(out, sv)

	obj := sourceRow{Kind: "object_storage", Table: tableObjectStore, Key: "", Name: "Object storage (S3)", Meta: map[string]string{}}
	if env != nil && env.ObjectStore != nil {
		obj.Enabled = true
		obj.Meta = env.ObjectStoreMeta
	} else {
		obj.Meta["configured"] = "no (artifacts are kept in PostgreSQL)"
	}
	out = append(out, obj)

	eg := sourceRow{Kind: "egress_proxy", Table: tableEgressProxy, Key: "", Name: "Egress proxy", Meta: map[string]string{}}
	if env != nil && env.EgressProxy != "" {
		eg.Enabled = true
		eg.Meta["host"] = HostOf(env.EgressProxy)
	} else {
		eg.Meta["configured"] = "no (PATHOS_EGRESS_PROXY_URL is not set)"
	}
	out = append(out, eg)
	return out, nil
}

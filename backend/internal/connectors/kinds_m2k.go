package connectors

// Kinds built by M2-K (feature/m2-kinds). Docs slugs follow the hub's
// convention (connectors#<kind>); the connectors user guide links each
// anchor to provider-integrations.md (Generic Git, Bitbucket Data Center),
// ci-cd-integration.md#bitbucket-pipelines and secret-references.md. They replace the planned entries
// of existing.go and update the self-hosted SCM kinds for the CA bundle.
//
//   - generic_git, bitbucket_data_center: SCM providers stored in
//     scm_connections; creatable here (Create → repos.Service.CreateFromConnector)
//     and on /admin/scm.
//   - bitbucket_pipelines: an inbound CI template.
//   - vault: a registry kind; configuration vault.Config, credential the
//     AppRole secret ID (none for Kubernetes auth). vault.Default resolves
//     "vault:" references from this registry (VaultSource).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/tenant"
	"pathos/internal/secrets"
	"pathos/internal/vault"
)

// ConfigField is one input of a creatable kind's form. Type is text, url,
// pem, textarea, secret_ref, select or boolean.
type ConfigField struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Required bool     `json:"required"`
	Options  []string `json:"options,omitempty"`
	Help     string   `json:"help,omitempty"`
}

// SCMCreator creates SCM connections for creatable SCM kinds
// (*repos.Service implements it); it returns the scm_connections ID.
type SCMCreator interface {
	CreateConnectorSource(ctx context.Context, p *authz.Principal, kind, name string, cfg map[string]any, credential string) (string, error)
}

var (
	caField  = ConfigField{Key: "ca_bundle_pem", Label: "Private CA bundle (PEM)", Type: "pem", Help: "Only for a certificate issued by a private CA; added to the system trust store for this connection."}
	refField = ConfigField{Key: "credential_ref", Label: "Credential as a Vault/OpenBao reference", Type: "secret_ref", Help: "vault:<mount>/<path>#<key> instead of pasting the token."}
)

func init() {
	createSCM := func(ctx context.Context, env *Env, p *authz.Principal, kind, name string, cfg map[string]any, credential string) (string, error) {
		if env.SCMCreator == nil {
			return "", errors.New("the SCM service is not available")
		}
		return env.SCMCreator.CreateConnectorSource(ctx, p, kind, name, cfg, credential)
	}
	scmKind := func(kind, label, note string, fields []ConfigField, auth ...string) Kind {
		return Kind{Kind: kind, Category: "scm_ide", Label: label, Status: KindExisting, AuthMethods: auth, OfflineOK: true, Direction: Outbound,
			ManagedAt: "/admin/scm", CheckedBy: RunsInAPI, Source: "scm_connections", Checker: CheckFunc(checkSCM), Note: note,
			CanRead: scmRead, CanManage: scmManage, NeedsInternet: scmNeedsInternet,
			Creatable: true, ConfigFields: fields, SecretRefs: true,
			Create: func(ctx context.Context, env *Env, p *authz.Principal, name string, cfg map[string]any, credential string) (string, error) {
				return createSCM(ctx, env, p, kind, name, cfg, credential)
			}}
	}
	RegisterKind(scmKind("generic_git", "Generic Git (HTTPS/SSH)",
		"One connection per repository; health is git ls-remote; SSH host keys are pinned (never accept-new).",
		[]ConfigField{
			{Key: "base_url", Label: "Repository URL", Type: "url", Required: true, Help: "https://git.example.com/team/app.git or ssh://git@git.example.com/team/app.git"},
			{Key: "auth_method", Label: "Authentication", Type: "select", Required: true, Options: []string{"https_token", "ssh_key"}},
			{Key: "username", Label: "HTTPS user name (optional, default git)", Type: "text"},
			{Key: "ssh_known_hosts", Label: "known_hosts entry (SSH)", Type: "textarea", Help: "From ssh-keyscan -t ed25519 <host>; [host]:port for other ports."},
			{Key: "ssh_host_key_fingerprint", Label: "Host key fingerprint SHA256:… (SSH)", Type: "text", Help: "Confirmed by the server administrator; must match the known_hosts entry."},
			caField, refField,
		}, "api_token", "ssh_key"))
	RegisterKind(scmKind("bitbucket_data_center", "Bitbucket Data Center",
		"REST 1.0; project/repository HTTP access tokens (Bearer) or user tokens; signed webhooks.",
		[]ConfigField{
			{Key: "base_url", Label: "Instance URL", Type: "url", Required: true, Help: "https://bitbucket.example.com (with its context path, if any)"},
			{Key: "auth_method", Label: "Token type", Type: "select", Required: true, Options: []string{"http_access_token", "user_token"}},
			{Key: "username", Label: "User name (user tokens only)", Type: "text"},
			{Key: "project_key", Label: "Project key (optional; required for a repository token)", Type: "text"},
			caField, refField,
		}, "pat", "api_token"))
	RegisterKind(Kind{Kind: "bitbucket_pipelines", Category: "cicd", Label: "Bitbucket Pipelines", Status: KindExisting,
		AuthMethods: []string{"api_token"}, OfflineOK: true, Direction: Inbound, ManagedAt: "/settings/tokens",
		Note: "Template integrations/bitbucket-pipelines/bitbucket-pipelines.yml."})
	RegisterKind(Kind{Kind: "vault", Category: "iam_secrets", Label: "HashiCorp Vault / OpenBao", Status: KindExisting,
		AuthMethods: []string{vault.AuthAppRole, vault.AuthKubernetes}, OfflineOK: true, Direction: Outbound,
		Creatable: true, CheckedBy: RunsInAPI, Checker: CheckFunc(checkVault), Validate: validateVault,
		CanRead: settings, CanManage: settings,
		Note: "Credentials of other connectors may be vault:<mount>/<path>#<key> references, resolved at use time.",
		ConfigFields: []ConfigField{
			{Key: "base_url", Label: "Vault address", Type: "url", Required: true, Help: "https://vault.example.com:8200 (without /v1)"},
			{Key: "auth_method", Label: "Authentication", Type: "select", Required: true, Options: []string{vault.AuthAppRole, vault.AuthKubernetes}},
			{Key: "role_id", Label: "AppRole role ID", Type: "text", Help: "The secret ID is the credential."},
			{Key: "kubernetes_role", Label: "Kubernetes auth role", Type: "text"},
			{Key: "auth_mount", Label: "Auth mount (optional)", Type: "text"},
			{Key: "namespace", Label: "Namespace (Vault Enterprise/HCP)", Type: "text"},
			{Key: "path_prefix", Label: "Allowed path prefix", Type: "text", Help: "e.g. secret/pathos; references outside it are refused."},
			{Key: "canary_ref", Label: "Canary reference for the health check", Type: "secret_ref"},
			{Key: "allow_private", Label: "Allow private network", Type: "boolean"},
			caField,
		}})

	// Self-hosted SCM kinds now accept a per-connection CA bundle.
	kindsMu.Lock()
	for kind, note := range map[string]string{
		"github_enterprise":   "Per-connection private CA; version check (GET /api/v3/meta).",
		"gitlab":              "Per-connection private CA and version report for self-managed; webhooks: signing token (HMAC) or the legacy secret token.",
		"azure_devops_server": "Per-connection private CA.",
	} {
		if k, ok := kinds[kind]; ok {
			if kind == "github_enterprise" {
				k.Status = KindExisting
			}
			k.Note, k.SecretRefs = note, true
			kinds[kind] = k
		}
	}
	for _, kind := range []string{"github", "bitbucket", "azure_devops", "jira", "servicenow", "webhook", "slack", "teams", "smtp"} {
		if k, ok := kinds[kind]; ok {
			k.SecretRefs = true // single-value tokens, passwords and URLs may be references
			kinds[kind] = k
		}
	}
	kindsMu.Unlock()
	scmAPIVersion["generic_git"] = "Git smart HTTP / SSH"
	scmAPIVersion["bitbucket_data_center"] = "REST 1.0"
}

// validateVault normalizes the registry configuration of a vault connector.
// The hub's common keys: base_url is the address, ca_bundle_pem the CA,
// scopes are ignored, a non-empty proxy_url or credential_ref is refused
// (the egress proxy applies; the secret ID cannot itself be a reference).
func validateVault(cfg map[string]any) (map[string]any, error) {
	in := map[string]any{}
	for k, v := range cfg {
		in[k] = v
	}
	if s, _ := in["proxy_url"].(string); strings.TrimSpace(s) != "" {
		return nil, errors.New("proxy_url: a per-connection proxy is not supported; PATHOS uses the installation's egress proxy")
	}
	if s, _ := in["credential_ref"].(string); strings.TrimSpace(s) != "" {
		return nil, errors.New("credential_ref: the Vault secret ID cannot itself be a vault: reference")
	}
	if s, ok := in["base_url"].(string); ok && in["address"] == nil {
		in["address"] = s
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	var c vault.Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("invalid Vault configuration")
	}
	if err := c.Validate(vault.Default.AllowHTTP); err != nil {
		return nil, err
	}
	out := map[string]any{}
	raw, _ = json.Marshal(c)
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

func vaultConfig(t Target, secret []byte) (vault.Config, error) {
	raw, _ := json.Marshal(t.Config)
	var c vault.Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	if vault.IsRef(secret) {
		return c, errors.New("the Vault secret ID cannot itself be a vault: reference")
	}
	c.SecretID = string(secret)
	return c, nil
}

// checkVault: sys/health, login, canary read (its value is discarded).
func checkVault(ctx context.Context, env *Env, t Target) Result {
	var secret []byte
	if env.Secrets != nil && t.SecretID != nil {
		s, err := env.Secrets.RevealStored(ctx, env.DB, t.OrgID, *t.SecretID, credentialKind)
		if err != nil {
			return failed("credential", err, "")
		}
		secret = s
	}
	cfg, err := vaultConfig(t, secret)
	if err != nil {
		return failed("configuration", err, "")
	}
	c, err := vault.NewClient(cfg, nil, vault.Default.AllowHTTP)
	if err != nil {
		return failed("configuration", err, "")
	}
	res, err := c.Check(ctx)
	steps := []Step{}
	for _, name := range []string{"reachability", "login", "canary"} {
		st := Step{Check: name, Status: res.Steps[name]}
		if st.Status == StepFail && err != nil {
			st.ErrorCode, st.Detail = vault.DiagCode(err), err.Error()
		}
		steps = append(steps, st)
	}
	if err != nil {
		return Result{Status: StatusFailing, ErrorCode: vault.DiagCode(err), Message: err.Error(), Steps: steps}
	}
	return summarize(steps, fmt.Sprintf("Vault %s reachable, login succeeded", res.Health.Version), map[string]any{"vault_version": res.Health.Version})
}

// VaultSource returns vault.Source over the connectors registry: the
// organization's enabled "vault" connector (the oldest if several).
func VaultSource(q db.Querier, store *secrets.Store) vault.Source {
	return func(ctx context.Context, orgID uuid.UUID) (vault.Config, error) {
		ctx = tenant.WithOrg(ctx, orgID) // never another organization's Vault
		var cfgRaw []byte
		var sid *uuid.UUID
		err := q.QueryRow(ctx, `SELECT config, secret_id FROM connectors
			WHERE organization_id = $1 AND kind = 'vault' AND source_table IS NULL AND enabled
			ORDER BY created_at LIMIT 1`, orgID).Scan(&cfgRaw, &sid)
		if err != nil {
			return vault.Config{}, vault.ErrNotConfigured
		}
		var cfg map[string]any
		if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
			return vault.Config{}, err
		}
		var secret []byte
		if sid != nil {
			// RevealStored: the secret ID itself is never resolved as a reference.
			if secret, err = store.RevealStored(ctx, q, orgID, *sid, credentialKind); err != nil {
				return vault.Config{}, err
			}
		}
		return vaultConfig(Target{Connector: Connector{Config: cfg}}, secret)
	}
}

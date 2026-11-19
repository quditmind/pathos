package repos

import (
	"context"
	"strings"

	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

// ConnectorKinds are the SCM providers that POST /api/v1/connectors (the
// Connectors hub) may create. They are stored in scm_connections like any
// SCM connection, so imports, scans, webhooks and clone credentials work
// unchanged; the hub lists them through its scm_connections source.
var ConnectorKinds = []string{scm.GenericGit, scm.BitbucketDataCenter}

// authAliases maps the hub's auth method names onto scm auth types.
var authAliases = map[string]string{
	"https_token": scm.AuthAPIToken, "token": "", "http_access_token": scm.AuthPAT, "user_token": scm.AuthAPIToken,
	"ssh": scm.AuthSSHKey, "ssh_key": scm.AuthSSHKey, "pat": scm.AuthPAT, "api_token": scm.AuthAPIToken,
}

func cfgString(cfg map[string]any, key string) (string, error) {
	v, ok := cfg[key]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", httpx.BadRequest("config." + key + " must be a string")
	}
	return strings.TrimSpace(s), nil
}

// CreateFromConnector creates an SCM connection from the Connectors hub's
// generic body: config keys base_url, auth_method, ca_bundle_pem,
// credential_ref, proxy_url, scopes (the hub's common fields) plus the
// kind's own keys (username, project_key, ssh_known_hosts,
// ssh_host_key_fingerprint), and the write-only credential (token or SSH
// private key). It returns the connection, already tested.
//
//   - credential_ref ("vault:<mount>/<path>#<key>") replaces a token; it is
//     not accepted for SSH keys (multi-part credentials).
//   - proxy_url: PATHOS uses the installation's egress proxy; a non-empty
//     per-connection proxy is refused rather than silently ignored.
//   - scopes: informational for these kinds (the vendor decides); ignored.
func (s *Service) CreateFromConnector(ctx context.Context, p *authz.Principal, kind, name string, cfg map[string]any, credential string) (Connection, error) {
	if p == nil || !p.HasOrgWide(authz.PermSCMManage) {
		return Connection{}, apiError(authz.ErrForbidden)
	}
	known := false
	for _, k := range ConnectorKinds {
		known = known || k == kind
	}
	if !known {
		return Connection{}, httpx.BadRequest("kind " + kind + " is not created through the Connectors hub")
	}
	get := func(key string) string {
		v, err := cfgString(cfg, key)
		if err != nil {
			return "\x00invalid"
		}
		return v
	}
	for _, key := range []string{"base_url", "auth_method", "ca_bundle_pem", "credential_ref", "proxy_url", "username", "project_key",
		"ssh_known_hosts", "ssh_host_key_fingerprint"} {
		if get(key) == "\x00invalid" {
			return Connection{}, httpx.BadRequest("config." + key + " must be a string")
		}
	}
	if get("proxy_url") != "" {
		return Connection{}, httpx.BadRequest("config.proxy_url: a per-connection proxy is not supported; PATHOS uses the installation's egress proxy")
	}
	base := get("base_url")
	auth := get("auth_method")
	if a, ok := authAliases[auth]; ok {
		auth = a
	}
	if auth == "" {
		switch {
		case kind == scm.GenericGit && (strings.HasPrefix(base, "ssh://") || (!strings.Contains(base, "://") && strings.Contains(base, "@"))):
			auth = scm.AuthSSHKey
		case kind == scm.GenericGit:
			auth = scm.AuthAPIToken
		default:
			auth = scm.AuthPAT
		}
	}
	ref := get("credential_ref")
	if ref != "" {
		if !secrets.IsReference([]byte(ref)) {
			return Connection{}, httpx.BadRequest("config.credential_ref must look like vault:<mount>/<path>#<key>")
		}
		if credential != "" {
			return Connection{}, httpx.BadRequest("send either a credential or config.credential_ref, not both")
		}
		if auth == scm.AuthSSHKey {
			return Connection{}, httpx.BadRequest("an SSH private key cannot be a vault: reference yet; paste the key")
		}
		credential = ref
	}
	str := func(v string) *string {
		if v == "" {
			return nil
		}
		return &v
	}
	req := connectionRequest{Name: &name, Provider: kind, BaseURL: str(base), AuthType: auth, Owner: str(get("project_key")),
		Username: str(get("username")), CABundlePEM: str(get("ca_bundle_pem")),
		SSHKnownHosts: str(get("ssh_known_hosts")), SSHHostKeyFingerprint: str(get("ssh_host_key_fingerprint"))}
	if auth == scm.AuthSSHKey {
		req.SSHPrivateKey = str(credential)
	} else {
		req.Token = str(credential)
	}
	c, err := s.createConn(ctx, p, req)
	if err != nil {
		return Connection{}, apiError(err)
	}
	return c, nil
}

// CreateConnectorSource is CreateFromConnector for the connectors package:
// it returns the new scm_connections ID (connectors.SCMCreator).
func (s *Service) CreateConnectorSource(ctx context.Context, p *authz.Principal, kind, name string, cfg map[string]any, credential string) (string, error) {
	c, err := s.CreateFromConnector(ctx, p, kind, name, cfg, credential)
	if err != nil {
		return "", err
	}
	return c.ID.String(), nil
}

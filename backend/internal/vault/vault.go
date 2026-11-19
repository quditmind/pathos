// Package vault resolves secret references against HashiCorp Vault or
// OpenBao (PATHOS 3.0, M2). A connector credential may be stored as a
// reference
//
//	vault:<mount>/<path>#<key>
//
// instead of the secret value. The server resolves it at use time: it logs
// in (AppRole or Kubernetes auth), reads the KV version 2 secret
// <mount>/data/<path> and returns field <key>. Nothing is written to disk:
// the value lives only in memory for the call that needs it, and only the
// Vault client token is kept in memory until shortly before its TTL ends.
//
// Vault HTTP API references (checked 2026-11-20):
//   - AppRole login: https://developer.hashicorp.com/vault/api-docs/auth/approle
//   - Kubernetes login: https://developer.hashicorp.com/vault/api-docs/auth/kubernetes
//   - KV v2 read: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2
//   - Health: https://developer.hashicorp.com/vault/api-docs/system/health
//   - Namespaces (X-Vault-Namespace): https://developer.hashicorp.com/vault/docs/enterprise/namespaces
//
// OpenBao (https://openbao.org/) implements the same HTTP API; PATHOS
// bundles neither and speaks plain HTTP.
package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"pathos/internal/scm"
	"pathos/internal/secrets"
)

// Auth methods.
const (
	AuthAppRole    = "approle"
	AuthKubernetes = "kubernetes"
)

// DefaultKubernetesTokenPath is where Kubernetes mounts the pod's service
// account token.
const DefaultKubernetesTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- a file path, not a credential

// Errors, mapped to catalogue codes by DiagCode.
var (
	// ErrSecretIDInvalid: AppRole login refused (secret ID expired, used up,
	// bound to other CIDRs, or wrong role ID). PTH-CONN-1601.
	ErrSecretIDInvalid = errors.New("vault: AppRole login refused (secret ID expired, used up or wrong)")
	// ErrPermissionDenied: the policy does not allow reading the path. PTH-CONN-1602.
	ErrPermissionDenied = errors.New("vault: the policy denies reading this path")
	// ErrNamespace: the namespace does not exist. PTH-CONN-1603.
	ErrNamespace = errors.New("vault: namespace not found")
	// ErrSealed: Vault is sealed or not initialized. PTH-CONN-1604.
	ErrSealed = errors.New("vault: Vault is sealed or not initialized")
	// ErrKubernetesRole: Kubernetes login refused (role does not match the
	// service account or namespace). PTH-CONN-1605.
	ErrKubernetesRole = errors.New("vault: Kubernetes auth role does not match this service account")
	// ErrSecretNotFound: no secret or no such key at the path. PTH-CONN-1606.
	ErrSecretNotFound = errors.New("vault: secret or key not found")
	// ErrRefOutsidePrefix: the reference is outside the connection's
	// allowed path prefix. PTH-CONN-1607.
	ErrRefOutsidePrefix = errors.New("vault: the reference is outside the allowed path prefix")
	// ErrInvalidRef: malformed reference.
	ErrInvalidRef = errors.New("vault: a reference must look like vault:<mount>/<path>#<key>")
	// ErrNotConfigured: the organization has no Vault connection. PTH-CONN-1608.
	ErrNotConfigured = errors.New("vault: no Vault/OpenBao connection is configured for this organization")
)

// DiagCode returns the catalogue code of a vault error ("" if none).
func DiagCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrSecretIDInvalid):
		return "PTH-CONN-1601"
	case errors.Is(err, ErrPermissionDenied):
		return "PTH-CONN-1602"
	case errors.Is(err, ErrNamespace):
		return "PTH-CONN-1603"
	case errors.Is(err, ErrSealed):
		return "PTH-CONN-1604"
	case errors.Is(err, ErrKubernetesRole):
		return "PTH-CONN-1605"
	case errors.Is(err, ErrSecretNotFound):
		return "PTH-CONN-1606"
	case errors.Is(err, ErrRefOutsidePrefix):
		return "PTH-CONN-1607"
	case errors.Is(err, ErrNotConfigured), errors.Is(err, secrets.ErrRefUnavailable):
		return "PTH-CONN-1608"
	}
	return scm.DiagCode(err) // transport, certificate, blocked address, timeout
}

// Ref is a parsed reference.
type Ref struct {
	Mount, Path, Key string
}

var refRe = regexp.MustCompile(`^vault:([A-Za-z0-9_.-]{1,64})/([A-Za-z0-9_.\-/]{1,512})#([A-Za-z0-9_.-]{1,128})$`)

// IsRef reports whether a stored credential is a reference.
func IsRef(b []byte) bool {
	return bytes.HasPrefix(b, []byte("vault:")) && refRe.Match(bytes.TrimSpace(b))
}

// ParseRef parses vault:<mount>/<path>#<key>.
func ParseRef(s string) (Ref, error) {
	m := refRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Ref{}, ErrInvalidRef
	}
	p := m[2]
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return Ref{}, ErrInvalidRef
		}
	}
	return Ref{Mount: m[1], Path: p, Key: m[3]}, nil
}

func (r Ref) String() string { return "vault:" + r.Mount + "/" + r.Path + "#" + r.Key }

// Config is one organization's Vault/OpenBao connection (non-secret part
// plus the AppRole secret ID).
type Config struct {
	// Address is the Vault URL, e.g. https://vault.example.com:8200.
	Address string `json:"address"`
	// Namespace (Vault Enterprise / HCP); "" for none.
	Namespace string `json:"namespace,omitempty"`
	// AuthMethod is approle or kubernetes; AuthMount the auth mount path
	// (default: the method name).
	AuthMethod string `json:"auth_method"`
	AuthMount  string `json:"auth_mount,omitempty"`
	// AppRole: role ID (not secret; it identifies the role) and secret ID
	// (secret, stored encrypted by PATHOS).
	RoleID   string `json:"role_id,omitempty"`
	SecretID string `json:"-"`
	// Kubernetes: the Vault role and the service account token file.
	KubernetesRole      string `json:"kubernetes_role,omitempty"`
	KubernetesTokenPath string `json:"kubernetes_token_path,omitempty"`
	// PathPrefix limits references to <mount>/<prefix>... ("" = any path
	// the Vault policy allows; a prefix is strongly recommended).
	PathPrefix string `json:"path_prefix,omitempty"`
	// CanaryRef is read by the health check (optional).
	CanaryRef string `json:"canary_ref,omitempty"`
	// CABundle is a private CA (PEM); AllowPrivate permits internal
	// addresses (Vault is usually internal).
	CABundle     string `json:"ca_bundle_pem,omitempty"`
	AllowPrivate bool   `json:"allow_private"`
}

// Validate normalizes a configuration (without the secret ID).
func (c *Config) Validate(allowHTTP bool) error {
	c.Address = strings.TrimRight(strings.TrimSpace(c.Address), "/")
	u, err := (scm.NetPolicy{AllowPrivate: c.AllowPrivate, AllowHTTP: allowHTTP}).ValidateBaseURL(c.Address)
	if err != nil {
		return fmt.Errorf("address: %w", err)
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("address must be the Vault root URL (without /v1)")
	}
	switch c.AuthMethod {
	case AuthAppRole:
		if c.RoleID == "" {
			return errors.New("role_id is required for AppRole")
		}
	case AuthKubernetes:
		if c.KubernetesRole == "" {
			return errors.New("kubernetes_role is required for Kubernetes auth")
		}
	default:
		return errors.New("auth_method must be approle or kubernetes")
	}
	if c.AuthMount == "" {
		c.AuthMount = c.AuthMethod
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.\-/]{1,128}$`).MatchString(c.AuthMount) || strings.Contains(c.AuthMount, "..") {
		return errors.New("auth_mount is invalid")
	}
	if c.Namespace != "" && !regexp.MustCompile(`^[A-Za-z0-9_.\-/]{1,256}$`).MatchString(c.Namespace) {
		return errors.New("namespace is invalid")
	}
	c.PathPrefix = strings.Trim(c.PathPrefix, "/")
	if c.CanaryRef != "" {
		if _, err := ParseRef(c.CanaryRef); err != nil {
			return fmt.Errorf("canary_ref: %w", err)
		}
	}
	if _, _, err := scm.ParseCABundle(c.CABundle, time.Now()); err != nil {
		return err
	}
	return nil
}

// allowed checks a reference against the path prefix.
func (c Config) allowed(r Ref) bool {
	if c.PathPrefix == "" {
		return true
	}
	full := r.Mount + "/" + r.Path
	return full == c.PathPrefix || strings.HasPrefix(full, c.PathPrefix+"/")
}

// Client talks to one Vault for one organization.
type Client struct {
	cfg Config
	hc  *http.Client
	// readFile reads the Kubernetes token (tests replace it).
	readFile func(string) ([]byte, error)

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// NewClient builds a client. hc may be nil (the network policy client with
// the configuration's CA bundle is used).
func NewClient(cfg Config, hc *http.Client, allowHTTP bool) (*Client, error) {
	if hc == nil {
		var err error
		if hc, err = (scm.NetPolicy{AllowPrivate: cfg.AllowPrivate, AllowHTTP: allowHTTP}).ClientWithCA(cfg.CABundle); err != nil {
			return nil, err
		}
	}
	return &Client{cfg: cfg, hc: hc, readFile: os.ReadFile}, nil
}

type apiErr struct {
	status int
	errs   []string
}

func (e *apiErr) Error() string {
	return fmt.Sprintf("vault: HTTP %d: %s", e.status, strings.Join(e.errs, "; "))
}

// do sends one request to /v1/<path>. Response bodies are decoded into out;
// error bodies keep only Vault's "errors" strings (never secret data).
func (c *Client) do(ctx context.Context, method, path string, body any, token string, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.Address+"/v1/"+path, rd)
	if err != nil {
		return 0, errors.New("vault: invalid request")
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if c.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.cfg.Namespace)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, fmt.Errorf("vault: request to %s failed: %w", req.URL.Host, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(raw, &e)
		for i := range e.Errors {
			if len(e.Errors[i]) > 200 {
				e.Errors[i] = e.Errors[i][:200]
			}
		}
		return resp.StatusCode, &apiErr{status: resp.StatusCode, errs: e.Errors}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, errors.New("vault: unexpected response (is the address a Vault server?)")
		}
	}
	return resp.StatusCode, nil
}

func errText(err error) string {
	var ae *apiErr
	if errors.As(err, &ae) {
		return strings.ToLower(strings.Join(ae.errs, " "))
	}
	return ""
}

func statusOf(err error) int {
	var ae *apiErr
	if errors.As(err, &ae) {
		return ae.status
	}
	return 0
}

// classify maps a Vault error response onto the package errors.
// login is the auth method when err comes from a login call, else "".
func classify(err error, login string) error {
	if err == nil {
		return nil
	}
	st, txt := statusOf(err), errText(err)
	switch {
	case st == 503 || st == 501 || strings.Contains(txt, "sealed"):
		return fmt.Errorf("%w (%v)", ErrSealed, err)
	case strings.Contains(txt, "namespace") && (st == 404 || st == 403 || st == 400):
		return fmt.Errorf("%w (%v)", ErrNamespace, err)
	case login == AuthKubernetes && (st == 400 || st == 401 || st == 403):
		return fmt.Errorf("%w (%v)", ErrKubernetesRole, err)
	case login == AuthAppRole && (st == 400 || st == 401 || st == 403):
		return fmt.Errorf("%w (%v)", ErrSecretIDInvalid, err)
	case st == 403:
		return fmt.Errorf("%w (%v)", ErrPermissionDenied, err)
	case st == 404:
		return fmt.Errorf("%w (%v)", ErrSecretNotFound, err)
	}
	return err
}

// login returns a client token, cached in memory until 30 s before expiry.
func (c *Client) login(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}
	var body map[string]string
	switch c.cfg.AuthMethod {
	case AuthAppRole:
		if c.cfg.SecretID == "" {
			return "", fmt.Errorf("%w (no secret ID stored)", ErrSecretIDInvalid)
		}
		body = map[string]string{"role_id": c.cfg.RoleID, "secret_id": c.cfg.SecretID}
	case AuthKubernetes:
		p := c.cfg.KubernetesTokenPath
		if p == "" {
			p = DefaultKubernetesTokenPath
		}
		jwt, err := c.readFile(p)
		if err != nil {
			return "", fmt.Errorf("%w (service account token not readable: PATHOS is not running in Kubernetes or the token is not mounted)", ErrKubernetesRole)
		}
		body = map[string]string{"role": c.cfg.KubernetesRole, "jwt": strings.TrimSpace(string(jwt))}
	default:
		return "", errors.New("vault: unknown auth method")
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if _, err := c.do(ctx, http.MethodPost, "auth/"+c.cfg.AuthMount+"/login", body, "", &out); err != nil {
		return "", classify(err, c.cfg.AuthMethod)
	}
	if out.Auth.ClientToken == "" {
		return "", errors.New("vault: login returned no token")
	}
	ttl := time.Duration(out.Auth.LeaseDuration) * time.Second
	if ttl <= 0 || ttl > time.Hour {
		ttl = time.Hour
	}
	c.token, c.tokenExp = out.Auth.ClientToken, time.Now().Add(ttl-30*time.Second)
	return c.token, nil
}

func (c *Client) dropToken(tok string) {
	c.mu.Lock()
	if c.token == tok {
		c.token = ""
	}
	c.mu.Unlock()
}

// Read resolves a reference: KV v2 GET /v1/<mount>/data/<path>, field <key>.
func (c *Client) Read(ctx context.Context, r Ref) ([]byte, error) {
	if !c.cfg.allowed(r) {
		return nil, ErrRefOutsidePrefix
	}
	for attempt := 0; ; attempt++ {
		tok, err := c.login(ctx)
		if err != nil {
			return nil, err
		}
		var out struct {
			Data struct {
				Data map[string]any `json:"data"`
			} `json:"data"`
		}
		_, err = c.do(ctx, http.MethodGet, url.PathEscape(r.Mount)+"/data/"+escapePath(r.Path), nil, tok, &out)
		if statusOf(err) == 403 && attempt == 0 && strings.Contains(errText(err), "invalid token") {
			c.dropToken(tok) // revoked or expired early: log in again once
			continue
		}
		if err != nil {
			return nil, classify(err, "")
		}
		v, ok := out.Data.Data[r.Key]
		if !ok {
			return nil, fmt.Errorf("%w: key %q", ErrSecretNotFound, r.Key)
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%w: key %q is not a string", ErrSecretNotFound, r.Key)
		}
		return []byte(s), nil
	}
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// HealthInfo is what GET /v1/sys/health reports.
type HealthInfo struct {
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Standby     bool   `json:"standby"`
	Version     string `json:"version"`
}

// Health calls GET /v1/sys/health (no token). 200 active, 429 standby
// (healthy for reads), 472/473 DR/performance standby, 501 not
// initialized, 503 sealed.
func (c *Client) Health(ctx context.Context) (HealthInfo, error) {
	var h HealthInfo
	st, err := c.do(ctx, http.MethodGet, "sys/health?standbyok=true&perfstandbyok=true", nil, "", &h)
	if err != nil {
		if st == 501 || st == 503 {
			return h, fmt.Errorf("%w (HTTP %d)", ErrSealed, st)
		}
		if st == 429 || st == 472 || st == 473 {
			return h, nil
		}
		return h, classify(err, "")
	}
	if h.Sealed || !h.Initialized {
		return h, ErrSealed
	}
	return h, nil
}

// CheckResult is the outcome of a full health check.
type CheckResult struct {
	Health HealthInfo
	// Steps: reachability, login, canary (each "pass", "fail" or "skipped").
	Steps map[string]string
}

// Check runs the health check: sys/health, login, then the canary read if
// one is configured. The canary's value is discarded.
func (c *Client) Check(ctx context.Context) (CheckResult, error) {
	res := CheckResult{Steps: map[string]string{"reachability": "fail", "login": "skipped", "canary": "skipped"}}
	h, err := c.Health(ctx)
	res.Health = h
	if err != nil {
		return res, err
	}
	res.Steps["reachability"] = "pass"
	if _, err := c.login(ctx); err != nil {
		res.Steps["login"] = "fail"
		return res, err
	}
	res.Steps["login"] = "pass"
	if c.cfg.CanaryRef != "" {
		r, _ := ParseRef(c.cfg.CanaryRef)
		if _, err := c.Read(ctx, r); err != nil {
			res.Steps["canary"] = "fail"
			return res, err
		}
		res.Steps["canary"] = "pass"
	}
	return res, nil
}

// Source returns the Vault configuration of an organization (with its
// secret ID revealed), or ErrNotConfigured. The connectors registry
// provides it.
type Source func(ctx context.Context, orgID uuid.UUID) (Config, error)

// Default is the process-wide resolver (cmd/pathos); the connectors wiring
// sets its Source.
var Default = &Resolver{}

// Resolver resolves references for secrets.Store. It keeps one client per
// organization and configuration (so a changed configuration or secret ID
// takes effect at once); nothing is cached but the Vault token.
type Resolver struct {
	Source    Source
	AllowHTTP bool
	// HTTP overrides the client (tests).
	HTTP *http.Client

	mu      sync.Mutex
	clients map[uuid.UUID]resolverEntry
}

type resolverEntry struct {
	key string
	c   *Client
}

func cfgKey(c Config) string {
	b, _ := json.Marshal(struct {
		Config
		S string
	}{c, c.SecretID})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Client returns the organization's client.
func (r *Resolver) Client(ctx context.Context, orgID uuid.UUID) (*Client, error) {
	if r == nil || r.Source == nil {
		return nil, ErrNotConfigured
	}
	cfg, err := r.Source(ctx, orgID)
	if err != nil {
		return nil, err
	}
	key := cfgKey(cfg)
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.clients[orgID]; ok && e.key == key {
		return e.c, nil
	}
	c, err := NewClient(cfg, r.HTTP, r.AllowHTTP)
	if err != nil {
		return nil, err
	}
	if r.clients == nil {
		r.clients = map[uuid.UUID]resolverEntry{}
	}
	r.clients[orgID] = resolverEntry{key: key, c: c}
	return c, nil
}

// Resolve implements secrets.RefResolver.
func (r *Resolver) Resolve(ctx context.Context, orgID uuid.UUID, ref string) ([]byte, error) {
	parsed, err := ParseRef(ref)
	if err != nil {
		return nil, err
	}
	c, err := r.Client(ctx, orgID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return c.Read(ctx, parsed)
}

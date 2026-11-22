// Package config loads and validates PATHOS runtime configuration from the
// environment. Any variable ending in _FILE is read from the named file
// instead (Docker secrets convention), e.g. PATHOS_MASTER_KEY_FILE.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Role selects which subsystems a pathos process runs.
type Role string

const (
	RoleAPI       Role = "api"
	RoleJobs      Role = "jobs"
	RoleScheduler Role = "scheduler"
)

type Config struct {
	Env      string // development | production
	Role     Role
	HTTPAddr string
	LogLevel string

	DatabaseURL string
	RedisURL    string

	// MasterKeys maps key version -> 32-byte AES key. The highest version is
	// used for new encryptions; older versions remain for decryption until
	// rotation completes.
	MasterKeys map[int][]byte

	PublicURL *url.URL // externally visible base URL, e.g. https://localhost

	OIDC OIDCConfig

	SessionIdleTTL     time.Duration
	SessionAbsoluteTTL time.Duration

	// Worker API (internal listener for scan workers).
	WorkerAPIAddr        string
	WorkerBootstrapToken string

	// SCM network policy (see internal/scm/safehttp.go).
	SCMAllowPrivate bool
	// MultiTenantAllowPrivate (PATHOS_MULTI_TENANT_ALLOW_PRIVATE_NETWORKS):
	// with multi-tenancy, organizations may point integrations (webhooks,
	// ticketing, Kubernetes and registries, Vault, self-hosted AI, SMTP) at
	// private addresses only when the operator sets this.
	MultiTenantAllowPrivate bool
	// Offline (PATHOS_OFFLINE): air-gapped operation. Intelligence feeds are
	// imported from files only; nothing is downloaded.
	Offline      bool
	SCMAllowHTTP bool

	// Connectors hub (M2): the egress proxy the hub checks
	// (PATHOS_EGRESS_PROXY_URL, e.g. http://egress:3128; empty: none) and
	// how often the jobs service checks every connector.
	EgressProxyURL         string
	ConnectorCheckInterval time.Duration

	// S3 object storage for scan artifacts; empty bucket keeps them in
	// PostgreSQL.
	S3Endpoint, S3Region, S3Bucket, S3AccessKey, S3SecretKey string
	S3PathStyle                                              bool

	// Repository onboarding (docs/REPOSITORY_ONBOARDING.md section 6).
	SourceStoreDir          string
	SourceS3Prefix          string
	UploadMaxBytes          int64
	ImportMaxFiles          int
	ImportMaxExtractedBytes int64
	ImportMaxFileBytes      int64
	ImportConcurrency       int
	ImportTimeout           time.Duration
	ImportWorkDir           string
	ClamAVAddress           string
	ClamAVRequired          bool
	// ScanLogRetentionDays keeps execution logs and stage events; scan
	// executions themselves are never deleted (360-day comparison window).
	ScanLogRetentionDays int

	// RequireMFA makes new users enrol a TOTP authenticator.
	RequireMFA bool

	// RateLimitScale multiplies every API rate limit; 0 disables limiting.
	RateLimitScale float64

	// Telemetry: OTLP/HTTP endpoint (e.g. http://otel-collector:4318);
	// empty disables export.
	OTLPEndpoint string

	OrgName             string
	OrgSlug             string
	BootstrapAdminEmail string

	// Multi-tenancy (enabled in the database with `pathosctl
	// multi-tenancy enable`; see docs/MULTI_TENANCY.md).
	// InstallationAdminEmail becomes a platform administrator at its first
	// login with a verified email (like BootstrapAdminEmail for the
	// organization).
	InstallationAdminEmail string
	// OrgClaim is the ID-token claim that lists a user's organizations
	// (default "groups"); OrgGroupPrefix selects and strips the entries
	// that name an organization slug (default "/pathos/", matching
	// Keycloak group paths /pathos/<slug>). An empty prefix takes every
	// entry as a slug.
	OrgClaim       string
	OrgGroupPrefix string
}

type OIDCConfig struct {
	// Issuer is the issuer as seen in tokens (the public Keycloak URL).
	Issuer string
	// DiscoveryURL is where the API fetches discovery/JWKS from (internal URL).
	// Defaults to Issuer.
	DiscoveryURL string
	ClientID     string
	ClientSecret string

	// Optional Keycloak admin API service account used to provision users.
	ProvisionerClientID     string
	ProvisionerClientSecret string
	AdminBaseURL            string // e.g. http://keycloak:8080/auth
	Realm                   string
}

func (c *Config) IsProduction() bool { return c.Env == "production" }

// CurrentKeyVersion returns the highest configured master key version.
func (c *Config) CurrentKeyVersion() int {
	v := 0
	for k := range c.MasterKeys {
		if k > v {
			v = k
		}
	}
	return v
}

// Load reads configuration from the process environment.
func Load() (*Config, error) { return LoadFrom(os.Getenv) }

// LoadFrom reads configuration using getenv, which makes it testable.
func LoadFrom(getenv func(string) string) (*Config, error) {
	var errs []error
	get := func(key, def string) string {
		if v := getenv(key); v != "" {
			return v
		}
		if path := getenv(key + "_FILE"); path != "" {
			// #nosec G304 -- *_FILE secrets: the operator chooses the path (Docker secrets convention)
			b, err := os.ReadFile(path)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s_FILE: %w", key, err))
				return ""
			}
			return strings.TrimSpace(string(b))
		}
		return def
	}
	dur := func(key, def string) time.Duration {
		s := get(key, def)
		d, err := time.ParseDuration(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid duration %q", key, s))
		}
		return d
	}

	c := &Config{
		Env:                     get("PATHOS_ENV", "production"),
		Role:                    Role(get("PATHOS_ROLE", string(RoleAPI))),
		HTTPAddr:                get("PATHOS_HTTP_ADDR", ":8080"),
		LogLevel:                get("PATHOS_LOG_LEVEL", "info"),
		DatabaseURL:             get("PATHOS_DATABASE_URL", ""),
		RedisURL:                get("PATHOS_REDIS_URL", ""),
		SessionIdleTTL:          dur("PATHOS_SESSION_IDLE_TTL", "8h"),
		SessionAbsoluteTTL:      dur("PATHOS_SESSION_ABSOLUTE_TTL", "24h"),
		WorkerAPIAddr:           get("PATHOS_WORKER_API_ADDR", ":8081"),
		WorkerBootstrapToken:    get("PATHOS_WORKER_BOOTSTRAP_TOKEN", ""),
		SCMAllowPrivate:         get("PATHOS_SCM_ALLOW_PRIVATE_NETWORKS", "false") == "true",
		MultiTenantAllowPrivate: get("PATHOS_MULTI_TENANT_ALLOW_PRIVATE_NETWORKS", "false") == "true",
		Offline:                 get("PATHOS_OFFLINE", "false") == "true",
		SCMAllowHTTP:            get("PATHOS_SCM_ALLOW_HTTP", "false") == "true",
		EgressProxyURL:          get("PATHOS_EGRESS_PROXY_URL", ""),
		ConnectorCheckInterval:  dur("PATHOS_CONNECTOR_CHECK_INTERVAL", "1h"),
		OTLPEndpoint:            get("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
		RequireMFA:              get("PATHOS_REQUIRE_MFA", "false") == "true",
		S3Endpoint:              get("PATHOS_S3_ENDPOINT", ""),
		S3Region:                get("PATHOS_S3_REGION", "us-east-1"),
		S3Bucket:                get("PATHOS_S3_BUCKET", ""),
		S3AccessKey:             get("PATHOS_S3_ACCESS_KEY", ""),
		S3SecretKey:             get("PATHOS_S3_SECRET_KEY", ""),
		S3PathStyle:             get("PATHOS_S3_PATH_STYLE", "true") == "true",
		OrgName:                 get("PATHOS_ORG_NAME", "Default Organization"),
		OrgSlug:                 get("PATHOS_ORG_SLUG", "default"),
		BootstrapAdminEmail:     strings.ToLower(get("PATHOS_BOOTSTRAP_ADMIN_EMAIL", "")),
		InstallationAdminEmail:  strings.ToLower(get("PATHOS_INSTALLATION_ADMIN_EMAIL", "")),
		OrgClaim:                get("PATHOS_OIDC_ORGANIZATION_CLAIM", "groups"),
		OrgGroupPrefix:          get("PATHOS_OIDC_ORGANIZATION_PREFIX", "/pathos/"),
		OIDC: OIDCConfig{
			Issuer:                  get("PATHOS_OIDC_ISSUER", ""),
			DiscoveryURL:            get("PATHOS_OIDC_DISCOVERY_URL", ""),
			ClientID:                get("PATHOS_OIDC_CLIENT_ID", "pathos-web"),
			ClientSecret:            get("PATHOS_OIDC_CLIENT_SECRET", ""),
			ProvisionerClientID:     get("PATHOS_KEYCLOAK_PROVISIONER_CLIENT_ID", ""),
			ProvisionerClientSecret: get("PATHOS_KEYCLOAK_PROVISIONER_CLIENT_SECRET", ""),
			AdminBaseURL:            get("PATHOS_KEYCLOAK_ADMIN_URL", ""),
			Realm:                   get("PATHOS_KEYCLOAK_REALM", "pathos"),
		},
	}
	if c.OIDC.DiscoveryURL == "" {
		c.OIDC.DiscoveryURL = c.OIDC.Issuer
	}
	num := func(key, def string, min, max int64) int64 {
		v, err := strconv.ParseInt(get(key, def), 10, 64)
		if err != nil || v < min || v > max {
			errs = append(errs, fmt.Errorf("%s must be an integer between %d and %d", key, min, max))
		}
		return v
	}
	c.SourceStoreDir = get("PATHOS_SOURCE_STORE_DIR", "/var/lib/pathos/sources")
	c.SourceS3Prefix = get("PATHOS_SOURCE_S3_PREFIX", "sources/")
	c.UploadMaxBytes = num("PATHOS_UPLOAD_MAX_BYTES", "2147483648", 1<<20, 64<<30)
	c.ImportMaxFiles = int(num("PATHOS_IMPORT_MAX_FILES", "200000", 1, 10_000_000))
	c.ImportMaxExtractedBytes = num("PATHOS_IMPORT_MAX_EXTRACTED_BYTES", "8589934592", 1<<20, 1<<40)
	c.ImportMaxFileBytes = num("PATHOS_IMPORT_MAX_FILE_BYTES", "1073741824", 1<<10, 1<<40)
	c.ImportConcurrency = int(num("PATHOS_IMPORT_CONCURRENCY", "2", 1, 64))
	c.ImportTimeout = dur("PATHOS_IMPORT_TIMEOUT", "30m")
	if c.ConnectorCheckInterval < 5*time.Minute || c.ConnectorCheckInterval > 7*24*time.Hour {
		errs = append(errs, fmt.Errorf("PATHOS_CONNECTOR_CHECK_INTERVAL must be between 5m and 168h"))
	}
	c.ImportWorkDir = get("PATHOS_IMPORT_WORK_DIR", "/tmp/pathos-import")
	c.ScanLogRetentionDays = int(num("PATHOS_SCAN_LOG_RETENTION_DAYS", "400", 360, 3650))
	c.ClamAVAddress = get("PATHOS_CLAMAV_ADDRESS", "")
	c.ClamAVRequired = get("PATHOS_CLAMAV_REQUIRED", "false") == "true"
	if c.ClamAVRequired && c.ClamAVAddress == "" {
		errs = append(errs, errors.New("PATHOS_CLAMAV_REQUIRED needs PATHOS_CLAMAV_ADDRESS"))
	}

	switch c.Env {
	case "development", "production":
	default:
		errs = append(errs, fmt.Errorf("PATHOS_ENV must be development or production, got %q", c.Env))
	}
	switch c.Role {
	case RoleAPI, RoleJobs, RoleScheduler:
	default:
		errs = append(errs, fmt.Errorf("PATHOS_ROLE must be api, jobs or scheduler, got %q", c.Role))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("PATHOS_LOG_LEVEL must be debug, info, warn or error, got %q", c.LogLevel))
	}
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("PATHOS_DATABASE_URL is required"))
	}
	if c.WorkerBootstrapToken != "" && len(c.WorkerBootstrapToken) < 32 {
		errs = append(errs, errors.New("PATHOS_WORKER_BOOTSTRAP_TOKEN must be at least 32 characters"))
	}
	if v, err := strconv.ParseFloat(get("PATHOS_RATE_LIMIT_SCALE", "1"), 64); err != nil || v < 0 || v > 1000 {
		errs = append(errs, errors.New("PATHOS_RATE_LIMIT_SCALE must be a number between 0 (disabled) and 1000"))
	} else {
		c.RateLimitScale = v
	}
	if c.S3Bucket != "" && (c.S3AccessKey == "" || c.S3SecretKey == "") {
		errs = append(errs, errors.New("PATHOS_S3_BUCKET requires PATHOS_S3_ACCESS_KEY and PATHOS_S3_SECRET_KEY"))
	}
	if c.SCMAllowHTTP && c.IsProduction() {
		errs = append(errs, errors.New("PATHOS_SCM_ALLOW_HTTP is only allowed in development"))
	}
	if c.SessionIdleTTL > c.SessionAbsoluteTTL {
		errs = append(errs, errors.New("PATHOS_SESSION_IDLE_TTL must not exceed PATHOS_SESSION_ABSOLUTE_TTL"))
	}
	if !validSlug(c.OrgSlug) {
		errs = append(errs, fmt.Errorf("PATHOS_ORG_SLUG %q must be lowercase letters, digits and hyphens", c.OrgSlug))
	}

	keys, err := parseMasterKeys(get("PATHOS_MASTER_KEY", ""), get("PATHOS_MASTER_KEYS_PREVIOUS", ""))
	if err != nil {
		errs = append(errs, err)
	}
	c.MasterKeys = keys

	// The public URL is needed by the API (redirects) and the jobs role
	// (links in notifications).
	if pub := get("PATHOS_PUBLIC_URL", ""); pub != "" || c.Role == RoleAPI || c.Role == RoleJobs {
		u, err := url.Parse(pub)
		if pub == "" || err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			errs = append(errs, fmt.Errorf("PATHOS_PUBLIC_URL must be an absolute http(s) URL, got %q", pub))
		} else {
			if c.IsProduction() && u.Scheme != "https" {
				errs = append(errs, errors.New("PATHOS_PUBLIC_URL must use https in production"))
			}
			u.Path = strings.TrimRight(u.Path, "/")
			c.PublicURL = u
		}
	}
	if c.Role == RoleAPI {
		if c.RedisURL == "" {
			errs = append(errs, errors.New("PATHOS_REDIS_URL is required for role api"))
		}
		if c.OIDC.Issuer == "" {
			errs = append(errs, errors.New("PATHOS_OIDC_ISSUER is required for role api"))
		}
		if c.OIDC.ClientSecret == "" {
			errs = append(errs, errors.New("PATHOS_OIDC_CLIENT_SECRET is required for role api"))
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// parseMasterKeys parses the current key ("v<N>:<base64>" or bare base64,
// which is version 1) and a comma-separated list of previous keys.
func parseMasterKeys(current, previous string) (map[int][]byte, error) {
	keys := map[int][]byte{}
	if current == "" {
		return nil, errors.New("PATHOS_MASTER_KEY is required (32 random bytes, base64; generate with: openssl rand -base64 32)")
	}
	parse := func(s string) (int, []byte, error) {
		ver := 1
		if strings.HasPrefix(s, "v") {
			if i := strings.IndexByte(s, ':'); i > 1 {
				n, err := strconv.Atoi(s[1:i])
				if err != nil || n < 1 {
					return 0, nil, errors.New("master key version must be a positive integer")
				}
				ver, s = n, s[i+1:]
			}
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
		if err != nil {
			return 0, nil, errors.New("master key is not valid base64")
		}
		if len(b) != 32 {
			return 0, nil, fmt.Errorf("master key must decode to 32 bytes, got %d", len(b))
		}
		return ver, b, nil
	}
	v, k, err := parse(current)
	if err != nil {
		return nil, fmt.Errorf("PATHOS_MASTER_KEY: %w", err)
	}
	keys[v] = k
	for _, p := range strings.Split(previous, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		pv, pk, err := parse(p)
		if err != nil {
			return nil, fmt.Errorf("PATHOS_MASTER_KEYS_PREVIOUS: %w", err)
		}
		if pv >= v {
			return nil, errors.New("PATHOS_MASTER_KEYS_PREVIOUS versions must be lower than the current key version")
		}
		keys[pv] = pk
	}
	return keys, nil
}

func validSlug(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

package connectors

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/secrets"
)

// Health states of a connector (the contract of /api/v1/connectors).
const (
	StatusHealthy  = "healthy"
	StatusDegraded = "degraded"
	StatusFailing  = "failing"
	StatusUnknown  = "unknown"
	StatusDisabled = "disabled"
)

// Step states.
const (
	StepPass    = "pass"
	StepWarn    = "warn"
	StepFail    = "fail"
	StepSkipped = "skipped"
)

// Connector is one registry row joined with its source.
type Connector struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	Kind        string
	SourceTable string // "" for kinds stored in the registry
	SourceKey   string
	Name        string
	Enabled     bool
	// Config is the stored configuration of a registry kind.
	Config   map[string]any
	SecretID *uuid.UUID
	// Meta is the non-secret metadata of the source (host, auth method,
	// allow_private, ...). It is shown in the detail view and sent, after
	// redaction, as AI troubleshooting context.
	Meta map[string]string
	// LastSyncAt comes from the source (last inventory, delivery, feed run).
	LastSyncAt *time.Time

	Status           string
	LastCheckAt      *time.Time
	LastOKAt         *time.Time
	LastErrorCode    string
	CheckRequestedAt *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Target is what a checker receives.
type Target struct {
	Connector
	// Credential reveals the credential of a registry kind (nil when none
	// is stored). Legacy kinds load their own through their service.
	Credential func(ctx context.Context) ([]byte, error)
}

// Step is one part of a health check (reachability, authentication, ...).
type Step struct {
	Check     string `json:"check"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Result is the outcome of one health check.
type Result struct {
	Status    string
	ErrorCode string
	// Message is a short, redacted explanation (never a credential, URL
	// query or response body).
	Message  string
	Steps    []Step
	Observed map[string]any
}

// Env is what checkers may use. Fields are optional: a checker reports
// "unknown" with a reason when the dependency it needs is missing.
type Env struct {
	DB      *pgxpool.Pool
	Secrets *secrets.Store
	Log     *slog.Logger
	// Role is "api" or "jobs" (the process running the check).
	Role    string
	Offline bool

	SCM         SCMChecker
	Tickets     TicketChecker
	Notify      NotifyChecker
	Runtime     RuntimeChecker
	AI          AIChecker
	ObjectStore ObjectStorePinger
	// SCMCreator creates the scm_connections row of a creatable SCM kind
	// (*repos.Service).
	SCMCreator SCMCreator
	// ObjectStoreMeta describes the object store (endpoint host, bucket).
	ObjectStoreMeta map[string]string
	// EgressProxy is the egress proxy URL (PATHOS_EGRESS_PROXY_URL); ""
	// when the installation does not use one.
	EgressProxy string
	// HTTP builds an outbound client applying the network policy (kinds
	// stored in the registry); tests override it.
	HTTP func(allowPrivate bool) *http.Client
	// Now is the clock (tests).
	Now func() time.Time
	// Interval is how often the jobs service checks each connector
	// (default 1 hour); a check older than twice the interval no longer
	// counts (the connector shows unknown, never an old "healthy").
	Interval time.Duration
}

func (e *Env) interval() time.Duration {
	if e != nil && e.Interval > 0 {
		return e.Interval
	}
	return time.Hour
}

func (e *Env) now() time.Time {
	if e != nil && e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// The legacy services implement these (wired in internal/server and
// cmd/pathos). Each reuses the service's own client and credential
// handling; the connectors package never reads a legacy credential itself.
type (
	// SCMChecker is repos.Service.
	SCMChecker interface {
		CheckConnection(ctx context.Context, orgID, id uuid.UUID) (SCMCheck, error)
	}
	// TicketChecker is tickets.Service.
	TicketChecker interface {
		CheckConnection(ctx context.Context, orgID, id uuid.UUID) (string, error)
	}
	// NotifyChecker is notify.Service.
	NotifyChecker interface {
		ProbeSMTP(ctx context.Context, orgID uuid.UUID) (SMTPProbe, error)
		CheckWebhook(ctx context.Context, orgID, id uuid.UUID) (WebhookCheck, error)
	}
	// RuntimeChecker is runtimectx.Service.
	RuntimeChecker interface {
		CheckCluster(ctx context.Context, orgID, id uuid.UUID) (ClusterCheck, error)
		CheckRegistry(ctx context.Context, orgID, id uuid.UUID) (RegistryCheck, error)
	}
	// AIChecker is ai.Service.
	AIChecker interface {
		ListModels(ctx context.Context, orgID, id uuid.UUID) (int, error)
	}
	// ObjectStorePinger is the object store (HeadBucket).
	ObjectStorePinger interface {
		Ping(ctx context.Context) error
	}
)

// SCMCheck is what an SCM connection check reports.
type SCMCheck struct {
	Account        string
	TokenExpiresAt *time.Time
	// Webhook verification in use for GitLab: "signature" or "token".
	GitLabWebhookAuth string
	// RateLimitRemaining, RateLimitLimit (when the provider reports them).
	RateLimitRemaining int
	RateLimitLimit     int
}

// SMTPProbe is what an SMTP probe reports (no message is sent).
type SMTPProbe struct {
	Configured bool
	Enabled    bool
	TLS        string // starttls | tls | none
	Auth       bool   // AUTH succeeded (false when no credentials are set)
}

// WebhookCheck is the state of an outbound webhook. No message is posted.
type WebhookCheck struct {
	Format string // json | slack | teams
	Host   string
	// LastStatus is the last finished delivery ("succeeded", "failed")
	// and LastAt its time; "" when nothing was delivered yet.
	LastStatus   string
	LastAt       *time.Time
	LastResponse int
	Failed24h    int
	// TriggerAuth (Teams): an Entra app is configured, and whether a
	// token was obtained now ("" when not configured).
	TriggerAuth      bool
	TriggerAuthError error
}

// ClusterCheck is what a Kubernetes check reports.
type ClusterCheck struct {
	ServerVersion string
	Readable      []string
	Denied        []string
	LongLived     bool
}

// RegistryCheck is what a registry check reports.
type RegistryCheck struct {
	Repository string
	Tags       int
	RateLimit  string // Docker Hub ratelimit-remaining
}

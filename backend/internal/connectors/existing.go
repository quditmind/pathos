package connectors

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/scanners"
	"pathos/internal/scm"
	"pathos/internal/tickets"
)

// The kinds PATHOS 2.2 already connects to, with the permissions of their
// existing pages and their health checks. Statuses follow
// docs/aspm/PATHOS_INTEGRATION_TECHNICAL_SPEC.md (connector inventory).

var (
	scmRead      = anywhere(authz.PermReposRead)
	scmManage    = orgWide(authz.PermSCMManage)
	ticketRead   = either(anywhere(authz.PermFindingsTriage), orgWide(authz.PermSettingsManage))
	settings     = orgWide(authz.PermSettingsManage)
	notifyManage = orgWide(authz.PermNotificationsManage)
	runtimeRead  = orgWide(authz.PermFindingsRead, authz.PermSettingsManage)
	aiRead       = either(anywhere(authz.PermAIReview), orgWide(authz.PermAIConfigure))
	aiManage     = orgWide(authz.PermAIConfigure)
	feedRead     = anywhere(authz.PermFindingsRead)
)

// publicSCMHosts are SCM API hosts on the internet (disabled offline).
var publicSCMHosts = []string{"api.github.com", "gitlab.com", "api.bitbucket.org", "dev.azure.com"}

func scmNeedsInternet(meta map[string]string, _ map[string]any) bool {
	u, err := url.Parse(meta["host"])
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, p := range publicSCMHosts {
		if h == p || strings.HasSuffix(h, ".visualstudio.com") {
			return true
		}
	}
	return false
}

func hostNeedsInternet(suffixes ...string) func(map[string]string, map[string]any) bool {
	return func(meta map[string]string, _ map[string]any) bool {
		u, err := url.Parse(meta["host"])
		if err != nil {
			return false
		}
		h := strings.ToLower(u.Hostname())
		for _, s := range suffixes {
			if h == s || strings.HasSuffix(h, "."+s) {
				return true
			}
		}
		return false
	}
}

func init() {
	scm := func(kind, label, status, note string, offline bool, auth ...string) Kind {
		return Kind{Kind: kind, Category: "scm_ide", Label: label, Status: status, AuthMethods: auth, OfflineOK: offline, Direction: Outbound,
			ManagedAt: "/admin/scm", CheckedBy: RunsInAPI, Source: "scm_connections", Checker: CheckFunc(checkSCM), Note: note,
			CanRead: scmRead, CanManage: scmManage, NeedsInternet: scmNeedsInternet}
	}
	for _, k := range []Kind{
		scm("github", "GitHub", KindExisting, "", false, "github_app", "pat", "oauth"),
		scm("github_enterprise", "GitHub Enterprise Server", KindPartial, "No per-connection CA bundle yet.", true, "github_app", "pat", "oauth"),
		scm("gitlab", "GitLab (gitlab.com and self-managed)", KindExisting, "Webhooks: signing token (HMAC) or the legacy secret token.", true, "pat", "oauth"),
		scm("bitbucket", "Bitbucket Cloud", KindExisting, "", false, "api_token", "pat", "oauth"),
		scm("azure_devops", "Azure DevOps Services", KindExisting, "", false, "service_principal", "pat", "oauth"),
		scm("azure_devops_server", "Azure DevOps Server", KindExisting, "", true, "pat"),

		{Kind: "jira", Category: "monitoring", Label: "Jira", Status: KindExisting, AuthMethods: []string{"basic", "scoped_api_token", "bearer"},
			OfflineOK: true, Direction: Outbound, ManagedAt: "/admin/integrations", CheckedBy: RunsInAPI, Source: "ticket_connections",
			Checker: CheckFunc(checkTicket), CanRead: ticketRead, CanManage: settings, NeedsInternet: hostNeedsInternet("atlassian.net")},
		{Kind: "servicenow", Category: "monitoring", Label: "ServiceNow", Status: KindExisting, AuthMethods: []string{"basic", "bearer"},
			OfflineOK: true, Direction: Outbound, ManagedAt: "/admin/integrations", CheckedBy: RunsInAPI, Source: "ticket_connections",
			Checker: CheckFunc(checkTicket), CanRead: ticketRead, CanManage: settings, NeedsInternet: hostNeedsInternet("service-now.com", "servicenowservices.com")},

		{Kind: "webhook", Category: "monitoring", Label: "Webhooks (signed JSON)", Status: KindExisting, AuthMethods: []string{"hmac_signature"},
			OfflineOK: true, Direction: Outbound, ManagedAt: "/admin/notifications", CheckedBy: RunsInAPI, Source: "outbound_webhooks",
			Checker: CheckFunc(checkWebhook), CanRead: notifyManage, CanManage: notifyManage, NeedsInternet: func(map[string]string, map[string]any) bool { return false }},
		{Kind: "slack", Category: "monitoring", Label: "Slack", Status: KindExisting, AuthMethods: []string{"incoming_webhook_url"},
			Direction: Outbound, ManagedAt: "/admin/notifications", CheckedBy: RunsInAPI, Source: "outbound_webhooks",
			Checker: CheckFunc(checkWebhook), CanRead: notifyManage, CanManage: notifyManage},
		{Kind: "teams", Category: "monitoring", Label: "Microsoft Teams (Workflows)", Status: KindExisting, AuthMethods: []string{"workflows_url", "entra_client_credentials"},
			Direction: Outbound, ManagedAt: "/admin/notifications", CheckedBy: RunsInAPI, Source: "outbound_webhooks",
			Note: "Office 365 connector webhooks were retired in May 2026; use a Workflows trigger.", Checker: CheckFunc(checkWebhook),
			CanRead: notifyManage, CanManage: notifyManage},
		{Kind: "smtp", Category: "monitoring", Label: "E-mail (SMTP)", Status: KindExisting, AuthMethods: []string{"none", "password"},
			OfflineOK: true, Direction: Outbound, ManagedAt: "/admin/notifications", CheckedBy: RunsInAPI, Source: "smtp_settings",
			Checker: CheckFunc(checkSMTP), CanRead: notifyManage, CanManage: notifyManage},

		{Kind: "kubernetes", Category: "containers", Label: "Kubernetes", Status: KindExisting, AuthMethods: []string{"service_account_token", "kubeconfig"},
			OfflineOK: true, Direction: Outbound, ManagedAt: "/runtime", CheckedBy: RunsInJobs, Source: "runtime_clusters",
			Checker: CheckFunc(checkCluster), CanRead: runtimeRead, CanManage: settings},
		{Kind: "container_registry", Category: "containers", Label: "Container registries (OCI)", Status: KindPartial,
			AuthMethods: []string{"none", "basic", "bearer"}, OfflineOK: true, Direction: Outbound, ManagedAt: "/runtime", CheckedBy: RunsInJobs,
			Note: "No ECR, ACR or Artifact Registry token exchange yet.", Source: "registry_connections", Checker: CheckFunc(checkRegistry),
			CanRead: runtimeRead, CanManage: settings,
			NeedsInternet: hostNeedsInternet("docker.io", "ghcr.io", "amazonaws.com", "azurecr.io", "pkg.dev", "gcr.io", "quay.io")},

		{Kind: "ai_provider", Category: "apis", Label: "AI providers", Status: KindExisting, AuthMethods: []string{"api_key", "none"},
			OfflineOK: true, Direction: Outbound, ManagedAt: "/admin/ai", CheckedBy: RunsInAPI, Source: "ai_providers",
			Checker: CheckFunc(checkAI), CanRead: aiRead, CanManage: aiManage,
			NeedsInternet: func(meta map[string]string, _ map[string]any) bool { return meta["provider"] != "self_hosted" }},

		{Kind: "vulnerability_feed", Category: "security", Label: "Vulnerability and end-of-life feeds", Status: KindExisting,
			AuthMethods: []string{"none"}, OfflineOK: true, Direction: Outbound, ManagedAt: "/admin/risk-intelligence", CheckedBy: RunsInAPI,
			Note: "Air-gapped installs import the feed files.", Source: "intel_feeds", Checker: CheckFunc(checkFeed), CanRead: feedRead, CanManage: settings},
		{Kind: "secret_validation", Category: "security", Label: "Live secret validation", Status: KindExisting, AuthMethods: []string{"none"},
			Direction: Outbound, ManagedAt: "/admin/secret-validation", CheckedBy: RunsInAPI, Source: "secret_validation_settings",
			Note: "Checked as configuration only: a live check would need a real secret.", Checker: CheckFunc(checkSecretValidation),
			CanRead: settings, CanManage: settings},
		{Kind: "object_storage", Category: "cloud", Label: "S3-compatible object storage", Status: KindPartial, AuthMethods: []string{"access_key"},
			OfflineOK: true, Direction: Platform, CheckedBy: RunsInAPI, Note: "Static access keys only (no IAM role); configured by environment.",
			Source: tableObjectStore, Checker: CheckFunc(checkObjectStore), CanRead: settings, CanManage: settings},
		{Kind: "egress_proxy", Category: "security", Label: "Egress proxy (scanner allowlist)", Status: KindExisting, AuthMethods: []string{"none"},
			OfflineOK: true, Direction: Platform, CheckedBy: RunsInJobs, Note: "Configured by environment (PATHOS_EGRESS_PROXY_URL).",
			Source: tableEgressProxy, Checker: CheckFunc(checkEgress), CanRead: settings, CanManage: settings},
	} {
		RegisterKind(k)
	}

	// Inbound and catalogue-only integrations: listed in the hub, no
	// connector rows (they call PATHOS, or have no health check yet).
	inbound := func(kind, cat, label, managed string, auth ...string) Kind {
		return Kind{Kind: kind, Category: cat, Label: label, Status: KindExisting, AuthMethods: auth, OfflineOK: true, Direction: Inbound, ManagedAt: managed}
	}
	for _, k := range []Kind{
		inbound("pathos_cli", "scm_ide", "PATHOS CLI", "/settings/tokens", "api_token"),
		inbound("vscode", "scm_ide", "VS Code extension", "/settings/tokens", "api_token"),
		inbound("jetbrains", "scm_ide", "JetBrains IDEs plugin", "/settings/tokens", "api_token"),
		inbound("github_actions", "cicd", "GitHub Actions", "/settings/tokens", "api_token"),
		inbound("gitlab_ci", "cicd", "GitLab CI/CD", "/settings/tokens", "api_token"),
		inbound("azure_pipelines", "cicd", "Azure Pipelines", "/settings/tokens", "api_token"),
		inbound("jenkins", "cicd", "Jenkins", "/settings/tokens", "api_token"),
		inbound("pre_commit", "cicd", "pre-commit and pre-receive hooks", "/settings/tokens", "api_token"),
		inbound("scanner_import", "security", "Scanner result import", "/scans/imports", "api_token"),
		inbound("mcp_api", "apis", "PATHOS REST API and MCP", "/settings/tokens", "api_token"),
		{Kind: "mcp_registry", Category: "apis", Label: "MCP registry (outbound MCP servers)", Status: KindExisting, AuthMethods: []string{"bearer", "none"},
			OfflineOK: true, Direction: Outbound, ManagedAt: "/admin/mcp", Note: "Approval and per-tool allow lists; no health check yet."},
		{Kind: "keycloak_sso", Category: "iam_secrets", Label: "Keycloak sign-in and SAML/OIDC SSO", Status: KindExisting, AuthMethods: []string{"oidc", "saml"},
			OfflineOK: true, Direction: Platform, Note: "Identity providers are configured in Keycloak."},
		{Kind: "sigstore", Category: "containers", Label: "Sigstore signature verification", Status: KindExisting, AuthMethods: []string{"public_key", "keyless"},
			OfflineOK: true, Direction: Outbound, ManagedAt: "/scans/targets", Note: "Keyless verification needs the internet."},
		{Kind: "deps_dev", Category: "security", Label: "deps.dev package health", Status: KindExisting, AuthMethods: []string{"none"},
			Direction: Outbound, Note: "Not available offline."},
		{Kind: "opentelemetry", Category: "monitoring", Label: "OpenTelemetry export", Status: KindExisting, AuthMethods: []string{"otlp_headers"},
			OfflineOK: true, Direction: Platform, Note: "Configured by environment (OTEL_EXPORTER_OTLP_ENDPOINT)."},
		{Kind: "openapi", Category: "apis", Label: "OpenAPI / Swagger", Status: KindPartial, AuthMethods: []string{"file"},
			OfflineOK: true, Direction: Inbound, ManagedAt: "/scans/targets", Note: "File upload for API scan targets."},
	} {
		RegisterKind(k)
	}

	// Planned kinds (docs/aspm/PATHOS_ARCHITECTURE_ASSESSMENT.md §8.6). A
	// builder implementing one registers it again (RegisterKind replaces a
	// planned entry).
	planned := func(kind, cat, label, note string, offline bool, auth ...string) Kind {
		return Kind{Kind: kind, Category: cat, Label: label, Status: KindPlanned, AuthMethods: auth, OfflineOK: offline, Direction: Outbound, Note: note}
	}
	for _, k := range []Kind{
		planned("generic_git", "scm_ide", "Generic Git (HTTPS/SSH)", "", true, "ssh_key", "https_token"),
		planned("bitbucket_data_center", "scm_ide", "Bitbucket Data Center", "", true, "http_access_token"),
		planned("bitbucket_pipelines", "cicd", "Bitbucket Pipelines", "", true, "api_token"),
		planned("vault", "iam_secrets", "HashiCorp Vault / OpenBao", "", true, "approle", "kubernetes"),
		planned("cloud_secret_manager", "iam_secrets", "Cloud secret managers", "Follows Vault.", false, "cloud_identity"),
		planned("aws", "cloud", "Amazon Web Services", "", false, "assume_role"),
		planned("azure", "cloud", "Microsoft Azure", "", false, "workload_identity", "service_principal_certificate"),
		planned("gcp", "cloud", "Google Cloud", "", false, "workload_identity"),
		planned("splunk", "security", "Splunk HTTP Event Collector", "", true, "hec_token"),
		planned("sentinel", "security", "Microsoft Sentinel", "", false, "entra_app"),
		planned("elastic", "security", "Elastic", "", true, "api_key"),
		planned("postman", "apis", "Postman collections", "With API discovery (M4).", true, "file", "api_key"),
		planned("graphql", "apis", "GraphQL schema", "With API discovery (M4).", true, "file", "bearer"),
		planned("prometheus", "monitoring", "Prometheus metrics", "", true, "none"),
		planned("argo_cd", "cicd", "Argo CD / deploy gate", "After the lifecycle release.", true, "api_token"),
		planned("visual_studio", "scm_ide", "Visual Studio", "After the lifecycle release.", true, "api_token"),
		planned("api_gateway", "apis", "API gateways", "After the lifecycle release.", false, "api_key"),
		planned("database", "databases", "Databases (PostgreSQL, MySQL, SQL Server, MongoDB, Oracle)", "After the lifecycle release.", true, "read_only_account"),
	} {
		RegisterKind(k)
	}
}

func legacyID(t Target) (uuid.UUID, Result, bool) {
	id, err := uuid.Parse(t.SourceKey)
	if err != nil {
		return id, Result{Status: StatusUnknown, Message: "the connector has no valid source"}, false
	}
	return id, Result{}, true
}

func unavailable(what string) Result {
	return Result{Status: StatusUnknown, Message: what + " is not available in this process"}
}

func failed(step string, err error, code string) Result {
	if code == "" {
		code = Classify(err)
	}
	msg := err.Error()
	return Result{Status: StatusFailing, ErrorCode: code, Message: msg, Steps: []Step{{Check: step, Status: StepFail, ErrorCode: code, Detail: msg}}}
}

// expiryStep warns when a credential expires within 14 days.
func expiryStep(now time.Time, exp *time.Time) (Step, bool) {
	if exp == nil {
		return Step{}, false
	}
	left := exp.Sub(now)
	switch {
	case left <= 0:
		return Step{Check: "credential_expiry", Status: StepFail, ErrorCode: "PTH-CONN-1008", Detail: "the credential expired " + exp.UTC().Format(time.DateOnly)}, true
	case left < 14*24*time.Hour:
		return Step{Check: "credential_expiry", Status: StepWarn, ErrorCode: "PTH-CONN-1021", Detail: "the credential expires " + exp.UTC().Format(time.DateOnly)}, true
	}
	return Step{Check: "credential_expiry", Status: StepPass, Detail: "expires " + exp.UTC().Format(time.DateOnly)}, true
}

// summarize derives the status from the steps: any fail → failing (first
// failing code), any warn → degraded (first warning code), else healthy.
func summarize(steps []Step, msg string, observed map[string]any) Result {
	r := Result{Status: StatusHealthy, Message: msg, Steps: steps, Observed: observed}
	for _, s := range steps {
		switch s.Status {
		case StepFail:
			if r.Status != StatusFailing {
				r.Status, r.ErrorCode, r.Message = StatusFailing, s.ErrorCode, s.Detail
			}
		case StepWarn:
			if r.Status == StatusHealthy && s.ErrorCode != "" && !infoOnly[s.ErrorCode] {
				r.Status, r.ErrorCode = StatusDegraded, s.ErrorCode
				if s.Detail != "" {
					r.Message = s.Detail
				}
			}
		}
	}
	return r
}

// infoOnly codes are reported as warnings on a step without degrading the
// connector (advice, not a fault).
var infoOnly = map[string]bool{"PTH-CONN-1112": true, "PTH-CONN-1514": true}

func checkSCM(ctx context.Context, env *Env, t Target) Result {
	if env.SCM == nil {
		return unavailable("the SCM service")
	}
	id, r, ok := legacyID(t)
	if !ok {
		return r
	}
	res, err := env.SCM.CheckConnection(ctx, t.OrgID, id)
	if err != nil {
		return failed("authentication", err, "")
	}
	steps := []Step{{Check: "authentication", Status: StepPass, Detail: "authenticated as " + res.Account}}
	if s, ok := expiryStep(env.now(), res.TokenExpiresAt); ok {
		steps = append(steps, s)
	}
	switch res.GitLabWebhookAuth {
	case "token":
		steps = append(steps, Step{Check: "webhook", Status: StepWarn, ErrorCode: "PTH-CONN-1112",
			Detail: "GitLab deliveries are verified with the legacy secret token; add the webhook signing token (GitLab 19.0+)"})
	case "signature":
		steps = append(steps, Step{Check: "webhook", Status: StepPass, Detail: "deliveries must carry a valid signature"})
	}
	obs := map[string]any{"api_version": t.Meta["api_version"]}
	if res.RateLimitLimit > 0 {
		obs["rate_limit_remaining"], obs["rate_limit_limit"] = res.RateLimitRemaining, res.RateLimitLimit
	}
	return summarize(steps, "authenticated as "+res.Account, obs)
}

func checkTicket(ctx context.Context, env *Env, t Target) Result {
	if env.Tickets == nil {
		return unavailable("the ticketing service")
	}
	id, r, ok := legacyID(t)
	if !ok {
		return r
	}
	who, err := env.Tickets.CheckConnection(ctx, t.OrgID, id)
	if err == nil {
		return summarize([]Step{{Check: "authentication", Status: StepPass, Detail: "authenticated as " + who}}, "authenticated as "+who, nil)
	}
	code := Classify(err)
	var he *tickets.HTTPError
	isHTTP := errors.As(err, &he)
	switch {
	case scm.UntrustedCertificate(err):
		// The connection takes a private CA bundle (2.2.2): name that fix.
		code = scm.DiagCAUntrusted
	case errors.Is(err, tickets.ErrCloudID):
		code = "PTH-CONN-1205"
	case t.Kind == "jira" && strings.Contains(err.Error(), "project ") && isHTTP && he.Status == http.StatusNotFound:
		code = "PTH-CONN-1201"
	case t.Kind == "servicenow" && isHTTP && he.Status == http.StatusForbidden:
		code = "PTH-CONN-1210"
	case t.Kind == "servicenow" && isHTTP && he.Status == http.StatusTooManyRequests:
		code = "PTH-CONN-1211"
	}
	res := failed("authentication", err, code)
	// A Jira Cloud token with scopes is refused by the site URL (401):
	// say so, without claiming it is the cause.
	if t.Kind == "jira" && code == "PTH-CONN-1007" && strings.HasSuffix(strings.ToLower(t.Meta["host"]), ".atlassian.net") &&
		!strings.HasPrefix(t.Meta["token_type"], "scoped") {
		res.Steps = append(res.Steps, Step{Check: "token_type", Status: StepWarn, ErrorCode: "PTH-CONN-1203",
			Detail: "if this is an API token with scopes, set the token type to scoped: such tokens only work through api.atlassian.com"})
	}
	return res
}

func checkWebhook(ctx context.Context, env *Env, t Target) Result {
	if env.Notify == nil {
		return unavailable("the notification service")
	}
	id, r, ok := legacyID(t)
	if !ok {
		return r
	}
	h, err := env.Notify.CheckWebhook(ctx, t.OrgID, id)
	if err != nil {
		return failed("configuration", err, "")
	}
	var steps []Step
	obs := map[string]any{"failed_24h": h.Failed24h}
	if h.Format == "teams" {
		host := strings.ToLower(strings.TrimPrefix(t.Meta["host"], "https://"))
		if host == "outlook.office.com" || strings.HasSuffix(host, "webhook.office.com") {
			return summarize([]Step{{Check: "configuration", Status: StepFail, ErrorCode: "PTH-CONN-1310",
				Detail: "this is a retired Office 365 connector URL; create a Workflows webhook"}}, "", obs)
		}
		if h.TriggerAuth {
			if h.TriggerAuthError != nil {
				steps = append(steps, Step{Check: "authentication", Status: StepFail, ErrorCode: "PTH-CONN-1313", Detail: h.TriggerAuthError.Error()})
			} else {
				steps = append(steps, Step{Check: "authentication", Status: StepPass, Detail: "Microsoft Entra issued a token for the Workflows trigger"})
			}
		}
	}
	switch h.LastStatus {
	case "":
		if len(steps) > 0 && steps[0].Status == StepFail {
			return summarize(steps, "", obs)
		}
		return Result{Status: StatusUnknown, Steps: append(steps, Step{Check: "last_delivery", Status: StepSkipped,
			Detail: "nothing delivered yet; a webhook has no read-only endpoint, so PATHOS does not post a message to check it (use Send test)"}),
			Message: "No delivery yet. Use Send test on the Notifications page to check the endpoint.", Observed: obs}
	case "succeeded":
		at := ""
		if h.LastAt != nil {
			at = " at " + h.LastAt.UTC().Format(time.RFC3339)
		}
		steps = append(steps, Step{Check: "last_delivery", Status: StepPass, Detail: "last delivery succeeded" + at})
		if h.Failed24h > 0 {
			steps = append(steps, Step{Check: "deliveries_24h", Status: StepWarn, ErrorCode: "PTH-SYNC-1005",
				Detail: strconv.Itoa(h.Failed24h) + " deliveries failed in the last 24 hours"})
		}
	default:
		code := "PTH-SYNC-1005"
		st := h.LastResponse
		switch {
		case h.Format == "slack" && (st == http.StatusNotFound || st == http.StatusGone):
			code = "PTH-CONN-1301"
		case h.Format == "slack" && st == http.StatusBadRequest:
			code = "PTH-CONN-1303"
		case h.Format == "slack" && st == http.StatusForbidden:
			code = "PTH-CONN-1302"
		case h.Format == "teams" && (st == http.StatusUnauthorized || st == http.StatusForbidden):
			code = "PTH-CONN-1311"
		case h.Format == "teams" && st == http.StatusRequestEntityTooLarge:
			code = "PTH-CONN-1312"
		case st >= 400 && st < 500 && st != 408 && st != 429:
			code = "PTH-CONN-1330"
		}
		obs["last_response_status"] = st
		steps = append(steps, Step{Check: "last_delivery", Status: StepFail, ErrorCode: code, Detail: fmt.Sprintf("the last delivery failed (HTTP %d)", st)})
	}
	return summarize(steps, "", obs)
}

// SMTP probe failure stages (notify.SMTPError) mapped by the server
// adapter onto these sentinel errors.
var (
	ErrSMTPNoSTARTTLS = errors.New("the mail server does not offer STARTTLS")
	ErrSMTPAuth       = errors.New("the mail server rejected the login")
)

func checkSMTP(ctx context.Context, env *Env, t Target) Result {
	if env.Notify == nil {
		return unavailable("the notification service")
	}
	p, err := env.Notify.ProbeSMTP(ctx, t.OrgID)
	switch {
	case err == nil && !p.Configured:
		return Result{Status: StatusDisabled, Message: "no mail relay is configured"}
	case err == nil && !p.Enabled:
		return Result{Status: StatusDisabled, Message: "e-mail delivery is turned off"}
	case errors.Is(err, ErrSMTPNoSTARTTLS):
		return failed("tls", err, "PTH-CONN-1320")
	case errors.Is(err, ErrSMTPAuth):
		return failed("authentication", err, "PTH-CONN-1321")
	case err != nil:
		return failed("connect", err, "")
	}
	steps := []Step{{Check: "reachability", Status: StepPass, Detail: "the server greeted PATHOS (no message sent)"}}
	if p.TLS != "none" {
		steps = append(steps, Step{Check: "tls", Status: StepPass, Detail: p.TLS})
	} else {
		steps = append(steps, Step{Check: "tls", Status: StepWarn, Detail: "the relay is used without TLS"})
	}
	if p.Auth {
		steps = append(steps, Step{Check: "authentication", Status: StepPass, Detail: "login accepted"})
	}
	return summarize(steps, "the mail relay accepted the connection", map[string]any{"tls_mode": p.TLS})
}

var k8sMinor = regexp.MustCompile(`^v?1\.(\d+)`)

// OldestSupportedKubernetesMinor is the oldest Kubernetes minor release with
// upstream support (1.35, 1.36 and 1.37 on 2026-11-20; https://kubernetes.io/releases/).
var OldestSupportedKubernetesMinor = 35

func checkCluster(ctx context.Context, env *Env, t Target) Result {
	if env.Runtime == nil {
		return unavailable("the runtime service")
	}
	id, r, ok := legacyID(t)
	if !ok {
		return r
	}
	h, err := env.Runtime.CheckCluster(ctx, t.OrgID, id)
	if err != nil {
		return failed("reachability", err, "")
	}
	steps := []Step{{Check: "authentication", Status: StepPass, Detail: "the API server accepted the credential"}}
	obs := map[string]any{"server_version": h.ServerVersion, "readable": h.Readable, "denied": h.Denied}
	if m := k8sMinor.FindStringSubmatch(h.ServerVersion); m != nil {
		if minor, _ := strconv.Atoi(m[1]); minor < OldestSupportedKubernetesMinor {
			steps = append(steps, Step{Check: "api_version", Status: StepWarn, ErrorCode: "PTH-CONN-1513",
				Detail: "Kubernetes " + h.ServerVersion + " is out of upstream support"})
		} else {
			steps = append(steps, Step{Check: "api_version", Status: StepPass, Detail: h.ServerVersion})
		}
	}
	switch {
	case len(h.Readable) == 0 && len(h.Denied) > 0:
		steps = append(steps, Step{Check: "scopes", Status: StepFail, ErrorCode: "PTH-CONN-1009", Detail: "the role cannot list any of the resource kinds"})
	case len(h.Denied) > 0:
		steps = append(steps, Step{Check: "scopes", Status: StepWarn, ErrorCode: "PTH-CONN-1512",
			Detail: "the role does not grant: " + strings.Join(h.Denied, ", ") + " (the inventory is partial)"})
	default:
		steps = append(steps, Step{Check: "scopes", Status: StepPass, Detail: "every resource kind is readable"})
	}
	if h.LongLived {
		steps = append(steps, Step{Check: "credential_expiry", Status: StepWarn, ErrorCode: "PTH-CONN-1514",
			Detail: "a service-account token without an expiry PATHOS can see; prefer a bound token and rotate it"})
	}
	return summarize(steps, "", obs)
}

func checkRegistry(ctx context.Context, env *Env, t Target) Result {
	if env.Runtime == nil {
		return unavailable("the runtime service")
	}
	id, r, ok := legacyID(t)
	if !ok {
		return r
	}
	h, err := env.Runtime.CheckRegistry(ctx, t.OrgID, id)
	obs := map[string]any{}
	if h.RateLimit != "" {
		obs["ratelimit_remaining"] = h.RateLimit
	}
	if err != nil {
		code := ""
		switch {
		case scm.UntrustedCertificate(err):
			// The registry connection takes a private CA bundle (2.2.2).
			code = scm.DiagCAUntrusted
		case Classify(err) == "PTH-CONN-1010" && strings.Contains(t.Meta["host"], "docker.io"):
			code = "PTH-CONN-1502"
		}
		res := failed("authentication", err, code)
		res.Observed = obs
		return res
	}
	steps := []Step{{Check: "reachability", Status: StepPass, Detail: "GET /v2/ answered"}}
	if h.Repository != "" {
		steps = append(steps, Step{Check: "authentication", Status: StepPass, Detail: "listed tags of " + h.Repository})
	}
	if strings.HasPrefix(h.RateLimit, "0;") || h.RateLimit == "0" {
		steps = append(steps, Step{Check: "rate_limit", Status: StepWarn, ErrorCode: "PTH-CONN-1502", Detail: "the Docker Hub pull limit is used up"})
	}
	return summarize(steps, "", obs)
}

func checkAI(ctx context.Context, env *Env, t Target) Result {
	if env.AI == nil {
		return unavailable("the AI service")
	}
	id, r, ok := legacyID(t)
	if !ok {
		return r
	}
	n, err := env.AI.ListModels(ctx, t.OrgID, id)
	if err != nil {
		return failed("authentication", err, "")
	}
	steps := []Step{{Check: "authentication", Status: StepPass, Detail: "the model list was returned (no tokens used)"}}
	if n == 0 {
		steps = append(steps, Step{Check: "models", Status: StepWarn, ErrorCode: "PTH-CONN-1022", Detail: "the provider lists no models (for a local server, pull one)"})
	}
	return summarize(steps, fmt.Sprintf("%d models available", n), map[string]any{"models": n})
}

func checkFeed(ctx context.Context, env *Env, t Target) Result {
	var interval int
	var status, msg string
	var finished, lastOK *time.Time
	err := env.DB.QueryRow(ctx, `SELECT f.interval_hours,
		  COALESCE((SELECT r.status FROM intel_feed_runs r WHERE r.feed = f.feed AND r.status <> 'running' ORDER BY r.started_at DESC LIMIT 1), ''),
		  COALESCE((SELECT r.error FROM intel_feed_runs r WHERE r.feed = f.feed AND r.status <> 'running' ORDER BY r.started_at DESC LIMIT 1), ''),
		  (SELECT r.finished_at FROM intel_feed_runs r WHERE r.feed = f.feed AND r.status <> 'running' ORDER BY r.started_at DESC LIMIT 1),
		  (SELECT max(r.finished_at) FROM intel_feed_runs r WHERE r.feed = f.feed AND r.status = 'succeeded')
		FROM intel_feeds f WHERE f.feed = $1`, t.SourceKey).Scan(&interval, &status, &msg, &finished, &lastOK)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Status: StatusUnknown, Message: "the feed is not configured"}
	}
	if err != nil {
		return failed("last_sync", err, "")
	}
	obs := map[string]any{"interval_hours": interval}
	if lastOK != nil {
		obs["last_success_at"] = lastOK.UTC().Format(time.RFC3339)
	}
	switch {
	case status == "":
		return Result{Status: StatusUnknown, Message: "the feed has not run yet", Observed: obs,
			Steps: []Step{{Check: "last_sync", Status: StepSkipped, Detail: "no run recorded"}}}
	case status == "failed":
		return summarize([]Step{{Check: "last_sync", Status: StepFail, ErrorCode: "PTH-SYNC-1020", Detail: "the last run failed: " + msg}}, "", obs)
	}
	if lastOK != nil && env.now().Sub(*lastOK) > 2*time.Duration(interval)*time.Hour {
		return summarize([]Step{{Check: "last_sync", Status: StepWarn, ErrorCode: "PTH-SYNC-1022",
			Detail: "the data is older than twice the feed interval (last success " + lastOK.UTC().Format(time.RFC3339) + ")"}}, "", obs)
	}
	return summarize([]Step{{Check: "last_sync", Status: StepPass, Detail: "the last run succeeded"}}, "", obs)
}

func checkSecretValidation(ctx context.Context, env *Env, t Target) Result {
	var providers []string
	err := env.DB.QueryRow(ctx, `SELECT providers FROM secret_validation_settings WHERE organization_id = $1`, t.OrgID).Scan(&providers)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && len(providers) == 0) {
		return Result{Status: StatusDisabled, Message: "no provider is enabled"}
	}
	if err != nil {
		return failed("configuration", err, "")
	}
	var steps []Step
	var hosts []string
	for _, id := range providers {
		p, ok := scanners.LookupSecretProvider(id)
		switch {
		case !ok:
			steps = append(steps, Step{Check: "configuration", Status: StepFail, ErrorCode: "PTH-CONN-1532", Detail: "unknown provider " + id})
		case !p.Checkable:
			steps = append(steps, Step{Check: "configuration", Status: StepWarn, ErrorCode: "PTH-CONN-1532", Detail: p.Name + " is recognised but never checked"})
		default:
			hosts = append(hosts, p.Hosts...)
		}
	}
	steps = append(steps, Step{Check: "configuration", Status: StepPass,
		Detail: "configuration only: a live check would need a real secret, so none is sent; the egress allowlist must contain " + strings.Join(hosts, ", ")})
	r := summarize(steps, "configuration valid (no live call)", map[string]any{"providers": providers, "hosts": hosts})
	// Real status only: a valid configuration is not proof that the
	// providers answer, and no live call is made, so it is never "healthy".
	if r.Status == StatusHealthy {
		r.Status = StatusUnknown
		r.Message = "configuration valid; not checked live (a live check would need a real secret)"
	}
	return r
}

func checkObjectStore(ctx context.Context, env *Env, t Target) Result {
	if env.ObjectStore == nil {
		return Result{Status: StatusDisabled, Message: "no object store is configured; artifacts are kept in PostgreSQL"}
	}
	err := env.ObjectStore.Ping(ctx)
	if err == nil {
		return summarize([]Step{{Check: "reachability", Status: StepPass, Detail: "the bucket answered HeadBucket (nothing written)"}}, "", nil)
	}
	code := ""
	switch {
	case errors.Is(err, ErrObjectStoreDenied):
		code = "PTH-CONN-1431"
	case errors.Is(err, ErrBucketNotFound):
		code = "PTH-CONN-1430"
	default:
		if c := Classify(err); c == "PTH-CONN-1012" {
			code = "PTH-CONN-1430"
		}
	}
	return failed("reachability", err, code)
}

// Object store adapter errors.
var (
	ErrBucketNotFound    = errors.New("the bucket does not exist")
	ErrObjectStoreDenied = errors.New("the object store denied access")
)

// egressDial overrides the dialer of the egress check (tests).
var egressDial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext

func checkEgress(ctx context.Context, env *Env, t Target) Result {
	if env.EgressProxy == "" {
		return Result{Status: StatusDisabled, Message: "no egress proxy is configured (PATHOS_EGRESS_PROXY_URL)"}
	}
	u, err := url.Parse(env.EgressProxy)
	if err != nil || u.Host == "" {
		return failed("configuration", errors.New("PATHOS_EGRESS_PROXY_URL is not a URL"), "PTH-CONN-1531")
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "3128")
	}
	start := time.Now()
	conn, err := egressDial(ctx, "tcp", addr)
	if err != nil {
		return failed("reachability", err, "PTH-CONN-1531")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// A request for a reserved name (RFC 2606): the proxy answers with an
	// error page (denied by the allowlist) without contacting anything.
	if _, err := conn.Write([]byte("HEAD http://pathos-egress-check.invalid/ HTTP/1.1\r\nHost: pathos-egress-check.invalid\r\nConnection: close\r\n\r\n")); err != nil {
		return failed("reachability", err, "PTH-CONN-1531")
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if n == 0 || !strings.HasPrefix(string(buf[:n]), "HTTP/") {
		if err == nil {
			err = errors.New("the egress proxy did not answer HTTP")
		}
		return failed("reachability", err, "PTH-CONN-1531")
	}
	status := strings.Fields(string(buf[:n]))
	obs := map[string]any{"latency_ms": time.Since(start).Milliseconds()}
	if len(status) > 1 {
		obs["probe_status"] = status[1]
	}
	return summarize([]Step{{Check: "reachability", Status: StepPass, Detail: "the egress proxy answered"}}, "", obs)
}

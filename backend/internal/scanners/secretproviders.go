package scanners

// Live secret validation: the providers a worker can ask whether a
// detected credential is still active. Every check is one read-only,
// non-mutating "who am I" request to the provider's own API host. The
// catalog is shared by the API (settings, allowlist guidance) and the
// worker (which implements the checks and refuses any other host).

// SecretProvider describes one validation provider.
type SecretProvider struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Hosts the check may contact. A leading dot matches subdomains (Squid
	// dstdomain syntax), as in deploy/egress/allowlist.txt.
	Hosts []string `json:"hosts"`
	// Endpoint is the request the check makes (documentation).
	Endpoint string `json:"endpoint"`
	// Checkable is false for credentials PATHOS recognizes but cannot
	// check without side effects (they are reported as not checked).
	Checkable bool   `json:"checkable"`
	Note      string `json:"note,omitempty"`
}

// SecretProviders lists the providers in the order candidates are tried.
var SecretProviders = []SecretProvider{
	{ID: "aws", Name: "AWS access key", Hosts: []string{"sts.amazonaws.com"}, Checkable: true,
		Endpoint: "POST https://sts.amazonaws.com/ Action=GetCallerIdentity (SigV4, us-east-1)",
		Note:     "Needs the access key ID and its secret access key within three lines of each other. Temporary keys (ASIA) need a session token and are not checked."},
	{ID: "github", Name: "GitHub token", Hosts: []string{"api.github.com"}, Checkable: true,
		Endpoint: "GET https://api.github.com/user (then GET /rate_limit when /user is not available to the token type)",
		Note:     "api.github.com is already covered by .github.com in the default allowlist."},
	{ID: "gitlab", Name: "GitLab token (gitlab.com)", Hosts: []string{"gitlab.com"}, Checkable: true,
		Endpoint: "GET https://gitlab.com/api/v4/user",
		Note:     "Only gitlab.com; tokens of self-managed GitLab instances are not checked."},
	{ID: "slack", Name: "Slack token", Hosts: []string{"slack.com"}, Checkable: true,
		Endpoint: "POST https://slack.com/api/auth.test",
		Note:     "Webhook URLs are not checked (the only way to test one is to post a message)."},
	{ID: "stripe", Name: "Stripe secret or restricted key", Hosts: []string{"api.stripe.com"}, Checkable: true,
		Endpoint: "GET https://api.stripe.com/v1/balance"},
	{ID: "openai", Name: "OpenAI API key", Hosts: []string{"api.openai.com"}, Checkable: true,
		Endpoint: "GET https://api.openai.com/v1/models"},
	{ID: "anthropic", Name: "Anthropic API key", Hosts: []string{"api.anthropic.com"}, Checkable: true,
		Endpoint: "GET https://api.anthropic.com/v1/models"},
	{ID: "sendgrid", Name: "SendGrid API key", Hosts: []string{"api.sendgrid.com"}, Checkable: true,
		Endpoint: "GET https://api.sendgrid.com/v3/scopes"},
	{ID: "twilio", Name: "Twilio account SID and auth token", Hosts: []string{"api.twilio.com"}, Checkable: true,
		Endpoint: "GET https://api.twilio.com/2010-04-01/Accounts/{AccountSid}.json",
		Note:     "Needs the account SID (AC…) and the auth token within three lines of each other."},
	{ID: "npm", Name: "npm access token", Hosts: []string{"registry.npmjs.org"}, Checkable: true,
		Endpoint: "GET https://registry.npmjs.org/-/whoami"},
	{ID: "google", Name: "Google API key", Hosts: []string{"generativelanguage.googleapis.com"}, Checkable: true,
		Endpoint: "GET https://generativelanguage.googleapis.com/v1beta/models (model list; no billable call)",
		Note:     "Google validates the key before the API: a key restricted to other APIs, or whose project has not enabled this API, is reported active with the restriction as evidence."},
	{ID: "azure-storage", Name: "Azure Storage account key", Hosts: []string{".blob.core.windows.net"}, Checkable: true,
		Endpoint: "GET https://{account}.blob.core.windows.net/?restype=service&comp=properties (Shared Key)",
		Note:     "Needs AccountName and AccountKey (a connection string). Reads the Blob service properties only."},
	{ID: "pypi", Name: "PyPI API token", Checkable: false,
		Note: "PyPI has no read-only endpoint that checks a token (only uploads use it), so PyPI tokens are recognized and reported as not checked."},
}

// LookupSecretProvider returns a provider by ID.
func LookupSecretProvider(id string) (SecretProvider, bool) {
	for _, p := range SecretProviders {
		if p.ID == id {
			return p, true
		}
	}
	return SecretProvider{}, false
}

// SecretValidationStatuses are the verdicts stored on a finding.
var SecretValidationStatuses = []string{"active", "inactive", "error", "not_checked"}

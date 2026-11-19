package scm

// Field names match the connection request JSON.
var (
	fieldToken = func(label, help string) AuthField {
		return AuthField{Name: "token", Label: label, Type: "password", Required: true, Secret: true, Help: help}
	}
	fieldOrganizations = func(required bool, help string) AuthField {
		return AuthField{Name: "organizations", Label: "Organizations", Type: "list", Required: required, Help: help}
	}
	oauthMethod = func(label, description, docs string) AuthMethod {
		return AuthMethod{Key: AuthOAuth, Label: label, Description: description, OAuth: true, Fields: []AuthField{}, DocsURL: docs}
	}
)

// Providers describes every provider and authentication method for the
// connection wizard.
func Providers() []ProviderInfo {
	githubMethods := func(enterprise bool) []AuthMethod {
		docs := "https://docs.github.com"
		if enterprise {
			docs = "https://docs.github.com/enterprise-server@latest"
		}
		return []AuthMethod{
			{
				Key: AuthGitHubApp, Label: "GitHub App",
				Description: "Recommended: least privilege, short-lived installation tokens. Install the app on the organization with Contents: read, Metadata: read and Pull requests: read.",
				Fields: []AuthField{
					{Name: "github_app_id", Label: "App ID", Type: "number", Required: true},
					{Name: "github_installation_id", Label: "Installation ID", Type: "number", Required: true, Help: "From the installation URL: …/settings/installations/<id>"},
					{Name: "private_key", Label: "Private key (PEM)", Type: "textarea", Required: true, Secret: true, Help: "The .pem file generated in the app settings."},
				},
				DocsURL: docs + "/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation",
			},
			{
				Key: AuthPAT, Label: "Personal access token",
				Description: "Fine-grained token with Contents: read and Metadata: read on the repositories, or a classic token with the repo scope.",
				Fields:      []AuthField{fieldToken("Token", "Fine-grained tokens are preferred; they can be limited to selected repositories.")},
				DocsURL:     docs + "/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
			},
			oauthMethod("OAuth App", "Sign in with GitHub through an OAuth App registered by an administrator (scopes repo read:org).",
				docs+"/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps"),
		}
	}
	return []ProviderInfo{
		{
			Key: GitHub, Label: "GitHub", Category: "git", DefaultBaseURL: "https://api.github.com",
			BaseURLHelp: "github.com uses https://api.github.com.", OwnerLabel: "Organization or user (optional)",
			Capabilities: Capabilities{Organizations: true, ServerSearch: true},
			AuthMethods:  githubMethods(false),
		},
		{
			Key: GitHubEnterprise, Label: "GitHub Enterprise Server", Category: "git", BaseURLRequired: true,
			BaseURLHelp: "API URL of the server, e.g. https://github.example.com/api/v3.", OwnerLabel: "Organization or user (optional)",
			Capabilities: Capabilities{Organizations: true, ServerSearch: true},
			AuthMethods:  githubMethods(true),
		},
		{
			Key: GitLab, Label: "GitLab", Category: "git", DefaultBaseURL: "https://gitlab.com",
			BaseURLHelp: "https://gitlab.com, or the root URL of a self-managed instance (without /api/v4).", OwnerLabel: "Group (optional)",
			Capabilities: Capabilities{Organizations: true, ServerSearch: true},
			AuthMethods: []AuthMethod{
				{
					Key: AuthPAT, Label: "Access token",
					Description: "Personal, group or project access token with the read_api and read_repository scopes (Reporter role or higher for group and project tokens).",
					Fields:      []AuthField{fieldToken("Token", "Group and project access tokens limit access to one group or project.")},
					DocsURL:     "https://docs.gitlab.com/user/profile/personal_access_tokens/",
				},
				oauthMethod("OAuth application", "Sign in with GitLab through an application registered by an administrator (scopes read_api read_repository).",
					"https://docs.gitlab.com/integration/oauth_provider/"),
			},
		},
		{
			Key: Bitbucket, Label: "Bitbucket Cloud", Category: "git", DefaultBaseURL: "https://api.bitbucket.org/2.0",
			BaseURLHelp: "Bitbucket Cloud only; the API URL is fixed.", OwnerLabel: "Workspace (required for access tokens)",
			Capabilities: Capabilities{Organizations: true, Projects: true, ServerSearch: true},
			AuthMethods: []AuthMethod{
				{
					Key: AuthPAT, Label: "Access token",
					Description: "Workspace, project or repository access token with the repository:read scope (and account:read / project:read to browse).",
					Fields:      []AuthField{fieldToken("Access token", "Set the workspace in the connection; access tokens cannot list workspaces.")},
					DocsURL:     "https://support.atlassian.com/bitbucket-cloud/docs/access-tokens/",
				},
				{
					Key: AuthAPIToken, Label: "API token",
					Description: "Atlassian account API token with scopes read:user, read:workspace, read:project and read:repository for Bitbucket.",
					Fields: []AuthField{
						{Name: "username", Label: "Atlassian account e-mail", Type: "text", Required: true},
						fieldToken("API token", "Create it at id.atlassian.com → Security → API tokens (\"with scopes\", app Bitbucket)."),
					},
					DocsURL: "https://support.atlassian.com/bitbucket-cloud/docs/using-api-tokens/",
				},
				oauthMethod("OAuth consumer", "Sign in with Bitbucket through a workspace OAuth consumer registered by an administrator (permissions: repository, account; scopes are set on the consumer).",
					"https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/"),
			},
		},
		{
			Key: AzureDevOps, Label: "Azure DevOps Services", Category: "devops", DefaultBaseURL: "https://dev.azure.com",
			BaseURLHelp: "https://dev.azure.com (organizations chosen per import) or https://dev.azure.com/<organization>.", OwnerLabel: "Project (optional)",
			Capabilities: Capabilities{Organizations: true, Projects: true},
			AuthMethods: []AuthMethod{
				{
					Key: AuthServicePrincipal, Label: "Service principal (Microsoft Entra ID)",
					Description: "App registration with a client secret or certificate, added to each Azure DevOps organization with Basic access and Reader permissions on the projects.",
					Fields: []AuthField{
						{Name: "tenant_id", Label: "Tenant ID", Type: "text", Required: true},
						{Name: "client_id", Label: "Client (application) ID", Type: "text", Required: true},
						{Name: "client_secret", Label: "Client secret", Type: "password", Secret: true, Help: "Either a client secret, or a certificate and its private key."},
						{Name: "certificate_pem", Label: "Certificate (PEM)", Type: "textarea", Help: "Public certificate uploaded to the app registration."},
						{Name: "private_key_pem", Label: "Certificate private key (PEM)", Type: "textarea", Secret: true},
						fieldOrganizations(true, "Service principals cannot list organizations; enter the organization names."),
					},
					DocsURL: "https://learn.microsoft.com/azure/devops/integrate/get-started/authentication/service-principal-managed-identity",
				},
				{
					Key: AuthPAT, Label: "Personal access token",
					Description: "PAT with Code (Read) and Project and Team (Read) scopes.",
					Fields: []AuthField{
						fieldToken("Token", "Scope the token to the organizations it should read."),
						fieldOrganizations(false, "Optional: limits discovery to these organizations."),
					},
					DocsURL: "https://learn.microsoft.com/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate",
				},
				oauthMethod("Microsoft Entra ID (OAuth)", "Sign in with a Microsoft Entra ID account through an app registration with the Azure DevOps user_impersonation permission.",
					"https://learn.microsoft.com/azure/devops/integrate/get-started/authentication/entra-oauth"),
			},
		},
		{
			Key: AzureDevOpsServer, Label: "Azure DevOps Server", Category: "devops", BaseURLRequired: true,
			BaseURLHelp: "Collection URL, e.g. https://ado.example.com/tfs/DefaultCollection.", OwnerLabel: "Project (optional)",
			Capabilities: Capabilities{Organizations: true, Projects: true},
			AuthMethods: []AuthMethod{
				{
					Key: AuthPAT, Label: "Personal access token",
					Description: "PAT with Code (Read) and Project and Team (Read) scopes.",
					Fields:      []AuthField{fieldToken("Token", "")},
					DocsURL:     "https://learn.microsoft.com/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops-server",
				},
			},
		},
	}
}

// caField is the per-connection private CA bundle (configuration, not a
// secret: see tlsca.go).
var caField = AuthField{Name: "ca_bundle_pem", Label: "Private CA bundle (PEM, optional)", Type: "textarea",
	Help: "Only for servers whose certificate is issued by a private CA. Added to the system trust store for this connection only."}

// ConnectorProviders are the providers added with the Connectors hub
// (PATHOS 3.0, M2). They are offered only when the organization's
// "connectors" feature flag is on.
func ConnectorProviders() []ProviderInfo {
	return []ProviderInfo{
		{
			Key: GenericGit, Label: "Generic Git (HTTPS or SSH)", Category: "git", BaseURLRequired: true,
			BaseURLHelp: "The repository URL: https://git.example.com/team/app.git or ssh://git@git.example.com/team/app.git (git@host:path is accepted). One connection per repository.",
			OwnerLabel:  "",
			AuthMethods: []AuthMethod{
				{
					Key: AuthAPIToken, Label: "HTTPS user name and token",
					Description: "A read-only token (or password) for the repository. The user name defaults to \"git\".",
					Fields: []AuthField{
						{Name: "username", Label: "User name (optional)", Type: "text"},
						fieldToken("Token", "Read access to this repository only."),
						caField,
					},
					DocsURL: "https://git-scm.com/docs/http-protocol",
				},
				{
					Key: AuthSSHKey, Label: "SSH deploy key",
					Description: "A read-only deploy key and the server's pinned host key. PATHOS never accepts an unknown host key.",
					Fields: []AuthField{
						{Name: "ssh_private_key", Label: "Private key (OpenSSH or PEM)", Type: "textarea", Required: true, Secret: true},
						{Name: "ssh_passphrase", Label: "Key passphrase (optional)", Type: "password", Secret: true},
						{Name: "ssh_known_hosts", Label: "known_hosts entry", Type: "textarea", Required: true,
							Help: "One line per host key, e.g. from ssh-keyscan -t ed25519 git.example.com, checked against the server's published fingerprint."},
						{Name: "ssh_host_key_fingerprint", Label: "Host key fingerprint (SHA256:…)", Type: "text", Required: true,
							Help: "From the server administrator (ssh-keygen -lf). Must match the known_hosts entry."},
					},
					DocsURL: "https://git-scm.com/docs/pack-protocol",
				},
			},
		},
		{
			Key: BitbucketDataCenter, Label: "Bitbucket Data Center", Category: "git", BaseURLRequired: true,
			BaseURLHelp:  "Root URL of the instance, e.g. https://bitbucket.example.com (with its context path, if any).",
			OwnerLabel:   "Project key (optional)",
			Capabilities: Capabilities{Projects: true, ServerSearch: true},
			AuthMethods: []AuthMethod{
				{
					Key: AuthPAT, Label: "Project or repository HTTP access token",
					Description: "Recommended: a project or repository token with Read permission (Write only for commit statuses and fix pull requests). Sent as a Bearer token.",
					Fields:      []AuthField{fieldToken("HTTP access token", "Project and repository tokens need a Data Center licence."), caField},
					DocsURL:     "https://confluence.atlassian.com/bitbucketserver/http-access-tokens-939515499.html",
				},
				{
					Key: AuthAPIToken, Label: "User HTTP access token",
					Description: "A personal HTTP access token with Project read and Repository read, sent with Basic authentication and the user name.",
					Fields: []AuthField{
						{Name: "username", Label: "User name", Type: "text", Required: true},
						fieldToken("HTTP access token", ""),
						caField,
					},
					DocsURL: "https://confluence.atlassian.com/bitbucketserver/http-access-tokens-939515499.html",
				},
			},
		},
	}
}

// ConnectorCatalog is what the connection wizard shows with the connectors
// feature on: every provider, and the private CA field on the non-OAuth
// methods of self-hosted providers (GitHub Enterprise Server, GitLab
// self-managed, Azure DevOps Server).
func ConnectorCatalog() []ProviderInfo {
	out := AllProviders()
	for i := range out {
		switch out[i].Key {
		case GitHubEnterprise, GitLab, AzureDevOpsServer:
		default:
			continue
		}
		for j := range out[i].AuthMethods {
			m := &out[i].AuthMethods[j]
			if !m.OAuth {
				m.Fields = append(append([]AuthField{}, m.Fields...), caField)
			}
		}
	}
	return out
}

// AllProviders is Providers plus ConnectorProviders.
func AllProviders() []ProviderInfo { return append(Providers(), ConnectorProviders()...) }

// IsConnectorProvider reports whether provider needs the connectors flag.
func IsConnectorProvider(provider string) bool {
	for _, p := range ConnectorProviders() {
		if p.Key == provider {
			return true
		}
	}
	return false
}

// AuthMethodFor returns the auth method of provider, if supported.
func AuthMethodFor(provider, authType string) (AuthMethod, bool) {
	for _, p := range AllProviders() {
		if p.Key != provider {
			continue
		}
		for _, m := range p.AuthMethods {
			if m.Key == authType {
				return m, true
			}
		}
	}
	return AuthMethod{}, false
}

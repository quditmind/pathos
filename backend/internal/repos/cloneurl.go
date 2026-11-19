package repos

import (
	"errors"
	"net/url"
	"strings"
)

// errUntrustedCloneURL means a provider returned a clone URL on a host the
// connection does not belong to (a compromised or misconfigured
// self-hosted server could otherwise send the clone credential elsewhere).
var errUntrustedCloneURL = errors.New("the provider returned a clone URL on an unexpected host")

// normalizeCloneURL validates a provider clone URL against the connection
// and strips embedded user names (Azure DevOps reports
// https://org@dev.azure.com/...; workers refuse URLs with user info).
func normalizeCloneURL(provider, baseURL, raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if provider == "generic_git" {
		// The clone URL is the connection's own repository URL (ssh:// keeps
		// its user name, which SSH needs).
		if raw != baseURL {
			return "", errUntrustedCloneURL
		}
		return raw, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errUntrustedCloneURL
	}
	b, err := url.Parse(baseURL)
	if err != nil {
		return "", errUntrustedCloneURL
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && b.Scheme == "http") {
		return "", errUntrustedCloneURL
	}
	host, base := strings.ToLower(u.Hostname()), strings.ToLower(b.Hostname())
	allowed := host == base || "api."+host == base
	switch provider {
	case "bitbucket":
		allowed = allowed || host == "bitbucket.org"
	case "azure_devops":
		allowed = allowed || host == "dev.azure.com" || strings.HasSuffix(host, ".visualstudio.com")
	}
	if !allowed || (u.Port() != "" && u.Port() != b.Port()) {
		return "", errUntrustedCloneURL
	}
	u.User = nil
	return u.String(), nil
}

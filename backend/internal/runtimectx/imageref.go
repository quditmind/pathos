// Package runtimectx links findings to what actually runs: a read-only
// Kubernetes inventory (workloads, their images and digests, Services,
// Ingresses, NetworkPolicies and pod security context), a read-only
// container registry inventory (OCI distribution API), and the linker that
// matches running images to image scan findings and repositories. The
// linker stores, per finding, whether it is deployed, internet-exposed,
// in a privileged workload or seen by a runtime alert, with the evidence;
// the risk engine turns these into explained factors.
//
// Connections are optional and contacted only by the jobs service, never
// by the API server.
package runtimectx

import (
	"regexp"
	"strings"
)

// ImageRef is a normalised container image reference.
type ImageRef struct {
	Registry   string `json:"registry"`   // docker.io, ghcr.io, registry.example.com:5000
	Repository string `json:"repository"` // library/nginx, org/app
	Tag        string `json:"tag,omitempty"`
	Digest     string `json:"digest,omitempty"` // sha256:...
}

var digestRe = regexp.MustCompile(`^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$`)

// ValidDigest reports whether d is a sha256 or sha512 content digest.
func ValidDigest(d string) bool { return digestRe.MatchString(d) }

// ParseImageRef normalises a reference the way the container runtime
// resolves it: no registry means docker.io, a single-component Docker Hub
// name means library/<name>, no tag and no digest means "latest".
// Kubelet image IDs ("docker-pullable://repo@sha256:...") are accepted.
func ParseImageRef(s string) (ImageRef, bool) {
	s = strings.TrimSpace(s)
	for _, p := range []string{"docker-pullable://", "docker://", "containerd://"} {
		s = strings.TrimPrefix(s, p)
	}
	if s == "" || strings.ContainsAny(s, " \t\n") {
		return ImageRef{}, false
	}
	var r ImageRef
	if i := strings.Index(s, "@"); i >= 0 {
		r.Digest = strings.ToLower(s[i+1:])
		s = s[:i]
		if !ValidDigest(r.Digest) {
			return ImageRef{}, false
		}
	}
	// A bare digest (an image ID without a name).
	if s == "" {
		return ImageRef{}, false
	}
	// The tag is after the last ":" that follows the last "/".
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		r.Tag = s[i+1:]
		s = s[:i]
	}
	first, rest, hasSlash := strings.Cut(s, "/")
	if hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		r.Registry, r.Repository = strings.ToLower(first), rest
	} else {
		r.Registry, r.Repository = "docker.io", s
	}
	switch r.Registry {
	case "index.docker.io", "registry-1.docker.io":
		r.Registry = "docker.io"
	}
	if r.Registry == "docker.io" && !strings.Contains(r.Repository, "/") {
		r.Repository = "library/" + r.Repository
	}
	r.Repository = strings.ToLower(r.Repository)
	if r.Repository == "" || len(r.Repository) > 500 || len(r.Tag) > 128 {
		return ImageRef{}, false
	}
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	return r, true
}

// Name is registry/repository.
func (r ImageRef) Name() string { return r.Registry + "/" + r.Repository }

// String is the canonical reference (name, then :tag, then @digest).
func (r ImageRef) String() string {
	s := r.Name()
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// SameRepository compares the registry and repository of two references.
func SameRepository(a, b ImageRef) bool {
	return a.Registry == b.Registry && a.Repository == b.Repository
}

// NormalizeSourceURL reduces an OCI source label or a repository URL to
// host/path (lower case, without scheme, credentials, ".git" and trailing
// slash), so https://github.com/Org/App.git and git@github.com:org/app
// compare equal.
func NormalizeSourceURL(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	} else if at := strings.Index(s, "@"); at >= 0 && strings.Contains(s[at:], ":") {
		// scp-like git@host:path
		s = strings.Replace(s[at+1:], ":", "/", 1)
	}
	if at := strings.LastIndex(s, "@"); at >= 0 && at < strings.Index(s+"/", "/") {
		s = s[at+1:]
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	// Drop default ports.
	host, path, _ := strings.Cut(s, "/")
	host = strings.TrimSuffix(strings.TrimSuffix(host, ":443"), ":80")
	if path == "" {
		return ""
	}
	return host + "/" + path
}

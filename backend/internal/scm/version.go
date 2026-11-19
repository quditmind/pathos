package scm

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Server version checks for self-hosted providers (PATHOS 3.0, M2).

// ErrVersionUnsupported means the server runs a release its vendor no
// longer supports. It is a warning: the connection keeps working.
var ErrVersionUnsupported = errors.New("scm: the server version is out of vendor support")

// Product-specific forms of ErrVersionUnsupported (distinct catalogue codes).
var (
	ErrGHESVersion = fmt.Errorf("%w (GitHub Enterprise Server)", ErrVersionUnsupported)
	ErrBBDCVersion = fmt.Errorf("%w (Bitbucket Data Center)", ErrVersionUnsupported)
)

func versionCode(err error) string {
	if errors.Is(err, ErrBBDCVersion) {
		return "PTH-CONN-1123"
	}
	return "PTH-CONN-1105"
}

// VersionInfo is the outcome of a version check.
type VersionInfo struct {
	Product string `json:"product"`
	Version string `json:"version"`
	// Supported is false when the version is below the oldest release the
	// vendor still supports (see the support tables below).
	Supported bool `json:"supported"`
	// Minimum is the oldest supported release PATHOS compares against.
	Minimum string `json:"minimum,omitempty"`
	// Note explains the result (end of support date).
	Note string `json:"note,omitempty"`
}

// VersionChecker is implemented by clients of self-hosted servers.
type VersionChecker interface {
	ServerVersion(ctx context.Context) (VersionInfo, error)
}

// release is a supported feature release and its end of support.
type release struct {
	version string
	eos     string // YYYY-MM-DD
}

// GitHub Enterprise Server releases and their end of support, from
// https://docs.github.com/en/enterprise-server@latest/admin/all-releases
// (checked 2026-11-20). 3.18 and older are out of support.
var ghesReleases = []release{{"3.19", "2026-12-09"}, {"3.20", "2027-03-17"}, {"3.21", "2027-06-11"}, {"3.22", "2027-09-08"}}

// Bitbucket Data Center: 9.4 LTS is the oldest supported release (end of
// support 2026-12-03); https://confluence.atlassian.com/support/atlassian-support-end-of-life-policy-201851003.html
// (checked 2026-11-20).
var bbdcReleases = []release{{"9.4", "2026-12-03"}}

// minSupported returns the oldest release whose end of support is still in
// the future at now, from a table ordered oldest first.
func minSupported(rel []release, now time.Time) release {
	for _, r := range rel {
		if eos, err := time.Parse("2006-01-02", r.eos); err == nil && now.Before(eos.AddDate(0, 0, 1)) {
			return r
		}
	}
	return rel[len(rel)-1]
}

// versionLess compares dotted numeric versions on major.minor.
func versionLess(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < 2; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func versionParts(v string) [2]int {
	var out [2]int
	parts := strings.SplitN(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".", 3)
	for i := 0; i < 2 && i < len(parts); i++ {
		n := parts[i]
		if j := strings.IndexFunc(n, func(r rune) bool { return r < '0' || r > '9' }); j >= 0 {
			n = n[:j]
		}
		out[i], _ = strconv.Atoi(n)
	}
	return out
}

// judge fills Supported / Minimum / Note for version against a table.
func judge(product, version string, rel []release, now time.Time) VersionInfo {
	min := minSupported(rel, now)
	vi := VersionInfo{Product: product, Version: version, Minimum: min.version, Supported: true}
	if version == "" {
		vi.Note = "the server did not report its version"
		return vi
	}
	if versionLess(version, min.version) {
		vi.Supported = false
		vi.Note = fmt.Sprintf("%s %s is out of vendor support; the oldest supported release is %s", product, version, min.version)
		return vi
	}
	for _, r := range rel {
		if versionParts(r.version) == versionParts(version) {
			vi.Note = "vendor support ends " + r.eos
		}
	}
	return vi
}

var nowFunc = time.Now

// ServerVersion reads GET /meta (installed_version) on GitHub Enterprise
// Server (https://docs.github.com/en/enterprise-server@latest/rest/meta/meta).
// github.com has no version: ErrNotSupported.
func (g *gitHub) ServerVersion(ctx context.Context) (VersionInfo, error) {
	if g.cfg.Provider != GitHubEnterprise {
		return VersionInfo{}, ErrNotSupported
	}
	var m struct {
		InstalledVersion string `json:"installed_version"`
	}
	if _, err := g.get(ctx, "/meta", &m); err != nil {
		return VersionInfo{}, err
	}
	vi := judge("GitHub Enterprise Server", m.InstalledVersion, ghesReleases, nowFunc())
	if !vi.Supported {
		return vi, ErrGHESVersion
	}
	return vi, nil
}

// ServerVersion reads GET /api/v4/version (https://docs.gitlab.com/api/version/).
// GitLab's supported-version policy is not encoded (not verified in M2), so
// the version is reported and never judged unsupported.
func (g *gitLab) ServerVersion(ctx context.Context) (VersionInfo, error) {
	var v struct {
		Version string `json:"version"`
	}
	if _, err := g.get(ctx, "/version", &v); err != nil {
		return VersionInfo{}, err
	}
	return VersionInfo{Product: "GitLab", Version: v.Version, Supported: true}, nil
}

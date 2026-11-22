// Package buildinfo holds the version and build metadata of every PATHOS
// binary (API, pathosctl, worker, CLI). The values are set at build time:
//
//	-ldflags "-X pathos/internal/platform/buildinfo.Version=3.0.2
//	          -X pathos/internal/platform/buildinfo.Commit=<git sha>
//	          -X pathos/internal/platform/buildinfo.BuildDate=<RFC 3339 UTC>"
//
// backend/Dockerfile, workers/core/Dockerfile and the release workflow pass
// them from the VERSION, COMMIT and BUILD_DATE build arguments
// (docs/OPERATIONS.md, "Build metadata").
package buildinfo

import (
	"fmt"
	"time"
)

// Build metadata. Never edit these by hand: they are injected by the build.
var (
	// Version is the release version without a leading "v" (or "dev").
	Version = "dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// BuildDate is when the binary was built (RFC 3339, UTC).
	BuildDate = "unknown"
)

// Product and Vendor name the software in banners and exports.
const (
	Product = "PATHOS"
	Vendor  = "Quditmind"
	// APIVersion is the version of the public REST API.
	APIVersion = "v1"
)

// ShortCommit returns the first 12 characters of the commit.
func ShortCommit() string {
	if len(Commit) > 12 {
		return Commit[:12]
	}
	return Commit
}

// Banner is the one-line version string of the CLI and pathosctl:
// "Quditmind PATHOS v3.0.2 (build 0123456789ab, 2026-11-20T10:00:00Z)".
func Banner() string {
	return fmt.Sprintf("%s %s v%s (build %s, %s)", Vendor, Product, Version, ShortCommit(), BuildDate)
}

// Stamp is the provenance line of every export:
// "Quditmind PATHOS v3.0.2 · build 0123456789ab · generated 2026-11-20T10:00:00Z".
func Stamp(now time.Time) string {
	return fmt.Sprintf("%s %s v%s · build %s · generated %s", Vendor, Product, Version, ShortCommit(), now.UTC().Format(time.RFC3339))
}

package httpx

import (
	"mime"
	"net/http"
	"time"

	"pathos/internal/platform/buildinfo"
)

// Version stamp headers of every download (prompt §2.2: "Quditmind PATHOS
// v{version} · build {commit} · generated {UTC timestamp}"). Formats that
// can hold it (JSON, SBOM, VEX, Markdown) also carry the stamp in the
// document; CSV keeps its header row first, so the headers are its stamp.
const (
	HeaderGeneratedBy = "X-PATHOS-Generated-By"
	HeaderVersion     = "X-PATHOS-Version"
	HeaderBuild       = "X-PATHOS-Build"
)

// StampHeaders sets the version stamp headers of an export.
func StampHeaders(w http.ResponseWriter, now time.Time) {
	h := w.Header()
	h.Set(HeaderGeneratedBy, buildinfo.Stamp(now))
	h.Set(HeaderVersion, buildinfo.Version)
	h.Set(HeaderBuild, buildinfo.Commit)
}

// Download prepares a file download: content type, attachment file name
// (quoted per RFC 6266, control characters and quotes replaced), nosniff
// and the version stamp headers. Every export endpoint uses it, so every
// export is version-stamped (TestDownloadsAreStamped enforces it).
func Download(w http.ResponseWriter, contentType, filename string) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": SafeFilename(filename)}))
	h.Set("X-Content-Type-Options", "nosniff")
	StampHeaders(w, time.Now())
}

// SafeFilename replaces characters that do not belong in a download name.
func SafeFilename(name string) string {
	out := []rune{}
	for _, c := range name {
		if c < 0x20 || c == 0x7f || c == '"' || c == '\\' || c == '/' {
			c = '_'
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return "download"
	}
	return string(out)
}

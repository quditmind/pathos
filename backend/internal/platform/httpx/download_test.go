package httpx

import (
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDownloadStamps(t *testing.T) {
	rec := httptest.NewRecorder()
	Download(rec, "text/csv", "a\"b/c.csv")
	h := rec.Header()
	if !strings.HasPrefix(h.Get(HeaderGeneratedBy), "Quditmind PATHOS v") || !strings.Contains(h.Get(HeaderGeneratedBy), " · build ") ||
		h.Get(HeaderVersion) == "" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("headers: %v", h)
	}
	if d := h.Get("Content-Disposition"); !strings.Contains(d, "a_b_c.csv") {
		t.Errorf("disposition: %q", d)
	}
	rec = httptest.NewRecorder()
	StampHeaders(rec, time.Now())
	if rec.Header().Get(HeaderBuild) == "" && rec.Header().Get(HeaderGeneratedBy) == "" {
		t.Error("stamp headers missing")
	}
}

// TestDownloadsAreStamped: every server download (a handler that sets
// Content-Disposition) goes through Download or StampHeaders, so every
// export carries the PATHOS version and build (prompt §2.2).
func TestDownloadsAreStamped(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		if strings.HasSuffix(filepath.ToSlash(path), "platform/httpx/download.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(b)
		if strings.Contains(src, `"Content-Disposition"`) && !strings.Contains(src, "httpx.StampHeaders(") {
			t.Errorf("%s sets Content-Disposition without the version stamp: use httpx.Download (or httpx.StampHeaders)", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

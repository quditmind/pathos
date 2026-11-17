package worker

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for n, c := range files {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(c))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func artifactAgent(t *testing.T, body []byte) *Agent {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || !strings.HasSuffix(r.URL.Path, "/target-file") {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	a := New(Config{APIURL: srv.URL, WorkDir: t.TempDir()}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a.token = "tok"
	return a
}

func TestPrepareArtifact(t *testing.T) {
	ctx := context.Background()
	// A release zip is extracted.
	z := zipOf(t, map[string]string{"app/package-lock.json": "{}", "app/bin/run.sh": "echo"})
	a := artifactAgent(t, z)
	dir, err := a.prepareArtifact(ctx, Job{JobID: "j", Target: &JobTarget{Kind: "artifact", SHA256: sum(z), FileName: "release.zip"}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "package-lock.json")); err != nil {
		t.Errorf("extracted (common top directory removed): %v", err)
	}
	// A Java archive is kept whole.
	j := zipOf(t, map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"})
	a = artifactAgent(t, j)
	dir, err = a.prepareArtifact(ctx, Job{JobID: "j", Target: &JobTarget{Kind: "artifact", SHA256: sum(j), FileName: "../evil/app.jar"}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "app.jar")); err != nil {
		t.Errorf("jar kept whole under its base name: %v", err)
	}
	// Path traversal is rejected.
	bad := zipOf(t, map[string]string{"../../etc/x": "x"})
	a = artifactAgent(t, bad)
	if _, err := a.prepareArtifact(ctx, Job{JobID: "j", Target: &JobTarget{Kind: "artifact", SHA256: sum(bad), FileName: "bad.zip"}}, t.TempDir()); err == nil {
		t.Error("traversal archive must be rejected")
	}
	// Checksum mismatch.
	a = artifactAgent(t, []byte("binary"))
	if _, err := a.prepareArtifact(ctx, Job{JobID: "j", Target: &JobTarget{Kind: "artifact", SHA256: sum([]byte("other")), FileName: "x.bin"}}, t.TempDir()); err == nil {
		t.Error("checksum mismatch must fail")
	}
}

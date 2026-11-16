package worker

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"pathos/internal/ingest"
)

// fakeAPI plays the worker API for one job.
type fakeAPI struct {
	t        *testing.T
	snapshot []byte
	mu       sync.Mutex
	complete map[string]string
	results  []ResultUpload
	auth     []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer worker-token" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/internal/worker/v1/jobs/j1/source":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(f.snapshot)
	case r.Method == http.MethodPost && r.URL.Path == "/internal/worker/v1/jobs/j1/results":
		var res ResultUpload
		_ = json.NewDecoder(r.Body).Decode(&res)
		f.mu.Lock()
		f.results = append(f.results, res)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == "/internal/worker/v1/jobs/j1/complete":
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.complete = body
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// recordingTool lists the files it was asked to scan.
type recordingTool struct {
	mu    sync.Mutex
	files []string
	input RunInput
	runs  int
}

func (r *recordingTool) Version(context.Context) (string, error) { return "1.0.0", nil }

func (r *recordingTool) Run(_ context.Context, in RunInput) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs++
	r.input = in
	_ = filepath.WalkDir(in.Src, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(in.Src, p)
			r.files = append(r.files, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(r.files)
	return "", os.WriteFile(in.Out, []byte(`{"version":"2.1.0","runs":[]}`), 0o600)
}

func snapshotOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, _ := zw.Create(n)
		_, _ = w.Write([]byte(files[n]))
	}
	_ = zw.Close()
	var out bytes.Buffer
	if _, err := ingest.Normalize(context.Background(), bytes.NewReader(zb.Bytes()), "zip", int64(zb.Len()), &out, ingest.Limits{}); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func newTestAgent(t *testing.T, api *fakeAPI, maxBytes int64) (*Agent, *recordingTool, string) {
	t.Helper()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	work := t.TempDir()
	a := New(Config{APIURL: srv.URL, WorkDir: work, MaxRepoBytes: maxBytes}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a.token = "worker-token"
	tool := &recordingTool{}
	a.tools = map[string]Tool{"fake": tool}
	return a, tool, work
}

func snapshotJob(sha string, size int64) Job {
	return Job{JobID: "j1", FullName: "upload/demo", TimeoutSeconds: 60, Scanners: []JobScanner{{Key: "fake"}},
		Source: &JobSource{Type: "snapshot", SHA256: sha, Size: size}}
}

func TestSnapshotJob(t *testing.T) {
	snap := snapshotOf(t, map[string]string{"demo/main.go": "package main\n", "demo/web/app.js": "x"})
	api := &fakeAPI{t: t, snapshot: snap}
	a, tool, work := newTestAgent(t, api, 1<<30)
	a.runJob(context.Background(), snapshotJob(sum(snap), int64(len(snap))))

	if api.complete["status"] != "succeeded" {
		t.Fatalf("complete: %v", api.complete)
	}
	if _, ok := api.complete["commit_sha"]; ok {
		t.Fatal("snapshot job must not report a commit")
	}
	if strings.Join(tool.files, ",") != "main.go,web/app.js" {
		t.Fatalf("scanner saw %v", tool.files)
	}
	if tool.input.GitHistory {
		t.Fatal("snapshot job must not request git history")
	}
	if len(api.results) != 1 || api.results[0].Status != "succeeded" {
		t.Fatalf("results %+v", api.results)
	}
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Fatalf("workspace not cleaned: %v", entries)
	}
}

func TestSnapshotJobFailures(t *testing.T) {
	good := snapshotOf(t, map[string]string{"a.txt": "hello"})
	var evil bytes.Buffer
	zw := gzip.NewWriter(&evil)
	tw := tar.NewWriter(zw)
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "../../escape", Size: 1, Mode: 0o644})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	_ = zw.Close()
	big := snapshotOf(t, map[string]string{"big.bin": strings.Repeat("A", 4096)})

	cases := map[string]struct {
		served   []byte
		job      Job
		maxBytes int64
		want     string
	}{
		"sha mismatch":     {good, snapshotJob(strings.Repeat("0", 64), int64(len(good))), 1 << 30, "SHA-256 mismatch"},
		"size mismatch":    {good, snapshotJob(sum(good), int64(len(good))+5), 1 << 30, "size mismatch"},
		"truncated":        {good[:len(good)-10], snapshotJob(sum(good), 0), 1 << 30, "snapshot download failed"},
		"invalid sha":      {good, snapshotJob("not-a-sha", 0), 1 << 30, "SHA-256"},
		"path traversal":   {evil.Bytes(), snapshotJob(sum(evil.Bytes()), int64(evil.Len())), 1 << 30, "path_traversal"},
		"over repo limit":  {big, snapshotJob(sum(big), int64(len(big))), 1024, "too_large"},
		"unsupported type": {good, Job{JobID: "j1", TimeoutSeconds: 60, Scanners: []JobScanner{{Key: "fake"}}, Source: &JobSource{Type: "svn"}}, 1 << 30, "unsupported source type"},
	}
	for name, c := range cases {
		api := &fakeAPI{t: t, snapshot: c.served}
		a, tool, work := newTestAgent(t, api, c.maxBytes)
		a.runJob(context.Background(), c.job)
		if api.complete["status"] != "failed" || !strings.Contains(api.complete["error"], c.want) {
			t.Errorf("%s: complete=%v", name, api.complete)
		}
		if tool.runs != 0 || len(api.results) != 0 {
			t.Errorf("%s: scanners ran on unverified source", name)
		}
		if entries, _ := os.ReadDir(work); len(entries) != 0 {
			t.Errorf("%s: workspace not cleaned", name)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(work), "escape")); err == nil {
			t.Fatalf("%s: file escaped the workspace", name)
		}
	}
}

func TestSnapshotRequiresWorkerToken(t *testing.T) {
	snap := snapshotOf(t, map[string]string{"a": "b"})
	api := &fakeAPI{t: t, snapshot: snap}
	a, _, _ := newTestAgent(t, api, 1<<30)
	a.token = "wrong"
	err := a.fetchSnapshot(context.Background(), snapshotJob(sum(snap), 0), filepath.Join(t.TempDir(), "src"))
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401, got %v", err)
	}
}

// TestFullHistoryClone clones a local repository served over Git's "dumb"
// HTTP protocol (which supports full clones only).
func TestFullHistoryClone(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	run := func(dir string, args ...string) string { return gitRun(t, dir, args...) }
	_ = os.MkdirAll(work, 0o700)
	run(work, "init", "-q", "-b", "main")
	_ = os.WriteFile(filepath.Join(work, "config.env"), []byte("TOKEN=old-secret\n"), 0o600)
	run(work, "add", ".")
	run(work, "commit", "-q", "-m", "first")
	first := run(work, "rev-parse", "HEAD")
	_ = os.WriteFile(filepath.Join(work, "config.env"), []byte("TOKEN=\n"), 0o600)
	run(work, "commit", "-q", "-am", "second")
	second := run(work, "rev-parse", "HEAD")
	bare := filepath.Join(base, "repo.git")
	run(base, "clone", "-q", "--bare", work, bare)
	run(bare, "update-server-info")
	srv := httptest.NewServer(http.FileServer(http.Dir(bare)))
	defer srv.Close()

	ws := t.TempDir()
	job := Job{CloneURL: srv.URL + "/", Ref: "main", FullHistory: true}
	commit, err := clone(context.Background(), job, filepath.Join(ws, "src"), filepath.Join(ws, "git"), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if commit != second {
		t.Fatalf("commit %s, want %s", commit, second)
	}
	// History is available through src/.git (a pointer file).
	if st, err := os.Lstat(filepath.Join(ws, "src", ".git")); err != nil || st.IsDir() {
		t.Fatalf(".git should be a gitdir pointer file: %v", err)
	}
	if n := run(filepath.Join(ws, "src"), "rev-list", "--count", "HEAD"); n != "2" {
		t.Fatalf("history has %s commits", n)
	}

	// Pinning an older commit checks it out and reports it.
	ws2 := t.TempDir()
	job.CommitSHA = first[:12]
	commit, err = clone(context.Background(), job, filepath.Join(ws2, "src"), filepath.Join(ws2, "git"), 1<<30)
	if err != nil || commit != first {
		t.Fatalf("pinned commit %s (%v), want %s", commit, err, first)
	}

	// The size limit counts the history too.
	ws3 := t.TempDir()
	job.CommitSHA = ""
	if _, err := clone(context.Background(), job, filepath.Join(ws3, "src"), filepath.Join(ws3, "git"), 64); err == nil {
		t.Fatal("expected size limit error")
	}
}

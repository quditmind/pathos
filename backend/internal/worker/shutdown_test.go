package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// shutdownAPI plays the worker API and records release and complete calls.
type shutdownAPI struct {
	fakeAPI
	mu        sync.Mutex
	released  map[string]string
	noRelease bool // an API before 2.2.2
}

func (f *shutdownAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/internal/worker/v1/jobs/j1/release" && !f.noRelease {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.released = body
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"queued"}`))
		return
	}
	f.fakeAPI.ServeHTTP(w, r)
}

// stopTool simulates SIGTERM arriving while it runs.
type stopTool struct{ stop context.CancelFunc }

func (s stopTool) Version(context.Context) (string, error) { return "1", nil }
func (s stopTool) Run(ctx context.Context, _ RunInput) (string, error) {
	s.stop()
	<-ctx.Done()
	return "", ctx.Err()
}

// O9: a worker stopped with SIGTERM during a scan hands the job back (the
// release call does not use the cancelled context) instead of failing to
// report and leaving the execution running until its lease expires.
func TestShutdownReleasesTheJob(t *testing.T) {
	for _, old := range []bool{false, true} {
		snap := snapshotOf(t, map[string]string{"demo/main.go": "package main\n"})
		api := &shutdownAPI{fakeAPI: fakeAPI{t: t, snapshot: snap}, noRelease: old}
		srv := httptest.NewServer(api)
		a := New(Config{APIURL: srv.URL, WorkDir: t.TempDir(), MaxRepoBytes: 1 << 30}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		a.token = "worker-token"
		parent, stop := context.WithCancel(context.Background())
		second := &recordingTool{}
		a.tools = map[string]Tool{"fake": stopTool{stop: stop}, "second": second}
		job := snapshotJob(sum(snap), int64(len(snap)))
		job.Scanners = append(job.Scanners, JobScanner{Key: "second"})
		a.runJob(parent, job)
		srv.Close()
		if second.runs != 0 {
			t.Error("no further tool runs once the worker is stopping")
		}
		if !old {
			if api.released == nil || !strings.Contains(api.released["reason"], "SIGTERM") {
				t.Fatalf("release on shutdown: %v", api.released)
			}
			if api.complete != nil {
				t.Errorf("a released job is not also completed: %v", api.complete)
			}
		} else if api.complete["status"] != "failed" || !strings.Contains(api.complete["error"], "SIGTERM") {
			t.Fatalf("an API without release gets the job failed: %v", api.complete)
		}
	}
}

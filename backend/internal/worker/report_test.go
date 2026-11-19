package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// eventsAPI wraps fakeAPI and records execution reports.
type eventsAPI struct {
	*fakeAPI
	mu      sync.Mutex
	status  int // response for /events (0 = 204)
	bodies  []string
	batches []reportBatch
	paths   []string // order of POST paths
}

func (e *eventsAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	e.paths = append(e.paths, r.URL.Path)
	e.mu.Unlock()
	if r.URL.Path != "/internal/worker/v1/jobs/j1/events" {
		e.fakeAPI.ServeHTTP(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer worker-token" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var b reportBatch
	if err := json.Unmarshal(raw, &b); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	e.mu.Lock()
	e.bodies = append(e.bodies, string(raw))
	e.batches = append(e.batches, b)
	status := e.status
	e.mu.Unlock()
	if status == 0 {
		status = http.StatusNoContent
	}
	w.WriteHeader(status)
}

func (e *eventsAPI) all() ([]jobEvent, []jobLog) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var ev []jobEvent
	var lg []jobLog
	for _, b := range e.batches {
		ev = append(ev, b.Events...)
		lg = append(lg, b.Logs...)
	}
	return ev, lg
}

func newEventsAgent(t *testing.T, api *eventsAPI) *Agent {
	t.Helper()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	a := New(Config{APIURL: srv.URL, WorkDir: t.TempDir(), Name: "w1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a.token = "worker-token"
	a.reportInterval = 20 * time.Millisecond
	return a
}

// shellTool runs a shell script through command(), like the real tools.
type shellTool struct{ script string }

func (s shellTool) Version(context.Context) (string, error) { return "9.9.9", nil }

func (s shellTool) Run(ctx context.Context, in RunInput) (string, error) {
	if _, err := command(ctx, nil, []int{0}, "sh", "-c", s.script); err != nil {
		return "", err
	}
	return "", os.WriteFile(in.Out, []byte(`{"version":"2.1.0","runs":[]}`), 0o600)
}

const secretToken = "ghs_SuperSecretToken1234567890"

func noisyScript() string {
	return strings.Join([]string{
		"echo 'scanning 12 files' >&2",
		"echo 'WARN slow rule set' >&2",
		"echo 'fatal: something broke' >&2",
		"echo 'remote said " + secretToken + " is bad' >&2",
		"echo 'Authorization: Basic abc' >&2",
		"echo 'http.extraHeader set' >&2",
		"printf 'no trailing newline' >&2",
		"echo 'FINDING on stdout'",
	}, "; ")
}

func credentialSnapshotJob(t *testing.T, snap []byte) Job {
	job := snapshotJob(sum(snap), int64(len(snap)))
	job.Scanners = []JobScanner{{Key: "noisy"}, {Key: "fake"}}
	job.Credential = &JobCredential{Username: "x-access-token", Token: secretToken}
	return job
}

func TestJobReportsStagesAndLogs(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not installed")
	}
	snap := snapshotOf(t, map[string]string{"a.go": "package a\n"})
	api := &eventsAPI{fakeAPI: &fakeAPI{t: t, snapshot: snap}}
	a := newEventsAgent(t, api)
	a.tools = map[string]Tool{"noisy": shellTool{noisyScript()}, "fake": &recordingTool{}}
	a.runJob(context.Background(), credentialSnapshotJob(t, snap))

	if api.complete["status"] != "succeeded" {
		t.Fatalf("complete: %v", api.complete)
	}
	events, logs := api.all()
	var got []string
	for _, e := range events {
		got = append(got, e.Stage+"/"+e.Scanner+"/"+e.Status)
	}
	want := "source//started,source//succeeded,scanner/noisy/started,scanner/fake/started"
	if strings.Join(got, ",") != want {
		t.Fatalf("events %v, want %s", got, want)
	}
	if !strings.Contains(events[1].Message, sum(snap)) {
		t.Fatalf("source succeeded message lacks the snapshot SHA: %q", events[1].Message)
	}

	levels := map[string]string{}
	var workerLines []string
	for _, l := range logs {
		switch l.Source {
		case "noisy":
			levels[l.Message] = l.Level
		case "worker":
			workerLines = append(workerLines, l.Message)
		}
	}
	for msg, lvl := range map[string]string{
		"scanning 12 files":             "info",
		"WARN slow rule set":            "warn",
		"fatal: something broke":        "error",
		"remote said [REDACTED] is bad": "info",
		"no trailing newline":           "info",
	} {
		if levels[msg] != lvl {
			t.Errorf("log %q: level %q, want %q (have %v)", msg, levels[msg], lvl, levels)
		}
	}
	if len(levels) != 5 {
		t.Errorf("unexpected scanner lines: %v", levels)
	}
	joined := strings.Join(workerLines, "\n")
	for _, s := range []string{"job started", "downloading snapshot", "running scanners: noisy, fake", "noisy succeeded", "job finished"} {
		if !strings.Contains(joined, s) {
			t.Errorf("worker log lacks %q:\n%s", s, joined)
		}
	}

	// Nothing sensitive left the worker, and every report preceded complete.
	api.mu.Lock()
	defer api.mu.Unlock()
	for _, b := range api.bodies {
		for _, bad := range []string{secretToken, "Authorization", "extraHeader", "FINDING", basicAuth("x-access-token", secretToken)} {
			if strings.Contains(b, bad) {
				t.Fatalf("report contains %q: %s", bad, b)
			}
		}
	}
	last := -1
	for i, p := range api.paths {
		if strings.HasSuffix(p, "/events") {
			last = i
		}
	}
	if last < 0 || !strings.HasSuffix(api.paths[len(api.paths)-1], "/complete") || last >= len(api.paths)-1 {
		t.Fatalf("request order %v", api.paths)
	}
}

func TestSourceFailureIsReported(t *testing.T) {
	snap := snapshotOf(t, map[string]string{"a": "b"})
	api := &eventsAPI{fakeAPI: &fakeAPI{t: t, snapshot: snap}}
	a := newEventsAgent(t, api)
	a.tools = map[string]Tool{"fake": &recordingTool{}}
	a.runJob(context.Background(), snapshotJob(strings.Repeat("0", 64), int64(len(snap))))
	events, _ := api.all()
	if len(events) != 2 || events[1].Stage != "source" || events[1].Status != "failed" || !strings.Contains(events[1].Message, "SHA-256 mismatch") {
		t.Fatalf("events %+v", events)
	}
}

func TestReportingFailuresDoNotFailJob(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusConflict, http.StatusUnauthorized} {
		snap := snapshotOf(t, map[string]string{"a.go": "x"})
		api := &eventsAPI{fakeAPI: &fakeAPI{t: t, snapshot: snap}, status: status}
		a := newEventsAgent(t, api)
		tool := &recordingTool{}
		a.tools = map[string]Tool{"fake": tool}
		a.runJob(context.Background(), snapshotJob(sum(snap), int64(len(snap))))
		if api.complete["status"] != "succeeded" || tool.runs != 1 || len(api.results) != 1 {
			t.Fatalf("status %d: complete=%v runs=%d results=%d", status, api.complete, tool.runs, len(api.results))
		}
		if status != http.StatusInternalServerError {
			api.mu.Lock()
			n := len(api.batches)
			api.mu.Unlock()
			if n != 1 {
				t.Fatalf("status %d: %d reports sent after rejection, want 1", status, n)
			}
		}
	}
}

func newTestReporter(t *testing.T, api *eventsAPI) *reporter {
	a := newEventsAgent(t, api)
	a.reportInterval = time.Hour // flush manually
	r := a.newReporter(Job{JobID: "j1"})
	t.Cleanup(r.close)
	return r
}

func TestReporterBatchLimits(t *testing.T) {
	api := &eventsAPI{fakeAPI: &fakeAPI{t: t}}
	r := newTestReporter(t, api)
	for i := range 250 {
		r.event("scanner", "fake", "info", fmt.Sprintf("event %d", i))
	}
	for i := range 2500 {
		r.logf("info", "line %d", i)
	}
	r.log("info", "worker", strings.Repeat("x", 5000))
	r.flush(false)

	api.mu.Lock()
	defer api.mu.Unlock()
	var nEvents, nLogs int
	for _, b := range api.batches {
		if len(b.Events) > maxEventsPerRequest || len(b.Logs) > maxLogsPerRequest {
			t.Fatalf("batch over limits: %d events, %d logs", len(b.Events), len(b.Logs))
		}
		nEvents += len(b.Events)
		nLogs += len(b.Logs)
		for _, l := range b.Logs {
			if len(l.Message) > maxMessageLen {
				t.Fatalf("message of %d chars", len(l.Message))
			}
		}
	}
	if nEvents != 250 {
		t.Fatalf("%d events delivered", nEvents)
	}
	// 2000 queued lines (oldest dropped) plus one drop notice.
	if nLogs != maxQueuedLogs+1 {
		t.Fatalf("%d logs delivered", nLogs)
	}
	first := api.batches[0].Logs[0]
	if first.Level != "warn" || !strings.Contains(first.Message, "501 older lines were dropped") {
		t.Fatalf("first log %+v", first)
	}
	if api.batches[0].Logs[1].Message != "line 501" {
		t.Fatalf("oldest kept line %q", api.batches[0].Logs[1].Message)
	}
}

func TestScannerOutputIsBounded(t *testing.T) {
	api := &eventsAPI{fakeAPI: &fakeAPI{t: t}}
	r := newTestReporter(t, api)
	c := &lineCollector{rep: r, source: "fake"}
	w := c.writer()
	for i := range 300 {
		_, _ = fmt.Fprintf(w, "line %d\n", i)
	}
	w.close()
	r.flush(true)
	_, logs := api.all()
	if len(logs) != maxScannerLines+1 || !strings.Contains(logs[maxScannerLines].Message, "truncated") {
		t.Fatalf("%d lines, last %+v", len(logs), logs[len(logs)-1])
	}
}

func TestReporterRetryAndStop(t *testing.T) {
	api := &eventsAPI{fakeAPI: &fakeAPI{t: t}, status: http.StatusBadGateway}
	r := newTestReporter(t, api)
	r.logf("info", "first")
	r.flush(false) // fails
	r.flush(false) // retries once, fails, dropped
	r.logf("info", "second")
	api.mu.Lock()
	api.status = 0
	api.mu.Unlock()
	r.flush(false)
	var msgs []string
	api.mu.Lock()
	for _, b := range api.batches {
		msgs = append(msgs, b.Logs[0].Message)
	}
	api.mu.Unlock()
	if strings.Join(msgs, ",") != "first,first,second" {
		t.Fatalf("sent %v", msgs)
	}

	api.mu.Lock()
	api.status = http.StatusConflict
	api.mu.Unlock()
	r.logf("info", "third")
	r.flush(false)
	r.logf("info", "fourth")
	r.event("scanner", "x", "started", "")
	r.flush(false)
	r.close()
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.batches) != 4 {
		t.Fatalf("%d requests; reporting must stop after 409", len(api.batches))
	}
}

func TestReporterRedaction(t *testing.T) {
	api := &eventsAPI{fakeAPI: &fakeAPI{t: t}}
	a := newEventsAgent(t, api)
	job := credentialSnapshotJob(t, nil)
	job.Credential.Username = "octocat-bot"
	r := a.newReporter(job)
	r.log("info", "fake", "user octocat-bot token "+secretToken)
	r.log("info", "fake", "url https://octocat-bot:"+secretToken+"@example.com/x.git")
	r.log("info", "fake", "x-access-token used")
	r.event("source", "", "failed", "clone failed: "+secretToken)
	r.close()
	api.mu.Lock()
	bodies := append([]string{}, api.bodies...)
	api.mu.Unlock()
	for _, b := range bodies {
		if strings.Contains(b, secretToken) || strings.Contains(b, "octocat-bot") || strings.Contains(b, "x-access-token") {
			t.Fatalf("secret leaked: %s", b)
		}
	}
	_, logs := api.all()
	if len(logs) != 2 {
		t.Fatalf("logs %+v", logs)
	}
}

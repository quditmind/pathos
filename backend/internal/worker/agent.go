// Package worker is the scan worker agent that runs inside worker images.
//
// It talks only to the PATHOS internal worker API (lease, heartbeat,
// results, complete). It never connects to PostgreSQL, Redis or Keycloak
// and holds no platform secrets: only its own worker token and, for the
// duration of one job, a clone credential.
package worker

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Config configures the agent.
type Config struct {
	APIURL         string // e.g. http://api:8081
	BootstrapToken string
	Name           string
	Family         string
	WorkDir        string // tmpfs workspace root
	CacheDir       string // vulnerability DB cache
	RulesDirs      []string
	PollInterval   time.Duration
	MaxRepoBytes   int64
	Version        string
}

// Agent runs jobs.
type Agent struct {
	cfg   Config
	log   *slog.Logger
	http  *http.Client
	token string
	tools map[string]Tool
}

// New builds an agent with the tools available in this image.
func New(cfg Config, log *slog.Logger) *Agent {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.MaxRepoBytes == 0 {
		cfg.MaxRepoBytes = 2 << 30
	}
	return &Agent{cfg: cfg, log: log, http: &http.Client{Timeout: 5 * time.Minute}, tools: Tools(cfg)}
}

// apiError carries the HTTP status of a failed API call.
type apiError struct {
	Status int
	Body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("worker API returned %d: %s", e.Status, e.Body) }

func (a *Agent) call(ctx context.Context, method, path, token string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.cfg.APIURL, "/")+path, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := a.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp.StatusCode, &apiError{Status: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func (a *Agent) register(ctx context.Context) error {
	versions := map[string]string{}
	for key, t := range a.tools {
		v, err := t.Version(ctx)
		if err != nil {
			a.log.Warn("tool unavailable", "scanner", key, "err", err)
			continue
		}
		versions[key] = v
	}
	var out struct {
		Token string `json:"token"`
	}
	if _, err := a.call(ctx, http.MethodPost, "/internal/worker/v1/register", a.cfg.BootstrapToken, map[string]any{
		"name": a.cfg.Name, "family": a.cfg.Family, "version": a.cfg.Version, "scanners": versions,
	}, &out); err != nil {
		return err
	}
	a.token = out.Token
	a.log.Info("registered", "name", a.cfg.Name, "scanners", versions)
	return nil
}

// Run registers and processes jobs until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		if err := a.register(ctx); err != nil {
			var ae *apiError
			if errors.As(err, &ae) && ae.Status == http.StatusForbidden {
				return fmt.Errorf("registration refused: %w", err)
			}
			a.log.Warn("registration failed, retrying", "err", err, "in", backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		break
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var job Job
		status, err := a.call(ctx, http.MethodPost, "/internal/worker/v1/lease", a.token, map[string]any{}, &job)
		switch {
		case err != nil:
			var ae *apiError
			if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
				a.log.Warn("worker token rejected; re-registering")
				if err := a.register(ctx); err != nil {
					return err
				}
				continue
			}
			a.log.Warn("lease failed", "err", err)
		case status == http.StatusOK:
			a.runJob(ctx, job)
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(a.cfg.PollInterval):
		}
	}
}

// Job is a leased scan job.
type Job struct {
	JobID          string       `json:"job_id"`
	FullName       string       `json:"full_name"`
	CloneURL       string       `json:"clone_url"`
	Ref            string       `json:"ref"`
	CommitSHA      string       `json:"commit_sha"`
	TimeoutSeconds int          `json:"timeout_seconds"`
	Scanners       []JobScanner `json:"scanners"`
	Credential     *struct {
		Username string `json:"username"`
		Token    string `json:"token"`
	} `json:"credential"`
	Public bool `json:"public"`
	// Source, when set, replaces the clone: the job scans an uploaded
	// snapshot served by the worker API.
	Source *JobSource `json:"source"`
	// FullHistory clones the complete history and makes Gitleaks scan it
	// (git mode). Default: shallow clone without history.
	FullHistory bool `json:"full_history"`
}

// JobSource identifies a non-Git source for a job.
type JobSource struct {
	Type   string `json:"type"`   // "snapshot"
	SHA256 string `json:"sha256"` // hex SHA-256 of the snapshot as served
	Size   int64  `json:"size"`   // snapshot bytes (0 = unknown)
}

// JobScanner is one scanner to run.
type JobScanner struct {
	Key    string          `json:"key"`
	Config json.RawMessage `json:"config"`
}

func (a *Agent) runJob(parent context.Context, job Job) {
	log := a.log.With("job_id", job.JobID, "repository", job.FullName)
	log.Info("job started", "ref", job.Ref, "scanners", len(job.Scanners))
	ctx, cancel := context.WithTimeout(parent, time.Duration(job.TimeoutSeconds)*time.Second)
	defer cancel()

	// Heartbeats keep the lease and deliver cancellation.
	var cancelled bool
	var mu sync.Mutex
	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				var out struct {
					Cancel bool `json:"cancel"`
				}
				_, err := a.call(ctx, http.MethodPost, "/internal/worker/v1/jobs/"+job.JobID+"/heartbeat", a.token, map[string]any{}, &out)
				var ae *apiError
				if out.Cancel || (errors.As(err, &ae) && ae.Status == http.StatusConflict) {
					mu.Lock()
					cancelled = true
					mu.Unlock()
					log.Info("job cancelled or lease lost; stopping")
					cancel()
					return
				}
			}
		}
	}()

	ws := filepath.Join(a.cfg.WorkDir, job.JobID)
	defer func() {
		cancel()
		<-hbDone
		if err := os.RemoveAll(ws); err != nil {
			log.Error("workspace cleanup failed", "err", err)
		}
	}()

	src := filepath.Join(ws, "src")
	gitDir := filepath.Join(ws, "git") // full-history object store, outside src
	out := filepath.Join(ws, "out")
	if err := os.MkdirAll(out, 0o700); err != nil {
		a.complete(parent, job, "workspace: "+err.Error(), "")
		return
	}
	commit := ""
	if job.Source != nil {
		job.Credential = nil
		if job.Source.Type != "snapshot" {
			a.complete(parent, job, "unsupported source type", "")
			return
		}
		start := time.Now()
		if err := a.fetchSnapshot(ctx, job, src); err != nil {
			log.Warn("snapshot download failed", "err", err)
			a.complete(parent, job, "snapshot download failed: "+err.Error(), "")
			return
		}
		log.Info("snapshot extracted", "duration_ms", time.Since(start).Milliseconds())
	} else {
		cloneStart := time.Now()
		var err error
		commit, err = clone(ctx, job, src, gitDir, a.cfg.MaxRepoBytes)
		if err != nil && job.Public && job.Credential != nil && ctx.Err() == nil {
			// An expired or wrong credential should not block scanning public
			// code; private repositories never fall back.
			log.Warn("authenticated clone failed; retrying anonymously (public repository)", "err", err)
			job.Credential = nil
			_ = os.RemoveAll(src)
			_ = os.RemoveAll(gitDir)
			commit, err = clone(ctx, job, src, gitDir, a.cfg.MaxRepoBytes)
		}
		if err != nil {
			job.Credential = nil
			log.Warn("clone failed", "err", err)
			a.complete(parent, job, "clone failed: "+err.Error(), "")
			return
		}
		job.Credential = nil // not needed past this point
		log.Info("cloned", "duration_ms", time.Since(cloneStart).Milliseconds(), "commit", commit, "full_history", job.FullHistory)
	}

	sbomPath := ""
	ordered := orderScanners(job.Scanners)
	for _, js := range ordered {
		mu.Lock()
		stop := cancelled
		mu.Unlock()
		if stop {
			return
		}
		tool, ok := a.tools[js.Key]
		res := ResultUpload{Scanner: js.Key}
		start := time.Now()
		if !ok {
			res.Status, res.Error = "skipped", "scanner not available in this worker image"
		} else {
			res.Version, _ = tool.Version(ctx)
			outFile := filepath.Join(out, js.Key+".out")
			skipped, err := tool.Run(ctx, RunInput{Src: src, Out: outFile, SBOM: sbomPath, Config: js.Config, GitHistory: job.FullHistory && job.Source == nil})
			switch {
			case skipped != "":
				res.Status, res.Error = "skipped", skipped
			case errors.Is(ctx.Err(), context.DeadlineExceeded):
				res.Status, res.Error = "timed_out", "scan timeout reached"
			case err != nil:
				res.Status, res.Error = "failed", err.Error()
			default:
				res.Status = "succeeded"
				if js.Key == "syft" {
					sbomPath = outFile
				}
			}
			if res.Status == "succeeded" || res.Status == "failed" {
				// #nosec G304 -- report path is created by the worker in its job directory
				if data, err := os.ReadFile(outFile); err == nil && len(data) > 0 {
					res.ContentType = "application/json"
					res.OutputGzip = gzipB64(data)
				}
			}
		}
		res.DurationMS = int(time.Since(start).Milliseconds())
		if len(res.Error) > 2000 {
			res.Error = res.Error[:2000]
		}
		if _, err := a.call(parent, http.MethodPost, "/internal/worker/v1/jobs/"+job.JobID+"/results", a.token, res, nil); err != nil {
			log.Error("result upload failed", "scanner", js.Key, "err", err)
		}
		log.Info("scanner finished", "scanner", js.Key, "status", res.Status, "duration_ms", res.DurationMS)
	}
	mu.Lock()
	stop := cancelled
	mu.Unlock()
	if !stop {
		a.complete(parent, job, "", commit)
	}
}

// orderScanners runs Syft before Grype (Grype consumes the SBOM).
func orderScanners(in []JobScanner) []JobScanner {
	out := make([]JobScanner, 0, len(in))
	for _, s := range in {
		if s.Key == "syft" {
			out = append(out, s)
		}
	}
	for _, s := range in {
		if s.Key != "syft" {
			out = append(out, s)
		}
	}
	return out
}

// complete reports the job outcome. commitSHA is the commit actually
// scanned (empty for snapshots or when unknown).
func (a *Agent) complete(ctx context.Context, job Job, failure, commitSHA string) {
	body := map[string]string{"status": "succeeded"}
	if failure != "" {
		body = map[string]string{"status": "failed", "error": failure}
	}
	if commitSHA != "" {
		body["commit_sha"] = commitSHA
	}
	if _, err := a.call(ctx, http.MethodPost, "/internal/worker/v1/jobs/"+job.JobID+"/complete", a.token, body, nil); err != nil {
		a.log.Error("complete failed", "job_id", job.JobID, "err", err)
	}
}

// ResultUpload mirrors scans.ResultUpload.
type ResultUpload struct {
	Scanner     string `json:"scanner"`
	Version     string `json:"version"`
	Status      string `json:"status"`
	DurationMS  int    `json:"duration_ms"`
	Error       string `json:"error"`
	ContentType string `json:"content_type"`
	OutputGzip  string `json:"output_gzip"`
}

func gzipB64(data []byte) string {
	var b bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&b, gzip.BestSpeed)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

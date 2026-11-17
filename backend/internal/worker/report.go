package worker

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Execution reporting: stage events and log lines are batched per job and
// posted to the worker API. Reporting is best effort: it never blocks
// scanning and never fails a job.

const (
	maxEventsPerRequest = 200
	maxLogsPerRequest   = 1000
	maxMessageLen       = 2000
	maxQueuedLogs       = 2000
	maxQueuedEvents     = 1000
	maxScannerLines     = 200
	reportTimeout       = 15 * time.Second
)

// jobEvent mirrors scans.WorkerEvent.
type jobEvent struct {
	Stage   string    `json:"stage"`
	Scanner string    `json:"scanner"`
	Status  string    `json:"status"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

// jobLog mirrors scans.WorkerLog.
type jobLog struct {
	At      time.Time `json:"at"`
	Level   string    `json:"level"`
	Source  string    `json:"source"`
	Message string    `json:"message"`
}

type reportBatch struct {
	Events []jobEvent `json:"events"`
	Logs   []jobLog   `json:"logs"`
}

// reporter queues and delivers the events and logs of one job.
type reporter struct {
	a       *Agent
	path    string
	secrets []string

	mu      sync.Mutex
	events  []jobEvent
	logs    []jobLog
	dropped int          // queued log lines dropped since the last flush
	retry   *reportBatch // batch that failed once; retried on the next flush
	stopped bool         // 409/401: the platform no longer accepts reports

	sendMu sync.Mutex // serializes flushes
	quit   chan struct{}
	done   chan struct{}
	once   sync.Once
}

// newReporter starts the reporter goroutine for a job. secrets are values
// (the job's credential) that must never leave the worker.
func (a *Agent) newReporter(job Job) *reporter {
	r := &reporter{a: a, path: "/internal/worker/v1/jobs/" + job.JobID + "/events",
		quit: make(chan struct{}), done: make(chan struct{})}
	if c := job.Credential; c != nil {
		for _, s := range []string{c.Token, c.Username + ":" + c.Token} {
			if len(s) >= 4 {
				r.secrets = append(r.secrets, s)
			}
		}
		// Short usernames ("git", "oauth2") are too common to strip.
		if len(c.Username) >= 6 {
			r.secrets = append(r.secrets, c.Username)
		}
		if c.Token != "" {
			r.secrets = append(r.secrets, basicAuth(c.Username, c.Token))
		}
	}
	r.secrets = append(r.secrets, job.Target.secrets()...)
	if t := job.Target; t != nil && t.AuthType == "basic" && t.Password != "" {
		r.secrets = append(r.secrets, basicAuth(t.Username, t.Password))
	}
	interval := a.reportInterval
	if interval <= 0 {
		interval = 3 * time.Second
	}
	go func() {
		defer close(r.done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-r.quit:
				return
			case <-t.C:
				r.flush(false)
			}
		}
	}()
	return r
}

// close stops the periodic flushes and delivers what is still queued.
// It is idempotent and must run before the job's complete call.
func (r *reporter) close() {
	r.once.Do(func() {
		close(r.quit)
		<-r.done
		r.flush(true)
	})
}

// sensitiveMarkers drop whole lines that may carry credentials.
var sensitiveMarkers = []string{"authorization:", "extraheader", "x-access-token"}

// clean redacts a message; ok is false when the line must not be sent.
func (r *reporter) clean(msg string) (string, bool) {
	lower := strings.ToLower(msg)
	for _, m := range sensitiveMarkers {
		if strings.Contains(lower, m) {
			return "", false
		}
	}
	for _, s := range r.secrets {
		msg = strings.ReplaceAll(msg, s, "[REDACTED]")
	}
	msg = credRe.ReplaceAllString(msg, "$1$2[REDACTED]")
	msg = strings.ToValidUTF8(strings.TrimRight(msg, "\r\n"), "?")
	if len(msg) > maxMessageLen {
		msg = strings.ToValidUTF8(msg[:maxMessageLen], "")
	}
	return msg, true
}

// event queues a stage event.
func (r *reporter) event(stage, scanner, status, msg string) {
	msg, ok := r.clean(msg)
	if !ok {
		msg = "[message withheld]"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	if len(r.events) >= maxQueuedEvents {
		r.events = r.events[1:]
	}
	r.events = append(r.events, jobEvent{Stage: stage, Scanner: scanner, Status: status, Message: msg, At: time.Now().UTC()})
}

// log queues a log line, dropping the oldest queued lines when full.
func (r *reporter) log(level, source, msg string) {
	msg, ok := r.clean(msg)
	if !ok || strings.TrimSpace(msg) == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	if len(r.logs) >= maxQueuedLogs {
		r.logs = r.logs[1:]
		r.dropped++
	}
	r.logs = append(r.logs, jobLog{At: time.Now().UTC(), Level: level, Source: source, Message: msg})
}

// logf queues a worker log line.
func (r *reporter) logf(level, format string, args ...any) {
	r.log(level, "worker", fmt.Sprintf(format, args...))
}

// next takes the next batch to send, honouring the per-request limits.
func (r *reporter) next() (b *reportBatch, retried bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return nil, false
	}
	if r.retry != nil {
		b, r.retry = r.retry, nil
		return b, true
	}
	if r.dropped > 0 {
		note := jobLog{At: time.Now().UTC(), Level: "warn", Source: "worker",
			Message: fmt.Sprintf("worker log queue full; %d older lines were dropped", r.dropped)}
		r.logs = append([]jobLog{note}, r.logs...)
		r.dropped = 0
	}
	if len(r.events) == 0 && len(r.logs) == 0 {
		return nil, false
	}
	ne, nl := min(len(r.events), maxEventsPerRequest), min(len(r.logs), maxLogsPerRequest)
	b = &reportBatch{Events: append([]jobEvent{}, r.events[:ne]...), Logs: append([]jobLog{}, r.logs[:nl]...)}
	r.events, r.logs = r.events[ne:], r.logs[nl:]
	return b, false
}

// flush sends queued batches until the queue is empty or a send fails. A
// failed batch is retried once (on the next flush, or immediately when
// final) and then dropped.
func (r *reporter) flush(final bool) {
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	for {
		b, retried := r.next()
		if b == nil {
			return
		}
		if b.Events == nil {
			b.Events = []jobEvent{}
		}
		if b.Logs == nil {
			b.Logs = []jobLog{}
		}
		ctx, cancel := context.WithTimeout(context.Background(), reportTimeout)
		_, err := r.a.call(ctx, http.MethodPost, r.path, r.a.token, b, nil)
		cancel()
		if err == nil {
			continue
		}
		var ae *apiError
		if errors.As(err, &ae) && (ae.Status == http.StatusConflict || ae.Status == http.StatusUnauthorized) {
			r.mu.Lock()
			r.stopped, r.events, r.logs, r.retry = true, nil, nil, nil
			r.mu.Unlock()
			r.a.log.Info("execution reporting stopped", "path", r.path, "status", ae.Status)
			return
		}
		r.a.log.Warn("execution report failed", "path", r.path, "err", err, "retried", retried)
		if retried {
			continue // dropped after its second failure
		}
		r.mu.Lock()
		r.retry = b
		r.mu.Unlock()
		if !final {
			return
		}
	}
}

// lineCollector turns process output into bounded, levelled log lines for
// one scanner.
type lineCollector struct {
	rep    *reporter
	source string
	mu     sync.Mutex
	lines  int
	// stdout is forwarded only for tools whose stdout carries no findings.
	stdout bool
}

// streamWriter splits one output stream into lines.
type streamWriter struct {
	c       *lineCollector
	partial []byte
}

func (c *lineCollector) writer() *streamWriter { return &streamWriter{c: c} }

func (w *streamWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\n' {
			w.c.emit(string(w.partial))
			w.partial = w.partial[:0]
			continue
		}
		if len(w.partial) < maxMessageLen {
			w.partial = append(w.partial, b)
		}
	}
	return len(p), nil
}

// close emits a trailing line without a newline.
func (w *streamWriter) close() {
	if len(w.partial) > 0 {
		w.c.emit(string(w.partial))
		w.partial = nil
	}
}

func (c *lineCollector) emit(line string) {
	line = strings.TrimRight(line, "\r")
	if strings.TrimSpace(line) == "" {
		return
	}
	c.mu.Lock()
	n := c.lines
	c.lines++
	c.mu.Unlock()
	switch {
	case n < maxScannerLines:
		c.rep.log(lineLevel(line), c.source, line)
	case n == maxScannerLines:
		c.rep.log("warn", c.source, fmt.Sprintf("output truncated after %d lines", maxScannerLines))
	}
}

func lineLevel(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "error"), strings.Contains(l, "fatal"):
		return "error"
	case strings.Contains(l, "warn"):
		return "warn"
	}
	return "info"
}

type collectorKey struct{}

// withCollector makes command() tee process output into c.
func withCollector(ctx context.Context, c *lineCollector) context.Context {
	return context.WithValue(ctx, collectorKey{}, c)
}

func collectorFrom(ctx context.Context) *lineCollector {
	c, _ := ctx.Value(collectorKey{}).(*lineCollector)
	return c
}

// stdoutSafe lists tools whose stdout is progress output only (their
// reports go to files). Gitleaks and Checkov stdout is never forwarded.
var stdoutSafe = map[string]bool{"trivy-fs": true, "syft": true, "grype": true, "osv-scanner": true, "opengrep": true}

func basicAuth(user, token string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + token))
}

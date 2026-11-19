package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/scans"
)

type ingestOptions struct {
	WorkerAPI, BootstrapToken, Out                       string
	Workers, Jobs, FindingsPerUpload, RepoOffset, Stride int
}

// latencies collects request durations per operation.
type latencies struct {
	mu sync.Mutex
	d  map[string][]time.Duration
}

func (l *latencies) add(op string, d time.Duration) {
	l.mu.Lock()
	l.d[op] = append(l.d[op], d)
	l.mu.Unlock()
}

func pct(xs []time.Duration, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	i := min(len(xs)-1, int(float64(len(xs))*p))
	return float64(xs[i].Microseconds()) / 1000
}

type opStats struct {
	Count int     `json:"count"`
	P50   float64 `json:"p50_ms"`
	P95   float64 `json:"p95_ms"`
	P99   float64 `json:"p99_ms"`
	Max   float64 `json:"max_ms"`
}

type roundStats struct {
	Round           int                `json:"round"`
	Jobs            int                `json:"jobs"`
	Uploads         int64              `json:"uploads"`
	FindingsSent    int64              `json:"findings_sent"`
	Errors          int64              `json:"errors"`
	Seconds         float64            `json:"seconds"`
	UploadsPerSec   float64            `json:"uploads_per_second"`
	JobsPerSec      float64            `json:"jobs_per_second"`
	FindingsPerSec  float64            `json:"findings_per_second"`
	Ops             map[string]opStats `json:"operations"`
	FirstErrorText  string             `json:"first_error,omitempty"`
	EnqueueSeconds  float64            `json:"enqueue_seconds"`
	Workers         int                `json:"workers"`
	FindingsPerScan int                `json:"findings_per_upload"`
}

type workerClient struct {
	base, token string
	hc          *http.Client
	lat         *latencies
}

func (c *workerClient) do(ctx context.Context, op, path string, body any, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	t := time.Now()
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	c.lat.add(op, time.Since(t))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("%s: HTTP %d: %s", op, resp.StatusCode, bytes.TrimSpace(b))
	}
	if out != nil && resp.StatusCode == http.StatusOK {
		return resp.StatusCode, json.Unmarshal(b, out)
	}
	return resp.StatusCode, nil
}

// sarif builds an Opengrep-style SARIF report with n results for a
// repository. In round 2, 10% of the results are new and 10% of round 1's
// are gone (fixed), as in a rescan after some commits.
func sarif(repo, n, round int) []byte {
	type loc struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
				EndLine   int `json:"endLine"`
				Snippet   struct {
					Text string `json:"text"`
				} `json:"snippet"`
			} `json:"region"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []loc `json:"locations"`
	}
	type rule struct {
		ID               string `json:"id"`
		ShortDescription struct {
			Text string `json:"text"`
		} `json:"shortDescription"`
		FullDescription struct {
			Text string `json:"text"`
		} `json:"fullDescription"`
		Properties struct {
			Tags []string `json:"tags"`
		} `json:"properties"`
	}
	levels := []string{"error", "warning", "warning", "note"}
	var results []result
	rules := map[string]rule{}
	shift := 0
	if round > 1 {
		shift = n / 10
	}
	for i := shift; i < n+shift; i++ {
		id := fmt.Sprintf("pathos.loadgen.rule-%d", (repo*7+i)%120)
		var r result
		r.RuleID, r.Level = id, levels[i%len(levels)]
		r.Message.Text = fmt.Sprintf("Possible injection: untrusted input reaches a sink (%d)", i)
		var l loc
		l.PhysicalLocation.ArtifactLocation.URI = fmt.Sprintf("src/module%d/handler%d.go", i%40, i)
		l.PhysicalLocation.Region.StartLine = 10 + i%300
		l.PhysicalLocation.Region.EndLine = 12 + i%300
		l.PhysicalLocation.Region.Snippet.Text = fmt.Sprintf("rows, _ := db.Query(\"SELECT * FROM t WHERE id = \" + q%d)", i)
		r.Locations = []loc{l}
		results = append(results, r)
		if _, ok := rules[id]; !ok {
			var ru rule
			ru.ID = id
			ru.ShortDescription.Text = "Untrusted input in a SQL query"
			ru.FullDescription.Text = "User-controlled data is concatenated into a SQL statement. Use parameterised queries."
			ru.Properties.Tags = []string{"security", "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"}
			rules[id] = ru
		}
	}
	ruleList := make([]rule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "Opengrep", "version": "1.0.0", "rules": ruleList}},
			"results": results,
		}},
	}
	b, _ := json.Marshal(doc)
	return b
}

func gz64(b []byte) string {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// ingest queues scan jobs with the API's own enqueue function, then lets
// fake workers lease them and upload results through the worker API, in two
// rounds (first scan, then a rescan of the same repositories).
func ingest(ctx context.Context, dsn string, o ingestOptions) error {
	if dsn == "" || o.BootstrapToken == "" {
		return errors.New("-db and -bootstrap-token are required")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	var org uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM organizations ORDER BY created_at LIMIT 1`).Scan(&org); err != nil {
		return err
	}
	var profileScanners []string
	if err := pool.QueryRow(ctx, `SELECT array_agg(ps.scanner_key) FROM profile_scanners ps
		JOIN scan_profiles p ON p.current_version_id = ps.profile_version_id WHERE p.organization_id = $1 AND p.is_default`, org).
		Scan(&profileScanners); err != nil {
		return err
	}
	lat := &latencies{d: map[string][]time.Duration{}}
	hc := &http.Client{Timeout: 120 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
	clients := make([]*workerClient, o.Workers)
	sc := map[string]string{}
	for _, k := range profileScanners {
		sc[k] = "1.0.0"
	}
	for i := range clients {
		c := &workerClient{base: o.WorkerAPI, token: o.BootstrapToken, hc: hc, lat: lat}
		var reg struct {
			Token string `json:"token"`
		}
		if _, err := c.do(ctx, "register", "/internal/worker/v1/register",
			map[string]any{"name": fmt.Sprintf("loadgen-%d", i), "family": "core", "version": "loadgen", "scanners": sc}, &reg); err != nil {
			return err
		}
		if reg.Token == "" {
			return errors.New("register returned no token")
		}
		c.token = reg.Token
		clients[i] = c
	}
	var all []roundStats
	for round := 1; round <= 2; round++ {
		lat.d = map[string][]time.Duration{}
		t0 := time.Now()
		for j := 0; j < o.Jobs; j++ {
			// Uploaded repositories are every tenth one (see seed).
			repo := uuid.MustParse(fmt.Sprintf("0000000b-0000-7000-8001-%012x", (o.RepoOffset/10+j*o.Stride)*10))
			if _, err := scans.EnqueueWith(ctx, pool, org, repo, "manual", "", "", nil, scans.EnqueueOpts{}); err != nil {
				return fmt.Errorf("enqueue %s: %w", repo, err)
			}
		}
		enq := time.Since(t0).Seconds()
		var uploads, findings, errs, done atomic.Int64
		var firstErr atomic.Value
		fail := func(err error) {
			errs.Add(1)
			firstErr.CompareAndSwap(nil, err.Error())
		}
		start := time.Now()
		var wg sync.WaitGroup
		for _, c := range clients {
			wg.Add(1)
			go func() {
				defer wg.Done()
				idle := 0
				for ctx.Err() == nil && done.Load() < int64(o.Jobs) {
					var job scans.LeasedJob
					st, err := c.do(ctx, "lease", "/internal/worker/v1/lease", map[string]any{}, &job)
					if err != nil {
						fail(err)
						time.Sleep(200 * time.Millisecond)
						continue
					}
					if st == http.StatusNoContent {
						// Another worker holds the remaining jobs.
						if idle++; idle > 600 {
							return
						}
						time.Sleep(100 * time.Millisecond)
						continue
					}
					idle = 0
					var repoNum int
					_, _ = fmt.Sscanf(job.RepositoryID.String()[24:], "%x", &repoNum)
					for _, ps := range job.Scanners {
						up := map[string]any{"scanner": ps.Key, "version": "1.0.0", "status": "succeeded", "duration_ms": 1000}
						if ps.Key == "opengrep" {
							up["content_type"] = "application/sarif+json"
							up["output_gzip"] = gz64(sarif(repoNum, o.FindingsPerUpload, round))
							findings.Add(int64(o.FindingsPerUpload))
						}
						if _, err := c.do(ctx, "upload "+map[bool]string{true: "(SARIF)", false: "(empty)"}[ps.Key == "opengrep"],
							"/internal/worker/v1/jobs/"+job.JobID.String()+"/results", up, nil); err != nil {
							fail(err)
						}
						uploads.Add(1)
					}
					if _, err := c.do(ctx, "complete", "/internal/worker/v1/jobs/"+job.JobID.String()+"/complete",
						map[string]any{"status": "succeeded", "commit_sha": fmt.Sprintf("%040x", repoNum*10+round)}, nil); err != nil {
						fail(err)
					}
					done.Add(1)
				}
			}()
		}
		wg.Wait()
		secs := time.Since(start).Seconds()
		rs := roundStats{Round: round, Jobs: int(done.Load()), Uploads: uploads.Load(), FindingsSent: findings.Load(), Errors: errs.Load(),
			Seconds: secs, EnqueueSeconds: enq, Workers: o.Workers, FindingsPerScan: o.FindingsPerUpload, Ops: map[string]opStats{}}
		rs.UploadsPerSec, rs.JobsPerSec, rs.FindingsPerSec = float64(rs.Uploads)/secs, float64(rs.Jobs)/secs, float64(rs.FindingsSent)/secs
		if v, ok := firstErr.Load().(string); ok {
			rs.FirstErrorText = v
		}
		for op, xs := range lat.d {
			slices.Sort(xs)
			rs.Ops[op] = opStats{Count: len(xs), P50: pct(xs, 0.50), P95: pct(xs, 0.95), P99: pct(xs, 0.99), Max: pct(xs, 1)}
		}
		all = append(all, rs)
		b, _ := json.MarshalIndent(rs, "", "  ")
		fmt.Println(string(b))
	}
	if o.Out != "" {
		b, _ := json.MarshalIndent(all, "", "  ")
		return os.WriteFile(o.Out, b, 0o600)
	}
	return nil
}

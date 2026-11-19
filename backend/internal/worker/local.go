package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"pathos/internal/scanners"
)

// Local runs (`pathos-worker run-local`) execute scanners of this image on
// a directory without an API: the same tool table, manifests, arguments and
// timeouts as a job, but the reports are written to an output directory
// instead of being uploaded. The benchmark harness (benchmarks/) uses them
// so that its numbers are those of the PATHOS worker images, not of the
// tools run by hand. Reports and results.json are readable by other UIDs
// (the operator reads them outside the container). A local run never
// clones, never validates secrets live and never contacts the API.

// LocalResult is one scanner's outcome in a local run (results.json).
type LocalResult struct {
	Scanner    string `json:"scanner"`
	Version    string `json:"version"`
	Status     string `json:"status"` // succeeded | failed | skipped | timed_out
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	// Output is the report file name in the output directory ("" if none).
	Output string `json:"output,omitempty"`
	// Parser is the manifest's parser, as the API would receive it (nil for
	// built-in tools, which the API parses by key).
	Parser *scanners.ToolParser `json:"parser,omitempty"`
}

var localKeyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// RunLocal runs the scanners keys on src and writes <key>.out for each, plus
// results.json, to outDir. timeout bounds the whole run (0 = 6h).
func (a *Agent) RunLocal(ctx context.Context, src, outDir string, keys []string, timeout time.Duration) ([]LocalResult, error) {
	if st, err := os.Stat(src); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("source %s is not a directory", src)
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 6 * time.Hour
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	results := make([]LocalResult, 0, len(keys))
	for _, key := range keys {
		if !localKeyRe.MatchString(key) {
			return nil, fmt.Errorf("invalid scanner key %q", key)
		}
		res := LocalResult{Scanner: key}
		start := time.Now()
		tool, ok := a.tools[key]
		if !ok {
			res.Status, res.Error = "skipped", "scanner not available in this worker image"
		} else {
			res.Version, _ = tool.Version(ctx)
			outFile := filepath.Join(outDir, key+".out")
			skipped, err := tool.Run(ctx, RunInput{Src: src, Out: outFile})
			switch {
			case skipped != "":
				res.Status, res.Error = "skipped", skipped
			case errors.Is(ctx.Err(), context.DeadlineExceeded):
				res.Status, res.Error = "timed_out", "timeout reached"
			case err != nil:
				res.Status, res.Error = "failed", err.Error()
			default:
				res.Status = "succeeded"
			}
			if st, err := os.Stat(outFile); err == nil && st.Size() > 0 {
				res.Output = key + ".out"
				// The operator who started the local run reads the
				// reports from outside the container (another UID).
				_ = os.Chmod(outFile, 0o644) // #nosec G302 -- local benchmark output, see above
			}
			if p, ok := a.manifestParser(key); ok && p.Kind != "sarif" {
				res.Parser = &p
			}
		}
		res.DurationMS = time.Since(start).Milliseconds()
		a.log.Info("scanner finished", "scanner", key, "status", res.Status, "duration_ms", res.DurationMS, "error", res.Error)
		results = append(results, res)
	}
	raw, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return results, err
	}
	// #nosec G306 -- read by the operator outside the container, like the reports
	return results, os.WriteFile(filepath.Join(outDir, "results.json"), raw, 0o644)
}

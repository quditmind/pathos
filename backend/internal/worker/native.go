package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"pathos/internal/scanners"
)

// Built-in scanners: implemented in the worker itself (pure Go) or, for
// ClamAV, as a client of the opt-in clamd service. Their reports use the
// scanners.NativeReport format. None of them executes anything from the
// scanned content.

// nativeVersion is reported for the built-in scanners.
func nativeVersion(cfg Config) string {
	if cfg.Version == "" {
		return "dev"
	}
	return cfg.Version
}

type nativeTool struct {
	version func(ctx context.Context) (string, error)
	run     func(ctx context.Context, in RunInput) (string, error)
}

func (t nativeTool) Version(ctx context.Context) (string, error)          { return t.version(ctx) }
func (t nativeTool) Run(ctx context.Context, in RunInput) (string, error) { return t.run(ctx, in) }

// nativeTools returns the built-in scanners.
func nativeTools(cfg Config) map[string]Tool {
	fixed := func(context.Context) (string, error) { return nativeVersion(cfg), nil }
	return map[string]Tool{
		scanners.LicenseCheck: nativeTool{version: fixed, run: func(ctx context.Context, in RunInput) (string, error) {
			if in.Target != nil {
				return "only runs for repository sources", nil
			}
			return "", runLicenseCheck(ctx, in.Src, in.Out, nativeVersion(cfg))
		}},
		scanners.BinaryHardening: nativeTool{version: fixed, run: func(ctx context.Context, in RunInput) (string, error) {
			dir := in.Src
			if in.Target != nil {
				if in.Target.Kind != "artifact" {
					return "only runs for repository sources and build artifacts", nil
				}
				dir = in.TargetFile
			}
			return "", runHardening(ctx, dir, in.Out, nativeVersion(cfg))
		}},
		scanners.ClamAV: nativeTool{
			version: func(ctx context.Context) (string, error) { return clamVersion(ctx, cfg.ClamAVAddress) },
			run: func(ctx context.Context, in RunInput) (string, error) {
				if cfg.ClamAVAddress == "" {
					return "ClamAV is not configured for this worker (set PATHOS_CLAMAV_ADDRESS and enable the clamav Compose profile)", nil
				}
				dir := in.Src
				if in.Target != nil {
					if in.Target.Kind != "artifact" {
						return "only runs for repository sources and build artifacts", nil
					}
					dir = in.TargetFile
				}
				return "", runClamAV(ctx, cfg.ClamAVAddress, dir, in.Out, nativeVersion(cfg))
			}},
	}
}

// writeNative writes a report.
func writeNative(path string, rep scanners.NativeReport) error {
	if rep.Findings == nil {
		rep.Findings = []scanners.NativeFinding{}
	}
	b, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// toolLog writes one line to the job's execution log (through the
// scanner's collector).
func toolLog(ctx context.Context, format string, args ...any) {
	if c := collectorFrom(ctx); c != nil {
		c.emit(fmt.Sprintf(format, args...))
	}
}

// walkFiles calls fn for every regular file below root (relative,
// slash-separated path), skipping .git. Symbolic links and other
// non-regular entries are counted, never followed. The walk stops when
// ctx is done.
func walkFiles(ctx context.Context, root string, fn func(rel string, size int64) error) (links int, err error) {
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if p == root {
				return werr
			}
			return nil // unreadable entry: reported by the caller's counts
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if d.Name() == ".git" && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == ".git" {
			return nil // gitdir pointer file of a full-history checkout
		}
		if !d.Type().IsRegular() {
			links++
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		return fn(filepath.ToSlash(rel), info.Size())
	})
	return links, err
}

// openIn opens a file below root without following symbolic links out of
// it (os.Root).
func openIn(root *os.Root, rel string) (*os.File, error) {
	return root.Open(filepath.FromSlash(rel))
}

// clip shortens s to n bytes.
func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// oneLine collapses whitespace.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// RunInput is what a tool needs for one run.
type RunInput struct {
	Src    string
	Out    string
	SBOM   string // Syft output, for Grype
	Config json.RawMessage
	// GitHistory means Src is a full-history checkout (Src/.git points to
	// the object store); history-aware tools scan the commits.
	GitHistory bool
	// Target is set for scan-target jobs (image, URL, API, SBOM);
	// TargetFile is the OpenAPI document or SBOM written for it.
	Target     *JobTarget
	TargetFile string
}

// Tool is one scanner binary.
type Tool interface {
	Version(ctx context.Context) (string, error)
	// Run writes the tool's report to in.Out. A non-empty skipped reason
	// means the tool deliberately did not run.
	Run(ctx context.Context, in RunInput) (skipped string, err error)
}

// command runs a binary in its own process group (so a timeout kills every
// child), with a scrubbed environment and bounded output capture.
func command(ctx context.Context, env []string, okCodes []int, name string, args ...string) ([]byte, error) {
	return commandTo(ctx, nil, env, okCodes, name, args...)
}

// commandTo is command with stdout written to w (for tools that print their
// report to stdout).
func commandTo(ctx context.Context, w io.Writer, env []string, okCodes []int, name string, args ...string) ([]byte, error) {
	return commandToIn(ctx, "", w, env, okCodes, name, args...)
}

// commandToIn is commandTo run in directory dir ("" = current).
func commandToIn(ctx context.Context, dir string, w io.Writer, env []string, okCodes []int, name string, args ...string) ([]byte, error) {
	// #nosec G204 -- scanner binaries and arguments come from the worker's fixed tool table; no shell is involved
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = append(baseEnv(), env...)
	var stderr bytes.Buffer
	cmd.Stdout = &limitedBuffer{max: 64 << 10}
	if w != nil {
		cmd.Stdout = w
	}
	cmd.Stderr = &limitedWriter{buf: &stderr, max: 64 << 10}
	// A collector in ctx receives the output line by line as well (stderr
	// always, stdout only for tools whose stdout carries no findings).
	var tees []*streamWriter
	if c := collectorFrom(ctx); c != nil {
		ew := c.writer()
		tees = append(tees, ew)
		cmd.Stderr = io.MultiWriter(cmd.Stderr, ew)
		if c.stdout {
			ow := c.writer()
			tees = append(tees, ow)
			cmd.Stdout = io.MultiWriter(cmd.Stdout, ow)
		}
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		for _, w := range tees {
			w.close()
		}
		done <- err
	}()
	select {
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return stderr.Bytes(), ctx.Err()
	case err := <-done:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			for _, c := range okCodes {
				if ee.ExitCode() == c {
					return stderr.Bytes(), nil
				}
			}
			return stderr.Bytes(), fmt.Errorf("%s exited with %d: %s", filepath.Base(name), ee.ExitCode(), lastLine(stderr.String()))
		}
		return stderr.Bytes(), err
	}
}

// baseEnv passes only what tools need; the worker's own token is never
// visible to scanners.
func baseEnv() []string {
	keep := []string{"PATH", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "SSL_CERT_FILE", "TZ", "LANG"}
	env := []string{"HOME=/tmp/home", "TMPDIR=/tmp"}
	for _, k := range keep {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.Len() < l.max {
		l.Buffer.Write(p[:min(len(p), l.max-l.Len())])
	}
	return len(p), nil
}

type limitedWriter struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.buf.Len() < l.max {
		l.buf.Write(p[:min(len(p), l.max-l.buf.Len())])
	}
	return len(p), nil
}

var credRe = regexp.MustCompile(`(?i)(authorization:\s*\S+\s+)\S+|(https?://)[^@/\s]+@`)

func lastLine(s string) string {
	s = strings.TrimSpace(credRe.ReplaceAllString(s, "$1$2[REDACTED]"))
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}

var versionRe = regexp.MustCompile(`v?(\d+\.\d+\.\d+[\w.+-]*)`)

func versionOf(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// #nosec G204 -- scanner binaries and arguments come from the worker's fixed tool table; no shell is involved
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", err
	}
	if m := versionRe.FindStringSubmatch(string(out)); m != nil {
		return m[1], nil
	}
	return strings.TrimSpace(string(out)), nil
}

// ensureReport writes an empty SARIF log when a tool produced none (for
// example when there was nothing to scan).
func ensureReport(path, tool string) error {
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		return nil
	}
	empty := fmt.Sprintf(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":%q}},"results":[]}]}`, tool)
	return os.WriteFile(path, []byte(empty), 0o600)
}

type simpleTool struct {
	bin         string
	versionArgs []string
	run         func(ctx context.Context, bin string, in RunInput) (string, error)
}

func (t simpleTool) Version(ctx context.Context) (string, error) {
	if _, err := exec.LookPath(t.bin); err != nil {
		return "", err
	}
	return versionOf(ctx, t.bin, t.versionArgs...)
}

func (t simpleTool) Run(ctx context.Context, in RunInput) (string, error) {
	return t.run(ctx, t.bin, in)
}

// Tools returns the core worker tool set.
func Tools(cfg Config) map[string]Tool {
	cache := func(sub string) string { return filepath.Join(cfg.CacheDir, sub) }
	tools := map[string]Tool{
		"gitleaks": simpleTool{"gitleaks", []string{"version"}, func(ctx context.Context, bin string, in RunInput) (string, error) {
			// --redact keeps secret values out of the report entirely.
			// Full-history checkouts are scanned commit by commit
			// ("gitleaks git"); otherwise the working tree ("gitleaks dir").
			mode := "dir"
			if in.GitHistory {
				if _, err := os.Stat(filepath.Join(in.Src, ".git")); err == nil {
					mode = "git"
				}
			}
			_, err := command(ctx, nil, []int{0}, bin, mode, in.Src, "--no-banner", "--redact", "--exit-code", "0",
				"--report-format", "sarif", "--report-path", in.Out, "--log-level", "warn")
			if err != nil {
				return "", err
			}
			return "", ensureReport(in.Out, "gitleaks")
		}},
		"opengrep": simpleTool{"opengrep", []string{"--version"}, func(ctx context.Context, bin string, in RunInput) (string, error) {
			args := []string{"scan", "--sarif", "--output", in.Out, "--quiet", "--timeout", "30", "--max-target-bytes", "1000000"}
			n := 0
			for _, d := range cfg.RulesDirs {
				if hasRules(d) {
					args = append(args, "--config", d)
					n++
				}
			}
			// Custom rule files managed in PATHOS (validated server-side).
			if dir, err := writeCustomRules(in.Config); err != nil {
				return "", err
			} else if dir != "" {
				defer os.RemoveAll(dir)
				args = append(args, "--config", dir)
				n++
			}
			if n == 0 {
				return "no rule sets available", nil
			}
			_, err := command(ctx, []string{"XDG_CACHE_HOME=/tmp/home/.cache"}, []int{0, 1}, bin, append(args, in.Src)...)
			if err != nil {
				return "", err
			}
			if err := ensureReport(in.Out, "opengrep"); err != nil {
				return "", err
			}
			return "", enrichSARIF(in.Out, in.Src)
		}},
		"trivy-fs": simpleTool{"trivy", []string{"--version"}, func(ctx context.Context, bin string, in RunInput) (string, error) {
			dir := in.Src
			if in.Target != nil && in.Target.Kind == "artifact" {
				dir = in.TargetFile
			}
			if cfg.Offline {
				if err := offlineReady(cfg.CacheDir, "trivy"); err != nil {
					return "", err
				}
			}
			args := append([]string{"fs", "--scanners", "vuln", "--format", "sarif", "--output", in.Out,
				"--cache-dir", cache("trivy"), "--quiet", "--skip-version-check", "--timeout", "20m"}, trivyOffline(cfg.Offline)...)
			_, err := command(ctx, nil, []int{0}, bin, append(args, dir)...)
			if err != nil {
				return "", err
			}
			return "", ensureReport(in.Out, "trivy")
		}},
		"syft": simpleTool{"syft", []string{"version"}, func(ctx context.Context, bin string, in RunInput) (string, error) {
			_, err := command(ctx, []string{"SYFT_CHECK_FOR_APP_UPDATE=false"}, []int{0}, bin, "scan", "dir:"+in.Src,
				"-o", "cyclonedx-json="+in.Out, "--quiet")
			return "", err
		}},
		"grype": simpleTool{"grype", []string{"version"}, func(ctx context.Context, bin string, in RunInput) (string, error) {
			target := "dir:" + in.Src
			if in.SBOM != "" {
				target = "sbom:" + in.SBOM
			}
			if cfg.Offline {
				if err := offlineReady(cfg.CacheDir, "grype"); err != nil {
					return "", err
				}
			}
			_, err := command(ctx, grypeEnv(cfg.CacheDir, cfg.Offline), []int{0}, bin,
				target, "-o", "json", "--file", in.Out, "--quiet")
			if err != nil {
				return "", err
			}
			if st, err := os.Stat(in.Out); err != nil || st.Size() == 0 {
				return "", os.WriteFile(in.Out, []byte(`{"matches":[]}`), 0o600)
			}
			return "", nil
		}},
		"osv-scanner": simpleTool{"osv-scanner", []string{"--version"}, func(ctx context.Context, bin string, in RunInput) (string, error) {
			// Exit 1 = vulnerabilities found; 128 = no packages found.
			flags, env := osvArgs(cfg.CacheDir, cfg.Offline)
			if cfg.Offline {
				if err := offlineReady(cfg.CacheDir, "osv-scanner"); err != nil {
					return "", err
				}
			}
			args := append(append([]string{"scan", "source", "-r", "--format", "sarif", "--output-file", in.Out}, flags...), in.Src)
			_, err := command(ctx, env, []int{0, 1, 128}, bin, args...)
			if err != nil {
				return "", err
			}
			return "", ensureReport(in.Out, "osv-scanner")
		}},
		"checkov": simpleTool{"checkov", []string{"--version"}, func(ctx context.Context, bin string, in RunInput) (string, error) {
			dir := filepath.Dir(in.Out)
			_, err := command(ctx, []string{"BC_SKIP_MAPPING=TRUE", "CHECKOV_RUN_SCA_PACKAGE_SCAN_V2=false"}, []int{0, 1}, bin,
				"-d", in.Src, "-o", "sarif", "--output-file-path", filepath.Join(dir, "checkov"), "--quiet", "--soft-fail",
				"--skip-download", "--download-external-modules", "false", "--framework",
				"terraform,cloudformation,kubernetes,helm,dockerfile,arm,bicep,serverless,github_actions,gitlab_ci,azure_pipelines,bitbucket_pipelines")
			if err != nil {
				return "", err
			}
			// #nosec G304,G703 -- paths are created by the worker inside its own job directory
			if b, err := os.ReadFile(filepath.Join(dir, "checkov", "results_sarif.sarif")); err == nil {
				if err := os.WriteFile(in.Out, b, 0o600); err != nil {
					return "", err
				}
				return "", enrichSARIF(in.Out, in.Src)
			}
			return "", ensureReport(in.Out, "checkov")
		}},
	}
	for k, t := range targetTools(cache, cfg) {
		tools[k] = t
	}
	for k, t := range nativeTools(cfg) {
		tools[k] = t
	}
	tools["pathos-endpoints"] = endpointsTool{cfg: cfg}
	tools["cosign"] = cosignTool{cfg: cfg}
	return tools
}

func hasRules(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return filepath.SkipDir
		}
		if !d.IsDir() && (strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
			found = true
		}
		return nil
	})
	return found
}

var refRe = regexp.MustCompile(`^[A-Za-z0-9._/+@-]{1,255}$`)
var shaRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

var fullSHARe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// clone performs a hardened clone of one ref and returns the commit
// checked out. By default the clone is shallow and the history is removed
// afterwards. With job.FullHistory the complete history is fetched into
// gitDir (outside dst; dst/.git is a "gitdir:" pointer file) so that
// history-aware scanners can read it while the others see only the working
// tree. The credential is passed through GIT_CONFIG_* environment
// variables, never in argv or the remote URL, and git hooks, file:// and
// ext:: transports and symlinks are disabled.
func clone(ctx context.Context, job Job, dst, gitDir string, maxBytes int64) (string, error) {
	u, err := url.Parse(job.CloneURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return "", errors.New("clone URL must be http(s) without embedded credentials")
	}
	if !refRe.MatchString(job.Ref) || strings.HasPrefix(job.Ref, "-") || strings.Contains(job.Ref, "..") {
		return "", errors.New("invalid ref")
	}
	env := []string{"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	if job.Credential != nil && job.Credential.Token != "" {
		header := "Authorization: Basic " + basicAuth(job.Credential.Username, job.Credential.Token)
		if job.Credential.Scheme == "bearer" {
			header = "Authorization: Bearer " + job.Credential.Token
		}
		env = append(env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0="+header)
	}
	hardening := []string{
		"-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
		"-c", "core.fsmonitor=false", "-c", "core.symlinks=false", "-c", "submodule.recurse=false",
		"-c", "transfer.fsckObjects=true", "-c", "http.followRedirects=false",
	}
	args := append(append([]string{}, hardening...), "clone")
	if job.FullHistory {
		args = append(args, "--separate-git-dir", gitDir)
	} else {
		args = append(args, "--depth", "1", "--single-branch")
	}
	args = append(args, "--no-tags", "--branch", job.Ref, "--", job.CloneURL, dst)
	if _, err := command(ctx, env, []int{0}, "git", args...); err != nil {
		return "", err
	}
	if job.CommitSHA != "" && shaRe.MatchString(job.CommitSHA) {
		head, _ := gitHead(ctx, dst)
		if !strings.HasPrefix(head, job.CommitSHA) {
			checkout := func() error {
				_, err := command(ctx, nil, []int{0}, "git", "-C", dst, "-c", "core.hooksPath=/dev/null", "checkout", "--detach", "--quiet", job.CommitSHA)
				return err
			}
			// A full clone usually has the commit already.
			if !job.FullHistory || checkout() != nil {
				fetch := append(append([]string{}, hardening...), "-C", dst, "fetch")
				if !job.FullHistory {
					fetch = append(fetch, "--depth", "1")
				}
				fetch = append(fetch, "origin", job.CommitSHA)
				if _, err := command(ctx, env, []int{0}, "git", fetch...); err == nil {
					_ = checkout()
				}
			}
		}
	}
	commit, err := gitHead(ctx, dst)
	if err != nil {
		return "", err
	}
	if !job.FullHistory {
		// History is not needed by the scanners; removing it also removes
		// the remote configuration.
		if err := os.RemoveAll(filepath.Join(dst, ".git")); err != nil {
			return "", err
		}
	}
	var size int64
	walk := func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if info, err := d.Info(); err == nil && !d.IsDir() {
			size += info.Size()
			if size > maxBytes {
				return fmt.Errorf("repository exceeds the %d MB size limit", maxBytes>>20)
			}
		}
		return nil
	}
	if err := filepath.WalkDir(dst, walk); err != nil {
		return "", err
	}
	if job.FullHistory {
		if err := filepath.WalkDir(gitDir, walk); err != nil {
			return "", err
		}
	}
	return commit, nil
}

// gitHead returns the full commit ID checked out in dir.
func gitHead(ctx context.Context, dir string) (string, error) {
	// #nosec G204 -- fixed binary and arguments; dir is the worker's own checkout directory
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "-c", "core.hooksPath=/dev/null", "rev-parse", "--verify", "HEAD^{commit}")
	cmd.Env = append(baseEnv(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("reading the checked-out commit: %w", err)
	}
	sha := strings.TrimSpace(string(out))
	if !fullSHARe.MatchString(sha) {
		return "", errors.New("reading the checked-out commit: unexpected output")
	}
	return sha, nil
}

// writeCustomRules writes the job's custom rule files to a private
// temporary directory ("" when there are none).
func writeCustomRules(raw json.RawMessage) (string, error) {
	var cfg struct {
		CustomRules []struct {
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"custom_rules"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &cfg) != nil || len(cfg.CustomRules) == 0 {
		return "", nil
	}
	dir, err := os.MkdirTemp("", "pathos-rules-")
	if err != nil {
		return "", err
	}
	for i, r := range cfg.CustomRules {
		if len(r.Content) > 256<<10 {
			continue
		}
		// File names are generated, never taken from the server.
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("custom-%03d.yml", i)), []byte(r.Content), 0o600); err != nil {
			_ = os.RemoveAll(dir)
			return "", err
		}
	}
	return dir, nil
}

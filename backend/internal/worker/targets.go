package worker

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"pathos/internal/ingest"
	"strconv"
	"strings"
	"time"
)

// JobTarget is a non-repository scan target: a container image, a web
// application URL (DAST), an API (OpenAPI), an imported SBOM, an uploaded
// build artifact or mobile app, declared endpoints or an LLM endpoint.
type JobTarget struct {
	Kind      string `json:"kind"` // image | url | api | sbom | artifact | mobile-app | endpoints | llm-endpoint
	Reference string `json:"reference"`
	// Spec is the OpenAPI document of an api target.
	Spec string `json:"spec,omitempty"`
	// SBOM targets are downloaded from the worker API and verified.
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
	// Credentials: basic (registry or HTTP) or a header (DAST).
	AuthType    string `json:"auth_type,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	HeaderName  string `json:"header_name,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`
	// DAST tuning.
	RateLimit   int    `json:"rate_limit,omitempty"`
	MinSeverity string `json:"min_severity,omitempty"`
	// FileName of an artifact target.
	FileName string `json:"file_name,omitempty"`
	// Model of an llm-endpoint target.
	Model string `json:"model,omitempty"`
	// Endpoints of an endpoints target (a repository's declared public
	// endpoints).
	Endpoints []JobEndpoint `json:"endpoints,omitempty"`
	// Signature verification policy (image and artifact targets) and the
	// uploaded signature or Sigstore bundle of an artifact.
	Signature         *SignatureConfig `json:"signature,omitempty"`
	SignatureMaterial string           `json:"signature_material,omitempty"`
	// ProvenanceMaterial is the artifact's provenance attestation bundle.
	ProvenanceMaterial string `json:"provenance_material,omitempty"`
	// IntrusiveAuthorized: intrusive testing of this target was
	// authorized; intrusive tools are skipped otherwise.
	IntrusiveAuthorized bool `json:"intrusive_authorized,omitempty"`
}

// secrets lists credential values the reporter must never log.
func (t *JobTarget) secrets() []string {
	if t == nil {
		return nil
	}
	var out []string
	for _, s := range []string{t.Password, t.HeaderValue} {
		if len(s) >= 4 {
			out = append(out, s)
		}
	}
	return out
}

// prepareTarget writes the files a target scan needs into dir and returns
// the target file path (OpenAPI document or SBOM).
func (a *Agent) prepareTarget(ctx context.Context, job Job, dir string) (string, error) {
	t := job.Target
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	switch t.Kind {
	case "image":
		return "", nil
	case "url":
		return "", checkReachable(ctx, t.Reference)
	case "api":
		if err := checkReachable(ctx, t.Reference); err != nil {
			return "", err
		}
		if strings.TrimSpace(t.Spec) == "" {
			return "", errors.New("the API target has no OpenAPI document")
		}
		p := filepath.Join(dir, "openapi.yaml")
		return p, os.WriteFile(p, []byte(t.Spec), 0o600)
	case "sbom":
		return a.fetchTargetFile(ctx, job, filepath.Join(dir, "target.sbom.json"))
	case "artifact", "mobile-app":
		if job.Kind == JobKindREA {
			// Reverse engineering analyses the artifact as uploaded
			// (pathos-rea extracts firmware itself, in the sandbox).
			return a.fetchTargetFile(ctx, job, filepath.Join(dir, reaInputName(t.FileName)))
		}
		return a.prepareArtifact(ctx, job, dir)
	case "llm-endpoint":
		if err := checkReachable(ctx, t.Reference); err != nil {
			return "", err
		}
		return writeLLMTarget(t, filepath.Join(dir, "llm-target.json"))
	case "endpoints":
		if a.cfg.Offline {
			return "", errors.New("endpoint verification is disabled in offline mode (PATHOS_OFFLINE=true)")
		}
		// The URL list Nuclei reads (authorized endpoints only).
		p := filepath.Join(dir, "endpoints.txt")
		return p, endpointList(t.Endpoints, p)
	}
	return "", fmt.Errorf("unsupported target kind %q", t.Kind)
}

// checkReachable makes one request to a web target through the egress
// proxy before scanning. Without it, a target the proxy blocks would be
// "scanned" against the proxy's error page and produce false findings.
func checkReachable(ctx context.Context, target string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	host := req.URL.Hostname()
	client := &http.Client{
		Transport: &http.Transport{
			// The worker's egress proxy (read per call, like the tools do).
			Proxy: func(*http.Request) (*url.URL, error) {
				if p := proxyURL(); p != "" {
					return url.Parse(p)
				}
				return nil, nil
			},
			// Reachability only: staging targets often use private CAs, and
			// Nuclei does not verify certificates either.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- reachability probe; no data is sent or trusted
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "403") || strings.Contains(strings.ToLower(msg), "forbidden") {
			return egressDenied(host)
		}
		return fmt.Errorf("%s is not reachable: %s", host, lastLine(msg))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch e := resp.Header.Get("X-Squid-Error"); {
	case strings.HasPrefix(e, "ERR_ACCESS_DENIED"):
		return egressDenied(host)
	case strings.HasPrefix(e, "ERR_DNS_FAIL"):
		return fmt.Errorf("%s does not resolve (DNS lookup by the egress proxy failed)", host)
	case e != "":
		return fmt.Errorf("the egress proxy could not reach %s (%s)", host, e)
	}
	return nil
}

func egressDenied(host string) error {
	return fmt.Errorf("the egress proxy denied access to %s: add it to deploy/egress/allowlist.txt "+
		"(private addresses also need an override in deploy/egress/conf.d) and restart the egress service", host)
}

// fetchTargetFile downloads an SBOM target and verifies its SHA-256.
func (a *Agent) fetchTargetFile(ctx context.Context, job Job, dst string) (string, error) {
	want := strings.ToLower(job.Target.SHA256)
	if !sha256Re.MatchString(want) {
		return "", errors.New("job has no valid target file SHA-256")
	}
	u := strings.TrimRight(a.cfg.APIURL, "/") + "/internal/worker/v1/jobs/" + url.PathEscape(job.JobID) + "/target-file"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	client := *a.http
	client.Timeout = 0
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", &apiError{Status: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	const maxSBOM = 512 << 20 // also bounds artifacts (the API limits them to 200 MiB)
	// #nosec G304 -- path is created by the worker inside its job directory
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxSBOM+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > maxSBOM {
		return "", errors.New("the target file is too large")
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("target file checksum mismatch: got %s, expected %s", got, want)
	}
	return dst, nil
}

// proxyURL returns the egress proxy for tools that need it as a flag.
func proxyURL() string {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// nucleiTemplates is where the image installs the reviewed template sets.
var nucleiTemplates = "/opt/pathos/nuclei-templates"

// nucleiArgs builds a Nuclei command line. DAST never runs denial-of-service,
// brute-force or intrusive templates. URL scans skip fuzzing; API scans fuzz
// the documented endpoints with the DAST templates (which send injection
// payloads) only when intrusive testing of the target is authorized, and
// otherwise run the same non-fuzzing checks as URL scans on the API's
// endpoints.
func nucleiArgs(t *JobTarget, out, specFile string) []string {
	args := []string{"-jsonl", "-o", out, "-or", "-ot", "-silent", "-nc", "-duc", "-ni", "-timeout", "10", "-retries", "1"}
	args = append(args, "-rl", strconv.Itoa(targetRate(t)))
	if p := proxyURL(); p != "" {
		args = append(args, "-proxy", p)
	}
	switch t.Kind {
	case "api":
		if t.IntrusiveAuthorized {
			args = append(args, "-l", specFile, "-im", "openapi", "-dast", "-t", filepath.Join(nucleiTemplates, "dast"),
				"-etags", "dos,intrusive,bruteforce")
		} else {
			args = append(args, "-l", specFile, "-im", "openapi", "-t", filepath.Join(nucleiTemplates, "http")+","+filepath.Join(nucleiTemplates, "ssl"),
				"-etags", "dos,intrusive,bruteforce,fuzz")
		}
	case "endpoints":
		// Declared public endpoints: the exposure subset only (exposed
		// files and panels, subdomain takeovers), never fuzzing.
		var sets []string
		for _, d := range []string{"exposures", "exposed-panels", "takeovers"} {
			sets = append(sets, filepath.Join(nucleiTemplates, "http", d))
		}
		args = append(args, "-l", specFile, "-t", strings.Join(sets, ","), "-etags", "dos,intrusive,bruteforce,fuzz")
	default:
		args = append(args, "-u", t.Reference, "-t", filepath.Join(nucleiTemplates, "http")+","+filepath.Join(nucleiTemplates, "ssl"),
			"-etags", "dos,intrusive,bruteforce,fuzz")
	}
	switch t.MinSeverity {
	case "low", "medium", "high", "critical":
		var sev []string
		for _, s := range []string{"low", "medium", "high", "critical"} {
			if severityAtLeast(s, t.MinSeverity) {
				sev = append(sev, s)
			}
		}
		args = append(args, "-s", strings.Join(sev, ","))
	}
	switch t.AuthType {
	case "header":
		if t.HeaderName != "" {
			args = append(args, "-H", t.HeaderName+": "+t.HeaderValue)
		}
	case "basic":
		if t.Username != "" {
			args = append(args, "-H", "Authorization: Basic "+basicAuth(t.Username, t.Password))
		}
	}
	return args
}

// targetRate is a web or API target's rate limit in requests per second
// (1-100; 20 when not set).
func targetRate(t *JobTarget) int {
	if t == nil || t.RateLimit <= 0 || t.RateLimit > 100 {
		return 20
	}
	return t.RateLimit
}

func severityAtLeast(s, min string) bool {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	return rank[s] >= rank[min]
}

// targetTools are the adapters for non-repository targets and CI/CD.
func targetTools(cache func(string) string, cfg Config) map[string]Tool {
	return map[string]Tool{
		"trivy-image": simpleTool{"trivy", []string{"--version"}, func(ctx context.Context, bin string, in RunInput) (string, error) {
			if in.Target == nil || in.Target.Kind != "image" {
				return "only runs for container image targets", nil
			}
			var env []string
			if in.Target.AuthType == "basic" && in.Target.Username != "" {
				env = append(env, "TRIVY_USERNAME="+in.Target.Username, "TRIVY_PASSWORD="+in.Target.Password)
			}
			if cfg.Offline {
				if err := offlineReady(cfg.CacheDir, "trivy"); err != nil {
					return "", err
				}
			}
			args := append([]string{"image", "--image-src", "remote", "--scanners", "vuln", "--format", "sarif",
				"--output", in.Out, "--cache-dir", cache("trivy"), "--quiet", "--skip-version-check", "--timeout", "20m"}, trivyOffline(cfg.Offline)...)
			_, err := command(ctx, env, []int{0}, bin, append(args, in.Target.Reference)...)
			return "", err
		}},
		"nuclei": simpleTool{"nuclei", []string{"-version"}, func(ctx context.Context, bin string, in RunInput) (string, error) {
			if in.Target == nil || (in.Target.Kind != "url" && in.Target.Kind != "api" && in.Target.Kind != "endpoints") {
				return "only runs for web application, API and declared endpoint targets", nil
			}
			if _, err := command(ctx, []string{"HOME=/tmp/home"}, []int{0}, bin, nucleiArgs(in.Target, in.Out, in.TargetFile)...); err != nil {
				return "", err
			}
			// No findings: an empty JSONL report.
			if _, err := os.Stat(in.Out); errors.Is(err, os.ErrNotExist) {
				return "", os.WriteFile(in.Out, nil, 0o600)
			}
			return "", nil
		}},
		"actionlint": simpleTool{"actionlint", []string{"-version"}, func(ctx context.Context, bin string, in RunInput) (string, error) {
			files := workflowFiles(in.Src)
			if len(files) == 0 {
				return "no GitHub Actions workflows in the repository", nil
			}
			// #nosec G304 -- report path is created by the worker in its job directory
			f, err := os.OpenFile(in.Out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return "", err
			}
			// Exit code 1 means problems were found. shellcheck and pyflakes
			// are not installed, so no script from the repository is run.
			args := append([]string{"-format", "{{json .}}", "-no-color"}, files...)
			_, err = commandToIn(ctx, in.Src, f, nil, []int{0, 1}, bin, args...)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return "", err
			}
			if st, err := os.Stat(in.Out); err == nil && st.Size() == 0 {
				return "", os.WriteFile(in.Out, []byte("[]"), 0o600)
			}
			return "", nil
		}},
		"zizmor": simpleTool{"zizmor", []string{"--version"}, func(ctx context.Context, bin string, in RunInput) (string, error) {
			if !hasWorkflows(in.Src) {
				return "no GitHub Actions workflows or actions in the repository", nil
			}
			// zizmor prints SARIF to stdout. Offline: no GitHub API calls.
			// Exit codes 10-14 mean findings at increasing severity.
			// #nosec G304 -- report path is created by the worker in its job directory
			f, err := os.OpenFile(in.Out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return "", err
			}
			_, err = commandTo(ctx, f, nil, []int{0, 10, 11, 12, 13, 14}, bin,
				"--offline", "--format", "sarif", "--no-progress", in.Src)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return "", err
			}
			return "", ensureReport(in.Out, "zizmor")
		}},
	}
}

// hasWorkflows reports whether src has GitHub Actions workflows or actions.
func hasWorkflows(src string) bool {
	if src == "" {
		return false
	}
	if entries, err := os.ReadDir(filepath.Join(src, ".github", "workflows")); err == nil && len(entries) > 0 {
		return true
	}
	for _, f := range []string{"action.yml", "action.yaml"} {
		if _, err := os.Stat(filepath.Join(src, f)); err == nil {
			return true
		}
	}
	return false
}

// workflowFiles lists the repository's workflow files (relative paths).
func workflowFiles(src string) []string {
	if src == "" {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(src, ".github", "workflows"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.Type().IsRegular() && (strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml")) && len(out) < 500 {
			out = append(out, filepath.Join(".github", "workflows", n))
		}
	}
	return out
}

// LLMTarget is the endpoint description an llm-endpoint tool reads
// ({llm_target}): the chat completions URL, the model and the credential.
// It is written with mode 0600 into the job directory (removed with it), so
// the credential is never part of a command line or of the environment of
// other tools.
type LLMTarget struct {
	URL   string `json:"url"`
	Model string `json:"model"`
	// API is the request format: "openai-chat" (OpenAI-compatible chat
	// completions).
	API string `json:"api"`
	// Headers to send (the credential: Authorization or the target's
	// header).
	Headers map[string]string `json:"headers"`
	// RateLimit is the target's request rate per second (0: the tool's
	// default, sequential requests).
	RateLimit int `json:"rate_limit,omitempty"`
}

func writeLLMTarget(t *JobTarget, p string) (string, error) {
	lt := LLMTarget{URL: t.Reference, Model: t.Model, API: "openai-chat", Headers: map[string]string{}, RateLimit: t.RateLimit}
	switch t.AuthType {
	case "header":
		if t.HeaderName != "" {
			lt.Headers[t.HeaderName] = t.HeaderValue
		}
	case "basic":
		if t.Username != "" {
			lt.Headers["Authorization"] = "Basic " + basicAuth(t.Username, t.Password)
		}
	}
	b, err := json.Marshal(lt)
	if err != nil {
		return "", err
	}
	return p, os.WriteFile(p, b, 0o600)
}

// mobilePackage reports whether name is an Android (APK, AAB) or iOS (IPA)
// package: mobile tools read the package itself, binary hardening the
// native libraries and executables inside it.
func mobilePackage(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".apk", ".aab", ".ipa":
		return true
	}
	return false
}

// javaArchive reports whether name is a Java archive, which scanners read
// whole (they look at the embedded manifests and nested archives).
func javaArchive(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jar", ".war", ".ear", ".aar", ".jpi", ".hpi":
		return true
	}
	return false
}

// prepareArtifact downloads an artifact target (checksum verified) and
// returns the directory to scan. Zip and tar archives are validated and
// extracted with the same safe extraction as uploaded source snapshots
// (no links, no path traversal, size, count and ratio limits); Java
// archives and other files are scanned as they are. Nothing from the
// artifact is ever executed.
func (a *Agent) prepareArtifact(ctx context.Context, job Job, dir string) (string, error) {
	name := artifactFileName(job.Target.FileName)
	raw := filepath.Join(dir, "download")
	if _, err := a.fetchTargetFile(ctx, job, raw); err != nil {
		return "", err
	}
	scan := filepath.Join(dir, "artifact")
	if err := os.MkdirAll(scan, 0o700); err != nil {
		return "", err
	}
	// #nosec G304 -- path is created by the worker inside its job directory
	f, err := os.Open(raw)
	if err != nil {
		return "", err
	}
	defer f.Close()
	head := make([]byte, 512)
	k, _ := io.ReadFull(f, head)
	format, ferr := ingest.DetectFormat(head[:k], "")
	if ferr == nil && mobilePackage(name) {
		// Mobile packages: the contents are extracted (native libraries,
		// Info.plist, executables) and the package itself is kept beside
		// them for the mobile tools. A package the safe extraction rejects
		// is scanned as a file only.
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
		if err := extractArtifact(ctx, f, format, dir, scan); err != nil {
			toolLog(ctx, "the package contents were not extracted (%v); scanning the package file only", err)
			if err := os.RemoveAll(scan); err != nil {
				return "", err
			}
			if err := os.MkdirAll(scan, 0o700); err != nil {
				return "", err
			}
		}
		keep := filepath.Join(scan, name)
		if _, err := os.Lstat(keep); err == nil {
			keep = filepath.Join(scan, "original-"+name)
		}
		return scan, os.Rename(raw, keep)
	}
	if ferr != nil || javaArchive(name) {
		// Not an archive (or a Java archive): scan the file itself.
		return scan, os.Rename(raw, filepath.Join(scan, name))
	}
	if err := extractArtifact(ctx, f, format, dir, scan); err != nil {
		return "", err
	}
	// The original file stays (outside the scan directory) when its
	// signature is verified.
	if job.Target.Signature == nil || job.Target.Signature.Mode == "" {
		_ = os.Remove(raw)
	}
	return scan, nil
}

// extractArtifact validates and extracts an archive into scan.
func extractArtifact(ctx context.Context, f *os.File, format, dir, scan string) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	norm := filepath.Join(dir, "normalized.tar.gz")
	// #nosec G304 -- path is created by the worker inside its job directory
	nf, err := os.OpenFile(norm, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = nf.Close()
		_ = os.Remove(norm)
	}()
	if _, err := ingest.Normalize(ctx, f, format, st.Size(), nf, ingest.DefaultLimits()); err != nil {
		return fmt.Errorf("the artifact archive was rejected: %w", err)
	}
	if _, err := nf.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := ingest.ExtractSnapshot(ctx, nf, scan, ingest.DefaultLimits()); err != nil {
		return fmt.Errorf("extracting the artifact: %w", err)
	}
	return nil
}

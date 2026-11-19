package worker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"pathos/internal/scanners"
)

// Live secret validation (off by default). When an administrator enables
// providers, the job carries them and, after the scanners ran, the worker
// asks each provider whether the credentials found in the checkout are
// still active. The secret is read from the checkout here, sent only to
// its own provider's read-only "who am I" endpoint through the egress
// proxy, and never leaves the worker in any other form: the API receives
// the verdict, the HTTP status and a non-secret identity (account ID,
// user name). Tools keep their own verification off (Gitleaks --redact,
// TruffleHog --no-verification, Kingfisher --no-validate).

// SecretValidationConfig is the job's validation setting; nil = off.
type SecretValidationConfig struct {
	Providers     []string `json:"providers"`
	RatePerSecond int      `json:"rate_per_second"`
	MaxChecks     int      `json:"max_checks"`
}

// SecretValidationReport is uploaded to the worker API.
type SecretValidationReport struct {
	Version   int             `json:"version"`
	Providers []string        `json:"providers"`
	Results   []SecretVerdict `json:"results"`
}

// SecretVerdict is the outcome for one finding location. It never holds
// the secret.
type SecretVerdict struct {
	Fingerprints []string  `json:"fingerprints"`
	File         string    `json:"file"`
	Line         int       `json:"line"`
	Provider     string    `json:"provider"`
	Status       string    `json:"status"` // active | inactive | error | not_checked
	Identity     string    `json:"identity,omitempty"`
	Endpoint     string    `json:"endpoint,omitempty"`
	HTTPStatus   int       `json:"http_status,omitempty"`
	Detail       string    `json:"detail"`
	CheckedAt    time.Time `json:"checked_at"`
}

const (
	maxSecretLocations  = 500
	secretWindow        = 3 // lines around a finding searched for the other half of a pair
	secretCheckTimeout  = 10 * time.Second
	maxProviderResponse = 64 << 10
)

// testBaseURLs replaces a provider's API base URL. Only tests set it; no
// configuration or environment variable can.
var testBaseURLs map[string]string

func providerBase(id, def string) string {
	if u, ok := testBaseURLs[id]; ok {
		return u
	}
	return def
}

// secretLocation is one secret finding location in the scanned files.
type secretLocation struct {
	File string // as the parser reports it (stored on the finding)
	Path string // normalized, relative to the checkout
	Line int
	// Commit is set for secrets Gitleaks found in the Git history: the
	// line is read from that commit, not from the checked-out files.
	Commit       string
	Fingerprints []string
	Rules        []string
}

// collectSecretLocations parses the secret scanners' reports in outDir.
func collectSecretLocations(outDir string, keys []string, parserOf func(string) (scanners.ToolParser, bool)) []secretLocation {
	byLoc := map[string]*secretLocation{}
	var order []string
	for _, key := range keys {
		// Secret scanners, and SAST tools whose secret rules produce
		// secret findings (Opengrep, Semgrep).
		if c := categoryOf(key); c != "secrets" && c != "sast" {
			continue
		}
		// #nosec G304 -- report path is created by the worker in its job directory
		raw, err := os.ReadFile(filepath.Join(outDir, key+".out"))
		if err != nil || len(raw) == 0 {
			continue
		}
		var fs []scanners.Finding
		if p, ok := parserOf(key); ok {
			fs, _ = scanners.ParseToolOutput(key, p, raw)
		} else {
			fs, _ = scanners.Parse(key, raw)
		}
		var commits []string
		if key == scanners.Gitleaks {
			if c := sarifCommits(raw); len(c) == len(fs) {
				commits = c
			}
		}
		for i, f := range fs {
			if f.Category != "secrets" || f.StartLine == nil || *f.StartLine <= 0 || f.FilePath == "" || f.Fingerprint == "" {
				continue
			}
			p := scanners.NormalizePath(f.FilePath)
			if p == "" || strings.HasPrefix(p, "..") || strings.Contains(p, "://") {
				continue
			}
			commit := ""
			if commits != nil && fullCommitRe.MatchString(commits[i]) {
				commit = commits[i]
			}
			k := fmt.Sprintf("%s\x00%d\x00%s", p, *f.StartLine, commit)
			l := byLoc[k]
			if l == nil {
				if len(byLoc) >= maxSecretLocations {
					continue
				}
				l = &secretLocation{File: f.FilePath, Path: p, Line: *f.StartLine, Commit: commit}
				byLoc[k] = l
				order = append(order, k)
			}
			if !slices.Contains(l.Fingerprints, f.Fingerprint) && len(l.Fingerprints) < 20 {
				l.Fingerprints = append(l.Fingerprints, f.Fingerprint)
			}
			if f.RuleID != "" && !slices.Contains(l.Rules, f.RuleID) {
				l.Rules = append(l.Rules, f.RuleID)
			}
		}
	}
	sort.Strings(order)
	out := make([]secretLocation, 0, len(order))
	for _, k := range order {
		out = append(out, *byLoc[k])
	}
	return out
}

var fullCommitRe = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// sarifCommits lists the commit of each SARIF result, in order (Gitleaks
// sets partialFingerprints.commitSha in git mode).
func sarifCommits(raw []byte) []string {
	var doc struct {
		Runs []struct {
			Results []struct {
				PF map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	out := []string{}
	for _, r := range doc.Runs {
		for _, res := range r.Results {
			out = append(out, res.PF["commitSha"])
		}
	}
	return out
}

// commitLines reads a file as it was in a commit of the full-history
// checkout (git cat-file: no filters, hooks or textconv drivers run).
func commitLines(ctx context.Context, src, commit, path string) []string {
	if !fullCommitRe.MatchString(commit) || path == "" || strings.HasPrefix(path, "-") || strings.HasPrefix(path, "..") {
		return nil
	}
	if _, err := os.Stat(filepath.Join(src, ".git")); err != nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	if _, err := commandTo(cctx, &limitedWriter{buf: &out, max: 5 << 20}, []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}, []int{0},
		"git", "-C", src, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "cat-file", "blob", commit+":"+path); err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
}

// --- recognizing credentials -------------------------------------------------

// secretCandidate is a credential recognized at a finding location.
type secretCandidate struct {
	Provider string
	Values   map[string]string
	// Reason is set when the credential cannot be checked (not_checked).
	Reason string
}

func (c secretCandidate) key() string {
	keys := make([]string, 0, len(c.Values))
	for k := range c.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte(c.Provider))
	for _, k := range keys {
		h.Write([]byte{0})
		h.Write([]byte(k + "=" + c.Values[k]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c secretCandidate) secretValues() []string {
	var out []string
	for _, v := range c.Values {
		out = append(out, v)
	}
	return out
}

var (
	githubTokenRe   = regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`)
	gitlabTokenRe   = regexp.MustCompile(`\b(glpat-[A-Za-z0-9_\-]{20,64})`)
	slackTokenRe    = regexp.MustCompile(`\b(xox[abposr]-[A-Za-z0-9\-]{10,250})`)
	stripeKeyRe     = regexp.MustCompile(`\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,247})\b`)
	openaiKeyRe     = regexp.MustCompile(`\b(sk-(?:(?:proj|svcacct|admin)-)?[A-Za-z0-9_\-]{20,100}T3BlbkFJ[A-Za-z0-9_\-]{20,100})`)
	anthropicKeyRe  = regexp.MustCompile(`\b(sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{20,200})`)
	sendgridKeyRe   = regexp.MustCompile(`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`)
	npmTokenRe      = regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`)
	googleKeyRe     = regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})(?:[^0-9A-Za-z_\-]|$)`)
	pypiTokenRe     = regexp.MustCompile(`\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})`)
	awsKeyIDRe      = regexp.MustCompile(`\b((?:AKIA|ASIA)[A-Z2-7]{16})\b`)
	awsSecretKwRe   = regexp.MustCompile(`(?i)secret[_\-\s]*(?:access[_\-\s]*)?key["'\s]*[:=]+\s*["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)`)
	awsSecretBareRe = regexp.MustCompile(`(?:^|[^A-Za-z0-9/+=])([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)`)
	twilioSIDRe     = regexp.MustCompile(`\b(AC[0-9a-f]{32})\b`)
	twilioTokenRe   = regexp.MustCompile(`(?i)(?:auth|token|secret)[A-Za-z_\-]*["'\s]*[:=]+\s*["']?([0-9a-f]{32})\b`)
	azureNameRe     = regexp.MustCompile(`(?i)AccountName=([a-z0-9]{3,24})(?:[;"'\s]|$)`)
	azureKeyRe      = regexp.MustCompile(`(?i)AccountKey=([A-Za-z0-9+/]{86}==)`)
)

// providerHints map rule IDs to providers when several match a line.
var providerHints = map[string][]string{
	"aws": {"aws"}, "github": {"github"}, "gitlab": {"gitlab"}, "slack": {"slack"}, "stripe": {"stripe"},
	"openai": {"openai"}, "anthropic": {"anthropic"}, "sendgrid": {"sendgrid"}, "twilio": {"twilio"},
	"npm": {"npm"}, "google": {"gcp", "google"}, "azure-storage": {"azure"}, "pypi": {"pypi"},
}

func firstSub(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}

func inWindow(re *regexp.Regexp, window []string) string {
	for _, l := range window {
		if v := firstSub(re, l); v != "" {
			return v
		}
	}
	return ""
}

// mixedCase: AWS secret keys are random base64; hex digests (commit
// SHAs) are not.
func mixedCase(s string) bool {
	var up, low bool
	for _, r := range s {
		up = up || unicode.IsUpper(r)
		low = low || unicode.IsLower(r)
	}
	return up && low
}

func awsSecretOn(line, keyID string) string {
	if v := firstSub(awsSecretKwRe, line); v != "" {
		return v
	}
	for _, m := range awsSecretBareRe.FindAllStringSubmatch(line, -1) {
		if m[1] != keyID && mixedCase(m[1]) {
			return m[1]
		}
	}
	return ""
}

type extractor func(own string, window []string) (secretCandidate, bool)

func single(provider string, re *regexp.Regexp, filter func(string) bool) extractor {
	return func(own string, _ []string) (secretCandidate, bool) {
		v := firstSub(re, own)
		if v == "" || (filter != nil && !filter(v)) {
			return secretCandidate{}, false
		}
		return secretCandidate{Provider: provider, Values: map[string]string{"token": v}}, true
	}
}

// extractors in provider order (scanners.SecretProviders).
var extractors = map[string]extractor{
	"aws": func(own string, window []string) (secretCandidate, bool) {
		id := firstSub(awsKeyIDRe, own)
		secret := ""
		switch {
		case id != "":
			secret = awsSecretOn(own, id)
			if secret == "" {
				secret = inWindow(awsSecretKwRe, window)
			}
		default:
			if secret = firstSub(awsSecretKwRe, own); secret == "" {
				return secretCandidate{}, false
			}
			id = inWindow(awsKeyIDRe, window)
		}
		c := secretCandidate{Provider: "aws", Values: map[string]string{}}
		if id != "" {
			c.Values["id"] = id
		}
		if secret != "" {
			c.Values["secret"] = secret
		}
		switch {
		case id == "" || secret == "":
			c.Reason = "the access key ID and its secret access key were not both found within three lines"
		case strings.HasPrefix(id, "ASIA"):
			c.Reason = "temporary credentials (ASIA) also need a session token; not checked"
		}
		return c, true
	},
	"github":    single("github", githubTokenRe, nil),
	"gitlab":    single("gitlab", gitlabTokenRe, nil),
	"slack":     single("slack", slackTokenRe, nil),
	"stripe":    single("stripe", stripeKeyRe, nil),
	"openai":    single("openai", openaiKeyRe, func(v string) bool { return !strings.HasPrefix(v, "sk-ant-") }),
	"anthropic": single("anthropic", anthropicKeyRe, nil),
	"sendgrid":  single("sendgrid", sendgridKeyRe, nil),
	"twilio": func(own string, window []string) (secretCandidate, bool) {
		sid, token := firstSub(twilioSIDRe, own), firstSub(twilioTokenRe, own)
		if sid == "" && token == "" {
			return secretCandidate{}, false
		}
		if sid == "" {
			sid = inWindow(twilioSIDRe, window)
		}
		if token == "" {
			token = inWindow(twilioTokenRe, window)
		}
		c := secretCandidate{Provider: "twilio", Values: map[string]string{}}
		if sid != "" {
			c.Values["sid"] = sid
		}
		if token != "" {
			c.Values["token"] = token
		}
		if sid == "" || token == "" {
			c.Reason = "the account SID and its auth token were not both found within three lines"
		}
		return c, true
	},
	"npm":    single("npm", npmTokenRe, nil),
	"google": single("google", googleKeyRe, nil),
	"azure-storage": func(own string, window []string) (secretCandidate, bool) {
		name, key := firstSub(azureNameRe, own), firstSub(azureKeyRe, own)
		if key == "" && name == "" {
			return secretCandidate{}, false
		}
		if name == "" {
			name = inWindow(azureNameRe, window)
		}
		if key == "" {
			key = inWindow(azureKeyRe, window)
		}
		c := secretCandidate{Provider: "azure-storage", Values: map[string]string{}}
		if name != "" {
			c.Values["account"] = strings.ToLower(name)
		}
		if key != "" {
			c.Values["key"] = key
		}
		if name == "" || key == "" {
			c.Reason = "AccountName and AccountKey were not both found within three lines"
		}
		return c, true
	},
	"pypi": func(own string, _ []string) (secretCandidate, bool) {
		v := firstSub(pypiTokenRe, own)
		if v == "" {
			return secretCandidate{}, false
		}
		return secretCandidate{Provider: "pypi", Values: map[string]string{"token": v},
			Reason: "PyPI has no read-only endpoint that checks a token; not checked"}, true
	},
}

// recognize finds the credential at line (1-based) of a file.
func recognize(lines []string, line int, rules []string) (secretCandidate, bool) {
	if line < 1 || line > len(lines) {
		return secretCandidate{}, false
	}
	own := lines[line-1]
	from, to := max(line-1-secretWindow, 0), min(line+secretWindow, len(lines))
	window := lines[from:to]
	var found []secretCandidate
	for _, p := range scanners.SecretProviders {
		if ex := extractors[p.ID]; ex != nil {
			if c, ok := ex(own, window); ok {
				found = append(found, c)
			}
		}
	}
	if len(found) == 0 {
		return secretCandidate{}, false
	}
	rule := strings.ToLower(strings.Join(rules, " "))
	for _, c := range found {
		for _, h := range providerHints[c.Provider] {
			if strings.Contains(rule, h) {
				return c, true
			}
		}
	}
	// A complete pair or token beats one that cannot be checked.
	for _, c := range found {
		if c.Reason == "" {
			return c, true
		}
	}
	return found[0], true
}

// --- checking ----------------------------------------------------------------

var errNoProxy = errors.New("no egress proxy is configured (HTTPS_PROXY): live secret validation only runs through the egress proxy")

// secretClient sends every check through the egress proxy (NO_PROXY is
// ignored) and never follows redirects.
func secretClient() (*http.Client, error) {
	p := proxyURL()
	if p == "" {
		return nil, errNoProxy
	}
	pu, err := url.Parse(p)
	if err != nil || pu.Host == "" {
		return nil, errNoProxy
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSHandshakeTimeout: secretCheckTimeout,
			ResponseHeaderTimeout: secretCheckTimeout, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second, ForceAttemptHTTP2: true},
		Timeout:       secretCheckTimeout + 5*time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// secretChecker runs the checks of one job.
type secretChecker struct {
	client   *http.Client
	clientEr error
	enabled  map[string]bool
	offline  bool
	interval time.Duration
	max      int
	checks   int
	last     time.Time
	denied   map[string]string        // provider -> egress refusal
	seen     map[string]SecretVerdict // candidate key -> verdict (each secret is checked once)
	redact   func(values ...string)   // registers values the job's logs must never contain
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
}

func newSecretChecker(cfg SecretValidationConfig, offline bool, redact func(...string)) *secretChecker {
	c := &secretChecker{enabled: map[string]bool{}, offline: offline, denied: map[string]string{}, seen: map[string]SecretVerdict{},
		redact: redact, now: time.Now, sleep: sleepCtx}
	for _, p := range cfg.Providers {
		if sp, ok := scanners.LookupSecretProvider(p); ok && sp.Checkable {
			c.enabled[p] = true
		}
	}
	rate := cfg.RatePerSecond
	if rate < 1 || rate > 10 {
		rate = 1
	}
	c.interval = time.Second / time.Duration(rate)
	c.max = cfg.MaxChecks
	if c.max < 1 || c.max > 500 {
		c.max = 50
	}
	if !offline {
		c.client, c.clientEr = secretClient()
	}
	return c
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func providerName(id string) string {
	if p, ok := scanners.LookupSecretProvider(id); ok {
		return p.Name
	}
	return id
}

// check returns the verdict for a recognized credential.
func (c *secretChecker) check(ctx context.Context, cand secretCandidate) SecretVerdict {
	v := SecretVerdict{Provider: cand.Provider, Status: "not_checked", CheckedAt: c.now().UTC()}
	if c.redact != nil {
		c.redact(cand.secretValues()...)
	}
	switch {
	case cand.Reason != "":
		v.Detail = cand.Reason
		return v
	case !c.enabled[cand.Provider]:
		v.Detail = providerName(cand.Provider) + " validation is not enabled (Administration → Secret validation)"
		return v
	case c.offline:
		v.Detail = "offline mode (PATHOS_OFFLINE=true): no provider is contacted"
		return v
	case c.clientEr != nil:
		v.Status, v.Detail = "error", c.clientEr.Error()
		return v
	case c.denied[cand.Provider] != "":
		v.Status, v.Detail = "error", "not attempted: "+c.denied[cand.Provider]
		return v
	}
	key := cand.key()
	if prev, ok := c.seen[key]; ok {
		prev.Fingerprints, prev.File, prev.Line = nil, "", 0
		if prev.Detail != "" {
			prev.Detail += " (same credential as another location; checked once)"
		}
		return prev
	}
	if c.checks >= c.max {
		v.Detail = fmt.Sprintf("the limit of %d checks per scan was reached", c.max)
		return v
	}
	if wait := c.interval - c.now().Sub(c.last); !c.last.IsZero() && wait > 0 {
		if err := c.sleep(ctx, wait); err != nil {
			v.Status, v.Detail = "error", "scan stopped before the check"
			return v
		}
	}
	c.checks++
	c.last = c.now()
	cctx, cancel := context.WithTimeout(ctx, secretCheckTimeout)
	defer cancel()
	out := providerChecks[cand.Provider](cctx, c, cand)
	out.Provider, out.CheckedAt = cand.Provider, c.now().UTC()
	out.Identity = cleanIdentity(out.Identity, cand)
	out.Detail = cleanDetail(out.Detail, cand)
	if out.Status == "error" && strings.Contains(out.Detail, "egress proxy denied") {
		c.denied[cand.Provider] = out.Detail
	}
	c.seen[key] = out
	return out
}

// cleanIdentity keeps a short, printable identity that does not contain
// any part of the secret.
func cleanIdentity(s string, cand secretCandidate) string {
	s = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > 200 {
		s = s[:200]
	}
	for k, v := range cand.Values {
		// Identifiers that are not secret may be the identity itself.
		if k == "id" || k == "sid" || k == "account" {
			continue
		}
		if v != "" && strings.Contains(s, v) {
			return ""
		}
	}
	return s
}

func cleanDetail(s string, cand secretCandidate) string {
	for k, v := range cand.Values {
		if k != "id" && k != "sid" && k != "account" && v != "" {
			s = strings.ReplaceAll(s, v, "[REDACTED]")
		}
	}
	if len(s) > 480 {
		s = s[:480]
	}
	return s
}

// providerResponse is what a check keeps of a response.
type providerResponse struct {
	status int
	header http.Header
	body   []byte
}

// hostAllowed: the provider's own hosts only (and, in tests, the stub).
func hostAllowed(provider, host string) bool {
	host = strings.ToLower(host)
	if u, ok := testBaseURLs[provider]; ok {
		if pu, err := url.Parse(u); err == nil && strings.EqualFold(pu.Hostname(), host) {
			return true
		}
	}
	p, ok := scanners.LookupSecretProvider(provider)
	if !ok {
		return false
	}
	for _, h := range p.Hosts {
		if strings.HasPrefix(h, ".") {
			if strings.HasSuffix(host, h) && len(host) > len(h) {
				return true
			}
		} else if host == h {
			return true
		}
	}
	return false
}

// send makes one request to the provider. It refuses other hosts and
// reports egress refusals and redirects as errors.
func (c *secretChecker) send(ctx context.Context, provider string, req *http.Request) (*providerResponse, error) {
	host := req.URL.Hostname()
	if !hostAllowed(provider, host) {
		return nil, fmt.Errorf("refused: %s is not a %s host", host, providerName(provider))
	}
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "PATHOS-secret-validation/1")
	resp, err := c.client.Do(req)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "403") || strings.Contains(strings.ToLower(msg), "forbidden") {
			return nil, egressDeniedSecret(host)
		}
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "Client.Timeout") {
			return nil, fmt.Errorf("%s did not answer within %s", host, secretCheckTimeout)
		}
		return nil, fmt.Errorf("%s is not reachable: %s", host, lastLine(msg))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponse))
	switch e := resp.Header.Get("X-Squid-Error"); {
	case strings.HasPrefix(e, "ERR_ACCESS_DENIED"):
		return nil, egressDeniedSecret(host)
	case strings.HasPrefix(e, "ERR_DNS_FAIL"):
		return nil, fmt.Errorf("%s does not resolve (DNS lookup by the egress proxy failed)", host)
	case e != "":
		return nil, fmt.Errorf("the egress proxy could not reach %s (%s)", host, safeCode(e))
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("%s answered with a redirect (HTTP %d), which is not followed", host, resp.StatusCode)
	}
	return &providerResponse{status: resp.StatusCode, header: resp.Header, body: body}, nil
}

func egressDeniedSecret(host string) error {
	return fmt.Errorf("the egress proxy denied %s: add it to deploy/egress/allowlist.txt and restart the egress service", host)
}

var safeCodeRe = regexp.MustCompile(`[^A-Za-z0-9_.:\- ]`)

// safeCode keeps provider error codes short and plain.
func safeCode(s string) string {
	s = safeCodeRe.ReplaceAllString(s, "")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// verdictFor maps a transport result to an error verdict, or returns
// nil when the caller should interpret the response.
func verdictFor(endpoint string, resp *providerResponse, err error) *SecretVerdict {
	if err != nil {
		return &SecretVerdict{Status: "error", Endpoint: endpoint, Detail: err.Error()}
	}
	return nil
}

func jsonField(body []byte, path ...string) string {
	var doc any
	if json.Unmarshal(body, &doc) != nil {
		return ""
	}
	for _, p := range path {
		m, ok := doc.(map[string]any)
		if !ok {
			return ""
		}
		doc = m[p]
	}
	switch v := doc.(type) {
	case string:
		return v
	case bool:
		return fmt.Sprint(v)
	case float64:
		return fmt.Sprintf("%.0f", v)
	}
	return ""
}

func generic(resp *providerResponse, endpoint string) SecretVerdict {
	v := SecretVerdict{Endpoint: endpoint, HTTPStatus: resp.status}
	switch {
	case resp.status == http.StatusOK:
		v.Status, v.Detail = "active", "the provider accepted the credential (HTTP 200)"
	case resp.status == http.StatusUnauthorized:
		v.Status, v.Detail = "inactive", "the provider rejected the credential (HTTP 401)"
	case resp.status == http.StatusTooManyRequests:
		v.Status, v.Detail = "error", "rate limited by the provider (HTTP 429); re-check later"
	default:
		v.Status, v.Detail = "error", fmt.Sprintf("unexpected answer (HTTP %d); validity unknown", resp.status)
	}
	return v
}

type providerCheck func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict

var providerChecks = map[string]providerCheck{
	"github": func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict {
		const ep = "GET https://api.github.com/user"
		base := providerBase("github", "https://api.github.com")
		req, _ := http.NewRequest(http.MethodGet, base+"/user", nil)
		req.Header.Set("Authorization", "Bearer "+cand.Values["token"])
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		resp, err := c.send(ctx, "github", req)
		if v := verdictFor(ep, resp, err); v != nil {
			return *v
		}
		v := generic(resp, ep)
		switch {
		case resp.status == http.StatusOK:
			v.Identity = jsonField(resp.body, "login")
			if v.Identity != "" {
				v.Identity = "user " + v.Identity
			}
		case resp.status == http.StatusForbidden && resp.header.Get("X-RateLimit-Remaining") == "0":
			v.Status, v.Detail = "error", "rate limited by GitHub (HTTP 403, no requests remaining); re-check later"
		case resp.status == http.StatusForbidden:
			// Installation tokens cannot read /user; /rate_limit accepts
			// every valid token.
			const ep2 = "GET https://api.github.com/rate_limit"
			req2, _ := http.NewRequest(http.MethodGet, base+"/rate_limit", nil)
			req2.Header.Set("Authorization", "Bearer "+cand.Values["token"])
			req2.Header.Set("Accept", "application/vnd.github+json")
			resp2, err := c.send(ctx, "github", req2)
			if v2 := verdictFor(ep2, resp2, err); v2 != nil {
				return *v2
			}
			v = generic(resp2, ep2)
			if v.Status == "active" {
				v.Detail = "the token is valid (GET /user answered 403 for this token type; /rate_limit answered 200)"
			}
		}
		return v
	},
	"gitlab": func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict {
		const ep = "GET https://gitlab.com/api/v4/user"
		req, _ := http.NewRequest(http.MethodGet, providerBase("gitlab", "https://gitlab.com")+"/api/v4/user", nil)
		req.Header.Set("PRIVATE-TOKEN", cand.Values["token"])
		resp, err := c.send(ctx, "gitlab", req)
		if v := verdictFor(ep, resp, err); v != nil {
			return *v
		}
		v := generic(resp, ep)
		switch {
		case resp.status == http.StatusOK:
			if u := jsonField(resp.body, "username"); u != "" {
				v.Identity = "user " + u
			}
		case resp.status == http.StatusForbidden && jsonField(resp.body, "error") == "insufficient_scope":
			v.Status, v.Detail = "active", "the token is valid but lacks the read_user scope (HTTP 403 insufficient_scope)"
		}
		return v
	},
	"slack": func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict {
		const ep = "POST https://slack.com/api/auth.test"
		req, _ := http.NewRequest(http.MethodPost, providerBase("slack", "https://slack.com")+"/api/auth.test", nil)
		req.Header.Set("Authorization", "Bearer "+cand.Values["token"])
		resp, err := c.send(ctx, "slack", req)
		if v := verdictFor(ep, resp, err); v != nil {
			return *v
		}
		v := generic(resp, ep)
		if resp.status != http.StatusOK {
			return v
		}
		// Slack answers 200 with ok=false for rejected tokens.
		switch code := jsonField(resp.body, "error"); {
		case jsonField(resp.body, "ok") == "true":
			v.Detail = "auth.test answered ok=true"
			if t, u := jsonField(resp.body, "team_id"), jsonField(resp.body, "user_id"); t != "" || u != "" {
				v.Identity = strings.TrimSpace("team " + t + " user " + u)
			}
		case slices.Contains([]string{"invalid_auth", "not_authed", "account_inactive", "token_revoked", "token_expired"}, code):
			v.Status, v.Detail = "inactive", "auth.test answered ok=false ("+code+")"
		default:
			v.Status, v.Detail = "error", "auth.test answered ok=false ("+safeCode(code)+"); validity unknown"
		}
		return v
	},
	"stripe": func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict {
		const ep = "GET https://api.stripe.com/v1/balance"
		req, _ := http.NewRequest(http.MethodGet, providerBase("stripe", "https://api.stripe.com")+"/v1/balance", nil)
		req.SetBasicAuth(cand.Values["token"], "")
		resp, err := c.send(ctx, "stripe", req)
		if v := verdictFor(ep, resp, err); v != nil {
			return *v
		}
		v := generic(resp, ep)
		switch resp.status {
		case http.StatusOK:
			if lm := jsonField(resp.body, "livemode"); lm != "" {
				v.Identity = map[string]string{"true": "live mode key", "false": "test mode key"}[lm]
			}
		case http.StatusForbidden:
			v.Status, v.Detail = "active", "the key is valid but may not read the balance (HTTP 403: a restricted key)"
		}
		return v
	},
	"openai": func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict {
		const ep = "GET https://api.openai.com/v1/models"
		req, _ := http.NewRequest(http.MethodGet, providerBase("openai", "https://api.openai.com")+"/v1/models", nil)
		req.Header.Set("Authorization", "Bearer "+cand.Values["token"])
		resp, err := c.send(ctx, "openai", req)
		if v := verdictFor(ep, resp, err); v != nil {
			return *v
		}
		v := generic(resp, ep)
		if v.Status == "active" {
			if o := resp.header.Get("Openai-Organization"); o != "" {
				v.Identity = "organization " + safeCode(o)
			}
		}
		return v
	},
	"anthropic": func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict {
		const ep = "GET https://api.anthropic.com/v1/models"
		req, _ := http.NewRequest(http.MethodGet, providerBase("anthropic", "https://api.anthropic.com")+"/v1/models", nil)
		req.Header.Set("X-Api-Key", cand.Values["token"])
		req.Header.Set("Anthropic-Version", "2023-06-01")
		resp, err := c.send(ctx, "anthropic", req)
		if v := verdictFor(ep, resp, err); v != nil {
			return *v
		}
		v := generic(resp, ep)
		if v.Status == "active" {
			if o := resp.header.Get("Anthropic-Organization-Id"); o != "" {
				v.Identity = "organization " + safeCode(o)
			}
		}
		return v
	},
	"sendgrid": func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict {
		const ep = "GET https://api.sendgrid.com/v3/scopes"
		req, _ := http.NewRequest(http.MethodGet, providerBase("sendgrid", "https://api.sendgrid.com")+"/v3/scopes", nil)
		req.Header.Set("Authorization", "Bearer "+cand.Values["token"])
		resp, err := c.send(ctx, "sendgrid", req)
		if v := verdictFor(ep, resp, err); v != nil {
			return *v
		}
		v := generic(resp, ep)
		if v.Status == "active" {
			var doc struct {
				Scopes []string `json:"scopes"`
			}
			if json.Unmarshal(resp.body, &doc) == nil {
				v.Detail = fmt.Sprintf("the key is valid and has %d scopes (HTTP 200)", len(doc.Scopes))
			}
		}
		return v
	},
	"twilio": func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict {
		const ep = "GET https://api.twilio.com/2010-04-01/Accounts/{AccountSid}.json"
		sid := cand.Values["sid"]
		req, _ := http.NewRequest(http.MethodGet, providerBase("twilio", "https://api.twilio.com")+"/2010-04-01/Accounts/"+url.PathEscape(sid)+".json", nil)
		req.SetBasicAuth(sid, cand.Values["token"])
		resp, err := c.send(ctx, "twilio", req)
		if v := verdictFor(ep, resp, err); v != nil {
			return *v
		}
		v := generic(resp, ep)
		if v.Status == "active" {
			v.Identity = "account " + sid
			if st := jsonField(resp.body, "status"); st != "" {
				v.Detail = "the credentials are valid; account status " + safeCode(st) + " (HTTP 200)"
			}
		}
		return v
	},
	"npm": func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict {
		const ep = "GET https://registry.npmjs.org/-/whoami"
		req, _ := http.NewRequest(http.MethodGet, providerBase("npm", "https://registry.npmjs.org")+"/-/whoami", nil)
		req.Header.Set("Authorization", "Bearer "+cand.Values["token"])
		resp, err := c.send(ctx, "npm", req)
		if v := verdictFor(ep, resp, err); v != nil {
			return *v
		}
		v := generic(resp, ep)
		if v.Status == "active" {
			if u := jsonField(resp.body, "username"); u != "" {
				v.Identity = "user " + u
			}
		}
		return v
	},
	"google": func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict {
		const ep = "GET https://generativelanguage.googleapis.com/v1beta/models"
		req, _ := http.NewRequest(http.MethodGet, providerBase("google", "https://generativelanguage.googleapis.com")+"/v1beta/models?pageSize=1", nil)
		// The key goes in a header, never in the URL (proxy logs).
		req.Header.Set("X-Goog-Api-Key", cand.Values["token"])
		resp, err := c.send(ctx, "google", req)
		if v := verdictFor(ep, resp, err); v != nil {
			return *v
		}
		v := generic(resp, ep)
		reason := googleReason(resp.body)
		switch {
		case resp.status == http.StatusOK:
		case reason == "API_KEY_INVALID":
			v.Status, v.Detail = "inactive", fmt.Sprintf("Google rejected the key (HTTP %d API_KEY_INVALID)", resp.status)
		case resp.status == http.StatusForbidden && slices.Contains([]string{"SERVICE_DISABLED", "API_KEY_SERVICE_BLOCKED",
			"API_KEY_HTTP_REFERRER_BLOCKED", "API_KEY_IP_ADDRESS_BLOCKED", "API_KEY_ANDROID_APP_BLOCKED", "API_KEY_IOS_APP_BLOCKED"}, reason):
			v.Status, v.Detail = "active", "the key exists but is restricted (HTTP 403 "+reason+")"
		case reason != "":
			v.Detail += " (" + safeCode(reason) + ")"
		}
		return v
	},
	"aws": func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict {
		const ep = "POST https://sts.amazonaws.com/ Action=GetCallerIdentity"
		body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
		req, _ := http.NewRequest(http.MethodPost, providerBase("aws", "https://sts.amazonaws.com")+"/", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		signSigV4(req, body, cand.Values["id"], cand.Values["secret"], "us-east-1", "sts", c.now())
		resp, err := c.send(ctx, "aws", req)
		if v := verdictFor(ep, resp, err); v != nil {
			return *v
		}
		v := generic(resp, ep)
		var doc struct {
			Result struct {
				Account string `xml:"Account"`
				Arn     string `xml:"Arn"`
			} `xml:"GetCallerIdentityResult"`
			Error struct {
				Code string `xml:"Code"`
			} `xml:"Error"`
		}
		_ = xml.Unmarshal(resp.body, &doc)
		code := doc.Error.Code
		switch {
		case resp.status == http.StatusOK:
			v.Identity = strings.TrimSpace("account " + doc.Result.Account + " " + doc.Result.Arn)
		case code == "InvalidClientTokenId" || code == "ExpiredToken":
			v.Status, v.Detail = "inactive", fmt.Sprintf("AWS rejected the key (HTTP %d %s)", resp.status, code)
		case code == "SignatureDoesNotMatch":
			v.Status, v.Detail = "error", "the key ID exists but the secret found next to it does not match (SignatureDoesNotMatch); validity of the pair unknown"
		case code != "":
			v.Detail += " (" + safeCode(code) + ")"
		}
		return v
	},
	"azure-storage": func(ctx context.Context, c *secretChecker, cand secretCandidate) SecretVerdict {
		const ep = "GET https://{account}.blob.core.windows.net/?restype=service&comp=properties"
		account := cand.Values["account"]
		key, err := base64.StdEncoding.DecodeString(cand.Values["key"])
		if err != nil {
			return SecretVerdict{Status: "not_checked", Endpoint: ep, Detail: "the AccountKey is not valid base64"}
		}
		req, _ := http.NewRequest(http.MethodGet, providerBase("azure-storage", "https://"+account+".blob.core.windows.net")+"/?restype=service&comp=properties", nil)
		signAzureSharedKey(req, account, key, c.now())
		resp, err := c.send(ctx, "azure-storage", req)
		if v := verdictFor(ep, resp, err); v != nil {
			return *v
		}
		v := generic(resp, ep)
		var doc struct {
			Code string `xml:"Code"`
		}
		_ = xml.Unmarshal(resp.body, &doc)
		switch {
		case resp.status == http.StatusOK:
			v.Identity = "storage account " + account
		case resp.status == http.StatusForbidden && doc.Code == "AuthenticationFailed":
			v.Status, v.Detail = "inactive", "Azure rejected the account key (HTTP 403 AuthenticationFailed)"
		case doc.Code != "":
			v.Detail += " (" + safeCode(doc.Code) + ")"
		}
		return v
	},
}

func googleReason(body []byte) string {
	var doc struct {
		Error struct {
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return ""
	}
	for _, d := range doc.Error.Details {
		if d.Reason != "" {
			return d.Reason
		}
	}
	return ""
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// signSigV4 signs a request with AWS Signature Version 4 (host,
// x-amz-date and, when set, content-type are signed).
func signSigV4(req *http.Request, body []byte, keyID, secret, region, service string, t time.Time) {
	amzDate := t.UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)
	headers := map[string]string{"host": req.URL.Host, "x-amz-date": amzDate}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		headers["content-type"] = ct
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{req.Method, path, req.URL.Query().Encode(), canonHeaders.String(), signed, sha256Hex(body)}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+keyID+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}

const azureStorageVersion = "2021-08-06"

// signAzureSharedKey signs a GET without body with the Shared Key scheme
// of Azure Storage.
func signAzureSharedKey(req *http.Request, account string, key []byte, t time.Time) {
	date := t.UTC().Format(http.TimeFormat)
	req.Header.Set("X-Ms-Date", date)
	req.Header.Set("X-Ms-Version", azureStorageVersion)
	// VERB, Content-Encoding, -Language, -Length, -MD5, -Type, Date,
	// If-Modified-Since, If-Match, If-None-Match, If-Unmodified-Since, Range.
	var b strings.Builder
	b.WriteString(req.Method + "\n" + strings.Repeat("\n", 11))
	b.WriteString("x-ms-date:" + date + "\nx-ms-version:" + azureStorageVersion + "\n")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	b.WriteString("/" + account + path)
	q := req.URL.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		vals := append([]string{}, q[k]...)
		sort.Strings(vals)
		b.WriteString("\n" + strings.ToLower(k) + ":" + strings.Join(vals, ","))
	}
	sig := base64.StdEncoding.EncodeToString(hmacSHA256(key, b.String()))
	req.Header.Set("Authorization", "SharedKey "+account+":"+sig)
}

// --- the job step --------------------------------------------------------------

// validateSecrets checks the secrets the job's scanners found and uploads
// the verdicts. Nothing runs unless the job carries enabled providers.
func (a *Agent) validateSecrets(ctx, parent context.Context, job Job, src, out string, keys []string, rep *reporter) {
	cfg := job.SecretValidation
	if cfg == nil || len(cfg.Providers) == 0 {
		return
	}
	locs := collectSecretLocations(out, keys, a.manifestParser)
	if len(locs) == 0 {
		rep.logf("info", "secret validation: no secret findings to check")
		return
	}
	start := time.Now()
	report := runSecretValidation(ctx, newSecretChecker(*cfg, a.cfg.Offline, rep.redact), src, locs)
	report.Providers = cfg.Providers
	counts := map[string]int{}
	for _, r := range report.Results {
		counts[r.Status]++
	}
	rep.logf("info", "secret validation: %d locations in %s: %d active, %d inactive, %d error, %d not checked",
		len(report.Results), time.Since(start).Round(time.Millisecond), counts["active"], counts["inactive"], counts["error"], counts["not_checked"])
	if _, err := a.call(parent, http.MethodPost, "/internal/worker/v1/jobs/"+job.JobID+"/secret-validation", a.token, report, nil); err != nil {
		a.log.Warn("secret validation upload failed", "job_id", job.JobID, "err", err)
		rep.logf("warn", "secret validation upload failed: %v", err)
	}
}

// runSecretValidation produces one verdict per location.
func runSecretValidation(ctx context.Context, c *secretChecker, src string, locs []secretLocation) SecretValidationReport {
	rep := SecretValidationReport{Version: 1, Results: []SecretVerdict{}}
	cache := map[string][]string{}
	for _, l := range locs {
		v := SecretVerdict{Status: "not_checked", CheckedAt: c.now().UTC()}
		ck := l.Commit + ":" + l.Path
		lines, ok := cache[ck]
		if !ok {
			if l.Commit != "" {
				lines = commitLines(ctx, src, l.Commit, l.Path)
			} else {
				lines = readLines(src, l.Path)
			}
			cache[ck] = lines
		}
		switch cand, found := recognize(lines, l.Line, l.Rules); {
		case ctx.Err() != nil:
			v.Detail = "scan stopped before the check"
		case l.Commit != "" && (len(lines) == 0 || l.Line > len(lines)):
			v.Detail = "the commit " + l.Commit[:12] + " that holds the secret is not available in the checkout"
		case len(lines) == 0 || l.Line > len(lines):
			v.Detail = "the location is not in the scanned files"
		case !found:
			v.Detail = "no credential of a supported provider was recognized on this line"
		default:
			v = c.check(ctx, cand)
		}
		v.Fingerprints, v.File, v.Line = l.Fingerprints, l.File, l.Line
		rep.Results = append(rep.Results, v)
	}
	return rep
}

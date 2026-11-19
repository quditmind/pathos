package worker

// Live secret validation tests. Every provider is played by a local stub
// server (testBaseURLs, which only tests can set) behind a stub egress
// proxy that, like Squid, forwards only the hosts on its allowlist and
// answers 403 with X-Squid-Error otherwise. Credential values are
// assembled at run time from obviously fake parts, so no file in the
// repository contains a string in a real provider token format.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"pathos/internal/scanners"
)

func rep(s string, n int) string { return strings.Repeat(s, n) }

// stubProxy is a minimal allowlisting forward proxy (plain HTTP).
type stubProxy struct {
	mu     sync.Mutex
	allow  map[string]bool
	denied []string
	hits   int
}

func (p *stubProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.hits++
	ok := p.allow[r.URL.Host]
	if !ok {
		p.denied = append(p.denied, r.URL.Host)
	}
	p.mu.Unlock()
	if r.Method == http.MethodConnect || r.URL.Host == "" {
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
		return
	}
	if !ok {
		w.Header().Set("X-Squid-Error", "ERR_ACCESS_DENIED 0")
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	resp, err := (&http.Transport{}).RoundTrip(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// stub is a provider stub that counts requests and records credentials.
type stub struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits int
	seen []string // full request dumps (headers and body)
}

func newStub(t *testing.T, h http.HandlerFunc) *stub {
	s := &stub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		s.mu.Lock()
		s.hits++
		var b strings.Builder
		_ = r.Header.Write(&b)
		s.seen = append(s.seen, r.Method+" "+r.URL.String()+"\n"+b.String()+"\n"+string(body))
		s.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stub) host() string { u, _ := url.Parse(s.srv.URL); return u.Host }

func (s *stub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func bearerOf(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func basicUser(r *http.Request) string { u, _, _ := r.BasicAuth(); return u }

// providerCase describes one provider: three credentials (accepted,
// rejected, provider failure), the file content holding each, the line
// of the finding, and the stub that plays the provider.
type providerCase struct {
	id                string
	good, bad, flaky  string // the file contents
	line              int
	wantIdentity      string
	handler           func(t *testing.T) http.HandlerFunc
	secretsInRequests []string // values that must reach only this stub
}

// tokenHandler answers by credential: good -> ok, bad -> reject, else 503.
func tokenHandler(method, path string, cred func(*http.Request) string, good, bad string, ok, reject func(http.ResponseWriter)) func(*testing.T) http.HandlerFunc {
	return func(t *testing.T) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method || r.URL.Path != path {
				t.Errorf("unexpected request %s %s (want %s %s)", r.Method, r.URL.Path, method, path)
				http.NotFound(w, r)
				return
			}
			switch cred(r) {
			case good:
				ok(w)
			case bad:
				reject(w)
			default:
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			}
		}
	}
}

func unauthorized(w http.ResponseWriter) {
	jsonOut(w, http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
}

// signedBy recomputes an AWS SigV4 signature for the given secret.
func awsSignatureValid(r *http.Request, body []byte, secret string) bool {
	t, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return false
	}
	check, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), bytes.NewReader(body))
	check.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	id := strings.SplitN(strings.TrimPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential="), "/", 2)[0]
	signSigV4(check, body, id, secret, "us-east-1", "sts", t)
	return check.Header.Get("Authorization") == r.Header.Get("Authorization")
}

// azureSignature is an independent implementation of the Shared Key
// string to sign for a GET without body (Azure Storage documentation).
func azureSignature(r *http.Request, account string, key []byte) string {
	q := r.URL.Query()
	parts := []string{
		"GET", "", "", "", "", "", "", "", "", "", "", "",
		"x-ms-date:" + r.Header.Get("X-Ms-Date"),
		"x-ms-version:" + r.Header.Get("X-Ms-Version"),
		"/" + account + "/",
		"comp:" + q.Get("comp"),
		"restype:" + q.Get("restype"),
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(strings.Join(parts, "\n")))
	return "SharedKey " + account + ":" + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func providerCases() []providerCase {
	gh := [3]string{"ghp_" + rep("Ab12", 9), "ghp_" + rep("Zz90", 9), "ghp_" + rep("Qq55", 9)}
	gl := [3]string{"glpat-" + rep("a1b2", 5), "glpat-" + rep("c3d4", 5), "glpat-" + rep("e5f6", 5)}
	sl := [3]string{"xoxb-" + "1234567890-" + rep("a", 12), "xoxb-" + "1234567890-" + rep("b", 12), "xoxb-" + "1234567890-" + rep("c", 12)}
	st := [3]string{"sk_" + "live_" + rep("Ab1", 8), "sk_" + "live_" + rep("Cd2", 8), "sk_" + "live_" + rep("Ef3", 8)}
	oa := [3]string{"sk-" + "proj-" + rep("a", 24) + "T3Blbk" + "FJ" + rep("b", 24), "sk-" + "proj-" + rep("c", 24) + "T3Blbk" + "FJ" + rep("d", 24),
		"sk-" + "proj-" + rep("e", 24) + "T3Blbk" + "FJ" + rep("f", 24)}
	an := [3]string{"sk-ant-" + "api03-" + rep("c", 40), "sk-ant-" + "api03-" + rep("d", 40), "sk-ant-" + "api03-" + rep("e", 40)}
	sg := [3]string{"SG." + rep("d", 22) + "." + rep("e", 43), "SG." + rep("f", 22) + "." + rep("g", 43), "SG." + rep("h", 22) + "." + rep("i", 43)}
	np := [3]string{"npm_" + rep("Q1", 18), "npm_" + rep("R2", 18), "npm_" + rep("S3", 18)}
	gk := [3]string{"AIza" + rep("g1", 17) + "g", "AIza" + rep("h2", 17) + "h", "AIza" + rep("i3", 17) + "i"}
	sid := "AC" + rep("0f", 16)
	tw := [3]string{rep("1a", 16), rep("2b", 16), rep("3c", 16)}
	awsID := [3]string{"AKIA" + rep("QZ", 8), "AKIA" + rep("ZQ", 8), "AKIA" + rep("Q2", 8)}
	awsSecret := rep("aB3/", 10)
	az := [3]string{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 64)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 64)),
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 64))}
	file := func(prefix string, v [3]string) [3]string {
		return [3]string{"# config\n" + prefix + v[0] + "\n", "# config\n" + prefix + v[1] + "\n", "# config\n" + prefix + v[2] + "\n"}
	}
	mk := func(id string, prefix string, v [3]string, identity string, h func(*testing.T) http.HandlerFunc) providerCase {
		f := file(prefix, v)
		return providerCase{id: id, good: f[0], bad: f[1], flaky: f[2], line: 2, wantIdentity: identity, handler: h, secretsInRequests: v[:]}
	}
	cases := []providerCase{
		mk("github", "GITHUB_TOKEN=", gh, "user octo-test", tokenHandler("GET", "/user", bearerOf, gh[0], gh[1],
			func(w http.ResponseWriter) { jsonOut(w, 200, map[string]string{"login": "octo-test"}) }, unauthorized)),
		mk("gitlab", "GITLAB_TOKEN=", gl, "user gl-test", tokenHandler("GET", "/api/v4/user", func(r *http.Request) string { return r.Header.Get("PRIVATE-TOKEN") }, gl[0], gl[1],
			func(w http.ResponseWriter) { jsonOut(w, 200, map[string]string{"username": "gl-test"}) }, unauthorized)),
		mk("slack", "SLACK_TOKEN=", sl, "team T001 user U001", tokenHandler("POST", "/api/auth.test", bearerOf, sl[0], sl[1],
			func(w http.ResponseWriter) {
				jsonOut(w, 200, map[string]any{"ok": true, "team_id": "T001", "user_id": "U001"})
			},
			func(w http.ResponseWriter) { jsonOut(w, 200, map[string]any{"ok": false, "error": "invalid_auth"}) })),
		mk("stripe", "STRIPE_KEY=", st, "live mode key", tokenHandler("GET", "/v1/balance", basicUser, st[0], st[1],
			func(w http.ResponseWriter) { jsonOut(w, 200, map[string]any{"object": "balance", "livemode": true}) }, unauthorized)),
		mk("openai", "OPENAI_API_KEY=", oa, "organization org-test", tokenHandler("GET", "/v1/models", bearerOf, oa[0], oa[1],
			func(w http.ResponseWriter) {
				w.Header().Set("Openai-Organization", "org-test")
				jsonOut(w, 200, map[string]any{"data": []any{}})
			}, unauthorized)),
		mk("anthropic", "ANTHROPIC_API_KEY=", an, "organization org-a", tokenHandler("GET", "/v1/models",
			func(r *http.Request) string {
				if r.Header.Get("Anthropic-Version") == "" {
					return ""
				}
				return r.Header.Get("X-Api-Key")
			}, an[0], an[1],
			func(w http.ResponseWriter) {
				w.Header().Set("Anthropic-Organization-Id", "org-a")
				jsonOut(w, 200, map[string]any{"data": []any{}})
			}, unauthorized)),
		mk("sendgrid", "SENDGRID_API_KEY=", sg, "", tokenHandler("GET", "/v3/scopes", bearerOf, sg[0], sg[1],
			func(w http.ResponseWriter) { jsonOut(w, 200, map[string]any{"scopes": []string{"mail.send"}}) }, unauthorized)),
		mk("npm", "//registry.npmjs.org/:_authToken=", np, "user npm-test", tokenHandler("GET", "/-/whoami", bearerOf, np[0], np[1],
			func(w http.ResponseWriter) { jsonOut(w, 200, map[string]string{"username": "npm-test"}) }, unauthorized)),
		mk("google", "GOOGLE_API_KEY=", gk, "", tokenHandler("GET", "/v1beta/models", func(r *http.Request) string { return r.Header.Get("X-Goog-Api-Key") }, gk[0], gk[1],
			func(w http.ResponseWriter) { jsonOut(w, 200, map[string]any{"models": []any{}}) },
			func(w http.ResponseWriter) {
				jsonOut(w, 400, map[string]any{"error": map[string]any{"code": 400, "message": "API key not valid.",
					"details": []any{map[string]any{"reason": "API_KEY_INVALID"}}}})
			})),
	}
	// Twilio: the SID on line 1, the auth token (the finding) on line 2.
	twFile := func(tok string) string { return "TWILIO_ACCOUNT_SID=" + sid + "\nTWILIO_AUTH_TOKEN=" + tok + "\n" }
	cases = append(cases, providerCase{id: "twilio", good: twFile(tw[0]), bad: twFile(tw[1]), flaky: twFile(tw[2]), line: 2,
		wantIdentity: "account " + sid, secretsInRequests: tw[:],
		handler: func(t *testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				u, p, _ := r.BasicAuth()
				if r.URL.Path != "/2010-04-01/Accounts/"+sid+".json" || u != sid {
					t.Errorf("unexpected twilio request %s", r.URL.Path)
				}
				switch p {
				case tw[0]:
					jsonOut(w, 200, map[string]string{"sid": sid, "status": "active"})
				case tw[1]:
					unauthorized(w)
				default:
					http.Error(w, "unavailable", 503)
				}
			}
		}})
	// AWS: key ID (the finding) on line 1, secret on line 2; the stub
	// verifies the SigV4 signature.
	awsFile := func(id string) string {
		return "aws_access_key_id = " + id + "\naws_secret_access_key = " + awsSecret + "\n"
	}
	cases = append(cases, providerCase{id: "aws", good: awsFile(awsID[0]), bad: awsFile(awsID[1]), flaky: awsFile(awsID[2]), line: 1,
		wantIdentity: "account 123456789012 arn:aws:iam::123456789012:user/ci", secretsInRequests: []string{awsSecret},
		handler: func(t *testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if r.Method != "POST" || string(body) != "Action=GetCallerIdentity&Version=2011-06-15" {
					t.Errorf("unexpected STS request %s %q", r.Method, body)
				}
				auth := r.Header.Get("Authorization")
				switch {
				case strings.Contains(auth, awsID[0]+"/") && awsSignatureValid(r, body, awsSecret):
					w.WriteHeader(200)
					_, _ = io.WriteString(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/ci</Arn>`+
						`<UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`)
				case strings.Contains(auth, awsID[0]+"/"):
					w.WriteHeader(403)
					_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>`)
				case strings.Contains(auth, awsID[1]+"/"):
					w.WriteHeader(403)
					_, _ = io.WriteString(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidClientTokenId</Code></Error></ErrorResponse>`)
				default:
					http.Error(w, "unavailable", 503)
				}
			}
		}})
	// Azure Storage: a connection string; the stub verifies Shared Key.
	azFile := func(key string) string {
		return "STORAGE=DefaultEndpointsProtocol=https;AccountName=pathostest;AccountKey=" + key + ";EndpointSuffix=core.windows.net\n"
	}
	cases = append(cases, providerCase{id: "azure-storage", good: "# storage\n" + azFile(az[0]), bad: "# storage\n" + azFile(az[1]),
		flaky: "# storage\n" + azFile(az[2]), line: 2, wantIdentity: "storage account pathostest", secretsInRequests: az[:],
		handler: func(t *testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("comp") != "properties" || r.URL.Query().Get("restype") != "service" {
					t.Errorf("unexpected Azure request %s", r.URL)
				}
				good, _ := base64.StdEncoding.DecodeString(az[0])
				bad, _ := base64.StdEncoding.DecodeString(az[1])
				switch r.Header.Get("Authorization") {
				case azureSignature(r, "pathostest", good):
					w.WriteHeader(200)
					_, _ = io.WriteString(w, `<?xml version="1.0"?><StorageServiceProperties></StorageServiceProperties>`)
				case azureSignature(r, "pathostest", bad):
					w.WriteHeader(403)
					_, _ = io.WriteString(w, `<?xml version="1.0"?><Error><Code>AuthenticationFailed</Code></Error>`)
				default:
					http.Error(w, "unavailable", 503)
				}
			}
		}})
	return cases
}

// harness wires stubs, the proxy and testBaseURLs for a test.
type harness struct {
	proxy *stubProxy
	stubs map[string]*stub
	src   string
}

func newHarness(t *testing.T, cases []providerCase, allowlisted bool) *harness {
	t.Helper()
	h := &harness{proxy: &stubProxy{allow: map[string]bool{}}, stubs: map[string]*stub{}, src: t.TempDir()}
	ps := httptest.NewServer(h.proxy)
	t.Cleanup(ps.Close)
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(k, "")
	}
	t.Setenv("HTTPS_PROXY", ps.URL)
	prev := testBaseURLs
	testBaseURLs = map[string]string{}
	t.Cleanup(func() { testBaseURLs = prev })
	for _, c := range cases {
		s := newStub(t, c.handler(t))
		h.stubs[c.id] = s
		testBaseURLs[c.id] = s.srv.URL
		if allowlisted {
			h.proxy.allow[s.host()] = true
		}
	}
	return h
}

func (h *harness) write(t *testing.T, name, content string) {
	t.Helper()
	p := filepath.Join(h.src, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func testChecker(providers []string, rate, maxChecks int) (*secretChecker, *[]time.Duration) {
	var slept []time.Duration
	c := newSecretChecker(SecretValidationConfig{Providers: providers, RatePerSecond: rate, MaxChecks: maxChecks}, false, nil)
	c.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	return c, &slept
}

func TestSecretValidationProviders(t *testing.T) {
	cases := providerCases()
	h := newHarness(t, cases, true)
	ids := []string{}
	for _, c := range cases {
		ids = append(ids, c.id)
	}
	for _, c := range cases {
		for _, v := range []struct{ variant, content, status string }{{"good", c.good, "active"}, {"bad", c.bad, "inactive"}, {"flaky", c.flaky, "error"}} {
			t.Run(c.id+"/"+v.variant, func(t *testing.T) {
				name := c.id + "-" + v.variant + ".env"
				h.write(t, name, v.content)
				chk, _ := testChecker(ids, 10, 50)
				before := h.stubs[c.id].count()
				rep := runSecretValidation(context.Background(), chk, h.src, []secretLocation{{File: name, Path: name, Line: c.line, Fingerprints: []string{"fp-" + name}}})
				if len(rep.Results) != 1 {
					t.Fatalf("results %+v", rep.Results)
				}
				got := rep.Results[0]
				if got.Status != v.status || got.Provider != c.id {
					t.Fatalf("got %s/%s (%s), want %s/%s", got.Provider, got.Status, got.Detail, c.id, v.status)
				}
				if h.stubs[c.id].count() == before {
					t.Fatal("the provider stub was not contacted")
				}
				if v.status == "active" && got.Identity != c.wantIdentity {
					t.Errorf("identity %q, want %q", got.Identity, c.wantIdentity)
				}
				if v.status != "active" && got.Identity != "" {
					t.Errorf("identity on a %s verdict: %q", v.status, got.Identity)
				}
				if got.Endpoint == "" || got.Detail == "" || got.Fingerprints[0] != "fp-"+name {
					t.Errorf("evidence missing: %+v", got)
				}
				if v.status != "error" && got.HTTPStatus == 0 {
					t.Errorf("no HTTP status recorded: %+v", got)
				}
				raw, _ := json.Marshal(got)
				for _, s := range c.secretsInRequests {
					if strings.Contains(string(raw), s) {
						t.Fatalf("verdict contains the secret: %s", raw)
					}
				}
			})
		}
	}
	// Each provider's secrets reached its own stub only.
	for _, c := range cases {
		for other, s := range h.stubs {
			if other == c.id {
				continue
			}
			for _, req := range s.seen {
				for _, v := range c.secretsInRequests {
					if strings.Contains(req, v) {
						t.Errorf("%s secret sent to the %s stub", c.id, other)
					}
				}
			}
		}
	}
}

// The AWS Signature Version 4 test suite ("get-vanilla").
func TestSigV4KnownVector(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	at, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	signSigV4(req, nil, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCY"+"EXAMPLEKEY", "us-east-1", "service", at)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestSecretValidationEgressNotAllowlisted(t *testing.T) {
	cases := providerCases()[:1] // github
	h := newHarness(t, cases, false)
	tok := "ghp_" + rep("Ab12", 9)
	tok2 := "ghp_" + rep("Cd34", 9)
	h.write(t, "a.env", "\nGITHUB_TOKEN="+tok+"\n")
	h.write(t, "b.env", "\nGITHUB_TOKEN="+tok2+"\n")
	chk, _ := testChecker([]string{"github"}, 10, 50)
	rep := runSecretValidation(context.Background(), chk, h.src, []secretLocation{
		{File: "a.env", Path: "a.env", Line: 2, Fingerprints: []string{"fa"}}, {File: "b.env", Path: "b.env", Line: 2, Fingerprints: []string{"fb"}}})
	for _, r := range rep.Results {
		if r.Status != "error" || !strings.Contains(r.Detail, "allowlist.txt") {
			t.Fatalf("want a fail-closed error naming the allowlist, got %+v", r)
		}
	}
	if !strings.Contains(rep.Results[1].Detail, "not attempted") {
		t.Errorf("second check after a refusal should not be attempted: %s", rep.Results[1].Detail)
	}
	if n := h.stubs["github"].count(); n != 0 {
		t.Fatalf("the provider was contacted %d times although the proxy denies it", n)
	}
	if h.proxy.hits != 1 {
		t.Errorf("proxy saw %d requests, want 1 (then the provider is skipped)", h.proxy.hits)
	}
}

func TestSecretValidationNeedsProxy(t *testing.T) {
	cases := providerCases()[:1]
	h := newHarness(t, cases, true)
	t.Setenv("HTTPS_PROXY", "")
	h.write(t, "a.env", "\nGITHUB_TOKEN=ghp_"+rep("Ab12", 9)+"\n")
	chk, _ := testChecker([]string{"github"}, 10, 50)
	rep := runSecretValidation(context.Background(), chk, h.src, []secretLocation{{File: "a.env", Path: "a.env", Line: 2, Fingerprints: []string{"fa"}}})
	if r := rep.Results[0]; r.Status != "error" || !strings.Contains(r.Detail, "egress proxy") {
		t.Fatalf("got %+v", r)
	}
	if h.stubs["github"].count() != 0 || h.proxy.hits != 0 {
		t.Fatal("no request may be made without the egress proxy")
	}
}

func TestSecretValidationProviderNotEnabledAndUnrecognized(t *testing.T) {
	cases := providerCases()[:1]
	h := newHarness(t, cases, true)
	h.write(t, "a.env", "\nGITHUB_TOKEN=ghp_"+rep("Ab12", 9)+"\n")
	h.write(t, "b.env", "password = hunter2-but-longer\n")
	h.write(t, "c.env", "PYPI_TOKEN=pypi-"+"AgEIcHlwaS5vcmc"+rep("h", 60)+"\n")
	h.write(t, "d.env", "aws_access_key_id = ASIA"+rep("QZ", 8)+"\naws_secret_access_key = "+rep("aB3/", 10)+"\n")
	chk, _ := testChecker([]string{"slack", "pypi"}, 10, 50)
	rep := runSecretValidation(context.Background(), chk, h.src, []secretLocation{
		{File: "a.env", Path: "a.env", Line: 2, Fingerprints: []string{"fa"}},
		{File: "b.env", Path: "b.env", Line: 1, Fingerprints: []string{"fb"}},
		{File: "c.env", Path: "c.env", Line: 1, Fingerprints: []string{"fc"}},
		{File: "d.env", Path: "d.env", Line: 1, Fingerprints: []string{"fd"}},
		{File: "gone.env", Path: "gone.env", Line: 3, Fingerprints: []string{"fe"}},
	})
	want := []struct{ provider, detail string }{
		{"github", "not enabled"}, {"", "no credential"}, {"pypi", "no read-only endpoint"}, {"aws", "session token"}, {"", "not in the scanned files"},
	}
	for i, w := range want {
		r := rep.Results[i]
		if r.Status != "not_checked" || r.Provider != w.provider || !strings.Contains(r.Detail, w.detail) {
			t.Errorf("%d: got %+v, want not_checked %s %q", i, r, w.provider, w.detail)
		}
	}
	if h.proxy.hits != 0 {
		t.Fatal("nothing may be contacted")
	}
}

func TestSecretValidationRateLimitDedupeAndCap(t *testing.T) {
	cases := providerCases()[:1]
	h := newHarness(t, cases, true)
	var locs []secretLocation
	for i, part := range []string{"Ab12", "Ab12", "Zz90", "Ef56"} {
		name := filepath.Join("cfg", string(rune('a'+i))+".env")
		h.write(t, name, "\nGITHUB_TOKEN=ghp_"+rep(part, 9)+"\n")
		locs = append(locs, secretLocation{File: name, Path: filepath.ToSlash(name), Line: 2, Fingerprints: []string{name}})
	}
	chk, slept := testChecker([]string{"github"}, 2, 2)
	rep := runSecretValidation(context.Background(), chk, h.src, locs)
	var st []string
	for _, r := range rep.Results {
		st = append(st, r.Status)
	}
	// Same token twice: checked once. Third distinct token: over the cap.
	if strings.Join(st, ",") != "active,active,inactive,not_checked" {
		t.Fatalf("statuses %v (%+v)", st, rep.Results)
	}
	if !strings.Contains(rep.Results[1].Detail, "checked once") || !strings.Contains(rep.Results[3].Detail, "limit of 2") {
		t.Errorf("details: %q / %q", rep.Results[1].Detail, rep.Results[3].Detail)
	}
	if n := h.stubs["github"].count(); n != 2 {
		t.Fatalf("provider contacted %d times, want 2", n)
	}
	if len(*slept) != 1 || (*slept)[0] <= 0 || (*slept)[0] > 500*time.Millisecond {
		t.Fatalf("rate limit waits %v, want one wait of at most 500ms", *slept)
	}
}

func TestSecretValidationRedirectNotFollowed(t *testing.T) {
	var followed bool
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer other.Close()
	c := providerCase{id: "github", handler: func(*testing.T) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
		}
	}}
	h := newHarness(t, []providerCase{c}, true)
	u, _ := url.Parse(other.URL)
	h.proxy.allow[u.Host] = true
	h.write(t, "a.env", "\nGITHUB_TOKEN=ghp_"+rep("Ab12", 9)+"\n")
	chk, _ := testChecker([]string{"github"}, 10, 50)
	rep := runSecretValidation(context.Background(), chk, h.src, []secretLocation{{File: "a.env", Path: "a.env", Line: 2, Fingerprints: []string{"fa"}}})
	if r := rep.Results[0]; r.Status != "error" || !strings.Contains(r.Detail, "redirect") {
		t.Fatalf("got %+v", r)
	}
	if followed {
		t.Fatal("the redirect was followed")
	}
}

func TestSecretValidationRefusesForeignHosts(t *testing.T) {
	if hostAllowed("github", "evil.example") || hostAllowed("github", "api.github.com.evil.example") || hostAllowed("nope", "api.github.com") {
		t.Fatal("foreign host allowed")
	}
	if !hostAllowed("github", "api.github.com") || !hostAllowed("azure-storage", "acct.blob.core.windows.net") || hostAllowed("azure-storage", "blob.core.windows.net") {
		t.Fatal("provider host refused")
	}
}

func TestRecognizePrefersRuleHint(t *testing.T) {
	gh := "ghp_" + rep("Ab12", 9)
	np := "npm_" + rep("Q1", 18)
	lines := []string{"x=" + gh + " y=" + np}
	if c, _ := recognize(lines, 1, []string{"npm-access-token"}); c.Provider != "npm" {
		t.Fatalf("got %s", c.Provider)
	}
	if c, _ := recognize(lines, 1, nil); c.Provider != "github" {
		t.Fatalf("got %s", c.Provider)
	}
	// An Anthropic key is not an OpenAI key.
	if c, ok := recognize([]string{"k=sk-ant-" + "api03-" + rep("c", 40) + "T3Blbk" + "FJ" + rep("d", 30)}, 1, nil); !ok || c.Provider != "anthropic" {
		t.Fatalf("got %+v", c)
	}
	// Commit SHAs next to an AWS key ID are not its secret.
	if c, _ := recognize([]string{"id=AKIA" + rep("QZ", 8) + " sha=" + rep("ab12", 10)}, 1, nil); c.Reason == "" {
		t.Fatal("a hex digest was taken as the secret access key")
	}
}

// --- end to end: the job step, its upload and its logs -------------------------

type recordingAPI struct {
	mu     sync.Mutex
	bodies map[string][]string
}

func (f *recordingAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	if f.bodies == nil {
		f.bodies = map[string][]string{}
	}
	f.bodies[r.URL.Path] = append(f.bodies[r.URL.Path], string(body))
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *recordingAPI) all() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.bodies))
	for k := range f.bodies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "\n" + strings.Join(f.bodies[k], "\n") + "\n")
	}
	return b.String()
}

// gitleaksTool writes what "gitleaks dir --redact" reports: the location
// and rule, never the value.
type gitleaksTool struct{}

func (gitleaksTool) Version(context.Context) (string, error) { return "8.0.0", nil }
func (gitleaksTool) Run(_ context.Context, in RunInput) (string, error) {
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":"github-pat","shortDescription":{"text":"GitHub Personal Access Token"}}]}},` +
		`"results":[{"ruleId":"github-pat","message":{"text":"github-pat has detected secret for file config/.env."},` +
		`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"config/.env"},"region":{"startLine":2,"startColumn":14,"endColumn":53,"snippet":{"text":"REDACTED"}}}}],` +
		`"partialFingerprints":{"commitSha":"","email":"","author":"","date":"","commitMessage":""}}]}]}`
	return "", os.WriteFile(in.Out, []byte(sarif), 0o600)
}

func runValidationJob(t *testing.T, cfg *SecretValidationConfig, token string, providerStatus int) (*recordingAPI, *stub, string) {
	t.Helper()
	c := providerCase{id: "github", handler: func(*testing.T) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if providerStatus != 200 {
				// A provider that echoes the credential in its error.
				jsonOut(w, providerStatus, map[string]string{"message": "bad token " + bearerOf(r)})
				return
			}
			jsonOut(w, 200, map[string]string{"login": "octo-test"})
		}
	}}
	h := newHarness(t, []providerCase{c}, true)
	api := &recordingAPI{}
	snap := snapshotOf(t, map[string]string{"app/config/.env": "# settings\nGITHUB_TOKEN=" + token + "\n", "app/main.go": "package main\n"})
	srv := httptest.NewServer(&snapshotServingAPI{inner: api, snapshot: snap})
	t.Cleanup(srv.Close)
	var logs bytes.Buffer
	a := New(Config{APIURL: srv.URL, WorkDir: t.TempDir()}, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	a.token = "worker-token"
	a.tools = map[string]Tool{"gitleaks": gitleaksTool{}}
	job := snapshotJob(sum(snap), int64(len(snap)))
	job.Scanners = []JobScanner{{Key: "gitleaks"}}
	job.SecretValidation = cfg
	a.runJob(context.Background(), job)
	return api, h.stubs["github"], logs.String()
}

// snapshotServingAPI serves the snapshot and records everything else.
type snapshotServingAPI struct {
	inner    *recordingAPI
	snapshot []byte
}

func (s *snapshotServingAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/source") {
		_, _ = w.Write(s.snapshot)
		return
	}
	s.inner.ServeHTTP(w, r)
}

func TestSecretValidationJobDisabledByDefault(t *testing.T) {
	tok := "ghp_" + rep("Ab12", 9)
	api, provider, _ := runValidationJob(t, nil, tok, 200)
	if provider.count() != 0 {
		t.Fatal("a provider was contacted although validation is off")
	}
	if _, ok := api.bodies["/internal/worker/v1/jobs/j1/secret-validation"]; ok {
		t.Fatal("a validation report was uploaded although validation is off")
	}
	if len(api.bodies["/internal/worker/v1/jobs/j1/complete"]) != 1 {
		t.Fatalf("job did not complete: %v", api.all())
	}
}

func TestSecretValidationJobUploadsVerdictAndNeverLogsSecret(t *testing.T) {
	for _, status := range []int{200, 401} {
		tok := "ghp_" + rep("Ab12", 9)
		api, provider, logs := runValidationJob(t, &SecretValidationConfig{Providers: []string{"github"}, RatePerSecond: 5, MaxChecks: 10}, tok, status)
		if provider.count() != 1 {
			t.Fatalf("provider contacted %d times", provider.count())
		}
		ups := api.bodies["/internal/worker/v1/jobs/j1/secret-validation"]
		if len(ups) != 1 {
			t.Fatalf("uploads: %v", api.all())
		}
		var rep SecretValidationReport
		if err := json.Unmarshal([]byte(ups[0]), &rep); err != nil || len(rep.Results) != 1 {
			t.Fatalf("report %s: %v", ups[0], err)
		}
		r := rep.Results[0]
		want := map[int]string{200: "active", 401: "inactive"}[status]
		if r.Status != want || r.File != "config/.env" || r.Line != 2 || len(r.Fingerprints) != 1 {
			t.Fatalf("verdict %+v", r)
		}
		// The secret is nowhere: not in the upload, the job's events and
		// logs, the scanner results or the worker's own log output.
		everything := api.all() + logs
		if strings.Contains(everything, tok) || strings.Contains(everything, rep2(tok)) {
			t.Fatalf("the secret leaked into what the worker sent or logged")
		}
		if !strings.Contains(api.all(), "secret validation: 1 locations") {
			t.Errorf("summary log line missing: %s", api.all())
		}
	}
}

// rep2 is the token without its prefix (a partial leak).
func rep2(tok string) string { return tok[len(tok)-20:] }

func TestReporterRedactsRegisteredValues(t *testing.T) {
	r := &reporter{}
	r.redact("short", "a-registered-secret-value")
	got, _ := r.clean("value a-registered-secret-value and short")
	if strings.Contains(got, "a-registered-secret-value") || !strings.Contains(got, "short") {
		t.Fatalf("got %q", got)
	}
}

// Gitleaks in git mode reports a secret at the commit that added it; the
// line is read from that commit, not from the checked-out files (where it
// may have been removed or replaced).
func TestSecretValidationReadsHistoryFromTheCommit(t *testing.T) {
	cases := providerCases()[:1]
	h := newHarness(t, cases, true)
	good := "ghp_" + rep("Ab12", 9)
	other := "ghp_" + rep("Zz90", 9) // rejected by the stub
	git := func(args ...string) {
		t.Helper()
		out, err := command(context.Background(), []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}, []int{0}, "git",
			append([]string{"-C", h.src, "-c", "user.name=t", "-c", "user.email=t@example.invalid"}, args...)...)
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	git("init", "-q")
	h.write(t, "config/.env", "# settings\nGITHUB_TOKEN="+good+"\n")
	git("add", ".")
	git("commit", "-q", "-m", "add")
	first, err := gitHead(context.Background(), h.src)
	if err != nil || len(first) != 40 {
		t.Fatalf("head %q %v", first, err)
	}
	h.write(t, "config/.env", "# settings\nGITHUB_TOKEN="+other+"\n")
	git("commit", "-q", "-am", "rotate")

	out := t.TempDir()
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":"github-pat"}]}},"results":[` +
		`{"ruleId":"github-pat","message":{"text":"github-pat has detected secret for file config/.env."},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"config/.env"},"region":{"startLine":2}}}],"partialFingerprints":{"commitSha":"` + first + `"}},` +
		`{"ruleId":"github-pat","message":{"text":"github-pat has detected secret for file config/.env."},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"config/.env"},"region":{"startLine":2}}}],"partialFingerprints":{"commitSha":"` + strings.Repeat("0", 40) + `"}}]}]}`
	if err := os.WriteFile(filepath.Join(out, "gitleaks.out"), []byte(sarif), 0o600); err != nil {
		t.Fatal(err)
	}
	locs := collectSecretLocations(out, []string{"gitleaks"}, func(string) (scanners.ToolParser, bool) { return scanners.ToolParser{}, false })
	if len(locs) != 2 {
		t.Fatalf("locations %+v", locs)
	}
	chk, _ := testChecker([]string{"github"}, 10, 50)
	rep := runSecretValidation(context.Background(), chk, h.src, locs)
	byCommit := map[string]SecretVerdict{}
	for i, l := range locs {
		byCommit[l.Commit] = rep.Results[i]
	}
	if v := byCommit[first]; v.Status != "active" {
		t.Fatalf("secret of the first commit: %+v (the checked-out file holds another token)", v)
	}
	if v := byCommit[strings.Repeat("0", 40)]; v.Status != "not_checked" || !strings.Contains(v.Detail, "not available") {
		t.Fatalf("unknown commit: %+v", v)
	}
}

package connectors

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"pathos/internal/ai"
	"pathos/internal/authz"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/diag"
	"pathos/internal/runtimectx"
	"pathos/internal/scm"
	"pathos/internal/secrets"
	"pathos/internal/tickets"
	"pathos/internal/vault"
)

func TestKindsCatalogue(t *testing.T) {
	all := Kinds()
	if len(all) < 40 {
		t.Fatalf("catalogue has %d kinds", len(all))
	}
	t.Logf("%d kinds", len(all))
	seen := map[string]bool{}
	for _, k := range all {
		if err := k.valid(); err != nil {
			t.Error(err)
		}
		if seen[k.Kind] {
			t.Errorf("duplicate %s", k.Kind)
		}
		seen[k.Kind] = true
		if k.Source != "" && (k.Checker == nil || k.CheckedBy == RunsNone) {
			t.Errorf("%s has a source but no health check", k.Kind)
		}
		if k.Status == KindPlanned && k.Checker != nil {
			t.Errorf("%s is planned but has a checker", k.Kind)
		}
		if k.DocsSlug != "connectors#"+k.Kind {
			t.Errorf("%s docs slug %q", k.Kind, k.DocsSlug)
		}
	}
	// The existing integrations of the brief and the eight the design
	// omitted are listed.
	for _, k := range []string{"github", "github_enterprise", "gitlab", "bitbucket", "azure_devops", "azure_devops_server", "jira", "servicenow",
		"webhook", "slack", "teams", "smtp", "kubernetes", "container_registry", "ai_provider", "vulnerability_feed", "secret_validation",
		"object_storage", "egress_proxy", "deps_dev", "mcp_registry", "generic_git", "bitbucket_data_center", "vault", "aws", "azure", "gcp"} {
		if !seen[k] {
			t.Errorf("kind %s missing", k)
		}
	}
	// Only the jobs service calls clusters, registries and the egress proxy.
	for _, k := range []string{"kubernetes", "container_registry", "egress_proxy"} {
		if kk, _ := LookupKind(k); kk.CheckedBy != RunsInJobs {
			t.Errorf("%s must be checked by the jobs service", k)
		}
	}
}

// The user guide documents every kind (docs_slug anchors).
func TestKindsAreDocumented(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "user-guide", "connectors.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, k := range Kinds() {
		if !strings.Contains(doc, "`"+k.Kind+"`") {
			t.Errorf("docs/user-guide/connectors.md does not mention kind `%s`", k.Kind)
		}
	}
	for _, e := range diag.All() {
		if strings.HasPrefix(e.Source, "internal/connectors") && !strings.Contains(doc, e.Code) {
			t.Errorf("docs/user-guide/connectors.md Troubleshooting does not list %s", e.Code)
		}
	}
}

func TestRegisterKindReplacesPlannedOnly(t *testing.T) {
	RegisterKind(Kind{Kind: "zz_test_planned", Category: "cloud", Label: "x", Status: KindPlanned, Direction: Outbound})
	RegisterKind(Kind{Kind: "zz_test_planned", Category: "cloud", Label: "y", Status: KindExisting, Direction: Outbound})
	if k, _ := LookupKind("zz_test_planned"); k.Label != "y" {
		t.Fatalf("planned kind not replaced: %+v", k)
	}
	defer func() {
		if recover() == nil {
			t.Error("replacing an existing kind did not panic")
		}
		kindsMu.Lock()
		delete(kinds, "zz_test_planned")
		kindsMu.Unlock()
	}()
	RegisterKind(Kind{Kind: "zz_test_planned", Category: "cloud", Label: "z", Status: KindExisting, Direction: Outbound})
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{scm.ErrAuth, "PTH-CONN-1007"},
		{fmt.Errorf("x: %w", scm.ErrForbidden), "PTH-CONN-1009"},
		{scm.ErrRateLimited, "PTH-CONN-1010"},
		{scm.ErrNotFound, "PTH-CONN-1011"},
		{scm.ErrBlockedAddress, "PTH-CONN-1003"},
		{scm.ErrTokenExpired, "PTH-CONN-1008"},
		{scm.ErrPlainHTTP, "PTH-CONN-1019"},
		{fmt.Errorf("tls: %w", x509.UnknownAuthorityError{}), "PTH-CONN-1004"},
		{fmt.Errorf("tls: %w", x509.HostnameError{Host: "x"}), "PTH-CONN-1005"},
		{fmt.Errorf("decrypt: %w", crypto.ErrDecrypt), "PTH-CONN-1016"},
		{&net.DNSError{Err: "no such host", Name: "x"}, "PTH-CONN-1001"},
		{&net.OpError{Op: "dial", Err: errors.New("connection refused")}, "PTH-CONN-1001"},
		{timeoutErr{}, "PTH-CONN-1002"},
		{context.DeadlineExceeded, "PTH-CONN-1002"},
		{errors.New("proxyconnect tcp: dial tcp: connection refused"), "PTH-CONN-1006"},
		{&tickets.HTTPError{Status: 401}, "PTH-CONN-1007"},
		{&tickets.HTTPError{Status: 200, Unreadable: true}, "PTH-CONN-1013"},
		{&tickets.HTTPError{Status: 503}, "PTH-CONN-1012"},
		{&runtimectx.APIError{Status: 403}, "PTH-CONN-1009"},
		{&runtimectx.RegistryError{Status: 429}, "PTH-CONN-1010"},
		{ai.ErrAuth, "PTH-CONN-1007"},
		{&ai.ProviderStatusError{Status: 404, Kind: "self_hosted"}, "PTH-CONN-1011"},
		{errors.New("something else"), "PTH-CONN-1012"},
		// Unresolved vault: references (Vault/OpenBao) keep their own codes.
		{fmt.Errorf("token: %w", vault.ErrSecretNotFound), "PTH-CONN-1606"},
		{vault.ErrRefOutsidePrefix, "PTH-CONN-1607"},
		{fmt.Errorf("resolve: %w", vault.ErrNotConfigured), "PTH-CONN-1608"},
		{fmt.Errorf("resolve: %w", secrets.ErrRefUnavailable), "PTH-CONN-1608"},
		{vault.ErrSealed, "PTH-CONN-1604"},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("%v: got %s, want %s", c.err, got, c.want)
		}
		if _, ok := diag.Lookup(c.want); !ok {
			t.Errorf("%s not in the catalogue", c.want)
		}
	}
	if Classify(nil) != "" {
		t.Error("nil error has a code")
	}
}

func TestRedact(t *testing.T) {
	in := "POST https://hooks.slack.com/services/T000/B000/XXXXSECRET?token=abc failed for bob@example.com with Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	out := Redact(in)
	for _, leak := range []string{"T000", "XXXXSECRET", "token=abc", "bob@example.com", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"} {
		if strings.Contains(out, leak) {
			t.Errorf("redacted text still contains %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, "https://hooks.slack.com") {
		t.Errorf("host removed: %s", out)
	}
	if len(Redact(strings.Repeat("a", 5000))) > 1000 {
		t.Error("not bounded")
	}
	if HostOf("https://user:pw@git.example.com:8443/path?q=1") != "https://git.example.com:8443" {
		t.Error("HostOf")
	}
}

func TestNormalizeAndSummarize(t *testing.T) {
	r := normalize(Result{Status: "weird", ErrorCode: "PTH-NOPE-0000"})
	if r.Status != StatusUnknown || r.ErrorCode != "" || r.Steps == nil || r.Observed == nil {
		t.Errorf("normalize: %+v", r)
	}
	if r := normalize(Result{Status: StatusFailing}); r.ErrorCode != "PTH-CONN-1012" {
		t.Errorf("failing without code: %+v", r)
	}
	// Never healthy with a failing step.
	if r := normalize(Result{Status: StatusHealthy, Steps: []Step{{Check: "x", Status: StepFail}}}); r.Status != StatusFailing {
		t.Errorf("healthy with a failed step: %+v", r)
	}
	s := summarize([]Step{{Check: "a", Status: StepPass}, {Check: "b", Status: StepWarn, ErrorCode: "PTH-CONN-1021", Detail: "soon"}}, "", nil)
	if s.Status != StatusDegraded || s.ErrorCode != "PTH-CONN-1021" {
		t.Errorf("warn: %+v", s)
	}
	s = summarize([]Step{{Check: "b", Status: StepWarn, ErrorCode: "PTH-CONN-1112"}}, "", nil)
	if s.Status != StatusHealthy {
		t.Errorf("info-only warning degraded the connector: %+v", s)
	}
	s = summarize([]Step{{Check: "a", Status: StepFail, ErrorCode: "PTH-CONN-1007", Detail: "no"}, {Check: "b", Status: StepFail, ErrorCode: "PTH-CONN-1009"}}, "", nil)
	if s.Status != StatusFailing || s.ErrorCode != "PTH-CONN-1007" {
		t.Errorf("fail: %+v", s)
	}
}

func TestEffectiveStatus(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	env := &Env{Now: func() time.Time { return now }, Interval: time.Hour}
	old, recent := now.Add(-3*time.Hour), now.Add(-10*time.Minute)
	cases := []struct {
		c    Connector
		want string
	}{
		{Connector{Kind: "github", Enabled: true}, StatusUnknown},
		{Connector{Kind: "github", Enabled: false, Status: StatusHealthy, LastCheckAt: &recent}, StatusDisabled},
		{Connector{Kind: "github", Enabled: true, Status: StatusHealthy, LastCheckAt: &recent}, StatusHealthy},
		{Connector{Kind: "github", Enabled: true, Status: StatusHealthy, LastCheckAt: &old}, StatusUnknown},
		{Connector{Kind: "github", Enabled: true, Status: StatusFailing, LastCheckAt: &old}, StatusFailing},
	}
	for i, c := range cases {
		if got, _ := EffectiveStatus(c.c, env); got != c.want {
			t.Errorf("%d: got %s, want %s", i, got, c.want)
		}
	}
	env.Offline = true
	gh := Connector{Kind: "github", Enabled: true, Meta: map[string]string{"host": "https://api.github.com"}}
	if got, code := EffectiveStatus(gh, env); got != StatusDisabled || code != "PTH-CONN-1015" {
		t.Errorf("offline github.com: %s %s", got, code)
	}
	ghes := Connector{Kind: "github_enterprise", Enabled: true, Meta: map[string]string{"host": "https://ghe.internal"}}
	if got, _ := EffectiveStatus(ghes, env); got != StatusUnknown {
		t.Errorf("offline GHES: %s", got)
	}
	ollama := Connector{Kind: "ai_provider", Enabled: true, Meta: map[string]string{"provider": "self_hosted"}}
	if got, _ := EffectiveStatus(ollama, env); got != StatusUnknown {
		t.Errorf("offline self-hosted AI: %s", got)
	}
}

// --- checkers with fake services -------------------------------------------

type fakeSCM struct {
	res SCMCheck
	err error
}

func (f fakeSCM) CheckConnection(context.Context, uuid.UUID, uuid.UUID) (SCMCheck, error) {
	return f.res, f.err
}

type fakeTickets struct {
	who string
	err error
}

func (f fakeTickets) CheckConnection(context.Context, uuid.UUID, uuid.UUID) (string, error) {
	return f.who, f.err
}

type fakeNotify struct {
	smtp    SMTPProbe
	smtpErr error
	wh      WebhookCheck
}

func (f fakeNotify) ProbeSMTP(context.Context, uuid.UUID) (SMTPProbe, error) {
	return f.smtp, f.smtpErr
}
func (f fakeNotify) CheckWebhook(context.Context, uuid.UUID, uuid.UUID) (WebhookCheck, error) {
	return f.wh, nil
}

type fakeRuntime struct {
	c    ClusterCheck
	r    RegistryCheck
	cErr error
	rErr error
}

func (f fakeRuntime) CheckCluster(context.Context, uuid.UUID, uuid.UUID) (ClusterCheck, error) {
	return f.c, f.cErr
}
func (f fakeRuntime) CheckRegistry(context.Context, uuid.UUID, uuid.UUID) (RegistryCheck, error) {
	return f.r, f.rErr
}

type fakeAI struct {
	n   int
	err error
}

func (f fakeAI) ListModels(context.Context, uuid.UUID, uuid.UUID) (int, error) { return f.n, f.err }

type fakeStore struct{ err error }

func (f fakeStore) Ping(context.Context) error { return f.err }

func target(kind string, meta map[string]string) Target {
	return Target{Connector: Connector{ID: uuid.New(), Kind: kind, SourceKey: uuid.NewString(), Enabled: true, Meta: meta}}
}

func check(t *testing.T, env *Env, tg Target) Result {
	t.Helper()
	k, _ := LookupKind(tg.Kind)
	return normalize(k.Checker.Check(context.Background(), env, tg))
}

func TestCheckers(t *testing.T) {
	now := time.Now()
	soon, past := now.Add(3*24*time.Hour), now.Add(-time.Hour)
	ctx := []struct {
		name     string
		env      *Env
		tg       Target
		status   string
		code     string
		stepCode string
	}{
		{"github ok", &Env{SCM: fakeSCM{res: SCMCheck{Account: "octo"}}}, target("github", nil), StatusHealthy, "", ""},
		{"github 401", &Env{SCM: fakeSCM{err: fmt.Errorf("w: %w", scm.ErrAuth)}}, target("github", nil), StatusFailing, "PTH-CONN-1007", ""},
		{"token expiring", &Env{SCM: fakeSCM{res: SCMCheck{Account: "octo", TokenExpiresAt: &soon}}}, target("gitlab", nil), StatusDegraded, "PTH-CONN-1021", ""},
		{"token expired", &Env{SCM: fakeSCM{res: SCMCheck{Account: "octo", TokenExpiresAt: &past}}}, target("bitbucket", nil), StatusFailing, "PTH-CONN-1008", ""},
		{"gitlab legacy token", &Env{SCM: fakeSCM{res: SCMCheck{Account: "a", GitLabWebhookAuth: "token"}}}, target("gitlab", nil), StatusHealthy, "", "PTH-CONN-1112"},
		{"no scm service", &Env{}, target("azure_devops", nil), StatusUnknown, "", ""},

		{"jira ok", &Env{Tickets: fakeTickets{who: "bot"}}, target("jira", nil), StatusHealthy, "", ""},
		{"jira scoped hint", &Env{Tickets: fakeTickets{err: &tickets.HTTPError{Status: 401, Msg: "authentication failed"}}},
			target("jira", map[string]string{"host": "https://acme.atlassian.net", "token_type": "unscoped (site URL)"}), StatusFailing, "PTH-CONN-1007", "PTH-CONN-1203"},
		{"jira cloud id", &Env{Tickets: fakeTickets{err: tickets.ErrCloudID}}, target("jira", nil), StatusFailing, "PTH-CONN-1205", ""},
		{"servicenow 403", &Env{Tickets: fakeTickets{err: &tickets.HTTPError{Status: 403}}}, target("servicenow", nil), StatusFailing, "PTH-CONN-1210", ""},
		{"servicenow 429", &Env{Tickets: fakeTickets{err: &tickets.HTTPError{Status: 429}}}, target("servicenow", nil), StatusFailing, "PTH-CONN-1211", ""},
		// A private CA the connection does not trust yet (2.2.2 CA bundles): the fix is the connection's own bundle.
		{"jira untrusted CA", &Env{Tickets: fakeTickets{err: fmt.Errorf("jira unreachable: %w", scm.WithCAHint(&url.Error{Op: "Get", URL: "https://jira.internal", Err: x509.UnknownAuthorityError{}}))}},
			target("jira", nil), StatusFailing, "PTH-CONN-1702", ""},

		{"webhook never delivered", &Env{Notify: fakeNotify{wh: WebhookCheck{Format: "json"}}}, target("webhook", nil), StatusUnknown, "", ""},
		{"webhook ok", &Env{Notify: fakeNotify{wh: WebhookCheck{Format: "json", LastStatus: "succeeded", LastAt: &now}}}, target("webhook", nil), StatusHealthy, "", ""},
		{"webhook flaky", &Env{Notify: fakeNotify{wh: WebhookCheck{Format: "json", LastStatus: "succeeded", Failed24h: 2}}}, target("webhook", nil), StatusDegraded, "PTH-SYNC-1005", ""},
		{"slack removed", &Env{Notify: fakeNotify{wh: WebhookCheck{Format: "slack", LastStatus: "failed", LastResponse: 404}}}, target("slack", nil), StatusFailing, "PTH-CONN-1301", ""},
		{"receiver 4xx", &Env{Notify: fakeNotify{wh: WebhookCheck{Format: "json", LastStatus: "failed", LastResponse: 400}}}, target("webhook", nil), StatusFailing, "PTH-CONN-1330", ""},
		{"receiver down", &Env{Notify: fakeNotify{wh: WebhookCheck{Format: "json", LastStatus: "failed", LastResponse: 503}}}, target("webhook", nil), StatusFailing, "PTH-SYNC-1005", ""},
		{"teams retired", &Env{Notify: fakeNotify{wh: WebhookCheck{Format: "teams"}}}, target("teams", map[string]string{"host": "https://acme.webhook.office.com"}), StatusFailing, "PTH-CONN-1310", ""},
		{"teams auth needed", &Env{Notify: fakeNotify{wh: WebhookCheck{Format: "teams", LastStatus: "failed", LastResponse: 401}}}, target("teams", map[string]string{"host": "https://x.logic.azure.com"}), StatusFailing, "PTH-CONN-1311", ""},
		{"teams token fails", &Env{Notify: fakeNotify{wh: WebhookCheck{Format: "teams", TriggerAuth: true, TriggerAuthError: errors.New("AADSTS7000215")}}},
			target("teams", map[string]string{"host": "https://x.logic.azure.com"}), StatusFailing, "PTH-CONN-1313", ""},
		{"teams token ok, nothing sent", &Env{Notify: fakeNotify{wh: WebhookCheck{Format: "teams", TriggerAuth: true}}},
			target("teams", map[string]string{"host": "https://x.logic.azure.com"}), StatusUnknown, "", ""},

		{"smtp off", &Env{Notify: fakeNotify{smtp: SMTPProbe{}}}, target("smtp", nil), StatusDisabled, "", ""},
		{"smtp ok", &Env{Notify: fakeNotify{smtp: SMTPProbe{Configured: true, Enabled: true, TLS: "starttls", Auth: true}}}, target("smtp", nil), StatusHealthy, "", ""},
		{"smtp no starttls", &Env{Notify: fakeNotify{smtp: SMTPProbe{Configured: true, Enabled: true}, smtpErr: ErrSMTPNoSTARTTLS}}, target("smtp", nil), StatusFailing, "PTH-CONN-1320", ""},
		{"smtp auth", &Env{Notify: fakeNotify{smtp: SMTPProbe{Configured: true, Enabled: true}, smtpErr: ErrSMTPAuth}}, target("smtp", nil), StatusFailing, "PTH-CONN-1321", ""},

		{"cluster ok", &Env{Runtime: fakeRuntime{c: ClusterCheck{ServerVersion: "v1.36.2", Readable: []string{"Pod"}}}}, target("kubernetes", nil), StatusHealthy, "", ""},
		{"cluster partial", &Env{Runtime: fakeRuntime{c: ClusterCheck{ServerVersion: "v1.36.2", Readable: []string{"Pod"}, Denied: []string{"Ingress"}}}}, target("kubernetes", nil), StatusDegraded, "PTH-CONN-1512", ""},
		{"cluster old", &Env{Runtime: fakeRuntime{c: ClusterCheck{ServerVersion: "v1.30.1", Readable: []string{"Pod"}}}}, target("kubernetes", nil), StatusDegraded, "PTH-CONN-1513", ""},
		{"cluster 401", &Env{Runtime: fakeRuntime{cErr: &runtimectx.APIError{Status: 401}}}, target("kubernetes", nil), StatusFailing, "PTH-CONN-1007", ""},
		{"registry ok", &Env{Runtime: fakeRuntime{r: RegistryCheck{Repository: "library/alpine", Tags: 1}}}, target("container_registry", nil), StatusHealthy, "", ""},
		{"registry untrusted CA", &Env{Runtime: fakeRuntime{rErr: &url.Error{Op: "Get", URL: "https://registry.internal/v2/", Err: x509.UnknownAuthorityError{}}}},
			target("container_registry", nil), StatusFailing, "PTH-CONN-1702", ""},
		{"docker hub limit", &Env{Runtime: fakeRuntime{rErr: &runtimectx.RegistryError{Status: 429}}}, target("container_registry", map[string]string{"host": "https://registry-1.docker.io"}), StatusFailing, "PTH-CONN-1502", ""},

		{"ai ok", &Env{AI: fakeAI{n: 3}}, target("ai_provider", nil), StatusHealthy, "", ""},
		{"ai no models", &Env{AI: fakeAI{n: 0}}, target("ai_provider", nil), StatusDegraded, "PTH-CONN-1022", ""},
		{"ai key", &Env{AI: fakeAI{err: ai.ErrAuth}}, target("ai_provider", nil), StatusFailing, "PTH-CONN-1007", ""},

		{"object store off", &Env{}, target("object_storage", nil), StatusDisabled, "", ""},
		{"object store ok", &Env{ObjectStore: fakeStore{}}, target("object_storage", nil), StatusHealthy, "", ""},
		{"object store denied", &Env{ObjectStore: fakeStore{err: errors.Join(ErrObjectStoreDenied, errors.New("403"))}}, target("object_storage", nil), StatusFailing, "PTH-CONN-1431", ""},
		{"object store missing bucket", &Env{ObjectStore: fakeStore{err: ErrBucketNotFound}}, target("object_storage", nil), StatusFailing, "PTH-CONN-1430", ""},

		{"egress off", &Env{}, target("egress_proxy", nil), StatusDisabled, "", ""},
	}
	for _, c := range ctx {
		r := check(t, c.env, c.tg)
		if r.Status != c.status || r.ErrorCode != c.code {
			t.Errorf("%s: got %s %s (%s), want %s %s", c.name, r.Status, r.ErrorCode, r.Message, c.status, c.code)
		}
		if c.stepCode != "" {
			found := false
			for _, s := range r.Steps {
				found = found || s.ErrorCode == c.stepCode
			}
			if !found {
				t.Errorf("%s: no step with %s: %+v", c.name, c.stepCode, r.Steps)
			}
		}
	}
}

func TestEgressCheck(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 512)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
			_ = c.Close()
		}
	}()
	r := check(t, &Env{EgressProxy: "http://" + ln.Addr().String()}, target("egress_proxy", nil))
	if r.Status != StatusHealthy || r.Observed["probe_status"] != "403" {
		t.Errorf("egress up: %+v", r)
	}
	addr := ln.Addr().String()
	ln.Close()
	r = check(t, &Env{EgressProxy: "http://" + addr}, target("egress_proxy", nil))
	if r.Status != StatusFailing || r.ErrorCode != "PTH-CONN-1531" {
		t.Errorf("egress down: %+v", r)
	}
}

func TestDisabledAndOfflineSkipTheCheck(t *testing.T) {
	called := false
	RegisterKind(Kind{Kind: "zz_probe", Category: "cloud", Label: "probe", Status: KindExisting, Direction: Outbound, CheckedBy: RunsInAPI,
		Checker: CheckFunc(func(context.Context, *Env, Target) Result { called = true; return Result{Status: StatusHealthy} })})
	defer func() { kindsMu.Lock(); delete(kinds, "zz_probe"); kindsMu.Unlock() }()
	if r := runChecker(context.Background(), &Env{}, Connector{Kind: "zz_probe", Enabled: false}); r.Status != StatusDisabled || called {
		t.Errorf("disabled: %+v called=%v", r, called)
	}
	if r := runChecker(context.Background(), &Env{Offline: true}, Connector{Kind: "zz_probe", Enabled: true}); r.Status != StatusDisabled || r.ErrorCode != "PTH-CONN-1015" || called {
		t.Errorf("offline: %+v called=%v", r, called)
	}
	if r := runChecker(context.Background(), &Env{}, Connector{Kind: "zz_probe", Enabled: true}); r.Status != StatusHealthy || !called {
		t.Errorf("enabled: %+v", r)
	}
}

func TestPermissionsMirrorExistingPages(t *testing.T) {
	org := uuid.New()
	p := func(perms ...authz.Permission) *authz.Principal {
		pr := &authz.Principal{OrganizationID: org}
		for _, x := range perms {
			pr.Grants = append(pr.Grants, authz.Grant{Permission: x, Scope: authz.Scope{Type: authz.ScopeOrganization, ID: org}})
		}
		return pr
	}
	gh, _ := LookupKind("github")
	if !gh.canRead(p(authz.PermReposRead)) || gh.canManage(p(authz.PermReposRead)) || !gh.canManage(p(authz.PermSCMManage)) {
		t.Error("github permissions")
	}
	sl, _ := LookupKind("slack")
	if sl.canRead(p(authz.PermSettingsManage)) || !sl.canManage(p(authz.PermNotificationsManage)) {
		t.Error("slack permissions")
	}
	k8s, _ := LookupKind("kubernetes")
	if !k8s.canRead(p(authz.PermFindingsRead)) || k8s.canManage(p(authz.PermFindingsRead)) {
		t.Error("kubernetes permissions")
	}
	aip, _ := LookupKind("ai_provider")
	if !aip.canManage(p(authz.PermAIConfigure)) || aip.canManage(p(authz.PermAIReview)) {
		t.Error("ai permissions")
	}
	if anyReadable(p()) {
		t.Error("no permission reads something")
	}
}

func TestSafeConfigKey(t *testing.T) {
	for _, k := range []string{"api_token", "client_secret", "password", "private_key", "AuthHeader", "ca_cert"} {
		if safeConfigKey(k) {
			t.Errorf("%s considered safe", k)
		}
	}
	for _, k := range []string{"region", "base_url", "project"} {
		if !safeConfigKey(k) {
			t.Errorf("%s considered unsafe", k)
		}
	}
}

var _ = http.StatusOK

func TestCreatableKindValidity(t *testing.T) {
	chk := CheckFunc(func(context.Context, *Env, Target) Result { return Result{} })
	create := func(context.Context, *Env, *authz.Principal, string, map[string]any, string) (string, error) {
		return "", nil
	}
	validate := func(c map[string]any) (map[string]any, error) { return c, nil }
	base := Kind{Kind: "zz", Category: "scm_ide", Label: "Z", Status: KindExisting, Direction: Outbound, Creatable: true, CheckedBy: RunsInAPI, Checker: chk}
	cases := []struct {
		name string
		edit func(*Kind)
		ok   bool
	}{
		{"registry kind with Validate", func(k *Kind) { k.Validate = validate }, true},
		{"registry kind without Validate", func(k *Kind) {}, false},
		{"legacy-table kind with Create", func(k *Kind) { k.Source, k.Create = "scm_connections", create }, true},
		{"legacy-table kind without Create", func(k *Kind) { k.Source, k.Validate = "scm_connections", validate }, false},
		{"no checker", func(k *Kind) { k.Validate, k.Checker, k.CheckedBy = validate, nil, RunsNone }, false},
	}
	for _, c := range cases {
		k := base
		c.edit(&k)
		if err := k.valid(); (err == nil) != c.ok {
			t.Errorf("%s: valid() = %v", c.name, err)
		}
	}
	for _, kind := range []string{"generic_git", "bitbucket_data_center"} {
		k, ok := LookupKind(kind)
		if !ok || !k.Creatable || k.Create == nil || k.Source != "scm_connections" || !k.SecretRefs || len(k.ConfigFields) == 0 {
			t.Errorf("%s: %+v", kind, k)
		}
	}
	if k, _ := LookupKind("vault"); !k.Creatable || k.Validate == nil || k.Create != nil {
		t.Errorf("vault must be a registry kind")
	}
}

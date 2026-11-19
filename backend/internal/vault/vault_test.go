package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

func TestParseRef(t *testing.T) {
	r, err := ParseRef("vault:secret/pathos/github#token")
	if err != nil || r.Mount != "secret" || r.Path != "pathos/github" || r.Key != "token" {
		t.Fatalf("%+v %v", r, err)
	}
	if r.String() != "vault:secret/pathos/github#token" {
		t.Fatal(r.String())
	}
	for _, bad := range []string{"vault:secret#k", "vault:/p#k", "vault:secret/p", "vault:secret/../x#k", "vault:secret//x#k",
		"secret/p#k", "vault:se cret/p#k", "vault:secret/p#k#2"} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
		if IsRef([]byte(bad)) && bad != "vault:secret/../x#k" && bad != "vault:secret//x#k" {
			t.Errorf("IsRef(%q)", bad)
		}
	}
	if !IsRef([]byte("vault:kv/a/b#c")) || IsRef([]byte("ghp_abc")) {
		t.Fatal("IsRef")
	}
	c := Config{PathPrefix: "secret/pathos"}
	if !c.allowed(Ref{Mount: "secret", Path: "pathos/x"}) || c.allowed(Ref{Mount: "secret", Path: "pathosx/y"}) || c.allowed(Ref{Mount: "other", Path: "pathos/x"}) {
		t.Fatal("prefix")
	}
}

// fakeVault mimics the Vault HTTP API for AppRole, Kubernetes and KV v2.
type fakeVault struct {
	*httptest.Server
	logins  atomic.Int32
	sealed  bool
	nsKnown string
}

func newFakeVault(t *testing.T) *fakeVault {
	f := &fakeVault{nsKnown: ""}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fail := func(code int, msg string) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
		}
		if ns := r.Header.Get("X-Vault-Namespace"); ns != "" && ns != f.nsKnown {
			fail(404, "namespace not found")
			return
		}
		if f.sealed {
			fail(503, "Vault is sealed")
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch {
		case r.URL.Path == "/v1/sys/health":
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false,"version":"2.4.4"}`))
		case r.URL.Path == "/v1/auth/approle/login":
			if body["role_id"] != "rid" || body["secret_id"] != "sid" {
				fail(400, "invalid role or secret ID")
				return
			}
			f.logins.Add(1)
			_, _ = w.Write([]byte(`{"auth":{"client_token":"tok","lease_duration":3600}}`))
		case r.URL.Path == "/v1/auth/k8s/login":
			if body["role"] != "pathos" || body["jwt"] != "sa-jwt" {
				fail(403, `service account name not authorized`)
				return
			}
			f.logins.Add(1)
			_, _ = w.Write([]byte(`{"auth":{"client_token":"tok","lease_duration":60}}`))
		case strings.HasPrefix(r.URL.Path, "/v1/secret/data/"):
			if r.Header.Get("X-Vault-Token") != "tok" {
				fail(403, "permission denied")
				return
			}
			switch strings.TrimPrefix(r.URL.Path, "/v1/secret/data/") {
			case "pathos/github":
				_, _ = w.Write([]byte(`{"data":{"data":{"token":"ghp_from_vault"},"metadata":{"version":3}}}`))
			case "forbidden/x":
				fail(403, "1 error occurred:\n\t* permission denied\n\n")
			default:
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"errors":[]}`))
			}
		default:
			fail(404, "unsupported path")
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func approle(f *fakeVault) Config {
	return Config{Address: f.URL, AuthMethod: AuthAppRole, AuthMount: "approle", RoleID: "rid", SecretID: "sid", PathPrefix: "secret/pathos"}
}

func TestReadAppRole(t *testing.T) {
	f := newFakeVault(t)
	ctx := context.Background()
	c, _ := NewClient(approle(f), f.Client(), true)
	v, err := c.Read(ctx, Ref{Mount: "secret", Path: "pathos/github", Key: "token"})
	if err != nil || string(v) != "ghp_from_vault" {
		t.Fatalf("%q %v", v, err)
	}
	_, _ = c.Read(ctx, Ref{Mount: "secret", Path: "pathos/github", Key: "token"})
	if f.logins.Load() != 1 {
		t.Fatalf("the client token must be reused in memory, logins=%d", f.logins.Load())
	}
	if _, err := c.Read(ctx, Ref{Mount: "secret", Path: "pathos/github", Key: "nope"}); DiagCode(err) != "PTH-CONN-1606" {
		t.Fatalf("missing key: %s %v", DiagCode(err), err)
	}
	if _, err := c.Read(ctx, Ref{Mount: "secret", Path: "pathos/none", Key: "k"}); DiagCode(err) != "PTH-CONN-1606" {
		t.Fatalf("missing secret: %s %v", DiagCode(err), err)
	}
	if _, err := c.Read(ctx, Ref{Mount: "secret", Path: "other/x", Key: "k"}); DiagCode(err) != "PTH-CONN-1607" {
		t.Fatalf("outside the prefix: %s %v", DiagCode(err), err)
	}
	open := approle(f)
	open.PathPrefix = ""
	c2, _ := NewClient(open, f.Client(), true)
	if _, err := c2.Read(ctx, Ref{Mount: "secret", Path: "forbidden/x", Key: "k"}); DiagCode(err) != "PTH-CONN-1602" {
		t.Fatalf("policy denies: %s %v", DiagCode(err), err)
	}
	bad := approle(f)
	bad.SecretID = "sid-SENSITIVE-9"
	c3, _ := NewClient(bad, f.Client(), true)
	if _, err := c3.Read(ctx, Ref{Mount: "secret", Path: "pathos/github", Key: "token"}); DiagCode(err) != "PTH-CONN-1601" {
		t.Fatalf("bad secret ID: %s %v", DiagCode(err), err)
	}
	if strings.Contains(errString(c3, ctx), "SENSITIVE") {
		t.Fatal("the secret ID must never appear in an error")
	}
}

func errString(c *Client, ctx context.Context) string {
	_, err := c.Read(ctx, Ref{Mount: "secret", Path: "pathos/github", Key: "token"})
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestKubernetesAuthAndHealth(t *testing.T) {
	f := newFakeVault(t)
	ctx := context.Background()
	cfg := Config{Address: f.URL, AuthMethod: AuthKubernetes, AuthMount: "k8s", KubernetesRole: "pathos", CanaryRef: "vault:secret/pathos/github#token"}
	c, _ := NewClient(cfg, f.Client(), true)
	c.readFile = func(string) ([]byte, error) { return []byte("sa-jwt\n"), nil }
	res, err := c.Check(ctx)
	if err != nil || res.Steps["login"] != "pass" || res.Steps["canary"] != "pass" || res.Health.Version != "2.4.4" {
		t.Fatalf("%+v %v", res, err)
	}
	cfg.KubernetesRole = "other"
	c, _ = NewClient(cfg, f.Client(), true)
	c.readFile = func(string) ([]byte, error) { return []byte("sa-jwt"), nil }
	if _, err := c.Check(ctx); DiagCode(err) != "PTH-CONN-1605" {
		t.Fatalf("role mismatch: %s %v", DiagCode(err), err)
	}
	c.readFile = func(string) ([]byte, error) { return nil, errors.New("no file") }
	if _, err := c.login(ctx); DiagCode(err) != "PTH-CONN-1605" {
		t.Fatalf("no token file: %s %v", DiagCode(err), err)
	}
	f.sealed = true
	if _, err := c.Check(ctx); DiagCode(err) != "PTH-CONN-1604" {
		t.Fatalf("sealed: %s %v", DiagCode(err), err)
	}
	f.sealed = false
	ns := approle(f)
	ns.Namespace = "team-a"
	c, _ = NewClient(ns, f.Client(), true)
	if _, err := c.Read(ctx, Ref{Mount: "secret", Path: "pathos/github", Key: "token"}); DiagCode(err) != "PTH-CONN-1603" {
		t.Fatalf("namespace: %s %v", DiagCode(err), err)
	}
}

func TestResolver(t *testing.T) {
	f := newFakeVault(t)
	org := uuid.New()
	calls := 0
	r := &Resolver{HTTP: f.Client(), AllowHTTP: true, Source: func(_ context.Context, o uuid.UUID) (Config, error) {
		calls++
		if o != org {
			return Config{}, ErrNotConfigured
		}
		return approle(f), nil
	}}
	v, err := r.Resolve(context.Background(), org, "vault:secret/pathos/github#token")
	if err != nil || string(v) != "ghp_from_vault" {
		t.Fatalf("%q %v", v, err)
	}
	if _, err := r.Resolve(context.Background(), uuid.New(), "vault:secret/pathos/github#token"); DiagCode(err) != "PTH-CONN-1608" {
		t.Fatalf("other organization: %v", err)
	}
	if _, err := (&Resolver{}).Resolve(context.Background(), org, "vault:secret/pathos/github#token"); DiagCode(err) != "PTH-CONN-1608" {
		t.Fatalf("no source: %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	c := Config{Address: "https://vault.example.com:8200/", AuthMethod: AuthAppRole, RoleID: "r"}
	if err := c.Validate(false); err != nil || c.AuthMount != "approle" || c.Address != "https://vault.example.com:8200" {
		t.Fatalf("%+v %v", c, err)
	}
	for _, bad := range []Config{
		{Address: "http://vault.example.com", AuthMethod: AuthAppRole, RoleID: "r"},
		{Address: "https://vault.example.com/v1", AuthMethod: AuthAppRole, RoleID: "r"},
		{Address: "https://vault.example.com", AuthMethod: AuthAppRole},
		{Address: "https://vault.example.com", AuthMethod: AuthKubernetes},
		{Address: "https://vault.example.com", AuthMethod: "token", RoleID: "r"},
		{Address: "https://vault.example.com", AuthMethod: AuthAppRole, RoleID: "r", AuthMount: "../x"},
		{Address: "https://vault.example.com", AuthMethod: AuthAppRole, RoleID: "r", CanaryRef: "nope"},
		{Address: "https://169.254.169.254", AuthMethod: AuthAppRole, RoleID: "r"},
	} {
		b := bad
		if err := b.Validate(false); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

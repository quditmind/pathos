//go:build integration

package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestOpenBao runs against a real OpenBao dev server:
//
//	docker run -d --name m2k-openbao -e BAO_DEV_ROOT_TOKEN_ID=root openbao/openbao:2.4.4 server -dev -dev-listen-address=0.0.0.0:8200
//	PATHOS_TEST_OPENBAO_ADDR=http://m2k-openbao:8200 PATHOS_TEST_OPENBAO_TOKEN=root go test -tags integration ./internal/vault/
//
// It enables AppRole, writes a read-only policy for secret/data/pathos/*,
// stores a KV v2 secret and resolves a reference the way the server does.
func TestOpenBao(t *testing.T) {
	addr, root := os.Getenv("PATHOS_TEST_OPENBAO_ADDR"), os.Getenv("PATHOS_TEST_OPENBAO_TOKEN")
	if addr == "" || root == "" {
		t.Skip("PATHOS_TEST_OPENBAO_ADDR / _TOKEN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	call := func(method, path string, body any, out any) int {
		t.Helper()
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req, _ := http.NewRequestWithContext(ctx, method, addr+"/v1/"+path, rd)
		req.Header.Set("X-Vault-Token", root)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil {
			_ = json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}
	// Wait for the dev server.
	for i := 0; i < 30; i++ {
		if call(http.MethodGet, "sys/health", nil, nil) == 200 {
			break
		}
		time.Sleep(time.Second)
	}
	if st := call(http.MethodPost, "sys/auth/approle", map[string]any{"type": "approle"}, nil); st >= 300 && st != 400 {
		t.Fatalf("enable approle: %d", st)
	}
	policy := `path "secret/data/pathos/*" { capabilities = ["read"] }`
	if st := call(http.MethodPut, "sys/policies/acl/pathos-read", map[string]any{"policy": policy}, nil); st >= 300 {
		t.Fatalf("policy: %d", st)
	}
	if st := call(http.MethodPost, "auth/approle/role/pathos", map[string]any{"token_policies": []string{"pathos-read"},
		"secret_id_ttl": "10m", "secret_id_num_uses": 0, "token_ttl": "5m"}, nil); st >= 300 {
		t.Fatalf("role: %d", st)
	}
	var rid struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	call(http.MethodGet, "auth/approle/role/pathos/role-id", nil, &rid)
	var sid struct {
		Data struct {
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	call(http.MethodPost, "auth/approle/role/pathos/secret-id", map[string]any{}, &sid)
	if rid.Data.RoleID == "" || sid.Data.SecretID == "" {
		t.Fatal("no role ID / secret ID")
	}
	if st := call(http.MethodPost, "secret/data/pathos/scm/github", map[string]any{"data": map[string]string{"token": "ghp_openbao_value"}}, nil); st >= 300 {
		t.Fatalf("write secret: %d", st)
	}
	if st := call(http.MethodPost, "secret/data/other/x", map[string]any{"data": map[string]string{"k": "v"}}, nil); st >= 300 {
		t.Fatalf("write other secret: %d", st)
	}

	cfg := Config{Address: addr, AuthMethod: AuthAppRole, RoleID: rid.Data.RoleID, SecretID: sid.Data.SecretID,
		CanaryRef: "vault:secret/pathos/scm/github#token", AllowPrivate: true}
	if err := cfg.Validate(true); err != nil {
		t.Fatal(err)
	}
	org := uuid.New()
	r := &Resolver{AllowHTTP: true, HTTP: http.DefaultClient, Source: func(context.Context, uuid.UUID) (Config, error) { return cfg, nil }}
	v, err := r.Resolve(ctx, org, "vault:secret/pathos/scm/github#token")
	if err != nil || string(v) != "ghp_openbao_value" {
		t.Fatalf("resolve: %q %v", v, err)
	}
	c, _ := r.Client(ctx, org)
	res, err := c.Check(ctx)
	if err != nil || res.Steps["canary"] != "pass" || res.Health.Sealed {
		t.Fatalf("check: %+v %v", res, err)
	}
	// The policy denies another path: PTH-CONN-1602.
	if _, err := r.Resolve(ctx, org, "vault:secret/other/x#k"); DiagCode(err) != "PTH-CONN-1602" {
		t.Fatalf("policy: %s %v", DiagCode(err), err)
	}
	// A wrong secret ID: PTH-CONN-1601, and the value never appears.
	bad := cfg
	bad.SecretID = "00000000-0000-0000-0000-000000000000"
	bc, _ := NewClient(bad, http.DefaultClient, true)
	_, err = bc.Read(ctx, Ref{Mount: "secret", Path: "pathos/scm/github", Key: "token"})
	if DiagCode(err) != "PTH-CONN-1601" || strings.Contains(err.Error(), bad.SecretID) {
		t.Fatalf("bad secret ID: %s %v", DiagCode(err), err)
	}
	// Changing the secret makes the next use see the new value: nothing
	// but the client token is cached.
	call(http.MethodPost, "secret/data/pathos/scm/github", map[string]any{"data": map[string]string{"token": "ghp_rotated"}}, nil)
	if v, _ := r.Resolve(ctx, org, "vault:secret/pathos/scm/github#token"); string(v) != "ghp_rotated" {
		t.Fatalf("rotated value not seen: %q", v)
	}
}

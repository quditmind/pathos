//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/repos"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

// M2 connector kinds through the SCM connections API: the connectors flag
// gate, a private CA bundle, Generic Git over HTTPS (real git http-backend
// behind a private-CA TLS server), Generic Git SSH host key pinning, and
// Bitbucket Data Center with a signed webhook.
func TestM2ConnectorKinds(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	h := &harness{t: t, mux: http.NewServeMux()}
	svc := &repos.Service{
		DB: appPool, Authz: &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}},
		Secrets: &secrets.Store{Keys: kr}, Log: log, Principal: auth.PrincipalFrom, PublicURL: "https://pathos.test",
		// The real clients with the per-connection CA client; only the
		// dialer is opened to loopback (the policy always blocks it).
		NewClient: func(cfg scm.Config) (scm.FullClient, error) {
			if cfg.HTTP != nil {
				if tr, ok := cfg.HTTP.Transport.(*http.Transport); ok {
					tr = tr.Clone()
					tr.DialContext, tr.Proxy = loopbackDial, nil
					cfg.HTTP = &http.Client{Transport: tr, Timeout: 20 * time.Second}
				}
			}
			return scm.New(cfg)
		},
	}
	svc.Register(h.mux)
	svc.RegisterPublic(h.mux)
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	sfx := uuid.NewString()[:8]

	// A bare repository served by git http-backend over TLS with a private CA.
	root := t.TempDir()
	work := filepath.Join(root, "work")
	gitRun := func(dir string, args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t",
			"GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	gitRun(root, "init", "-q", "-b", "main", work)
	_ = os.WriteFile(filepath.Join(work, "f"), []byte("x"), 0o600)
	gitRun(work, "add", "f")
	gitRun(work, "commit", "-q", "-m", "c")
	gitRun(root, "clone", "-q", "--bare", work, filepath.Join(root, "app.git"))
	gitSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, p, ok := r.BasicAuth(); !ok || p != "tok-"+sfx {
			w.WriteHeader(401)
			return
		}
		(&cgi.Handler{Path: git, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1",
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}}).ServeHTTP(w, r)
	}))
	defer gitSrv.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gitSrv.Certificate().Raw}))

	generic := map[string]any{"name": "Generic " + sfx, "provider": "generic_git", "auth_type": "api_token",
		"base_url": exampleURL(gitSrv) + "/app.git", "username": "reader", "token": "tok-" + sfx, "ca_bundle_pem": caPEM}

	// 1. Flag off: the new kinds and the CA field do not exist.
	if code, _ := h.do(admin, "POST", "/api/v1/scm-connections", generic); code != 400 {
		t.Fatalf("generic_git with the connectors flag off: want 400, got %d", code)
	}
	_, prov := h.do(admin, "GET", "/api/v1/scm-providers", nil)
	if raw, _ := json.Marshal(prov); bytes.Contains(raw, []byte("generic_git")) {
		t.Fatal("generic_git must not be offered with the flag off")
	}
	if code, _ := h.do(admin, "POST", "/api/v1/scm-connections", map[string]any{"name": "GH " + sfx, "provider": "github",
		"auth_type": "pat", "token": "x", "ca_bundle_pem": caPEM}); code != 400 {
		t.Fatalf("ca_bundle_pem with the flag off: want 400, got %d", code)
	}

	// 2. Flag on.
	if _, err := ownerPool.Exec(ctx, `INSERT INTO feature_flags (id, organization_id, name, enabled) VALUES ($1, $2, 'connectors', true)
		ON CONFLICT (organization_id, name) DO UPDATE SET enabled = true`, uuid.New(), orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = ownerPool.Exec(context.Background(), `DELETE FROM feature_flags WHERE organization_id = $1 AND name = 'connectors'`, orgID)
	})
	_, prov = h.do(admin, "GET", "/api/v1/scm-providers", nil)
	if raw, _ := json.Marshal(prov); !bytes.Contains(raw, []byte("generic_git")) || !bytes.Contains(raw, []byte("bitbucket_data_center")) {
		t.Fatal("the new kinds must be offered with the flag on")
	}
	if code, r := h.do(admin, "POST", "/api/v1/scm-connections", map[string]any{"name": "Bad CA " + sfx, "provider": "github_enterprise",
		"base_url": "https://ghe.example.com", "auth_type": "pat", "token": "x",
		"ca_bundle_pem": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}); code != 400 {
		t.Fatalf("a private key as CA bundle: want 400, got %d %v", code, r)
	}

	// 3. Generic Git over HTTPS with the private CA: health check is ls-remote.
	code, conn := h.do(admin, "POST", "/api/v1/scm-connections", generic)
	if code != 201 || conn["status"] != "ok" || !strings.Contains(conn["status_message"].(string), "HEAD → main") {
		t.Fatalf("generic git create: %d %v", code, conn)
	}
	if raw, _ := json.Marshal(conn); bytes.Contains(raw, []byte("tok-"+sfx)) {
		t.Fatal("credential leaked")
	}
	if certs := conn["ca_certificates"].([]any); len(certs) != 1 || len(certs[0].(map[string]any)["sha256_fingerprint"].(string)) != 64 {
		t.Fatalf("CA bundle metadata: %v", conn["ca_certificates"])
	}
	if conn["has_ca_bundle"] != true {
		t.Fatalf("has_ca_bundle: %v", conn["has_ca_bundle"])
	}
	if raw, _ := json.Marshal(conn); bytes.Contains(raw, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("the CA PEM must not be returned")
	}
	gid := conn["id"].(string)
	code, disc := h.do(admin, "GET", "/api/v1/scm-connections/"+gid+"/discover", nil)
	if code != 200 || len(disc["items"].([]any)) != 1 {
		t.Fatalf("discover: %d %v", code, disc)
	}
	cred, err := svc.CloneCredential(ctx, orgID, uuid.MustParse(gid))
	if err != nil || cred.Token != "tok-"+sfx || cred.CABundle == "" {
		t.Fatalf("clone credential must carry the token and the CA bundle: %v", err)
	}
	// Removing the CA makes the check fail with the certificate code.
	if code, _ := h.do(admin, "PATCH", "/api/v1/scm-connections/"+gid, map[string]any{"ca_bundle_pem": ""}); code != 200 {
		t.Fatalf("clear CA: %d", code)
	}
	_, tested := h.do(admin, "POST", "/api/v1/scm-connections/"+gid+"/test", nil)
	if tested["status"] != "error" || !strings.Contains(tested["status_message"].(string), "certificate") {
		t.Fatalf("without the CA the check must fail on the certificate: %v", tested)
	}

	// 3b. The same through the Connectors hub's generic body.
	hubCfg := map[string]any{"base_url": exampleURL(gitSrv) + "/app.git", "auth_method": "https_token", "ca_bundle_pem": caPEM,
		"username": "reader", "proxy_url": "", "scopes": []any{"read"}, "credential_ref": ""}
	hc, err := svc.CreateFromConnector(ctx, admin, "generic_git", "Hub "+sfx, hubCfg, "tok-"+sfx)
	if err != nil || hc.Status != "ok" || !hc.HasCABundle {
		t.Fatalf("hub create: %+v %v", hc, err)
	}
	hubCfg["proxy_url"] = "http://proxy.example.com:3128"
	if _, err := svc.CreateFromConnector(ctx, admin, "generic_git", "Hub2 "+sfx, hubCfg, "x"); err == nil {
		t.Fatal("a per-connection proxy must be refused")
	}
	hubCfg["proxy_url"] = ""
	if _, err := svc.CreateFromConnector(ctx, scoped("security_manager", authz.Scope{Type: authz.ScopeOrganization, ID: orgID}),
		"generic_git", "Hub3 "+sfx, hubCfg, "x"); err == nil {
		t.Fatal("creating needs scm.manage")
	}
	if _, err := svc.CreateFromConnector(ctx, admin, "github", "Hub4 "+sfx, hubCfg, "x"); err == nil {
		t.Fatal("only the hub's SCM kinds are created this way")
	}
	hubCfg["credential_ref"] = "vault:secret/pathos/git#token"
	ref, err := svc.CreateFromConnector(ctx, admin, "generic_git", "Hub5 "+sfx, hubCfg, "")
	if err != nil || ref.Status != "error" || !strings.Contains(ref.StatusMessage, "Vault") {
		t.Fatalf("a vault reference without a Vault connection is stored and fails at use time: %+v %v", ref, err)
	}

	// 4. Generic Git over SSH: the fingerprint must match the known_hosts entry.
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	known := "git.example.com " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())))
	_, cliPriv, _ := ed25519.GenerateKey(rand.Reader)
	blk, _ := ssh.MarshalPrivateKey(cliPriv, "")
	keyPEM := string(pem.EncodeToMemory(blk))
	sshReq := map[string]any{"name": "SSH " + sfx, "provider": "generic_git", "auth_type": "ssh_key",
		"base_url": "git@git.example.com:team/app.git", "ssh_private_key": keyPEM, "ssh_known_hosts": known,
		"ssh_host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	code, r := h.do(admin, "POST", "/api/v1/scm-connections", sshReq)
	if code != 400 || r["error"].(map[string]any)["error_code"] != "PTH-CONN-1140" {
		t.Fatalf("mismatching fingerprint: %d %v", code, r)
	}
	sshReq["ssh_host_key_fingerprint"] = ssh.FingerprintSHA256(hostSigner.PublicKey())
	code, sc := h.do(admin, "POST", "/api/v1/scm-connections", sshReq)
	if code != 201 || sc["base_url"] != "ssh://git@git.example.com/team/app.git" {
		t.Fatalf("ssh create: %d %v", code, sc)
	}
	if raw, _ := json.Marshal(sc); bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("SSH private key leaked")
	}
	keys := sc["ssh_host_keys"].([]any)
	if len(keys) != 1 || keys[0].(map[string]any)["fingerprint"] != ssh.FingerprintSHA256(hostSigner.PublicKey()) {
		t.Fatalf("pinned host keys: %v", keys)
	}
	if code, _ := h.do(admin, "POST", "/api/v1/scm-connections", map[string]any{"name": "Mixed " + sfx, "provider": "generic_git",
		"auth_type": "api_token", "base_url": "ssh://git@git.example.com/x.git", "token": "x"}); code != 400 {
		t.Fatalf("api_token with an ssh URL must be refused, got %d", code)
	}

	// 5. Bitbucket Data Center behind the private CA, then a signed webhook.
	bb := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer bbdc-"+sfx {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/bitbucket/rest/api/1.0/application-properties":
			_, _ = w.Write([]byte(`{"version":"10.1.0"}`))
		case "/bitbucket/rest/api/1.0/repos":
			_, _ = w.Write([]byte(`{"values":[{"id":7,"slug":"api","name":"api","project":{"key":"SEC"},"links":{"clone":[{"name":"http","href":"https://` + r.Host + `/bitbucket/scm/sec/api.git"}]}}],"isLastPage":true}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer bb.Close()
	bbCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bb.Certificate().Raw}))
	code, bc := h.do(admin, "POST", "/api/v1/scm-connections", map[string]any{"name": "BBDC " + sfx, "provider": "bitbucket_data_center",
		"base_url": exampleURL(bb) + "/bitbucket/rest/api/1.0", "auth_type": "pat", "token": "bbdc-" + sfx, "ca_bundle_pem": bbCA})
	if code != 201 || bc["status"] != "ok" || bc["base_url"] != exampleURL(bb)+"/bitbucket" {
		t.Fatalf("bitbucket data center: %d %v", code, bc)
	}
	bid := bc["id"].(string)
	if !strings.HasSuffix(bc["webhook_url"].(string), "/api/webhooks/bitbucket-data-center/"+bid) {
		t.Fatalf("webhook URL %v", bc["webhook_url"])
	}
	_, wh := h.do(admin, "POST", "/api/v1/scm-connections/"+bid+"/webhook-secret", nil)
	secret := []byte(wh["webhook_secret"].(string))
	body := []byte(`{"eventKey":"repo:refs_changed","repository":{"id":7},"changes":[{"ref":{"displayId":"main","type":"BRANCH"},"toHash":"2222222222222222222222222222222222222222","type":"UPDATE"}]}`)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	hook := "/api/webhooks/bitbucket-data-center/" + bid
	if code, _ := h.do(nil, "POST", hook, body, "X-Event-Key", "repo:refs_changed", "X-Request-Id", "r-"+sfx, "X-Hub-Signature", "sha256=00"); code != 401 {
		t.Errorf("bad signature: want 401, got %d", code)
	}
	if code, r := h.do(nil, "POST", hook, body, "X-Event-Key", "repo:refs_changed", "X-Request-Id", "r-"+sfx,
		"X-Hub-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil))); code != 202 {
		t.Errorf("signed delivery: %d %v", code, r)
	}
}

// exampleURL names an httptest TLS server by a host its certificate covers
// (example.com) instead of 127.0.0.1, which every SCM URL check refuses;
// loopbackDial connects example.com:<port> to the local listener.
func exampleURL(s *httptest.Server) string {
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(s.URL, "https://"))
	return "https://example.com:" + port
}

func loopbackDial(ctx context.Context, network, addr string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, "127.0.0.1:"+port)
}

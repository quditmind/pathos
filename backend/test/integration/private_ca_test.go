//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/auth"
	"pathos/internal/authz"
	"pathos/internal/notify"
	"pathos/internal/org"
	"pathos/internal/platform/crypto"
	"pathos/internal/runtimectx"
	"pathos/internal/secrets"
	"pathos/internal/tickets"
)

// TestPrivateCAConnections: registry connections, outbound webhooks and
// ticket connections accept a per-connection private CA bundle, return it
// with its certificate details, refuse anything but certificates
// (PTH-CONN-1701), and use it for TLS (VALIDATION_REPORT O3). Slack and
// Teams webhooks created with sign=true get a warning (O11).
func TestPrivateCAConnections(t *testing.T) {
	ctx := t.Context()
	az := &authz.Authorizer{H: &org.Hierarchy{DB: appPool, OrgID: orgID}}
	kr, _ := crypto.NewKeyring(map[int][]byte{1: testKey})
	store := &secrets.Store{Keys: kr}
	admin := principalWithRole(t, authz.RoleSuperAdmin)
	tag := uuid.NewString()[:6]

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"team/app","tags":[]}`))
	}))
	defer srv.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	keyPEM := "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"

	var gotTLS *tls.Config
	rt := &runtimectx.Service{DB: appPool, Authz: az, Secrets: store, Log: log, Principal: auth.PrincipalFrom, AllowHTTP: true,
		NewHTTP: func(_ bool, tlsCfg *tls.Config) *http.Client {
			gotTLS = tlsCfg
			// example.com is in the httptest certificate; connect to the
			// test server instead of resolving it.
			return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg,
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
				}}}
		}}
	nt := &notify.Service{DB: appPool, Authz: az, Secrets: store, Log: log, Principal: auth.PrincipalFrom, BaseURL: "https://pathos.test"}
	tk := &tickets.Service{DB: appPool, Authz: az, Secrets: store, Log: log, Principal: auth.PrincipalFrom, PublicURL: "https://pathos.test"}
	mux := http.NewServeMux()
	rt.Register(mux)
	nt.Register(mux)
	tk.Register(mux)
	call := func(method, path string, body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(auth.WithPrincipal(ctx, admin))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	diag := func(out map[string]any) string {
		e, _ := out["error"].(map[string]any)
		s, _ := e["error_code"].(string)
		return s
	}
	certs := func(m map[string]any) int {
		l, _ := m["ca_certificates"].([]any)
		return len(l)
	}

	// --- registry -----------------------------------------------------------
	reg := map[string]any{"name": "ca-reg-" + tag, "base_url": "https://example.com", "repositories": []string{"team/app"}, "allow_private": true}
	reg["ca_bundle_pem"] = keyPEM
	if code, out := call("POST", "/api/v1/runtime/registries", reg); code != 400 || diag(out) != "PTH-CONN-1701" {
		t.Errorf("registry with a private key as CA: %d %v", code, out)
	}
	reg["ca_bundle_pem"] = caPEM
	code, r := call("POST", "/api/v1/runtime/registries", reg)
	if code != 201 || r["ca_bundle_pem"] != strings.TrimSpace(caPEM) || certs(r) != 1 {
		t.Fatalf("registry with CA: %d %v", code, r)
	}
	if status, err := rt.SyncRegistry(ctx, uuid.MustParse(r["id"].(string))); err != nil || status == "failed" {
		t.Errorf("registry sync through the private CA: %s %v", status, err)
	}
	if gotTLS == nil || gotTLS.RootCAs == nil || gotTLS.InsecureSkipVerify || gotTLS.MinVersion != tls.VersionTLS12 {
		t.Errorf("registry TLS configuration: %+v", gotTLS)
	}
	// Updating without the field keeps the bundle; "" removes it.
	delete(reg, "ca_bundle_pem")
	if code, out := call("PUT", "/api/v1/runtime/registries/"+r["id"].(string), reg); code != 200 || certs(out) != 1 {
		t.Errorf("update keeps the bundle: %d %v", code, out)
	}
	reg["ca_bundle_pem"] = ""
	if code, out := call("PUT", "/api/v1/runtime/registries/"+r["id"].(string), reg); code != 200 || certs(out) != 0 {
		t.Errorf("update removes the bundle: %d %v", code, out)
	}
	gotTLS = nil
	if status, _ := rt.SyncRegistry(ctx, uuid.MustParse(r["id"].(string))); status != "failed" {
		t.Errorf("without the CA the registry certificate is not trusted: %s", status)
	}

	// --- webhooks -----------------------------------------------------------
	hook := map[string]any{"name": "ca-hook-" + tag, "format": "slack", "url": "https://hooks.example.test/T/B/x", "events": []string{"scan.failed"},
		"sign": true, "ca_bundle_pem": keyPEM}
	if code, out := call("POST", "/api/v1/notifications/webhooks", hook); code != 400 || diag(out) != "PTH-CONN-1701" {
		t.Errorf("webhook with a private key as CA: %d %v", code, out)
	}
	hook["ca_bundle_pem"] = caPEM
	code, out := call("POST", "/api/v1/notifications/webhooks", hook)
	wh, _ := out["webhook"].(map[string]any)
	warnings, _ := out["warnings"].([]any)
	if code != 201 || wh["signed"] != false || certs(wh) != 1 || len(warnings) != 1 || !strings.Contains(warnings[0].(string), "not signed") {
		t.Fatalf("slack webhook with CA and sign: %d %v", code, out)
	}

	// --- ticket connections -------------------------------------------------
	tc := map[string]any{"kind": "jira", "name": "ca-jira-" + tag, "base_url": "https://jira.example.test", "auth_type": "bearer", "secret": "t",
		"config": map[string]any{"project_key": "SEC"}, "ca_bundle_pem": keyPEM}
	if code, out := call("POST", "/api/v1/ticket-connections", tc); code != 400 || diag(out) != "PTH-CONN-1701" {
		t.Errorf("ticket connection with a private key as CA: %d %v", code, out)
	}
	tc["ca_bundle_pem"] = caPEM
	if code, out := call("POST", "/api/v1/ticket-connections", tc); code != 201 || certs(out) != 1 {
		t.Errorf("ticket connection with CA: %d %v", code, out)
	}
}

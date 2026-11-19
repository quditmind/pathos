package runtimectx

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func kubeconfigFor(server, ca, user string) string {
	return `apiVersion: v1
kind: Config
current-context: pathos
clusters:
- name: prod
  cluster:
    server: ` + server + `
    certificate-authority-data: ` + base64.StdEncoding.EncodeToString([]byte(ca)) + `
contexts:
- name: pathos
  context: {cluster: prod, user: reader}
users:
- name: reader
  user:
` + user
}

func TestKubeconfigAgainstFakeAPIServer(t *testing.T) {
	api := &fakeAPI{token: "sa-token-value"}
	srv := httptest.NewTLSServer(api)
	defer srv.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))

	creds, err := ParseKubeconfig([]byte(kubeconfigFor(srv.URL, ca, "    token: sa-token-value\n")), "")
	if err != nil {
		t.Fatal(err)
	}
	if creds.Server != srv.URL || creds.Token != "sa-token-value" {
		t.Fatalf("creds: %+v", creds)
	}
	// The CA from the kubeconfig verifies the server (no InsecureSkipVerify).
	tlsCfg, err := creds.TLSConfig()
	if err != nil || tlsCfg.InsecureSkipVerify {
		t.Fatal(err)
	}
	u, _ := url.Parse(creds.Server)
	kc := &KubeClient{Base: u, HTTP: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}, Token: creds.Token}
	if _, err := kc.List(context.Background(), Resources[0], ""); err != nil {
		t.Fatalf("list with kubeconfig CA: %v", err)
	}
	// Without the CA the server's certificate is not trusted.
	kc.HTTP = &http.Client{}
	if _, err := kc.List(context.Background(), Resources[0], ""); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("untrusted certificate must fail: %v", err)
	}
}

func TestKubeconfigRefusals(t *testing.T) {
	ca := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	for name, c := range map[string]struct{ cfg, want string }{
		"exec plugin":   {kubeconfigFor("https://k8s.example.com", ca, "    exec:\n      command: aws\n"), "exec"},
		"auth provider": {kubeconfigFor("https://k8s.example.com", ca, "    auth-provider:\n      name: gcp\n"), "exec"},
		"token file":    {kubeconfigFor("https://k8s.example.com", ca, "    tokenFile: /var/run/token\n"), "files"},
		"cert file":     {kubeconfigFor("https://k8s.example.com", ca, "    client-certificate: /tmp/c.crt\n    client-key: /tmp/c.key\n"), "files"},
		"no credential": {kubeconfigFor("https://k8s.example.com", ca, "    username: admin\n"), "no token"},
		"insecure": {strings.Replace(kubeconfigFor("https://k8s.example.com", ca, "    token: x\n"), "    certificate-authority-data:",
			"    insecure-skip-tls-verify: true\n    x-ca:", 1), "insecure-skip-tls-verify"},
		"bad CA":          {kubeconfigFor("https://k8s.example.com", "not a certificate", "    token: x\n"), "PEM"},
		"unknown context": {strings.Replace(kubeconfigFor("https://k8s.example.com", ca, "    token: x\n"), "current-context: pathos", "current-context: other", 1), "not found"},
		"not yaml":        {"{{{", "kubeconfig"},
	} {
		if _, err := ParseKubeconfig([]byte(c.cfg), ""); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

package notify

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// loopbackOnly lets a policy client reach an httptest server (the policy
// always blocks 127.0.0.0/8); the TLS configuration is what is under test.
func loopbackOnly(c *http.Client) *http.Client {
	tr := c.Transport.(*http.Transport)
	tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	tr.Proxy = nil
	return c
}

// A webhook endpoint behind a private CA: without the bundle the delivery
// fails with an untrusted certificate and the corrective action; with it,
// it is delivered (VALIDATION_REPORT O3).
func TestWebhookPrivateCA(t *testing.T) {
	got := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { got++ }))
	defer srv.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	ep := endpoint{id: uuid.New(), format: "slack", url: srv.URL}
	d := &Data{BaseURL: "https://pathos.test", Event: "webhook.test"}

	_, err := sendWebhook(context.Background(), loopbackOnly(endpointClient(ep)), ep, uuid.New(), "webhook.test", time.Now(), d)
	if err == nil || !strings.Contains(err.Error(), "PTH-CONN-1702") || !strings.Contains(err.Error(), "ca_bundle_pem") {
		t.Fatalf("untrusted private CA: %v", err)
	}
	ep.caBundle = caPEM
	c := endpointClient(ep)
	tls := c.Transport.(*http.Transport).TLSClientConfig
	if tls == nil || tls.InsecureSkipVerify || tls.MinVersion < 0x0303 {
		t.Fatalf("TLS configuration: %+v", tls)
	}
	if status, err := sendWebhook(context.Background(), loopbackOnly(c), ep, uuid.New(), "webhook.test", time.Now(), d); err != nil || status != 200 || got != 1 {
		t.Fatalf("with the CA bundle: %d %v (received %d)", status, err, got)
	}
}

func TestSigningWarning(t *testing.T) {
	if w := signingWarning(webhookInput{Format: "slack", Sign: true}); len(w) != 1 || !strings.Contains(w[0], "not signed") {
		t.Errorf("slack: %v", w)
	}
	if w := signingWarning(webhookInput{Format: "teams", Sign: true}); len(w) != 1 {
		t.Errorf("teams: %v", w)
	}
	if w := signingWarning(webhookInput{Format: "json", Sign: true}); len(w) != 0 {
		t.Errorf("json: %v", w)
	}
}

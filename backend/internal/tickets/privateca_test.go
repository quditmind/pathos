package tickets

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func loopbackOnly(c *http.Client) *http.Client {
	tr := c.Transport.(*http.Transport)
	tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	tr.Proxy = nil
	return c
}

// A Jira server behind a private CA (VALIDATION_REPORT O3).
func TestTicketPrivateCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key":"SEC","name":"Security","displayName":"Bot"}`))
	}))
	defer srv.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	c := Conn{Kind: "jira", BaseURL: srv.URL, AuthType: "bearer", Secret: "t", Config: Config{ProjectKey: "SEC"}}

	c.HTTP = loopbackOnly(connClient(false, ""))
	if _, err := c.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "PTH-CONN-1702") {
		t.Fatalf("untrusted private CA: %v", err)
	}
	c.HTTP = loopbackOnly(connClient(false, caPEM))
	if tc := c.HTTP.Transport.(*http.Transport).TLSClientConfig; tc.InsecureSkipVerify || tc.MinVersion < 0x0303 {
		t.Fatalf("TLS configuration: %+v", tc)
	}
	if _, err := c.Check(context.Background()); err != nil {
		t.Fatalf("with the CA bundle: %v", err)
	}
}

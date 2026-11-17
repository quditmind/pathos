package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLookupPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v3/systems/npm/packages/@sigstore/sign":
			_, _ = w.Write([]byte(`{"versions":[{"versionKey":{"version":"3.0.0"},"isDeprecated":true},{"versionKey":{"version":"3.1.0"},"isDefault":true,"publishedAt":"2025-01-01T00:00:00Z"}]}`))
		case "/v3/systems/npm/packages/@sigstore/sign/versions/3.1.0":
			_, _ = w.Write([]byte(`{"slsaProvenances":[{"sourceRepository":"https://github.com/sigstore/sigstore-js","commit":"06cd267c","verified":true}],
				"relatedProjects":[{"projectKey":{"id":"github.com/sigstore/sigstore-js"},"relationType":"SOURCE_REPO"}]}`))
		case "/v3/projects/github.com/sigstore/sigstore-js":
			_, _ = w.Write([]byte(`{"scorecard":{"overallScore":7.9}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	s := &Service{HTTP: srv.Client()}
	h, err := s.lookupPackage(context.Background(), srv.URL+"/v3/", "npm", "@sigstore/sign", "3.1.0", true)
	if err != nil || !h.found {
		t.Fatalf("%v %+v", err, h)
	}
	if h.latest != "3.1.0" || len(h.deprecated) != 1 || h.deprecated[0] != "3.0.0" || h.published == nil {
		t.Errorf("versions: %+v", h)
	}
	if h.scorecard == nil || *h.scorecard != 7.9 || h.project != "github.com/sigstore/sigstore-js" {
		t.Errorf("scorecard: %+v", h)
	}
	if h.provVersion != "3.1.0" || h.provenance == nil || !h.provenance.Verified || h.provenance.Source != "https://github.com/sigstore/sigstore-js" {
		t.Errorf("provenance: %+v", h.provenance)
	}
	// Transitive dependencies: one request, no provenance or Scorecard.
	h, _ = s.lookupPackage(context.Background(), srv.URL+"/v3", "npm", "@sigstore/sign", "3.1.0", false)
	if h.provVersion != "" || h.scorecard != nil {
		t.Errorf("transitive lookups stay cheap: %+v", h)
	}
	// Unknown packages (private names) are not found, not errors.
	h, err = s.lookupPackage(context.Background(), srv.URL+"/v3", "npm", "@acme/internal", "1.0.0", true)
	if err != nil || h.found {
		t.Errorf("unknown package: %v %+v", err, h)
	}
}

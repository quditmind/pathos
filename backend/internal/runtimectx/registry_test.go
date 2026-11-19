package runtimectx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
)

const (
	digIndex  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digAmd64  = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digConfig = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// fakeRegistry implements the read side of the OCI distribution API with
// Docker token authentication.
type fakeRegistry struct {
	mu      sync.Mutex
	methods []string
	srv     *httptest.Server
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.methods = append(f.methods, r.Method)
	f.mu.Unlock()
	if r.URL.Path == "/token" {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "robot" || pass != "pw" || r.URL.Query().Get("scope") != "repository:acme/shop:pull" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"token":"tok-123"}`))
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok-123" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+f.srv.URL+`/token",service="fake",scope="repository:acme/shop:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/v2/acme/shop/tags/list":
		if r.URL.Query().Get("last") == "" {
			w.Header().Set("Link", `</v2/acme/shop/tags/list?n=2&last=1.1>; rel="next"`)
			_, _ = w.Write([]byte(`{"name":"acme/shop","tags":["1.0","1.1"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"name":"acme/shop","tags":["latest"]}`))
	case "/v2/acme/shop/manifests/1.0", "/v2/acme/shop/manifests/1.1", "/v2/acme/shop/manifests/latest":
		w.Header().Set("Docker-Content-Digest", digIndex)
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		_, _ = w.Write([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
			{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"` + digConfig + `","platform":{"os":"unknown","architecture":"unknown"}},
			{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"` + digAmd64 + `","platform":{"os":"linux","architecture":"amd64"}}]}`))
	case "/v2/acme/shop/manifests/" + digAmd64:
		w.Header().Set("Docker-Content-Digest", digAmd64)
		_, _ = w.Write([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"` + digConfig + `"}}`))
	case "/v2/acme/shop/blobs/" + digConfig:
		_, _ = w.Write([]byte(`{"created":"2026-11-01T10:00:00Z","config":{"Labels":{"org.opencontainers.image.source":"https://github.com/acme/shop",
			"org.opencontainers.image.revision":"0123456789abcdef0123456789abcdef01234567"}}}`))
	default:
		http.NotFound(w, r)
	}
}

func TestRegistryClientFake(t *testing.T) {
	f := &fakeRegistry{}
	f.srv = httptest.NewTLSServer(f)
	defer f.srv.Close()
	u, _ := url.Parse(f.srv.URL)
	rc := &RegistryClient{Base: u, HTTP: f.srv.Client(), Auth: "basic", Username: "robot", Secret: "pw"}
	tags, truncated, err := rc.Tags(context.Background(), "acme/shop", 50)
	if err != nil || truncated || strings.Join(tags, ",") != "1.0,1.1,latest" {
		t.Fatalf("tags: %v %v %v", tags, truncated, err)
	}
	tags, truncated, _ = rc.Tags(context.Background(), "acme/shop", 1)
	if len(tags) != 1 || !truncated {
		t.Errorf("max tags: %v", tags)
	}
	img, err := rc.Image(context.Background(), "acme/shop", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if img.Digest != digIndex || img.SourceURL != "https://github.com/acme/shop" || !strings.HasPrefix(img.Revision, "0123456789") ||
		img.Created != "2026-11-01T10:00:00Z" {
		t.Errorf("image: %+v", img)
	}
	for _, m := range f.methods {
		if m != http.MethodGet && m != http.MethodHead {
			t.Errorf("read-only: %s", m)
		}
	}
	// Wrong credentials: the token service refuses.
	rc = &RegistryClient{Base: u, HTTP: f.srv.Client(), Auth: "basic", Username: "robot", Secret: "wrong"}
	if _, _, err := rc.Tags(context.Background(), "acme/shop", 10); err == nil {
		t.Error("wrong credentials must fail")
	}
	if nextLink(`<https://evil.example/v2/x/tags/list?n=1>; rel="next"`, u) != "" {
		t.Error("pagination links to other hosts are not followed")
	}
	if !ValidRepositoryName("acme/shop") || ValidRepositoryName("Acme/Shop") || ValidRepositoryName("../etc") {
		t.Error("repository names")
	}
}

// TestRegistryClientLive runs against a real registry:2 container when
// PATHOS_TEST_REGISTRY_URL is set (scripts in the PR: docker run --name
// c4-registry registry:2, then push an image with OCI labels as
// acme/shop:1.0). It is skipped otherwise; it never contacts a public
// registry.
func TestRegistryClientLive(t *testing.T) {
	base := os.Getenv("PATHOS_TEST_REGISTRY_URL")
	if base == "" {
		t.Skip("PATHOS_TEST_REGISTRY_URL not set")
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	rc := &RegistryClient{Base: u, HTTP: &http.Client{}, Auth: "none"}
	if err := rc.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	tags, _, err := rc.Tags(context.Background(), "acme/shop", 10)
	if err != nil || len(tags) == 0 {
		t.Fatalf("tags: %v %v", tags, err)
	}
	img, err := rc.Image(context.Background(), "acme/shop", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("live registry image: %+v", img)
	if !ValidDigest(img.Digest) || img.SourceURL != "https://github.com/acme-test/shop" || img.Revision != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("live image: %+v", img)
	}
	if want := os.Getenv("PATHOS_TEST_REGISTRY_DIGEST"); want != "" && img.Digest != want {
		t.Errorf("digest %s, want %s (docker push output)", img.Digest, want)
	}
}

package scans

import (
	"strings"
	"testing"
)

func TestValidateImageRef(t *testing.T) {
	ok := map[string]string{
		"ghcr.io/acme/api:1.4.2":                            "ghcr.io",
		"nginx":                                             "index.docker.io",
		"library/nginx:1.27":                                "index.docker.io",
		"docker.io/library/nginx:latest":                    "index.docker.io",
		"registry-1.docker.io/library/nginx:1.25":           "index.docker.io",
		"team-registry/app/web:1.0":                         "index.docker.io", // no dot or port: a Docker Hub namespace
		"registry.corp.example:5000/team/svc:v2":            "registry.corp.example",
		"localhost:5000/svc":                                "localhost",
		"quay.io/org/app@sha256:" + strings.Repeat("a", 64): "quay.io",
	}
	for ref, host := range ok {
		got, err := ValidateImageRef(ref)
		if err != nil || got != host {
			t.Errorf("%s: got %q, %v; want %q", ref, got, err, host)
		}
	}
	for _, bad := range []string{"", "Nginx", "ghcr.io/acme/api:", "a b", "ghcr.io/acme/api; rm -rf /", "--help", "https://ghcr.io/acme/api"} {
		if _, err := ValidateImageRef(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestValidateTargetURL(t *testing.T) {
	if h, err := ValidateTargetURL("https://App.Example.com:8443/base"); err != nil || h != "app.example.com" {
		t.Errorf("got %q %v", h, err)
	}
	for _, bad := range []string{"", "ftp://x", "https://", "https://user:pw@x.example", "https://x.example/#frag", "javascript:alert(1)", "x.example"} {
		if _, err := ValidateTargetURL(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestValidateAPISpec(t *testing.T) {
	good := "openapi: 3.0.0\ninfo: {title: t, version: '1'}\nservers: [{url: 'https://api.example.com/v1'}]\npaths:\n  /orders: {get: {responses: {'200': {description: ok}}}}\n"
	if err := ValidateAPISpec(good, "api.example.com"); err != nil {
		t.Fatal(err)
	}
	// JSON is YAML.
	if err := ValidateAPISpec(`{"swagger":"2.0","host":"api.example.com:443","paths":{"/a":{}}}`, "api.example.com"); err != nil {
		t.Error(err)
	}
	cases := map[string]string{
		"other host":  strings.Replace(good, "api.example.com", "evil.example", 1),
		"relative":    strings.Replace(good, "https://api.example.com/v1", "/v1", 1),
		"no servers":  "openapi: 3.0.0\npaths: {/a: {}}\n",
		"no paths":    "openapi: 3.1.0\nservers: [{url: 'https://api.example.com'}]\n",
		"not openapi": "hello: world\n",
		"invalid":     "openapi: [\n",
	}
	for name, spec := range cases {
		if err := ValidateAPISpec(spec, "api.example.com"); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestTargetFieldsApply(t *testing.T) {
	name, ref := "API", "https://api.example.com"
	spec := "openapi: 3.0.0\nservers: [{url: 'https://api.example.com'}]\npaths: {/a: {}}\n"
	f := targetFields{kind: "api"}
	if err := f.apply(targetRequest{Name: &name, Reference: &ref, APISpec: &spec}); err != nil || f.egress != "api.example.com" || f.authType != "none" {
		t.Fatalf("%v %+v", err, f)
	}
	hdr, hname := "header", "X-API-Key"
	if err := f.apply(targetRequest{AuthType: &hdr, AuthHeaderName: &hname}); err != nil || f.authHeader != "X-API-Key" {
		t.Errorf("header auth: %v", err)
	}
	bad := "X API Key\r\nInjected: 1"
	if err := f.apply(targetRequest{AuthHeaderName: &bad}); err == nil {
		t.Error("header names with spaces or newlines must be rejected")
	}
	basic, colon := "basic", "bot:admin"
	if err := (&targetFields{kind: "url", name: "x", reference: "https://x.example"}).apply(targetRequest{AuthType: &basic, AuthUsername: &colon}); err == nil {
		t.Error("usernames with a colon must be rejected")
	}
	img := targetFields{kind: "image"}
	iname, iref := "img", "ghcr.io/acme/api:1"
	if err := img.apply(targetRequest{Name: &iname, Reference: &iref, AuthType: &hdr, AuthHeaderName: &hname}); err == nil {
		t.Error("images only support basic authentication")
	}
	cfg := TargetConfig{RateLimit: 500}
	if err := (&targetFields{kind: "url", name: "x", reference: "https://x.example"}).apply(targetRequest{Config: &cfg}); err == nil {
		t.Error("rate limit above 100 must be rejected")
	}
}

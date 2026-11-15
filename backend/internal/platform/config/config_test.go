package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func validAPIEnv() map[string]string {
	return map[string]string{
		"PATHOS_ENV":                "production",
		"PATHOS_DATABASE_URL":       "postgres://x",
		"PATHOS_REDIS_URL":          "redis://x",
		"PATHOS_MASTER_KEY":         testKey,
		"PATHOS_PUBLIC_URL":         "https://pathos.example.com/",
		"PATHOS_OIDC_ISSUER":        "https://pathos.example.com/auth/realms/pathos",
		"PATHOS_OIDC_CLIENT_SECRET": "s3cret",
	}
}

func TestLoadValid(t *testing.T) {
	c, err := LoadFrom(env(validAPIEnv()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.PublicURL.String() != "https://pathos.example.com" {
		t.Errorf("public URL not normalized: %s", c.PublicURL)
	}
	if c.OIDC.DiscoveryURL != c.OIDC.Issuer {
		t.Errorf("discovery URL should default to issuer")
	}
	if c.CurrentKeyVersion() != 1 {
		t.Errorf("want key version 1, got %d", c.CurrentKeyVersion())
	}
}

func TestLoadCollectsAllErrors(t *testing.T) {
	_, err := LoadFrom(env(map[string]string{"PATHOS_ROLE": "bogus", "PATHOS_ENV": "staging"}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"PATHOS_ENV", "PATHOS_ROLE", "PATHOS_DATABASE_URL", "PATHOS_MASTER_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s: %v", want, err)
		}
	}
}

func TestProductionRequiresHTTPS(t *testing.T) {
	m := validAPIEnv()
	m["PATHOS_PUBLIC_URL"] = "http://pathos.example.com"
	if _, err := LoadFrom(env(m)); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected https error, got %v", err)
	}
	m["PATHOS_ENV"] = "development"
	if _, err := LoadFrom(env(m)); err != nil {
		t.Fatalf("development should allow http: %v", err)
	}
}

func TestMasterKeyValidation(t *testing.T) {
	m := validAPIEnv()
	m["PATHOS_MASTER_KEY"] = base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := LoadFrom(env(m)); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("expected key length error, got %v", err)
	}

	m["PATHOS_MASTER_KEY"] = "v3:" + testKey
	m["PATHOS_MASTER_KEYS_PREVIOUS"] = "v1:" + testKey + ", v2:" + testKey
	c, err := LoadFrom(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if c.CurrentKeyVersion() != 3 || len(c.MasterKeys) != 3 {
		t.Fatalf("want 3 keys with current v3, got %d keys, current v%d", len(c.MasterKeys), c.CurrentKeyVersion())
	}

	m["PATHOS_MASTER_KEYS_PREVIOUS"] = "v4:" + testKey
	if _, err := LoadFrom(env(m)); err == nil {
		t.Fatal("previous key with higher version must be rejected")
	}
}

func TestFileVariables(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	if err := os.WriteFile(p, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := validAPIEnv()
	delete(m, "PATHOS_OIDC_CLIENT_SECRET")
	m["PATHOS_OIDC_CLIENT_SECRET_FILE"] = p
	c, err := LoadFrom(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if c.OIDC.ClientSecret != "from-file" {
		t.Fatalf("want secret from file, got %q", c.OIDC.ClientSecret)
	}
}

func TestJobsRoleDoesNotNeedWebSettings(t *testing.T) {
	base := map[string]string{
		"PATHOS_ROLE":         "jobs",
		"PATHOS_DATABASE_URL": "postgres://x",
		"PATHOS_MASTER_KEY":   testKey,
	}
	if _, err := LoadFrom(env(base)); err == nil || !strings.Contains(err.Error(), "PATHOS_PUBLIC_URL") {
		t.Fatalf("jobs role needs the public URL for notification links, got %v", err)
	}
	base["PATHOS_PUBLIC_URL"] = "https://pathos.example.com/"
	c, err := LoadFrom(env(base))
	if err != nil {
		t.Fatalf("jobs role should not require OIDC/Redis: %v", err)
	}
	if c.PublicURL.String() != "https://pathos.example.com" {
		t.Fatalf("public URL not normalized: %s", c.PublicURL)
	}
}

func TestSchedulerRoleNeedsOnlyTheDatabase(t *testing.T) {
	_, err := LoadFrom(env(map[string]string{
		"PATHOS_ROLE":         "scheduler",
		"PATHOS_DATABASE_URL": "postgres://x",
		"PATHOS_MASTER_KEY":   testKey,
	}))
	if err != nil {
		t.Fatalf("scheduler role: %v", err)
	}
}

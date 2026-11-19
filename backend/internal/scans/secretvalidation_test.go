package scans

import (
	"strings"
	"testing"
	"time"
)

func TestValidateSecretSettings(t *testing.T) {
	got, err := validateSecretSettings([]string{"slack", "github", "github"}, 2, 10)
	if err != nil || strings.Join(got, ",") != "github,slack" {
		t.Fatalf("got %v %v", got, err)
	}
	if got, err := validateSecretSettings([]string{}, 1, 1); err != nil || len(got) != 0 {
		t.Fatalf("empty list turns validation off: %v %v", got, err)
	}
	for _, c := range []struct {
		providers []string
		rate, max int
	}{{[]string{"pypi"}, 1, 1}, {[]string{"nope"}, 1, 1}, {nil, 0, 1}, {nil, 11, 1}, {nil, 1, 0}, {nil, 1, 501}} {
		if _, err := validateSecretSettings(c.providers, c.rate, c.max); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestNormalizeVerdict(t *testing.T) {
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	ok := SecretVerdictInput{Fingerprints: []string{"fp"}, Provider: "github", Status: "active", Identity: "user\x00 octo", Detail: "ok", CheckedAt: now}
	v, keep := normalizeVerdict(ok, []string{"github"}, now)
	if !keep || v.Status != "active" || v.Identity != "user octo" {
		t.Fatalf("got %+v %v", v, keep)
	}
	// A provider that is not enabled cannot produce a verdict.
	v, keep = normalizeVerdict(ok, []string{"slack"}, now)
	if !keep || v.Status != "not_checked" || v.Identity != "" || !strings.Contains(v.Detail, "not enabled") {
		t.Fatalf("fail closed: %+v", v)
	}
	// Identities are kept for active verdicts only.
	in := ok
	in.Status = "inactive"
	if v, _ := normalizeVerdict(in, []string{"github"}, now); v.Identity != "" {
		t.Errorf("identity on inactive: %q", v.Identity)
	}
	// Clock skew is replaced by the server time.
	in = ok
	in.CheckedAt = now.Add(48 * time.Hour)
	if v, _ := normalizeVerdict(in, []string{"github"}, now); !v.CheckedAt.Equal(now) {
		t.Errorf("checked_at %v", v.CheckedAt)
	}
	for _, bad := range []SecretVerdictInput{
		{Fingerprints: []string{"fp"}, Status: "valid"},
		{Fingerprints: nil, Status: "active", Provider: "github"},
		{Fingerprints: []string{"fp"}, Status: "active", Provider: "unknown"},
		{Fingerprints: []string{strings.Repeat("x", 200)}, Status: "error"},
	} {
		if _, keep := normalizeVerdict(bad, []string{"github"}, now); keep {
			t.Errorf("%+v kept", bad)
		}
	}
}

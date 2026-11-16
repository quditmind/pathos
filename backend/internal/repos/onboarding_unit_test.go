package repos

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/scm"
)

func TestSafeReturnTo(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "/admin/scm",
		"/repositories/import":   "/repositories/import",
		"//evil.example/x":       "/admin/scm",
		"https://evil.example/x": "/admin/scm",
		"/\\evil.example":        "/admin/scm",
		"/x\r\nSet-Cookie: a=b":  "/admin/scm",
		"relative/path":          "/admin/scm",
		"/\t/evil.example":       "/admin/scm",
		"/\x7f":                  "/admin/scm",
		"/repositories?x=1":      "/repositories?x=1",
	} {
		if got := safeReturnTo(in); got != want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUploadFormat(t *testing.T) {
	for name, want := range map[string]string{"a.zip": "zip", "A.TAR.GZ": "tar.gz", "b.tgz": "tar.gz", "c.tar": "tar", "d.rar": "", "e.zip.exe": ""} {
		got, ok := uploadFormat(name)
		if got != want || ok != (want != "") {
			t.Errorf("uploadFormat(%q) = %q %v", name, got, ok)
		}
	}
}

func TestUploadParts(t *testing.T) {
	u := SourceUpload{Size: 20<<20 + 5, ChunkSize: 8 << 20}
	if u.parts() != 3 || u.partSize(0) != 8<<20 || u.partSize(2) != 4<<20+5 {
		t.Errorf("parts=%d last=%d", u.parts(), u.partSize(2))
	}
	exact := SourceUpload{Size: 16 << 20, ChunkSize: 8 << 20}
	if exact.parts() != 2 || exact.partSize(1) != 8<<20 {
		t.Errorf("exact multiple: %d %d", exact.parts(), exact.partSize(1))
	}
}

func TestClassifyProviderError(t *testing.T) {
	cases := []struct {
		err       error
		code      string
		transient bool
		attention bool
	}{
		{fmt.Errorf("x: %w", scm.ErrNotFound), "repository_not_found", false, false},
		{scm.ErrForbidden, "permission_denied", false, false},
		{scm.ErrTokenExpired, "token_expired", false, true},
		{scm.ErrRateLimited, "provider_unavailable", true, false},
		{errors.New("boom"), "provider_error", true, false},
	}
	for _, c := range cases {
		var ie *importError
		if !errors.As(classifyProviderError(c.err), &ie) || ie.Code != c.code || ie.Transient != c.transient || ie.Attention != c.attention {
			t.Errorf("%v → %+v", c.err, ie)
		}
	}
}

func TestMetadataApplyAndRequired(t *testing.T) {
	v := defaultValues()
	owner := uuid.New()
	desc, color := "  Billing  ", " #ABCDEF "
	changed := AssetMetadata{Description: &desc, Color: &color, BusinessOwnerID: optUUID{Set: true, Val: &owner},
		ComplianceScopes: &[]string{"gdpr", "gdpr", " pci_dss "}}.Apply(&v)
	if v.Description != "Billing" || v.Color != "#abcdef" || *v.BusinessOwnerID != owner || len(v.ComplianceScopes) != 2 || len(changed) != 4 {
		t.Errorf("apply: %+v %v", v, changed)
	}
	ap := &assetPolicy{Required: []string{"technical_owner"}}
	if !ap.required("business_owner") || !ap.required("technical_owner") || ap.required("cost_centre") {
		t.Error("required-field policy")
	}
	if !v.empty("technical_owner_id") || v.empty("business_owner_id") || !v.empty("internet_exposure") {
		t.Error("empty checks")
	}
}

func TestTopLanguages(t *testing.T) {
	got := topLanguages(map[string]int64{"Go": 10, "TypeScript": 30, "Shell": 1, "YAML": 30}, 2)
	if len(got) != 2 || got[0] != "TypeScript" || got[1] != "YAML" {
		t.Errorf("topLanguages = %v", got)
	}
}

func TestNormalizeCloneURL(t *testing.T) {
	cases := []struct {
		provider, base, clone, want string
		ok                          bool
	}{
		{"github", "https://api.github.com", "https://github.com/acme/x.git", "https://github.com/acme/x.git", true},
		{"github_enterprise", "https://ghe.acme.test/api/v3", "https://ghe.acme.test/acme/x.git", "https://ghe.acme.test/acme/x.git", true},
		{"github_enterprise", "https://ghe.acme.test/api/v3", "https://evil.example/acme/x.git", "", false},
		{"gitlab", "https://gitlab.com", "https://gitlab.com/g/x.git", "https://gitlab.com/g/x.git", true},
		{"gitlab", "https://gitlab.acme.test", "http://gitlab.acme.test/g/x.git", "", false},
		{"bitbucket", "https://api.bitbucket.org/2.0", "https://bitbucket.org/ws/x.git", "https://bitbucket.org/ws/x.git", true},
		{"azure_devops", "https://dev.azure.com/acme", "https://acme@dev.azure.com/acme/p/_git/x", "https://dev.azure.com/acme/p/_git/x", true},
		{"azure_devops_server", "https://ado.acme.test/coll", "https://ado.acme.test:8443/coll/_git/x", "", false},
		{"github", "https://api.github.com", "https://github.com/x.git?token=1", "", false},
	}
	for _, c := range cases {
		got, err := normalizeCloneURL(c.provider, c.base, c.clone)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("%s %s: got %q, %v", c.provider, c.clone, got, err)
		}
	}
}

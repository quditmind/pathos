package tenant

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestSettings(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	bg := context.Background()
	cases := []struct {
		name        string
		ctx         context.Context
		def         uuid.UUID
		org, bypass string
	}{
		{"none fails closed", bg, uuid.Nil, "", "off"},
		{"default org for single-organization pools", bg, a, a.String(), "off"},
		{"org", WithOrg(bg, b), a, b.String(), "off"},
		{"system", WithSystem(bg), a, "", "on"},
		{"org narrows system", WithOrg(WithSystem(bg), b), uuid.Nil, b.String(), "off"},
		{"system after org widens explicitly", WithSystem(WithOrg(bg, b)), uuid.Nil, "", "on"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			org, bypass := Settings(c.ctx, c.def)
			if org != c.org || bypass != c.bypass {
				t.Fatalf("got (%q, %q), want (%q, %q)", org, bypass, c.org, c.bypass)
			}
		})
	}
	if _, ok := OrgFrom(WithSystem(bg)); ok {
		t.Fatal("system context must not report an organization")
	}
	if IsSystem(WithOrg(WithSystem(bg), a)) {
		t.Fatal("an organization scope inside system work must not bypass row-level security")
	}
}

package tenancy

import (
	"slices"
	"testing"
)

func TestSlugsFromClaim(t *testing.T) {
	cases := []struct {
		name   string
		claim  any
		prefix string
		want   []string
	}{
		{"keycloak group paths", []any{"/pathos/acme", "/pathos/globex", "/other/x", "/pathos/Bad Slug"}, "/pathos/", []string{"acme", "globex"}},
		{"single string", "/pathos/acme", "/pathos/", []string{"acme"}},
		{"plain slugs without prefix", []any{"acme", "globex", "acme"}, "-", []string{"acme", "globex"}},
		{"empty prefix", []string{"acme"}, "", []string{"acme"}},
		{"missing claim", nil, "/pathos/", nil},
		{"wrong type", 42, "/pathos/", nil},
		{"nested path is not a slug", []any{"/pathos/acme/team"}, "/pathos/", nil},
		{"case folded", []any{"/pathos/ACME"}, "/pathos/", []string{"acme"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SlugsFromClaim(c.claim, c.prefix); !slices.Equal(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
	many := make([]any, 500)
	for i := range many {
		many[i] = "/pathos/o" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))
	}
	if n := len(SlugsFromClaim(many, "/pathos/")); n > 100 {
		t.Fatalf("claim mapping must be bounded, got %d", n)
	}
}

func TestValidSlug(t *testing.T) {
	for s, ok := range map[string]bool{"acme": true, "acme-eu-1": true, "": false, "Acme": false, "a_b": false, "../x": false} {
		if ValidSlug(s) != ok {
			t.Errorf("ValidSlug(%q) = %v", s, !ok)
		}
	}
}

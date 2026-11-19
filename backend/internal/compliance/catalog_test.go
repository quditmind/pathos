package compliance

import (
	"regexp"
	"slices"
	"testing"

	"pathos/internal/scanners"
)

func TestCatalog(t *testing.T) {
	cats := scanners.FindingCategories
	cwe := regexp.MustCompile(`^CWE-[0-9]+$`)
	seen := map[string]bool{}
	for _, f := range Frameworks {
		if seen[f.Key] || f.Name == "" || len(f.Controls) == 0 {
			t.Errorf("framework %q", f.Key)
		}
		seen[f.Key] = true
		ids := map[string]bool{}
		for _, c := range f.Controls {
			if ids[c.ID] || c.Title == "" {
				t.Errorf("%s: control %q duplicated or untitled", f.Key, c.ID)
			}
			ids[c.ID] = true
			if len(c.Categories) == 0 && len(c.CWE) == 0 && !c.Malicious {
				t.Errorf("%s %s maps nothing", f.Key, c.ID)
			}
			for _, x := range c.Categories {
				if !slices.Contains(cats, x) {
					t.Errorf("%s %s: unknown category %s", f.Key, c.ID, x)
				}
			}
			for _, x := range c.CWE {
				if !cwe.MatchString(x) {
					t.Errorf("%s %s: bad CWE %s", f.Key, c.ID, x)
				}
			}
		}
	}
	if _, c, ok := LookupControl("pci_dss_4:6.3.3"); !ok || !c.Malicious {
		t.Error("lookup")
	}
	if _, _, ok := LookupControl("pci_dss_4:9.9"); ok {
		t.Error("unknown control")
	}
	var args []any
	ph := func(v any) string { args = append(args, v); return "$x" }
	if got := MatchSQL(Control{Categories: []string{"sca"}, Malicious: true}, ph); got != "(f.category = ANY($x::text[]) OR f.malicious)" {
		t.Errorf("match: %s", got)
	}
}

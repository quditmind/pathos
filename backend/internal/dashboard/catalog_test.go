package dashboard

import (
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"pathos/internal/authz"
)

func TestKPICatalog(t *testing.T) {
	if len(KPIs) != 24 {
		t.Fatalf("dashboard has a 6x4 grid: want 24 KPIs, got %d", len(KPIs))
	}
	seen := map[string]bool{}
	for _, k := range KPIs {
		if seen[k.Key] {
			t.Errorf("duplicate KPI %s", k.Key)
		}
		seen[k.Key] = true
		if !slices.Contains(Groups, k.Group) {
			t.Errorf("KPI %s has unknown group %q", k.Key, k.Group)
		}
		if _, ok := authz.LookupPermission(k.Requires); !ok {
			t.Errorf("KPI %s requires unknown permission %s", k.Key, k.Requires)
		}
		if !strings.HasPrefix(k.Drill, "/") {
			t.Errorf("KPI %s drill-down must be an app route", k.Key)
		}
		if k.Phase < 1 || k.Phase > 8 {
			t.Errorf("KPI %s has invalid phase %d", k.Key, k.Phase)
		}
	}
	for _, c := range Charts {
		if _, ok := authz.LookupPermission(c.Requires); !ok {
			t.Errorf("chart %s requires unknown permission", c.Key)
		}
	}
}

func TestParseFilters(t *testing.T) {
	ok := []string{"", "days=7", "days=365&region_id=0194a3f2-0000-7000-8000-000000000000"}
	for _, q := range ok {
		if _, err := ParseFilters(httptest.NewRequest("GET", "/?"+q, nil)); err != nil {
			t.Errorf("%q: %v", q, err)
		}
	}
	bad := []string{"days=3", "days=abc", "region_id=nope", "business_unit_id=1"}
	for _, q := range bad {
		if _, err := ParseFilters(httptest.NewRequest("GET", "/?"+q, nil)); err == nil {
			t.Errorf("%q should be rejected", q)
		}
	}
}

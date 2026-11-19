package scans

import (
	"net/url"
	"slices"
	"strings"
	"testing"

	"pathos/internal/authz"
	"pathos/migrations"
)

// The findings list is fast only while its ORDER BY expressions are the
// ones indexed by migration 00038 (PostgreSQL matches index expressions
// structurally): changing sevRank or riskRank needs a new index.
func TestFindingsListRanksAreIndexed(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00038_findings_list_indexes.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for name, expr := range map[string]string{"sevRank": sevRank, "riskRank": riskRank} {
		if !strings.Contains(sql, "("+strings.ReplaceAll(expr, "f.", "")+")") {
			t.Errorf("%s (%s) is not the expression indexed by 00038", name, expr)
		}
	}
	// The partial indexes cover the list's default filter (FindingsWhere).
	where, _, err := FindingsWhere(&authz.Principal{Grants: []authz.Grant{{Permission: authz.PermFindingsRead,
		Scope: authz.Scope{Type: authz.ScopeOrganization}}}}, url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(where, "f.status IN ('open', 'in_progress', 'needs_review')") ||
		!strings.Contains(sql, "WHERE status IN ('open', 'in_progress', 'needs_review')") {
		t.Errorf("the partial index predicate must match the default open filter: %v", where)
	}
}

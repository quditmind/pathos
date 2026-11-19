package inventory

import (
	"slices"
	"testing"

	"github.com/google/uuid"
)

func TestSourceKeyNormalisesEquivalentLocations(t *testing.T) {
	same := []string{
		"https://github.com/Acme/Payments-API",
		"https://github.com/acme/payments-api.git",
		"https://user:token@github.com/acme/payments-api/",
		"git@github.com:acme/payments-api.git",
		"ssh://git@github.com:22/acme/payments-api.git",
		"github.com/acme/payments-api",
	}
	for _, u := range same {
		if k := SourceKey(u, "", "x/y"); k != "github.com/acme/payments-api" {
			t.Errorf("SourceKey(%q) = %q", u, k)
		}
	}
	if k := SourceKey("https://git.example:8443/team/app", "", ""); k != "git.example:8443/team/app" {
		t.Errorf("custom port kept: %q", k)
	}
	if k := SourceKey("", "gitlab.example", "Group/Sub/App.git"); k != "gitlab.example/group/sub/app" {
		t.Errorf("fallback: %q", k)
	}
	if k := SourceKey("", "", ""); k != "" {
		t.Errorf("empty: %q", k)
	}
	if SourceKey("https://github.com/acme/a", "", "") == SourceKey("https://github.com/acme/b", "", "") {
		t.Error("different repositories must differ")
	}
}

func TestNamespaceAndHost(t *testing.T) {
	if Namespace("acme/payments-api") != "acme" || Namespace("Group/Sub/repo") != "group/sub" || Namespace("solo") != "" {
		t.Error("Namespace")
	}
	if HostOf("https://dev.azure.com/org/proj/_git/repo") != "dev.azure.com" {
		t.Error("HostOf")
	}
}

func TestNameSimilarity(t *testing.T) {
	cases := []struct {
		a, b string
		min  float64
		max  float64
	}{
		{"payments-api", "Payments Platform", 0.6, 1},
		{"payments-api", "payments", 0.99, 1},
		{"hr-portal", "HR Portal", 0.99, 1},
		{"paymnets", "payments", 0.7, 0.99},
		{"website", "Payments Platform", 0, 0.5},
		{"", "x", 0, 0},
	}
	for _, c := range cases {
		got := NameSimilarity(c.a, c.b)
		if got < c.min || got > c.max {
			t.Errorf("NameSimilarity(%q, %q) = %.2f, want [%.2f, %.2f]", c.a, c.b, got, c.min, c.max)
		}
	}
}

func TestSuggestName(t *testing.T) {
	if got := suggestName("acme/payments-api"); got != "Payments API" {
		t.Errorf("got %q", got)
	}
	if got := suggestName("hr_portal"); got != "Hr Portal" {
		t.Errorf("got %q", got)
	}
}

func TestDetectFromPackages(t *testing.T) {
	fw, rt := DetectFromPackages([]string{
		"pkg:npm/react@18.3.1", "pkg:npm/react-dom@18.3.1", "pkg:npm/%40angular/core@17.0.0",
		"pkg:golang/github.com/go-chi/chi/v5@v5.0.12", "pkg:maven/org.springframework.boot/spring-boot-starter-web@3.2.0",
		"pkg:nuget/Microsoft.AspNetCore.App@8.0.0", "pkg:pypi/django@5.0", "not-a-purl",
	})
	wantFw := []string{"ASP.NET Core", "Angular", "Django", "React", "Spring Boot", "chi"}
	if !slices.Equal(fw, wantFw) {
		t.Errorf("frameworks = %v, want %v", fw, wantFw)
	}
	wantRt := []string{".NET", "Go", "JVM", "Node.js", "Python"}
	if !slices.Equal(rt, wantRt) {
		t.Errorf("runtimes = %v, want %v", rt, wantRt)
	}
	if fw, _ := DetectFromPackages([]string{"pkg:npm/nextjs-helper@1.0.0", "pkg:npm/vue-router@4"}); len(fw) != 0 {
		t.Errorf("prefix look-alikes must not match: %v", fw)
	}
}

func TestTopLanguagesAndRuntimes(t *testing.T) {
	got := TopLanguages(map[string]int64{"Go": 9000, "TypeScript": 4000, "Shell": 50, "HTML": 300})
	if !slices.Equal(got, []string{"Go", "TypeScript", "HTML"}) {
		t.Errorf("TopLanguages = %v", got)
	}
	if rt := RuntimesFromLanguages([]string{"Go", "TypeScript", "HTML"}); !slices.Equal(rt, []string{"Go", "Node.js"}) {
		t.Errorf("RuntimesFromLanguages = %v", rt)
	}
}

func TestGlobRegexp(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"acme/payments-*", "acme/payments-api", true},
		{"acme/payments-*", "acme/payments/api", false},
		{"platform/**", "platform/core/infra", true},
		{"*/infra-?", "team/infra-1", true},
		{"*/infra-?", "team/infra-10", false},
		{"ACME/*", "acme/x", true},
		{"a.b/*", "axb/c", false},
	}
	for _, c := range cases {
		re, err := GlobRegexp(c.pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := re.MatchString(c.name); got != c.want {
			t.Errorf("%q ~ %q = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestProgress(t *testing.T) {
	cat := uuid.New()
	a := Application{OnboardingStatus: "draft", Criticality: "high", Environment: "production", Languages: []string{"Go"},
		InternetExposure: "unknown", ApplicationType: "api"}
	a.ComputeProgress([]string{"owner", "criticality", "languages", "internet_exposure", "environment"},
		[]mandatoryCategory{{ID: cat, Name: "Team", Types: []string{"api"}}, {ID: uuid.New(), Name: "Mobile only", Types: []string{"mobile_application"}}})
	if a.Progress.Filled != 3 || a.Progress.Required != 5 || a.Progress.Label != "Onboarding: 3 of 5 fields" {
		t.Errorf("progress = %+v", a.Progress)
	}
	if !slices.Equal(a.Progress.Missing, []string{"owner", "internet_exposure"}) {
		t.Errorf("missing = %v", a.Progress.Missing)
	}
	if len(a.Progress.MissingTagCategories) != 1 || a.Progress.MissingTagCategories[0].Name != "Team" {
		t.Errorf("tag categories = %v", a.Progress.MissingTagCategories)
	}
	a.Tags = []AppTag{{CategoryID: cat}}
	a.OnboardingStatus = "complete"
	a.ComputeProgress(nil, []mandatoryCategory{{ID: cat, Name: "Team", Types: []string{"all"}}})
	if a.Progress.Label != "Registered" || len(a.Progress.MissingTagCategories) != 0 {
		t.Errorf("complete = %+v", a.Progress)
	}
	// Every listed field is a known field with a label.
	for _, f := range ApplicationFields {
		if FieldLabels[f] == "" {
			t.Errorf("no label for %s", f)
		}
	}
}

func TestValidateRule(t *testing.T) {
	ok := Rule{Name: "PCI", TargetType: "application", Condition: "classification", Field: "compliance_scopes", Value: "pci_dss"}
	if err := validateRule(ok); err != nil {
		t.Fatal(err)
	}
	bad := []Rule{
		{Name: "", TargetType: "application", Condition: "classification", Field: "environment", Value: "x"},
		{Name: "x", TargetType: "repository", Condition: "classification", Field: "environment", Value: "x"},
		{Name: "x", TargetType: "application", Condition: "classification", Field: "nope", Value: "x"},
		{Name: "x", TargetType: "repository", Condition: "path_pattern", Field: "environment", Value: "a/*"},
		{Name: "x", TargetType: "repository", Condition: "telepathy", Value: "a"},
		{Name: "x", TargetType: "repository", Condition: "repository_topic", Value: ""},
	}
	for i, r := range bad {
		if validateRule(r) == nil {
			t.Errorf("case %d should be invalid: %+v", i, r)
		}
	}
}

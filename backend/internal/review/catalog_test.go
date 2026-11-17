package review

import (
	"slices"
	"testing"
)

func TestCheckUpload(t *testing.T) {
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 16)...)
	cases := []struct {
		name string
		head []byte
		ok   bool
	}{
		{"shot.png", png, true},
		{"shot.PNG", png, true},
		{"shot.jpg", png, false},                 // content does not match
		{"payload.svg", []byte("<svg/>"), false}, // active content
		{"page.html", []byte("<html>"), false},
		{"run.exe", []byte("MZ"), false},
		{"notes.txt", []byte("hello"), true},
		{"bin.txt", []byte("a\x00b"), false},
		{"req.http", []byte("GET / HTTP/1.1"), true},
		{"report.pdf", []byte("%PDF-1.7\n"), true},
		{"fake.pdf", []byte("hello"), false},
	}
	for _, c := range cases {
		_, err := CheckUpload(c.name, c.head)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
	if got := cleanFileName(`..\..\evil"name<>.png`); got != "evilname.png" {
		t.Errorf("cleanFileName: %q", got)
	}
}

func TestOWASPFor(t *testing.T) {
	if got := OWASPFor([]string{"CWE-89"}, "sast"); !slices.Equal(got, []string{"A03:2021 Injection"}) {
		t.Errorf("CWE-89: %v", got)
	}
	if got := OWASPFor([]string{"cwe-918", "CWE-22"}, "sast"); len(got) != 2 {
		t.Errorf("multiple: %v", got)
	}
	if got := OWASPFor(nil, "sca"); !slices.Equal(got, []string{"A06:2021 Vulnerable and Outdated Components"}) {
		t.Errorf("sca: %v", got)
	}
	if got := OWASPFor([]string{"CWE-99999"}, "sast"); len(got) != 0 {
		t.Errorf("unknown CWE: %v", got)
	}
}

func TestSettingsValidation(t *testing.T) {
	ok := Settings{AutoMinSeverity: "medium", AssignmentStrategy: "manual", EvidenceMaxMB: 10,
		RequiredFields: []string{"reachable", "attack_scenario"}, PriorityBySeverity: map[string]string{"critical": "p1"}, SLADays: map[string]int{"high": 5}}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	bad := []func(s *Settings){
		func(s *Settings) { s.RequiredFields = []string{"nope"} },
		func(s *Settings) { s.AssignmentStrategy = "least_loaded" }, // empty pool
		func(s *Settings) { s.PriorityBySeverity = map[string]string{"critical": "p9"} },
		func(s *Settings) { s.SLADays = map[string]int{"high": -1} },
		func(s *Settings) { s.IndependentReviewDispositions = []string{"needs_more_information"} },
		func(s *Settings) { s.AutoScanners = []string{"not-a-scanner"} },
		func(s *Settings) { s.EvidenceMaxMB = 0 },
	}
	for i, f := range bad {
		s := ok
		f(&s)
		if err := s.validate(); err == nil {
			t.Errorf("case %d: expected a validation error", i)
		}
	}
}

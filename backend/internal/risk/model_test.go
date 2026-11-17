package risk

import (
	"strings"
	"testing"
)

func f(v float64) *float64 { return &v }

func TestComputeOrdering(t *testing.T) {
	w := Default()
	worst := Compute(Input{Status: "open", Severity: "critical", KEV: true, Criticality: "critical", Exposure: "yes", Reachability: "reachable",
		Confidence: "high", FixAvailable: true}, w)
	if worst.Score != 100 {
		t.Errorf("worst case should cap at 100, got %v", worst.Score)
	}
	neutralKEV := Compute(Input{Status: "open", Severity: "critical", KEV: true}, w)
	neutral := Compute(Input{Status: "open", Severity: "critical"}, w)
	if Band(neutralKEV.Score) != "critical" || Band(neutral.Score) != "high" {
		t.Errorf("calibration: critical+KEV %v (%s), critical %v (%s)", neutralKEV.Score, Band(neutralKEV.Score), neutral.Score, Band(neutral.Score))
	}
	low := Compute(Input{Status: "open", Severity: "low", Criticality: "medium", Exposure: "no", Confidence: "unknown"}, w)
	if low.Score <= 0 || low.Score > 15 {
		t.Errorf("low finding: %v", low.Score)
	}
	// Exploit signals raise risk at equal severity.
	plain := Compute(Input{Status: "open", Severity: "high"}, w)
	epss := Compute(Input{Status: "open", Severity: "high", EPSSPercentile: f(0.97)}, w)
	kev := Compute(Input{Status: "open", Severity: "high", KEV: true}, w)
	if !(plain.Score < epss.Score && epss.Score <= kev.Score) {
		t.Errorf("plain %v < epss %v <= kev %v", plain.Score, epss.Score, kev.Score)
	}
	// A low EPSS lowers likelihood below "unknown", but never to zero.
	lowEPSS := Compute(Input{Status: "open", Severity: "high", EPSSPercentile: f(0.01)}, w)
	if lowEPSS.Score >= plain.Score || lowEPSS.Score <= 0 {
		t.Errorf("low EPSS %v vs unknown %v", lowEPSS.Score, plain.Score)
	}
	// Context matters.
	internal := Compute(Input{Status: "open", Severity: "high", Exposure: "no", Criticality: "low"}, w)
	exposed := Compute(Input{Status: "open", Severity: "high", Exposure: "yes", Criticality: "critical"}, w)
	if internal.Score >= exposed.Score {
		t.Errorf("exposure/criticality: %v vs %v", internal.Score, exposed.Score)
	}
	// Not reachable lowers but does not hide.
	nr := Compute(Input{Status: "open", Severity: "critical", Reachability: "not_reachable"}, w)
	if nr.Score <= 0 {
		t.Error("not reachable must not hide a finding")
	}
}

func TestComputeHumanAndClosed(t *testing.T) {
	w := Default()
	for _, st := range []string{"fixed", "false_positive", "accepted_risk"} {
		if r := Compute(Input{Status: st, Severity: "critical", KEV: true}, w); r.Score != 0 || r.Reason == "" {
			t.Errorf("%s: %+v", st, r)
		}
	}
	scanner := Compute(Input{Status: "open", Severity: "critical"}, w)
	human := Compute(Input{Status: "open", Severity: "critical", HumanSeverity: "low"}, w)
	if human.Score >= scanner.Score || human.Factors[0].Label != "Human-assessed severity" {
		t.Errorf("human-assessed severity wins: %v vs %v", human, scanner)
	}
	controls := Compute(Input{Status: "open", Severity: "high", Compensating: true}, w)
	if controls.Score >= Compute(Input{Status: "open", Severity: "high"}, w).Score {
		t.Error("compensating controls lower risk")
	}
	cvss := Compute(Input{Status: "open", Severity: "medium", CVSS: f(9.8)}, w)
	if cvss.Base != 9.8 || !strings.Contains(cvss.Factors[0].Label, "CVSS") {
		t.Errorf("CVSS preferred: %+v", cvss)
	}
	w.UseCVSS = false
	if r := Compute(Input{Status: "open", Severity: "medium", CVSS: f(9.8)}, w); r.Base != 5 {
		t.Errorf("CVSS disabled: %+v", r)
	}
}

func TestValidate(t *testing.T) {
	w := Weights{KEV: 1, ExploitAvailable: 0.8, EPSSWeight: 1, LikelihoodUnknown: 0.5, HumanConfirmed: 1.1, CompensatingControls: 0.7, FixAvailable: 1}
	if err := w.Validate(); err != nil || w.Severity["critical"] != 9.5 {
		t.Fatalf("missing maps are filled: %v %v", err, w.Severity)
	}
	bad := []func(*Weights){
		func(w *Weights) { w.Severity["bogus"] = 1 },
		func(w *Weights) { w.Exposure["yes"] = 10 },
		func(w *Weights) { w.KEV = 2 },
		func(w *Weights) { w.LikelihoodUnknown = 0 },
		func(w *Weights) { w.FixAvailable = 0 },
	}
	for i, mut := range bad {
		x := Default()
		mut(&x)
		if err := x.Validate(); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	if Band(85) != "critical" || Band(0) != "none" || Band(40) != "medium" || Band(55) != "high" {
		t.Error("bands")
	}
}

func TestMaliciousPackages(t *testing.T) {
	w := Default()
	base := Input{Status: "open", Severity: "high", Criticality: "medium", Exposure: "unknown", Reachability: "not_reachable", Confidence: "high"}
	plain := Compute(base, w)
	mal := base
	mal.Malicious = true
	r := Compute(mal, w)
	if r.Score <= plain.Score {
		t.Fatalf("malware raises risk: %v <= %v", r.Score, plain.Score)
	}
	var reach, like string
	for _, f := range r.Factors {
		switch f.Key {
		case "reachability":
			reach = f.Value
		case "likelihood":
			like = f.Value
		}
	}
	if reach != "reachable" || like != "malicious package (runs when installed)" {
		t.Errorf("malware ignores reachability and has maximal likelihood: %q %q", reach, like)
	}
}

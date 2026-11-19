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

func TestActiveSecret(t *testing.T) {
	w := Default()
	base := Input{Status: "open", Severity: "critical", Criticality: "medium", Exposure: "unknown", Confidence: "medium"}
	plain := Compute(base, w)
	live := base
	live.SecretActive = true
	r := Compute(live, w)
	if r.Score <= plain.Score || Band(r.Score) != "critical" {
		t.Fatalf("an active secret is critical risk: %v (plain %v)", r.Score, plain.Score)
	}
	for _, f := range r.Factors {
		if f.Key == "likelihood" && f.Value != "leaked credential validated as active" {
			t.Errorf("likelihood source: %q", f.Value)
		}
	}
}

func factor(r Result, key string) *Factor {
	for i := range r.Factors {
		if r.Factors[i].Key == key {
			return &r.Factors[i]
		}
	}
	return nil
}

func TestRuntimeFactors(t *testing.T) {
	w := Default()
	base := Input{Status: "open", Severity: "high", Exposure: "unknown"}
	plain := Compute(base, w)
	for _, k := range []string{"deployed", "runtime_exposure", "privileged", "runtime_alert"} {
		if factor(plain, k) != nil {
			t.Errorf("no runtime data, no %s factor", k)
		}
	}

	dep := base
	dep.RuntimeStatus = "deployed"
	dep.RuntimeEvidence.Deployed = []string{"cluster prod, namespace shop, Deployment web"}
	deployed := Compute(dep, w)
	nd := base
	nd.RuntimeStatus = "not_deployed"
	nd.RuntimeEvidence.Deployed = []string{"no workload in the 1 connected cluster(s) (prod) runs ghcr.io/acme/shop:1.0"}
	notDeployed := Compute(nd, w)
	if !(notDeployed.Score < plain.Score && plain.Score < deployed.Score) {
		t.Errorf("not deployed %v < unknown %v < deployed %v", notDeployed.Score, plain.Score, deployed.Score)
	}
	if f := factor(deployed, "deployed"); f == nil || len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "namespace shop") {
		t.Errorf("deployed factor carries its evidence: %+v", f)
	}
	if f := factor(notDeployed, "deployed"); f == nil || f.Weight >= 1 || f.Value != "not running in any connected cluster" {
		t.Errorf("not deployed factor: %+v", f)
	}

	// Observed exposure replaces the declared one (no double counting).
	exp := dep
	exp.Exposure = "yes"
	exp.RuntimeExposed = true
	exp.RuntimeEvidence.Exposed = []string{"Ingress shop routes https://shop.example.com/"}
	observed := Compute(exp, w)
	declaredOnly := dep
	declaredOnly.Exposure = "yes"
	declared := Compute(declaredOnly, w)
	if f := factor(observed, "exposure"); f == nil || f.Weight != 1 {
		t.Errorf("declared exposure neutral when observed: %+v", f)
	}
	if f := factor(observed, "runtime_exposure"); f == nil || f.Evidence[0] != exp.RuntimeEvidence.Exposed[0] {
		t.Errorf("runtime exposure factor: %+v", f)
	}
	if observed.Score != declared.Score {
		// Same default weight (1.3) for declared and observed exposure.
		t.Errorf("observed %v vs declared %v exposure with equal weights", observed.Score, declared.Score)
	}

	all := exp
	all.RuntimePrivileged, all.RuntimeAlert = true, true
	all.RuntimeEvidence.Privileged = []string{"privileged container"}
	all.RuntimeEvidence.Alerts = []string{"Terminal shell in container"}
	worst := Compute(all, w)
	if worst.Score <= observed.Score || factor(worst, "privileged") == nil || factor(worst, "runtime_alert") == nil {
		t.Errorf("privileged + alert raise risk: %v vs %v", worst.Score, observed.Score)
	}
	// Closed findings stay at zero whatever runs.
	all.Status = "fixed"
	if Compute(all, w).Score != 0 {
		t.Error("closed finding")
	}
}

func TestRuntimeWeightsBackwardCompatible(t *testing.T) {
	// A model stored before the runtime weights existed validates and gets
	// the defaults.
	old := Weights{Severity: map[string]float64{}, KEV: 1, ExploitAvailable: 0.8, EPSSWeight: 1, LikelihoodUnknown: 0.5,
		HumanConfirmed: 1.1, CompensatingControls: 0.7, FixAvailable: 1.05}
	if err := old.Validate(); err != nil {
		t.Fatal(err)
	}
	d := Default()
	if old.RuntimeExposed != d.RuntimeExposed || old.Deployment["not_deployed"] != d.Deployment["not_deployed"] || old.RuntimeAlert != d.RuntimeAlert {
		t.Errorf("defaults filled: %+v", old)
	}
	bad := Default()
	bad.Deployment["not_deployed"] = 5
	if bad.Validate() == nil {
		t.Error("deployment weight out of range")
	}
	bad = Default()
	bad.Deployment["running"] = 1
	if bad.Validate() == nil {
		t.Error("unknown deployment key")
	}
}

// A function-level answer uses its own weights and says how it was found.
func TestFunctionReachability(t *testing.T) {
	w := Default()
	base := Input{Status: "open", Severity: "high", Criticality: "medium", Exposure: "unknown", Confidence: "high"}
	score := func(reach, method string) (float64, Factor) {
		in := base
		in.Reachability, in.ReachabilityMethod = reach, method
		r := Compute(in, w)
		for _, f := range r.Factors {
			if f.Key == "reachability" {
				return r.Score, f
			}
		}
		t.Fatal("no reachability factor")
		return 0, Factor{}
	}
	pkgReach, f1 := score("reachable", "import")
	fnReach, f2 := score("reachable", "call_graph")
	fnNot, f3 := score("not_reachable", "symbol_calls")
	pkgNot, _ := score("not_reachable", "import")
	if !(fnReach > pkgReach && pkgReach > pkgNot && pkgNot > fnNot && fnNot > 0) {
		t.Errorf("order: %v %v %v %v", fnReach, pkgReach, pkgNot, fnNot)
	}
	if f1.Label != "Reachability" || f2.Label != "Reachability (vulnerable function, call graph)" || f2.Value != "called" ||
		f3.Label != "Reachability (vulnerable function, calls in the code)" || f3.Value != "not called" || f3.Weight != 0.5 {
		t.Errorf("factors: %+v %+v %+v", f1, f2, f3)
	}
	// stored models without the new weights get the defaults
	old := Default()
	old.FunctionReachability = nil
	if err := old.Validate(); err != nil || old.FunctionReachability["reachable"] != 1.3 {
		t.Errorf("validate: %v %v", err, old.FunctionReachability)
	}
	bad := Default()
	bad.FunctionReachability["maybe"] = 1
	if bad.Validate() == nil {
		t.Error("unknown key accepted")
	}
}

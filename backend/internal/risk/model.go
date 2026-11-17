// Package risk computes the contextual risk score of findings: an
// explainable 0-100 score that combines severity (or CVSS) with exploit
// likelihood (EPSS, CISA KEV, public exploits), business context
// (criticality, internet exposure), reachability, confidence, human review
// outcomes and fix availability. Severity is never changed; the score is a
// separate, versioned and configurable signal (docs/aspm/PATHOS_IMPLEMENTATION_ROADMAP.md §4).
package risk

import (
	"errors"
	"fmt"
	"math"
)

// Weights is a risk model. Every value is a multiplier (or a base score)
// that administrators can tune; Validate bounds them.
type Weights struct {
	// Base score per severity when no CVSS score is known (0-10 scale).
	Severity map[string]float64 `json:"severity"`
	// UseCVSS prefers the finding's CVSS base score over the severity base.
	UseCVSS bool `json:"use_cvss"`

	// Likelihood: the maximum of the EPSS percentile, KEV and exploit
	// signals; Unknown applies when no signal exists (never zero).
	KEV               float64 `json:"kev"`
	ExploitAvailable  float64 `json:"exploit_available"`
	EPSSWeight        float64 `json:"epss_weight"`
	LikelihoodUnknown float64 `json:"likelihood_unknown"`

	Criticality  map[string]float64 `json:"criticality"`
	Exposure     map[string]float64 `json:"exposure"`
	Reachability map[string]float64 `json:"reachability"`
	Confidence   map[string]float64 `json:"confidence"`

	// HumanConfirmed applies when a reviewer confirmed the finding;
	// CompensatingControls when the review recorded such controls.
	HumanConfirmed       float64 `json:"human_confirmed"`
	CompensatingControls float64 `json:"compensating_controls"`
	FixAvailable         float64 `json:"fix_available"`
}

// Default is the built-in model (version 0).
func Default() Weights {
	return Weights{
		Severity:             map[string]float64{"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0},
		UseCVSS:              true,
		KEV:                  1.0,
		ExploitAvailable:     0.8,
		EPSSWeight:           1.0,
		LikelihoodUnknown:    0.5,
		Criticality:          map[string]float64{"critical": 1.3, "high": 1.15, "medium": 1.0, "low": 0.8},
		Exposure:             map[string]float64{"yes": 1.3, "unknown": 1.1, "no": 0.85},
		Reachability:         map[string]float64{"reachable": 1.2, "unknown": 1.0, "not_reachable": 0.6},
		Confidence:           map[string]float64{"high": 1.0, "medium": 0.9, "low": 0.75, "unknown": 0.9},
		HumanConfirmed:       1.1,
		CompensatingControls: 0.7,
		FixAvailable:         1.05,
	}
}

var (
	severities   = []string{"critical", "high", "medium", "low", "info"}
	criticality  = []string{"critical", "high", "medium", "low"}
	exposures    = []string{"yes", "unknown", "no"}
	reachability = []string{"reachable", "unknown", "not_reachable"}
	confidences  = []string{"high", "medium", "low", "unknown"}
)

// Validate checks a model and fills missing keys from Default.
func (w *Weights) Validate() error {
	d := Default()
	fill := func(name string, m *map[string]float64, keys []string, def map[string]float64, lo, hi float64) error {
		if *m == nil {
			*m = map[string]float64{}
		}
		for k := range *m {
			if !contains(keys, k) {
				return fmt.Errorf("%s: unknown key %q", name, k)
			}
		}
		for _, k := range keys {
			v, ok := (*m)[k]
			if !ok {
				(*m)[k] = def[k]
				continue
			}
			if math.IsNaN(v) || v < lo || v > hi {
				return fmt.Errorf("%s.%s must be between %g and %g", name, k, lo, hi)
			}
		}
		return nil
	}
	for _, f := range []error{
		fill("severity", &w.Severity, severities, d.Severity, 0, 10),
		fill("criticality", &w.Criticality, criticality, d.Criticality, 0.1, 3),
		fill("exposure", &w.Exposure, exposures, d.Exposure, 0.1, 3),
		fill("reachability", &w.Reachability, reachability, d.Reachability, 0.1, 3),
		fill("confidence", &w.Confidence, confidences, d.Confidence, 0.1, 3),
	} {
		if f != nil {
			return f
		}
	}
	for name, v := range map[string]float64{"kev": w.KEV, "exploit_available": w.ExploitAvailable, "epss_weight": w.EPSSWeight,
		"likelihood_unknown": w.LikelihoodUnknown} {
		if math.IsNaN(v) || v < 0 || v > 1 {
			return fmt.Errorf("%s must be between 0 and 1", name)
		}
	}
	for name, v := range map[string]float64{"human_confirmed": w.HumanConfirmed, "compensating_controls": w.CompensatingControls,
		"fix_available": w.FixAvailable} {
		if math.IsNaN(v) || v < 0.1 || v > 3 {
			return fmt.Errorf("%s must be between 0.1 and 3", name)
		}
	}
	if w.LikelihoodUnknown == 0 {
		return errors.New("likelihood_unknown must be greater than 0: missing data must not lower risk to zero")
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Input is everything the score depends on.
type Input struct {
	Status           string // finding status
	Severity         string // scanner severity
	HumanSeverity    string // human-assessed severity ("" if none)
	CVSS             *float64
	EPSSPercentile   *float64
	KEV              bool
	ExploitAvailable bool
	Criticality      string // highest of application and repository criticality
	Exposure         string // yes | no | unknown
	Reachability     string
	Confidence       string
	HumanDisposition string // "" or a Human Eye disposition
	Compensating     bool   // a review recorded compensating controls
	FixAvailable     bool
	// Malicious: the package itself is malware (OSV MAL-*): it runs when
	// installed, so likelihood is maximal and reachability does not lower it.
	Malicious bool
}

// Factor is one term of the explanation.
type Factor struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Value  string  `json:"value"`
	Weight float64 `json:"weight"`
}

// Result is a score with its explanation.
type Result struct {
	Score   float64  `json:"score"`
	Base    float64  `json:"base"`
	Factors []Factor `json:"factors"`
	Reason  string   `json:"reason,omitempty"`
	Version int      `json:"model_version"`
}

// Compute scores one finding:
//
//	score = clamp(10 × base × (0.5 + likelihood) × context / 1.75, 0, 100)
//
// where base is 0-10 (human-assessed severity, else CVSS, else severity),
// likelihood is 0-1 and context is the product of the multipliers. With
// default weights and a neutral context, a critical KEV-listed finding
// scores about 81 (critical), a critical finding without exploit signals
// about 54 (high) and a low finding about 11 (low); internet exposure and
// business criticality move them up, internal-only assets down.
func Compute(in Input, w Weights) Result {
	switch in.Status {
	case "fixed", "false_positive", "accepted_risk":
		return Result{Score: 0, Reason: "not open (" + in.Status + ")", Factors: []Factor{}}
	}
	r := Result{Factors: []Factor{}}
	add := func(key, label, value string, weight float64) {
		r.Factors = append(r.Factors, Factor{Key: key, Label: label, Value: value, Weight: round(weight, 3)})
	}
	switch {
	case in.HumanSeverity != "":
		r.Base = w.Severity[in.HumanSeverity]
		add("base", "Human-assessed severity", in.HumanSeverity, r.Base)
	case w.UseCVSS && in.CVSS != nil:
		r.Base = *in.CVSS
		add("base", "CVSS base score", fmt.Sprintf("%.1f", *in.CVSS), r.Base)
	default:
		r.Base = w.Severity[in.Severity]
		add("base", "Scanner severity", in.Severity, r.Base)
	}

	likelihood, lsrc := w.LikelihoodUnknown, "no exploit signal"
	if in.EPSSPercentile != nil {
		if v := *in.EPSSPercentile * w.EPSSWeight; v > likelihood || lsrc == "no exploit signal" {
			likelihood, lsrc = v, fmt.Sprintf("EPSS percentile %.0f%%", *in.EPSSPercentile*100)
		}
	}
	if in.ExploitAvailable && w.ExploitAvailable > likelihood {
		likelihood, lsrc = w.ExploitAvailable, "public exploit available"
	}
	if in.KEV && w.KEV >= likelihood {
		likelihood, lsrc = w.KEV, "listed in CISA KEV (exploited in the wild)"
	}
	if in.Malicious && w.KEV >= likelihood {
		likelihood, lsrc = w.KEV, "malicious package (runs when installed)"
	}
	add("likelihood", "Exploit likelihood", lsrc, 0.5+likelihood)

	mult := 1.0
	m := func(key, label, value string, table map[string]float64) {
		v, ok := table[value]
		if !ok {
			v = 1
		}
		mult *= v
		add(key, label, value, v)
	}
	m("criticality", "Business criticality", orUnknown(in.Criticality, "medium"), w.Criticality)
	m("exposure", "Internet exposure", orUnknown(in.Exposure, "unknown"), w.Exposure)
	if in.Malicious {
		// Malware acts at install time, whether or not the code imports it.
		m("reachability", "Reachability", "reachable", w.Reachability)
	} else {
		m("reachability", "Reachability", orUnknown(in.Reachability, "unknown"), w.Reachability)
	}
	if in.HumanDisposition == "confirmed" {
		mult *= w.HumanConfirmed
		add("confidence", "Confidence", "confirmed by a human reviewer", w.HumanConfirmed)
	} else {
		m("confidence", "Scanner confidence", orUnknown(in.Confidence, "unknown"), w.Confidence)
	}
	if in.Compensating {
		mult *= w.CompensatingControls
		add("controls", "Compensating controls", "recorded in review", w.CompensatingControls)
	}
	if in.FixAvailable {
		mult *= w.FixAvailable
		add("fix", "Fix available", "yes", w.FixAvailable)
	}
	score := 10 * r.Base * (0.5 + likelihood) * mult / 1.75
	r.Score = round(math.Max(0, math.Min(100, score)), 2)
	return r
}

func orUnknown(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

// Band names a score range for display.
func Band(score float64) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	case score > 0:
		return "low"
	}
	return "none"
}

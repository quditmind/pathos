package review

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
)

// CVSS is a parsed vector.
type CVSS struct {
	Version string            // "3.0", "3.1" or "4.0"
	Metrics map[string]string // metric -> value
	// Score is computed for CVSS 3.x base vectors. CVSS 4.0 scores come
	// from the analyst (FIRST calculator); PATHOS validates the vector.
	Score *float64
}

var cvss3Base = map[string][]string{
	"AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "PR": {"N", "L", "H"}, "UI": {"N", "R"},
	"S": {"U", "C"}, "C": {"H", "L", "N"}, "I": {"H", "L", "N"}, "A": {"H", "L", "N"},
}

var cvss3Optional = map[string][]string{
	"E": {"X", "H", "F", "P", "U"}, "RL": {"X", "U", "W", "T", "O"}, "RC": {"X", "C", "R", "U"},
	"CR": {"X", "H", "M", "L"}, "IR": {"X", "H", "M", "L"}, "AR": {"X", "H", "M", "L"},
	"MAV": {"X", "N", "A", "L", "P"}, "MAC": {"X", "L", "H"}, "MPR": {"X", "N", "L", "H"}, "MUI": {"X", "N", "R"},
	"MS": {"X", "U", "C"}, "MC": {"X", "H", "L", "N"}, "MI": {"X", "H", "L", "N"}, "MA": {"X", "H", "L", "N"},
}

var cvss4Base = map[string][]string{
	"AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "AT": {"N", "P"}, "PR": {"N", "L", "H"}, "UI": {"N", "P", "A"},
	"VC": {"H", "L", "N"}, "VI": {"H", "L", "N"}, "VA": {"H", "L", "N"},
	"SC": {"H", "L", "N"}, "SI": {"H", "L", "N"}, "SA": {"H", "L", "N"},
}

var cvss4Optional = map[string][]string{
	"E":  {"X", "A", "P", "U"},
	"CR": {"X", "H", "M", "L"}, "IR": {"X", "H", "M", "L"}, "AR": {"X", "H", "M", "L"},
	"MAV": {"X", "N", "A", "L", "P"}, "MAC": {"X", "L", "H"}, "MAT": {"X", "N", "P"}, "MPR": {"X", "N", "L", "H"},
	"MUI": {"X", "N", "P", "A"}, "MVC": {"X", "H", "L", "N"}, "MVI": {"X", "H", "L", "N"}, "MVA": {"X", "H", "L", "N"},
	"MSC": {"X", "H", "L", "N"}, "MSI": {"X", "S", "H", "L", "N"}, "MSA": {"X", "S", "H", "L", "N"},
	"S": {"X", "N", "P"}, "AU": {"X", "N", "Y"}, "R": {"X", "A", "U", "I"}, "V": {"X", "D", "C"},
	"RE": {"X", "L", "M", "H"}, "U": {"X", "Clear", "Green", "Amber", "Red"},
}

// ParseCVSS validates a CVSS 3.0, 3.1 or 4.0 vector and computes the base
// score for 3.x.
func ParseCVSS(vector string) (CVSS, error) {
	vector = strings.TrimSpace(vector)
	if len(vector) > 300 {
		return CVSS{}, errors.New("CVSS vector is too long")
	}
	prefix, rest, ok := strings.Cut(vector, "/")
	if !ok {
		return CVSS{}, errors.New("CVSS vector must start with CVSS:3.1/ or CVSS:4.0/")
	}
	var base, optional map[string][]string
	c := CVSS{Metrics: map[string]string{}}
	switch prefix {
	case "CVSS:3.0", "CVSS:3.1":
		c.Version, base, optional = strings.TrimPrefix(prefix, "CVSS:"), cvss3Base, cvss3Optional
	case "CVSS:4.0":
		c.Version, base, optional = "4.0", cvss4Base, cvss4Optional
	default:
		return CVSS{}, errors.New("CVSS vector must start with CVSS:3.1/ or CVSS:4.0/")
	}
	for _, part := range strings.Split(rest, "/") {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			return CVSS{}, fmt.Errorf("invalid CVSS metric %q", part)
		}
		allowed, known := base[k]
		if !known {
			allowed, known = optional[k]
		}
		if !known {
			return CVSS{}, fmt.Errorf("unknown CVSS %s metric %q", c.Version, k)
		}
		if !slices.Contains(allowed, v) {
			return CVSS{}, fmt.Errorf("invalid value %q for CVSS metric %s", v, k)
		}
		if _, dup := c.Metrics[k]; dup {
			return CVSS{}, fmt.Errorf("CVSS metric %s appears twice", k)
		}
		c.Metrics[k] = v
	}
	for k := range base {
		if _, ok := c.Metrics[k]; !ok {
			return CVSS{}, fmt.Errorf("CVSS %s vector is missing base metric %s", c.Version, k)
		}
	}
	if c.Version != "4.0" {
		s := cvss3BaseScore(c.Metrics)
		c.Score = &s
	}
	return c, nil
}

func roundUp1(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

// cvss3BaseScore implements the CVSS v3.1 base score equations.
func cvss3BaseScore(m map[string]string) float64 {
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	changed := m["S"] == "C"
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	iss := 1 - (1-cia[m["C"]])*(1-cia[m["I"]])*(1-cia[m["A"]])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	expl := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0
	}
	if changed {
		return roundUp1(math.Min(1.08*(impact+expl), 10))
	}
	return roundUp1(math.Min(impact+expl, 10))
}

// SeverityForScore maps a CVSS score to a PATHOS severity (CVSS "None"
// maps to info).
func SeverityForScore(s float64) string {
	switch {
	case s >= 9:
		return "critical"
	case s >= 7:
		return "high"
	case s >= 4:
		return "medium"
	case s > 0:
		return "low"
	}
	return "info"
}

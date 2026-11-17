package review

import "testing"

func TestCVSS31Scores(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 6.5,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N": 0,
		"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N": 3.8,
	}
	for v, want := range cases {
		c, err := ParseCVSS(v)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if c.Score == nil || *c.Score != want {
			t.Errorf("%s: score %v, want %v", v, c.Score, want)
		}
	}
}

func TestCVSS40Validation(t *testing.T) {
	ok := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
	c, err := ParseCVSS(ok)
	if err != nil || c.Version != "4.0" || c.Score != nil {
		t.Fatalf("valid 4.0 vector: %+v %v", c, err)
	}
	for _, bad := range []string{
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N", // missing SA
		"CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:N",
		"CVSS:2.0/AV:N",
		"AV:N/AC:L",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1",
	} {
		if _, err := ParseCVSS(bad); err == nil {
			t.Errorf("%s: expected an error", bad)
		}
	}
}

func TestSeverityForScore(t *testing.T) {
	for s, want := range map[float64]string{0: "info", 0.1: "low", 3.9: "low", 4: "medium", 6.9: "medium", 7: "high", 8.9: "high", 9: "critical", 10: "critical"} {
		if got := SeverityForScore(s); got != want {
			t.Errorf("%v: %s, want %s", s, got, want)
		}
	}
}

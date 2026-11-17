package posture

import "testing"

func TestVersionLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"4.17.20", "4.17.21", true}, {"1.2.9", "1.2.10", true}, {"1.0.1", "0.0.1", false}, {"2.0.0", "2.0.0", false},
		{"v1.4", "1.4.1", true}, {"3.0.0-rc.1", "3.0.0", true}, {"3.0.0", "3.0.0-rc.1", false}, {"2.8.29", "3.19.3", true},
		{"latest", "1.0.0", false}, {"1.0.0", "1.0.0.Final", false},
	} {
		if got := VersionLess(c.a, c.b); got != c.want {
			t.Errorf("%s < %s: got %v", c.a, c.b, got)
		}
	}
}

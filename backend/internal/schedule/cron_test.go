package schedule

import (
	"testing"
	"time"
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	l, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestCronNext(t *testing.T) {
	utc := time.UTC
	base := time.Date(2026, 11, 15, 10, 7, 30, 0, utc) // Sunday
	cases := []struct {
		expr string
		want string
	}{
		{"0 2 * * *", "2026-11-16T02:00:00Z"},
		{"@daily", "2026-11-16T00:00:00Z"},
		{"@hourly", "2026-11-15T11:00:00Z"},
		{"*/15 * * * *", "2026-11-15T10:15:00Z"},
		{"30 1 * * MON-FRI", "2026-11-16T01:30:00Z"},
		{"0 3 * * 7", "2026-11-22T03:00:00Z"},
		{"0 0 1 * *", "2026-12-01T00:00:00Z"},
		{"0 0 1 JAN *", "2027-01-01T00:00:00Z"},
		{"0 6 13 * 5", "2026-11-20T06:00:00Z"}, // dom OR dow: Friday 20th comes first
		{"5/20 10 * * *", "2026-11-15T10:25:00Z"},
		{"0 0 29 2 *", "2028-02-29T00:00:00Z"},
	}
	for _, c := range cases {
		cr, err := ParseCron(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if got := cr.Next(base, utc).Format(time.RFC3339); got != c.want {
			t.Errorf("%s: next = %s, want %s", c.expr, got, c.want)
		}
	}
}

func TestCronTimezoneAndDST(t *testing.T) {
	ny := mustLoc(t, "America/New_York")
	cr, _ := ParseCron("0 2 * * *")
	// 2026-03-08 is the US spring-forward day: 02:00 does not exist.
	got := cr.Next(time.Date(2026, 3, 7, 12, 0, 0, 0, ny), ny)
	if got.Day() != 8 || got.Hour() != 3 {
		t.Errorf("spring forward: got %s", got)
	}
	// Ordinary day: 02:00 local is 07:00 UTC in winter.
	got = cr.Next(time.Date(2026, 1, 10, 12, 0, 0, 0, ny), ny)
	if got.UTC().Hour() != 7 {
		t.Errorf("winter offset: got %s", got.UTC())
	}
	// Fall back (2026-11-01): one run, and the loop terminates.
	cr2, _ := ParseCron("30 1 * * *")
	got = cr2.Next(time.Date(2026, 10, 31, 12, 0, 0, 0, ny), ny)
	if got.Day() != 1 || got.Hour() != 1 || got.Minute() != 30 {
		t.Errorf("fall back: got %s", got)
	}
	if n := cr2.Next(got, ny); n.Day() != 2 && !(n.Day() == 1 && n.Hour() == 1) {
		t.Errorf("after fall back: got %s", n)
	}
}

func TestCronInvalid(t *testing.T) {
	for _, e := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "5-1 * * * *", "*/0 * * * *", "a * * * *", "0 0 * * * *"} {
		if _, err := ParseCron(e); err == nil {
			t.Errorf("%q: expected error", e)
		}
	}
	cr, _ := ParseCron("0 0 31 2 *")
	if !cr.Next(time.Now(), time.UTC).IsZero() {
		t.Error("Feb 31 should never fire")
	}
}

func TestMinInterval(t *testing.T) {
	cr, _ := ParseCron("*/15 * * * *")
	if d := cr.MinInterval(time.Now(), time.UTC, 10); d != 15*time.Minute {
		t.Errorf("got %s", d)
	}
	cr, _ = ParseCron("0 2,3 * * *")
	if d := cr.MinInterval(time.Now(), time.UTC, 10); d != time.Hour {
		t.Errorf("got %s", d)
	}
}

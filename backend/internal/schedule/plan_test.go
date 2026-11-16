package schedule

import (
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestTimingKinds(t *testing.T) {
	c, _ := ParseCron("0 2 * * *")
	tm := Timing{Kind: "cron", Cron: c, Loc: time.UTC}
	if got := tm.Next(at("2026-11-17T01:00:00Z")); !got.Equal(at("2026-11-17T02:00:00Z")) {
		t.Errorf("cron: %s", got)
	}
	once := at("2026-11-20T10:00:00Z")
	tm = Timing{Kind: "once", RunAt: &once, Loc: time.UTC}
	if got := tm.Next(at("2026-11-17T00:00:00Z")); !got.Equal(once) {
		t.Errorf("once before: %s", got)
	}
	if got := tm.Next(once); !got.IsZero() {
		t.Errorf("once after: %s", got)
	}
	start := at("2026-11-17T00:00:00Z")
	tm = Timing{Kind: "interval", IntervalMinutes: 360, RunAt: &start, Loc: time.UTC}
	if got := tm.Next(at("2026-11-17T07:00:00Z")); !got.Equal(at("2026-11-17T12:00:00Z")) {
		t.Errorf("interval: %s", got)
	}
	if got := tm.Next(at("2026-11-17T12:00:00Z")); !got.Equal(at("2026-11-17T18:00:00Z")) {
		t.Errorf("interval strictly after: %s", got)
	}
}

func TestWindows(t *testing.T) {
	night := &Window{Start: 22 * time.Hour, End: 4 * time.Hour}
	for in, want := range map[string]bool{
		"2026-11-17T23:00:00Z": true, "2026-11-18T03:59:00Z": true, "2026-11-18T04:00:00Z": false, "2026-11-17T12:00:00Z": false,
	} {
		if got := night.contains(at(in)); got != want {
			t.Errorf("overnight contains(%s) = %v", in, got)
		}
	}
	if got := night.nextOpen(at("2026-11-17T12:00:00Z")); !got.Equal(at("2026-11-17T22:00:00Z")) {
		t.Errorf("nextOpen: %s", got)
	}
	// Weekends only (Sat=6, Sun=0); 2026-11-17 is a Tuesday.
	wk := &Window{Start: 1 * time.Hour, End: 5 * time.Hour, Days: []int{0, 6}}
	if got := wk.nextOpen(at("2026-11-17T02:00:00Z")); !got.Equal(at("2026-11-21T01:00:00Z")) {
		t.Errorf("weekend window: %s", got)
	}
	// An overnight window started on Saturday still counts on Sunday morning.
	sat := &Window{Start: 22 * time.Hour, End: 4 * time.Hour, Days: []int{6}}
	if !sat.contains(at("2026-11-22T02:00:00Z")) || sat.contains(at("2026-11-23T02:00:00Z")) {
		t.Error("overnight window day attribution")
	}
	c, _ := ParseCron("0 * * * *")
	tm := Timing{Kind: "cron", Cron: c, Loc: time.UTC, Window: night}
	if got := tm.Next(at("2026-11-17T12:30:00Z")); !got.Equal(at("2026-11-17T22:00:00Z")) {
		t.Errorf("cron deferred into window: %s", got)
	}
}

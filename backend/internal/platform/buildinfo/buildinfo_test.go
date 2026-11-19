package buildinfo

import (
	"testing"
	"time"
)

func TestBannerAndStamp(t *testing.T) {
	v, c, d := Version, Commit, BuildDate
	defer func() { Version, Commit, BuildDate = v, c, d }()
	Version, Commit, BuildDate = "3.0.0", "0123456789abcdef0123", "2026-11-20T10:00:00Z"
	if got, want := Banner(), "Quditmind PATHOS v3.0.0 (build 0123456789ab, 2026-11-20T10:00:00Z)"; got != want {
		t.Errorf("Banner() = %q, want %q", got, want)
	}
	now := time.Date(2026, 11, 20, 12, 30, 0, 0, time.FixedZone("CET", 3600))
	if got, want := Stamp(now), "Quditmind PATHOS v3.0.0 · build 0123456789ab · generated 2026-11-20T11:30:00Z"; got != want {
		t.Errorf("Stamp() = %q, want %q", got, want)
	}
	Commit = "abc"
	if ShortCommit() != "abc" {
		t.Errorf("short commit: %q", ShortCommit())
	}
}

func TestDefaults(t *testing.T) {
	if Version == "" || Commit == "" || BuildDate == "" {
		t.Fatal("build metadata must never be empty")
	}
}

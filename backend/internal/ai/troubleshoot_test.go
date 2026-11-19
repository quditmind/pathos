package ai

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestValidateTroubleshoot(t *testing.T) {
	out, err := ValidateTroubleshoot([]byte(`{"likely_cause":"c","probable_causes":["a"," "],"actions":["do x"],"verify":["check"]}`))
	if err != nil || out.LikelyCause != "c" || len(out.ProbableCauses) != 1 || out.Actions[0] != "do x" {
		t.Fatalf("%+v %v", out, err)
	}
	for _, bad := range []string{`{"likely_cause":"c","probable_causes":[],"actions":[],"verify":[]}`, `{"actions":["x"],"extra":1}`, `not json`} {
		if _, err := ValidateTroubleshoot([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	long := `{"likely_cause":"` + strings.Repeat("x", 5000) + `","probable_causes":[],"actions":["a","b","c","d","e","f","g","h","i","j","k","l"],"verify":[]}`
	out, err = ValidateTroubleshoot([]byte(long))
	if err != nil || len(out.LikelyCause) > 700 || len(out.Actions) != 10 {
		t.Errorf("bounds: %d %d %v", len(out.LikelyCause), len(out.Actions), err)
	}
}

func TestAIDiagCode(t *testing.T) {
	for err, want := range map[error]string{
		ErrNotConfigured:                 "PTH-AI-1001",
		fmt.Errorf("x: %w", ErrAuth):     "PTH-AI-1003",
		ErrRateLimited:                   "PTH-AI-1004",
		ErrRefused:                       "PTH-AI-1005",
		ErrTruncated:                     "PTH-AI-1006",
		ErrTooLarge{Bytes: 1}:            "PTH-AI-1011",
		errors.New("connection refused"): "PTH-AI-1006",
	} {
		if got := DiagCode(err); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
}

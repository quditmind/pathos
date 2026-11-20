package scans

import "testing"

// Stored execution errors map to their catalogue codes, including the
// 2.2.x errors that carry the code in their text.
func TestJobErrorCode(t *testing.T) {
	cases := map[string]string{
		"":                                     "",
		"could not obtain clone credential: x": "PTH-SCAN-1001",
		"worker lease expired twice":           "PTH-SCAN-1002",
		MissingToolsMessage([]string{"gosec", "psalm"}):                                     "PTH-SCAN-1101",
		"scanners failed: semgrep; " + MissingToolsMessage([]string{"gosec"}):               "PTH-SCAN-1101",
		"clone failed: PTH-ONB-1102: the server refused an anonymous clone; the repository": "PTH-ONB-1102",
		"something else": "",
	}
	for msg, want := range cases {
		if got := JobErrorCode(msg); got != want {
			t.Errorf("%q: got %q, want %q", msg, got, want)
		}
	}
}

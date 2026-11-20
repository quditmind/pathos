package scans

import "testing"

func TestDefaultProfileHasNoNoisyTools(t *testing.T) {
	st := DefaultSettings()
	for _, sc := range st.Scanners {
		if sc.Key == "talisman" {
			t.Fatal("the default profile must not contain Talisman")
		}
	}
	if st.SecretDefaultExclusions != nil && !*st.SecretDefaultExclusions {
		t.Error("default secret exclusions must be on in the default profile")
	}
}

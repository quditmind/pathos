package pushprotect

import (
	"strings"
	"testing"
)

// Fake secrets are assembled at runtime so that secret scanners run on
// this repository do not flag the test file.
func fake(prefix string, body string) string { return prefix + body }

const alnum = "Q7xK2mP9vR4tW8yZ3bN6cL1dF5gH0jS2aE7uI9oT4" // high entropy

func TestScanLineRules(t *testing.T) {
	cases := map[string]string{
		"aws-access-key-id":       "key = '" + fake("AK"+"IA", "QX7Z2M4N6P3R5T7V") + "'",
		"aws-secret-access-key":   "aws_secret_access_key = " + alnum[:40],
		"github-token":            "token: " + fake("gh"+"p_", alnum[:36]),
		"github-fine-grained-pat": fake("github"+"_pat_", strings.Repeat("aB3dE5fG7h", 8)+"Zq"),
		"gitlab-token":            fake("gl"+"pat-", "Ab3De5Fg7Hj9Kl1Mn3Pq"),
		"slack-token":             fake("xo"+"xb-", "1234567890-abcdefGHIJKL"),
		"stripe-live-key":         fake("sk"+"_live_", alnum[:30]),
		"google-api-key":          fake("AI"+"za", alnum[:35]),
		"private-key":             "-----BEGIN RSA " + "PRIVATE KEY-----",
		"npm-token":               fake("np"+"m_", alnum[:36]),
		"azure-storage-key":       "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + (alnum + alnum + alnum)[:86] + "==",
	}
	for rule, line := range cases {
		ms := ScanLine(line)
		found := false
		for _, m := range ms {
			if m.RuleID == rule {
				found = true
				if len(m.Digest) != 16 {
					t.Errorf("%s: digest %q", rule, m.Digest)
				}
			}
		}
		if !found {
			t.Errorf("%s not detected (got %+v)", rule, ms)
		}
	}
}

func TestPlaceholdersIgnored(t *testing.T) {
	for _, line := range []string{
		"AWS_KEY=" + "AK" + "IAIOSFODNN7EXAMPLE",
		"aws_secret_access_key = " + strings.Repeat("a", 40),
		"no secrets here",
		"token = os.environ['GITHUB_TOKEN']",
	} {
		if ms := ScanLine(line); len(ms) != 0 {
			t.Errorf("false positive on %q: %+v", line, ms)
		}
	}
}

func TestScanPatchAddedLinesOnly(t *testing.T) {
	secret := fake("gh"+"p_", alnum[:36])
	patch := strings.Join([]string{
		"@@ -10,3 +20,4 @@ func x()",
		" context",
		"-old = \"" + secret + "\"",
		"+new = \"" + secret + "\"",
		" more",
		"+again = \"" + secret + "\"",
	}, "\n")
	ms := ScanPatch(patch)
	if len(ms) != 2 {
		t.Fatalf("want 2 matches, got %+v", ms)
	}
	if ms[0].Line != 21 || ms[1].Line != 23 {
		t.Errorf("line numbers: %d, %d", ms[0].Line, ms[1].Line)
	}
	if ScanPatch("@@ -1 +1 @@\n-"+secret+"\n+removed") != nil {
		t.Error("removed secret alerted")
	}
}

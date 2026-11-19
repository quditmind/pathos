package ai

import (
	"fmt"
	"strings"
	"testing"
)

func TestBuildFixRegion(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 1000; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	r := BuildFixRegion("a.py", []byte(b.String()), 500, 502)
	if r.FirstLine != 440 || r.LastLine != 562 || r.TotalLines != 1000 || !strings.HasPrefix(r.Code, "line 440\n") || !strings.HasSuffix(r.Code, "line 562\n") {
		t.Errorf("region: %d-%d of %d: %.40q", r.FirstLine, r.LastLine, r.TotalLines, r.Code)
	}
	small := BuildFixRegion("b.py", []byte("a\nb\nc\n"), 2, 0)
	if small.FirstLine != 1 || small.LastLine != 3 || small.Code != "a\nb\nc\n" {
		t.Errorf("whole small file: %+v", small)
	}
	long := strings.Repeat(strings.Repeat("x", 400)+"\n", 300)
	if r := BuildFixRegion("c.py", []byte(long), 150, 150); len(r.Code) > fixMaxRegionBytes || r.FirstLine > 150 || r.LastLine < 150 {
		t.Errorf("byte limit: %d bytes, %d-%d", len(r.Code), r.FirstLine, r.LastLine)
	}
}

func TestFixPromptRedactsSecrets(t *testing.T) {
	code := "import os\n\nDB_PASSWORD = \"pw-fake.value!\"\nAPI = \"token_FAKE_0000_not_real_0000\"\n\ndef connect():\n    return db(\"pw-fake.value!\")\n"
	in := FixInput{
		Finding: FixFinding{Category: "secrets", RuleID: "generic-api-key", FilePath: "app/settings.py", StartLine: 3, EndLine: 4,
			Title: "Hard-coded secret", Description: "Found a secret"},
		File: FixRegion{Path: "app/settings.py", FirstLine: 1, LastLine: 7, TotalLines: 7, Code: code},
	}
	system, user, sha := FixPrompt(in, "Use the config module.", nil)
	for _, leak := range []string{"pw-fake.value!", "token_FAKE_0000_not_real_0000"} {
		if strings.Contains(user, leak) {
			t.Errorf("secret %q sent to the provider:\n%s", leak, user)
		}
	}
	if !strings.Contains(user, "DB_PASSWORD = \\\"[REDACTED]\\\"") || !strings.Contains(user, "def connect") {
		t.Errorf("context lost:\n%s", user)
	}
	if !strings.Contains(system, "Organization guidance") || !strings.Contains(system, "never write [REDACTED]") || len(sha) != 64 {
		t.Errorf("system prompt or hash: %s", sha)
	}
	if !strings.Contains(user, "<untrusted_evidence") {
		t.Error("evidence not fenced")
	}
	// Non-secret findings keep identifiers but still pass the general redaction.
	in.Finding.Category = "sast"
	in.File.Code = "password = \"S3cr3tFakeValue\"\nrun(cmd, shell=True)\n"
	_, user, _ = FixPrompt(in, "", nil)
	if strings.Contains(user, "S3cr3tFakeValue") || !strings.Contains(user, "shell=True") {
		t.Errorf("sast redaction:\n%s", user)
	}
}

func TestValidateFix(t *testing.T) {
	if _, err := ValidateFix([]byte(`{"summary":"needs more context","diff":""}`)); err == nil || !strings.Contains(err.Error(), "needs more context") {
		t.Errorf("empty diff: %v", err)
	}
	if _, err := ValidateFix([]byte(`{"summary":"x","diff":"--- a/x\n","extra":1}`)); err == nil {
		t.Error("unknown field accepted")
	}
	p, err := ValidateFix([]byte(`{"summary":" ok ","diff":"--- a/x\n+++ b/x\n"}`))
	if err != nil || p.Summary != "ok" {
		t.Errorf("valid: %+v %v", p, err)
	}
}

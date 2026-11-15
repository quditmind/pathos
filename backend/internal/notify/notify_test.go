package notify

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultTemplatesRender(t *testing.T) {
	for _, e := range append(Events, testEvent) {
		sub, body, err := Render(e.Subject, e.Body, Sample(e.Key, "https://pathos.example"))
		if err != nil {
			t.Errorf("%s: %v", e.Key, err)
			continue
		}
		if sub == "" || strings.ContainsAny(sub, "\r\n") || !strings.HasPrefix(sub, "[PATHOS]") {
			t.Errorf("%s: bad subject %q", e.Key, sub)
		}
		if strings.Contains(body, "<no value>") {
			t.Errorf("%s: body references a missing field:\n%s", e.Key, body)
		}
		if !strings.Contains(body, "https://pathos.example/admin/notifications") {
			t.Errorf("%s: footer missing", e.Key)
		}
	}
}

func TestEventCatalogConsistency(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range Events {
		if seen[e.Key] {
			t.Errorf("duplicate event %s", e.Key)
		}
		seen[e.Key] = true
		for _, d := range e.Dynamic {
			if _, ok := DynamicLabels[d]; !ok {
				t.Errorf("%s: unknown dynamic recipient %s", e.Key, d)
			}
		}
	}
	for _, r := range systemRules {
		def, ok := LookupEvent(r.event)
		if !ok {
			t.Errorf("system rule %s: unknown event %s", r.key, r.event)
			continue
		}
		for _, d := range r.rc.Dynamic {
			if !contains(def.Dynamic, d) {
				t.Errorf("system rule %s: dynamic %s not valid for %s", r.key, d, r.event)
			}
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestRenderRejectsBrokenTemplates(t *testing.T) {
	d := Sample("scan.failed", "https://p")
	for _, tc := range [][2]string{{"{{.Nope}}", "x"}, {"ok", "{{range}}"}, {"ok", "{{.Scan.Missing}}"}} {
		if _, _, err := Render(tc[0], tc[1], d); err == nil {
			t.Errorf("%q / %q should fail", tc[0], tc[1])
		}
	}
	// Output is bounded.
	huge := "{{range .Findings}}" + strings.Repeat("x", 40000) + "{{end}}"
	if _, _, err := Render("s", huge, d); err == nil {
		t.Error("oversized output should fail")
	}
}

func TestBuildNeverLetsDataIntoHeaders(t *testing.T) {
	cfg := SMTPConfig{FromAddress: "pathos@acme.test", FromName: "PATHOS\r\nBcc: evil@x.test"}
	raw, err := Build(cfg, Message{To: "dev@acme.test", Subject: "Hello\r\nBcc: evil@x.test\nX-Evil: 1", Body: "line1\nline2", Event: "scan.failed\r\nX: y"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	head, body, _ := strings.Cut(string(raw), "\r\n\r\n")
	for _, line := range strings.Split(head, "\r\n") {
		name, _, _ := strings.Cut(line, ":")
		switch name {
		case "From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type", "Content-Transfer-Encoding",
			"Auto-Submitted", "X-Auto-Response-Suppress", "X-PATHOS-Event":
		default:
			t.Errorf("unexpected header line %q", line)
		}
	}
	if !strings.Contains(body, "line1\r\nline2") {
		t.Errorf("body line endings not normalized: %q", body)
	}
	for _, bad := range []string{"x\r\nBcc: e@x", "a@b.test, c@d.test", "Name <a@b.test>", ""} {
		if _, err := Build(cfg, Message{To: bad}, time.Now()); err == nil {
			t.Errorf("recipient %q should be rejected", bad)
		}
	}
}

func TestValidateHost(t *testing.T) {
	for _, h := range []string{"169.254.169.254", "127.0.0.1", "", "a b", "host:25", "x@y"} {
		if ValidateHost(h) == nil {
			t.Errorf("%q should be rejected", h)
		}
	}
	for _, h := range []string{"smtp.example.com", "mailpit", "10.0.0.5"} {
		if err := ValidateHost(h); err != nil {
			t.Errorf("%q: %v", h, err)
		}
	}
}

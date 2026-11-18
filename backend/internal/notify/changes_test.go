package notify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestChangeSummaryInNotifications(t *testing.T) {
	def, _ := LookupEvent("findings.new")
	d := Sample("findings.new", "https://pathos.example")
	_, body, err := Render(def.Subject, def.Body, d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "Changes since the previous scanned commit 3f6c1d2e9a8b (now 9a8b7c6d5e4f): +3 new (1 critical, 2 high), -1 fixed (1 medium).") {
		t.Errorf("body:\n%s", body)
	}
	// Scans without a summary render as before.
	d.Scan.Changes = nil
	_, body, _ = Render(def.Subject, def.Body, d)
	if strings.Contains(body, "Changes since") {
		t.Errorf("summary without data:\n%s", body)
	}
	// Webhooks carry the summary in scan.changes.
	d = Sample("findings.new", "https://pathos.example")
	raw, err := webhookPayload("json", uuid.New(), "findings.new", time.Now(), d)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Scan struct {
			Changes struct {
				BaseCommit string         `json:"base_commit"`
				New        map[string]int `json:"new"`
				FixedTotal int            `json:"fixed_total"`
			} `json:"changes"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(raw, &p); err != nil || p.Scan.Changes.BaseCommit == "" || p.Scan.Changes.New["critical"] != 1 || p.Scan.Changes.FixedTotal != 1 {
		t.Errorf("payload %s", raw)
	}
	if parseChanges([]byte(`{"base_commit":"abc","new":{"high":2},"new_total":2}`)).NewText != "2 high" || parseChanges(nil) != nil {
		t.Error("parseChanges")
	}
}

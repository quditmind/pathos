// Package notify delivers notifications: an outbox of events, rules that map
// events to recipients, templates, SMTP delivery with retries and an in-app
// inbox.
package notify

// EventDef describes one notification event.
type EventDef struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Severity    bool     `json:"severity"`   // carries a severity (rules may filter)
	Repository  bool     `json:"repository"` // scoped to a repository (rules may scope)
	Dynamic     []string `json:"dynamic"`    // dynamic recipients that apply
	Subject     string   `json:"default_subject"`
	Body        string   `json:"default_body"`
}

// Events is the catalog, in display order. smtp.test is internal.
var Events = []EventDef{
	{
		Key: "findings.new", Label: "New findings", Severity: true, Repository: true,
		Description: "A scan found new findings. Severity is the highest new severity.",
		Dynamic:     []string{"owners"},
		Subject:     `[PATHOS] {{.Scan.New}} new finding{{if ne .Scan.New 1}}s{{end}} in {{.Repository}}`,
		Body: `A {{.Scan.Trigger}} scan of {{.Repository}} found {{.Scan.New}} new finding{{if ne .Scan.New 1}}s{{end}}{{if .Scan.Fixed}} and resolved {{.Scan.Fixed}}{{end}}.
{{if .Scan.GateFailed}}
The security gate FAILED for this scan.
{{end}}
{{range .Findings}}- [{{.Severity}}] {{.Title}}{{if .Location}} ({{.Location}}){{end}}
{{end}}{{if gt .More 0}}…and {{.More}} more.
{{end}}
Review: {{.Link}}`,
	},
	{
		Key: "scan.failed", Label: "Scan failed", Repository: true,
		Description: "A scan job failed after its retries.",
		Dynamic:     []string{"owners"},
		Subject:     `[PATHOS] Scan failed: {{.Repository}}`,
		Body: `The {{.Scan.Trigger}} scan of {{.Repository}} failed after {{.Scan.Attempts}} attempt{{if ne .Scan.Attempts 1}}s{{end}}.

Error: {{.Scan.Error}}

Details: {{.Link}}`,
	},
	{
		Key: "finding.sla_breached", Label: "SLA breached", Severity: true, Repository: true,
		Description: "Open findings passed their remediation deadline (one message per repository and run).",
		Dynamic:     []string{"assignee", "owners"},
		Subject:     `[PATHOS] SLA breached: {{.Count}} finding{{if ne .Count 1}}s{{end}} in {{.Repository}}`,
		Body: `{{.Count}} open finding{{if ne .Count 1}}s{{end}} in {{.Repository}} passed {{if eq .Count 1}}its{{else}}their{{end}} remediation deadline:

{{range .Findings}}- [{{.Severity}}] {{.Title}} (due {{.SLADue}}{{if .Assignee}}, assigned to {{.Assignee}}{{end}})
{{end}}{{if gt .More 0}}…and {{.More}} more.
{{end}}
Review: {{.Link}}`,
	},
	{
		Key: "finding.assigned", Label: "Finding assigned", Severity: true, Repository: true,
		Description: "Someone assigned a finding to a user (self-assignment is not notified).",
		Dynamic:     []string{"assignee"},
		Subject:     `[PATHOS] Assigned to you: {{.Finding.Title}}`,
		Body: `{{if .Actor}}{{.Actor}}{{else}}Someone{{end}} assigned you a {{.Finding.Severity}} finding in {{.Repository}}:

{{.Finding.Title}}{{if .Finding.Location}}
Location: {{.Finding.Location}}{{end}}{{if .Finding.SLADue}}
Remediation due: {{.Finding.SLADue}}{{end}}

Open: {{.Link}}`,
	},
	{
		Key: "risk.requested", Label: "Risk acceptance requested", Severity: true, Repository: true,
		Description: "A risk acceptance awaits approval. Approvers are users who may accept risk for the repository, excluding the requester.",
		Dynamic:     []string{"approvers", "owners"},
		Subject:     `[PATHOS] Risk acceptance requested: {{.Finding.Title}}`,
		Body: `{{.Risk.RequestedBy}} requested a risk acceptance until {{.Risk.ExpiresAt}} for a {{.Finding.Severity}} finding in {{.Repository}}:

{{.Finding.Title}}

Justification:
{{.Risk.Justification}}

Approve or reject: {{.Link}}`,
	},
	{
		Key: "risk.decided", Label: "Risk acceptance decided", Severity: true, Repository: true,
		Description: "A risk acceptance was approved, rejected, revoked or expired.",
		Dynamic:     []string{"requester", "assignee"},
		Subject:     `[PATHOS] Risk acceptance {{.Risk.Status}}: {{.Finding.Title}}`,
		Body: `The risk acceptance for "{{.Finding.Title}}" in {{.Repository}} was {{.Risk.Status}}{{if .Risk.DecidedBy}} by {{.Risk.DecidedBy}}{{end}}.{{if .Risk.Note}}

Note: {{.Risk.Note}}{{end}}{{if eq .Risk.Status "expired" "revoked"}}

The finding is open again.{{end}}

Open: {{.Link}}`,
	},
	{
		Key: "schedule.missed", Label: "Schedule missed runs",
		Description: "The scheduler was unavailable when a schedule was due; it caught up once.",
		Subject:     `[PATHOS] Scan schedule missed {{.Schedule.Missed}} run{{if ne .Schedule.Missed 1}}s{{end}}: {{.Schedule.Name}}`,
		Body: `The scan schedule "{{.Schedule.Name}}" was due at {{.Schedule.DueAt}} but did not run on time; {{.Schedule.Missed}} activation{{if ne .Schedule.Missed 1}}s were{{else}} was{{end}} missed. PATHOS queued one catch-up run.

Check that the scheduler service is running: {{.Link}}`,
	},
	{
		Key: "worker.offline", Label: "Scan worker offline",
		Description: "A scan worker stopped polling for jobs.",
		Subject:     `[PATHOS] Scan worker offline: {{.Worker.Name}}`,
		Body: `The {{.Worker.Family}} scan worker "{{.Worker.Name}}" has not contacted PATHOS since {{.Worker.LastSeen}}.
{{.Worker.Queued}} scan job{{if ne .Worker.Queued 1}}s are{{else}} is{{end}} waiting in the queue.

Workers: {{.Link}}`,
	},
}

var testEvent = EventDef{
	Key: "smtp.test", Label: "Test email",
	Subject: `[PATHOS] Test email`,
	Body: `This is a test email from PATHOS ({{.Org}}).

If you can read this, email delivery works.`,
}

// LookupEvent returns the definition of key.
func LookupEvent(key string) (EventDef, bool) {
	if key == testEvent.Key {
		return testEvent, true
	}
	for _, e := range Events {
		if e.Key == key {
			return e, true
		}
	}
	return EventDef{}, false
}

// DynamicLabels names dynamic recipients for the UI.
var DynamicLabels = map[string]string{
	"assignee":  "Assignee",
	"requester": "Requester",
	"approvers": "Eligible approvers",
	"owners":    "Application owners",
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

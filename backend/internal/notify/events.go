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
{{with .Scan.Changes}}
Changes since the previous scanned commit{{if .BaseCommit}} {{.BaseShort}}{{end}}{{if .HeadCommit}} (now {{.HeadShort}}){{end}}: +{{.NewTotal}} new{{if .NewText}} ({{.NewText}}){{end}}, -{{.FixedTotal}} fixed{{if .FixedText}} ({{.FixedText}}){{end}}.
{{end}}{{if .Scan.GateFailed}}
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
		Key: "policy.violated", Label: "Security policy violated", Severity: true, Repository: true,
		Description: "Open findings newly violate a security policy that notifies (one message per policy, repository and run).",
		Dynamic:     []string{"assignee", "owners"},
		Subject:     `[PATHOS] Policy "{{.Policy}}": {{.Count}} finding{{if ne .Count 1}}s{{end}} in {{.Repository}}`,
		Body: `{{.Count}} open finding{{if ne .Count 1}}s{{end}} in {{.Repository}} violate{{if eq .Count 1}}s{{end}} the security policy "{{.Policy}}":

{{range .Findings}}- [{{.Severity}}] {{.Title}}{{if .Location}} ({{.Location}}){{end}}
{{end}}{{if gt .More 0}}…and {{.More}} more.
{{end}}
Review: {{.Link}}`,
	},
	{
		Key: "report.scheduled", Label: "Scheduled report", Repository: false,
		Description: "A scheduled custom report is ready. Recipients open it in PATHOS, where it shows only what they may see.",
		Dynamic:     []string{"report_recipients"},
		Subject:     `[PATHOS] Report ready: {{.Report}}`,
		Body: `Your scheduled report "{{.Report}}" is ready.

Open it: {{.Link}}`,
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
		Key: "repository.sync_failed", Label: "Repository sync failed", Repository: true,
		Description: "A repository could not be synchronized with its provider (deleted, access lost or provider error).",
		Dynamic:     []string{"owners"},
		Subject:     `[PATHOS] Repository sync failed: {{.Repository}}`,
		Body: `PATHOS could not synchronize {{.Repository}} with its source provider.

Status: {{.Sync.Status}}
Error: {{.Sync.Error}}

Check the repository and its connection: {{.Link}}`,
	},
	{
		Key: "import.failed", Label: "Repository import failed",
		Description: "A repository import job finished with failed items or items that need attention.",
		Dynamic:     []string{"requester"},
		Subject:     `[PATHOS] Repository import {{.Import.Status}}: {{.Import.Failed}} of {{.Import.Total}} item{{if ne .Import.Total 1}}s{{end}}`,
		Body: `A repository import requested by {{.Import.RequestedBy}} finished with {{.Import.Failed}} of {{.Import.Total}} item{{if ne .Import.Total 1}}s{{end}} failed or needing attention.

Review and retry: {{.Link}}`,
	},
	{
		Key: "schedule.completed", Label: "Scheduled scans completed",
		Description: "Every execution of a schedule activation finished successfully (only for schedules that ask for it).",
		Dynamic:     []string{"requester"},
		Subject:     `[PATHOS] Scheduled scans completed: {{.Schedule.Name}}`,
		Body: `All {{.Schedule.Succeeded}} scan execution{{if ne .Schedule.Succeeded 1}}s{{end}} of the schedule "{{.Schedule.Name}}" finished.

Details: {{.Link}}`,
	},
	{
		Key: "schedule.failed", Label: "Scheduled scans failed",
		Description: "A schedule activation finished with failed executions after its retries (only for schedules that ask for it).",
		Dynamic:     []string{"requester"},
		Subject:     `[PATHOS] Scheduled scans failed: {{.Schedule.Name}}`,
		Body: `The schedule "{{.Schedule.Name}}" finished with {{.Schedule.Failed}} failed and {{.Schedule.Succeeded}} successful scan execution{{if ne .Schedule.Succeeded 1}}s{{end}} (after the schedule's retries).

Details: {{.Link}}`,
	},
	{
		Key: "worker.offline", Label: "Scan worker offline",
		Description: "A scan worker stopped polling for jobs.",
		Subject:     `[PATHOS] Scan worker offline: {{.Worker.Name}}`,
		Body: `The {{.Worker.Family}} scan worker "{{.Worker.Name}}" has not contacted PATHOS since {{.Worker.LastSeen}}.
{{.Worker.Queued}} scan job{{if ne .Worker.Queued 1}}s are{{else}} is{{end}} waiting in the queue.

Workers: {{.Link}}`,
	},
	{
		Key: "review.assigned", Label: "Human Eye review assigned", Severity: true, Repository: true,
		Description: "A finding was assigned to an analyst for manual review (self-assignment is not notified).",
		Dynamic:     []string{"assignee"},
		Subject:     `[PATHOS] Review assigned to you: {{.Review.Key}} {{.Finding.Title}}`,
		Body: `{{if .Actor}}{{.Actor}}{{else}}PATHOS{{end}} assigned you a {{.Review.Priority}} review of a {{.Finding.Severity}} finding in {{.Repository}}:

{{.Finding.Title}}{{if .Finding.Location}}
Location: {{.Finding.Location}}{{end}}{{if .Review.DueAt}}
Review due: {{.Review.DueAt}}{{end}}

Open the assessment workspace: {{.Link}}`,
	},
	{
		Key: "review.independent_requested", Label: "Independent review requested", Severity: true, Repository: true,
		Description: "An analyst submitted a review decision that needs a second, independent reviewer.",
		Dynamic:     []string{"independent_reviewers"},
		Subject:     `[PATHOS] Independent review needed: {{.Review.Key}} ({{.Review.Disposition}})`,
		Body: `{{.Actor}} submitted the decision "{{.Review.Disposition}}" for a {{.Finding.Severity}} finding in {{.Repository}}:

{{.Finding.Title}}

The decision needs an independent review before the finding can be closed.

Review it: {{.Link}}`,
	},
	{
		Key: "review.independent_decided", Label: "Independent review decided", Severity: true, Repository: true,
		Description: "An independent reviewer approved, rejected or asked for more information on a review decision.",
		Dynamic:     []string{"requester", "assignee"},
		Subject:     `[PATHOS] Independent review {{.Review.Outcome}}: {{.Review.Key}}`,
		Body: `{{.Actor}} {{.Review.Outcome}} the decision on {{.Review.Key}} ({{.Finding.Title}}) in {{.Repository}}.

Open: {{.Link}}`,
	},
	{
		Key: "review.overdue", Label: "Human Eye review overdue", Severity: true, Repository: true,
		Description: "A human review passed its due date (one message per review).",
		Dynamic:     []string{"assignee"},
		Subject:     `[PATHOS] Review overdue: {{.Review.Key}} {{.Finding.Title}}`,
		Body: `The review {{.Review.Key}} of a {{.Finding.Severity}} finding in {{.Repository}} was due {{.Review.DueAt}} and is still {{.Review.Status}}:

{{.Finding.Title}}

Open: {{.Link}}`,
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
	"assignee":              "Assignee",
	"requester":             "Requester",
	"approvers":             "Eligible approvers",
	"owners":                "Application owners",
	"independent_reviewers": "Eligible independent reviewers",
	"report_recipients":     "Report recipients",
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

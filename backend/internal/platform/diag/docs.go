package diag

import (
	"fmt"
	"strings"
)

// DocsUpdated is the "updated" date of the generated pages. Change it when
// the catalogue changes (the docs test fails until `make docs-errors` is
// run, which keeps pages and catalogue in step).
const DocsUpdated = "2026-11-20"

// DocsSection is the Help Center section of the generated pages.
const DocsSection = "troubleshooting"

// docsOrderBase keeps troubleshooting pages after the API reference.
const docsOrderBase = 100

// EntriesOf returns the entries of an area in code order.
func EntriesOf(area string) []Entry {
	var out []Entry
	for _, e := range All() {
		if e.Area == area {
			out = append(out, e)
		}
	}
	return out
}

// DocFiles returns every generated page: file name → content. Areas
// without entries get no page; "index.md" lists the areas.
func DocFiles() map[string]string {
	out := map[string]string{"index.md": indexPage()}
	for i, a := range Areas {
		if es := EntriesOf(a.Key); len(es) > 0 {
			out[a.Slug+".md"] = areaPage(i, a, es)
		}
	}
	return out
}

const generatedNote = "> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.\n"

func frontMatter(title string, order int, summary string) string {
	return fmt.Sprintf("---\ntitle: %s\nsection: %s\norder: %d\nversion: \"1.0\"\nupdated: %s\nsummary: %s\n---\n",
		title, DocsSection, order, DocsUpdated, summary)
}

func indexPage() string {
	var b strings.Builder
	b.WriteString(frontMatter("Troubleshooting codes", docsOrderBase, "Every PATHOS error code (PTH-<AREA>-<NNNN>) by area, with its cause, impact, fix and how to verify it."))
	b.WriteString("\n# Troubleshooting codes\n\n")
	b.WriteString("Quditmind PATHOS · status: Production-ready\n\n")
	b.WriteString(generatedNote)
	b.WriteString("\nEvery error PATHOS reports carries a code of the form `PTH-<AREA>-<NNNN>` and a request ID. API errors return them in `error.error_code` and `error.request_id` (see the API reference, \"Errors\"); the server log lines of the same error carry `error_code` and `request_id`. Search for the code below, or open **Help → Troubleshooting centre**.\n\n")
	b.WriteString("| Area | Page | Codes |\n|---|---|---|\n")
	for _, a := range Areas {
		es := EntriesOf(a.Key)
		if len(es) == 0 {
			continue
		}
		fmt.Fprintf(&b, "| `%s` | [%s](%s.md) | %d |\n", a.Key, a.Title, a.Slug, len(es))
	}
	b.WriteString("\nAreas without codes yet: ")
	var empty []string
	for _, a := range Areas {
		if len(EntriesOf(a.Key)) == 0 {
			empty = append(empty, "`"+a.Key+"` ("+a.Title+")")
		}
	}
	b.WriteString(strings.Join(empty, ", ") + ". Their modules are planned; codes are added with them.\n")
	b.WriteString("\n## Confirmed and probable causes\n\n")
	b.WriteString("A cause is **confirmed** when the check that raised the error proves it (for example a rejected API token). Otherwise PATHOS lists **probable causes**, most likely first; work through them in order. **Troubleshoot with AI** is offered for codes marked \"AI help: offered\"; it sends only the code, the redacted message and non-secret context, and the catalogue steps below always remain available.\n")
	return b.String()
}

func areaPage(i int, a Area, es []Entry) string {
	var b strings.Builder
	b.WriteString(frontMatter("Troubleshooting: "+a.Title, docsOrderBase+1+i, fmt.Sprintf("%s (%d codes, PTH-%s-*)", strings.TrimSuffix(a.Summary, "."), len(es), a.Key)))
	fmt.Fprintf(&b, "\n# Troubleshooting: %s\n\n", a.Title)
	b.WriteString("Quditmind PATHOS · status: Production-ready\n\n")
	b.WriteString(generatedNote)
	fmt.Fprintf(&b, "\n%s\n\n", a.Summary)
	b.WriteString("| Code | Title | Severity |\n|---|---|---|\n")
	for _, e := range es {
		fmt.Fprintf(&b, "| [%s](#%s) | %s | %s |\n", e.Code, e.Code, e.Title, e.Severity)
	}
	for _, e := range es {
		b.WriteString("\n")
		writeEntry(&b, e)
	}
	return b.String()
}

func writeEntry(b *strings.Builder, e Entry) {
	fmt.Fprintf(b, "<a id=\"%s\"></a>\n\n## %s: %s\n\n", e.Code, e.Code, e.Title)
	b.WriteString("| | |\n|---|---|\n")
	fmt.Fprintf(b, "| Severity | %s |\n| Category | %s |\n", e.Severity, e.Category)
	if e.HTTPStatus != 0 {
		fmt.Fprintf(b, "| HTTP status | %d |\n", e.HTTPStatus)
	} else {
		b.WriteString("| HTTP status | none (background work and logs) |\n")
	}
	ai := "not offered"
	if e.AIHelp {
		ai = "offered"
	}
	fmt.Fprintf(b, "| AI help | %s |\n", ai)
	if len(e.Legacy) > 0 {
		ls := make([]string, len(e.Legacy))
		for i, l := range e.Legacy {
			ls[i] = "`" + l + "`"
		}
		fmt.Fprintf(b, "| Short codes | %s |\n", strings.Join(ls, ", "))
	}
	fmt.Fprintf(b, "| Raised in | %s |\n\n", e.Source)
	fmt.Fprintf(b, "**What it means.** %s\n\n", e.Description)
	how := "Confirmed automatically when this code is raised."
	if !e.Proven {
		how = "Shown as confirmed only when the failing check proves it; otherwise use the probable causes."
	}
	fmt.Fprintf(b, "**Confirmed cause.** %s %s\n\n", e.ConfirmedCause, how)
	writeList(b, "Probable causes", e.ProbableCauses)
	fmt.Fprintf(b, "**Impact.** %s\n\n", e.Impact)
	writeList(b, "How to fix", e.Actions)
	writeList(b, "Verify", e.Verify)
}

func writeList(b *strings.Builder, title string, items []string) {
	fmt.Fprintf(b, "**%s**\n\n", title)
	for i, it := range items {
		fmt.Fprintf(b, "%d. %s\n", i+1, it)
	}
	b.WriteString("\n")
}

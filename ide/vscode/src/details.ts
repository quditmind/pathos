// Finding details webview HTML. Pure: no VS Code dependency.
//
// Every value from PATHOS is untrusted scanner output and is HTML-escaped.
// The page has no scripts and loads nothing: the CSP is default-src 'none'
// with one nonce-protected inline style.

import { displayPath, formatCwes, severityLabel } from "./mapping";
import type { Finding } from "./types";

export function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"'`]/g, (c) => {
    switch (c) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      case "'":
        return "&#39;";
      default:
        return "&#96;";
    }
  });
}

/** Only absolute http(s) URLs are rendered as links. */
export function safeHttpUrl(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.toString() : null;
  } catch {
    return null;
  }
}

export interface DetailsOptions {
  /** Link to the finding in the PATHOS web UI. */
  webUrl: string;
  /** Random nonce for the inline style. */
  nonce: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#b42318",
  high: "#c4320a",
  medium: "#b54708",
  low: "#175cd3",
  info: "#475467",
};

function row(label: string, value: unknown): string {
  if (value === null || value === undefined || value === "") return "";
  return `<tr><th scope="row">${escapeHtml(label)}</th><td>${escapeHtml(value)}</td></tr>`;
}

function fmtDate(v: string | null | undefined): string {
  if (!v) return "";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? v : d.toISOString().slice(0, 10);
}

function humanize(v: string | null | undefined): string {
  return v ? v.replace(/_/g, " ") : "";
}

function remediation(f: Finding): string {
  if (f.package_name && f.fixed_version) {
    return `Upgrade ${f.package_name}${f.package_version ? ` from ${f.package_version}` : ""} to ${f.fixed_version} or later.`;
  }
  return "";
}

export function buildDetailsHtml(f: Finding, opts: DetailsOptions): string {
  const nonce = escapeHtml(opts.nonce);
  const sev = String(f.severity || "").toLowerCase();
  const color = SEVERITY_COLORS[sev] ?? SEVERITY_COLORS.info;
  const link = safeHttpUrl(opts.webUrl);
  const path = displayPath(f.file_path);
  const location = path ? (f.start_line ? `${path}:${f.start_line}` : path) : "";
  const pkg = f.package_name ? `${f.package_name}${f.package_version ? `@${f.package_version}` : ""}` : "";
  const fix = remediation(f);
  const review = f.human_review_key
    ? `${f.human_review_key}${f.human_review_status ? ` (${humanize(f.human_review_status)})` : ""}${f.human_disposition ? `: ${humanize(f.human_disposition)}` : ""}`
    : "";

  const rows = [
    row("Severity", severityLabel(f.severity)),
    row("Status", humanize(f.lifecycle_status || f.status)),
    row("Risk score", typeof f.risk_score === "number" ? `${Math.round(f.risk_score)} / 100` : "not scored"),
    row("CWE", formatCwes(f.cwe).join(", ")),
    row("CVE", f.cve),
    row("CVSS", typeof f.cvss === "number" ? f.cvss.toFixed(1) : ""),
    row("EPSS percentile", typeof f.epss_percentile === "number" ? `${Math.round(f.epss_percentile * 100)}%` : ""),
    row("Known exploited (KEV)", f.kev ? "yes" : ""),
    row("Reachability", f.reachability && f.reachability !== "unknown" ? humanize(f.reachability) : ""),
    row("Scanner", (f.scanner_keys ?? []).join(", ")),
    row("Rule", f.rule_id),
    row("Category", f.category),
    row("Location", location),
    row("Package", pkg),
    row("Target", f.scan_target_name ? `${f.scan_target_kind ?? ""} ${f.scan_target_name}`.trim() : ""),
    row("Assignee", f.assignee_name),
    row("SLA due", fmtDate(f.sla_due_at)),
    row("Human Eye review", review),
    row("Repository", f.repository_name),
    row("First seen", fmtDate(f.first_seen_at)),
    row("Last seen", fmtDate(f.last_seen_at)),
  ].join("");

  const snippet = f.snippet
    ? `<h2>Code</h2><pre class="code">${escapeHtml(f.snippet)}</pre>${
        f.snippet_start_line ? `<p class="muted">From line ${escapeHtml(f.snippet_start_line)}</p>` : ""
      }`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; img-src 'none'; script-src 'none'; form-action 'none'; base-uri 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(f.title || "Finding")}</title>
<style nonce="${nonce}">
body { font-family: var(--vscode-font-family); font-size: var(--vscode-font-size); color: var(--vscode-foreground); padding: 0 16px 24px; line-height: 1.5; }
h1 { font-size: 1.4em; margin: 16px 0 8px; word-break: break-word; }
h2 { font-size: 1.1em; margin: 20px 0 6px; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px; color: #fff; background: ${color}; font-size: 0.85em; font-weight: 600; }
table { border-collapse: collapse; margin: 8px 0; }
th { text-align: left; font-weight: 600; padding: 3px 16px 3px 0; vertical-align: top; white-space: nowrap; color: var(--vscode-descriptionForeground); }
td { padding: 3px 0; word-break: break-word; }
.text { white-space: pre-wrap; word-break: break-word; }
pre.code { font-family: var(--vscode-editor-font-family); font-size: var(--vscode-editor-font-size); background: var(--vscode-textCodeBlock-background); padding: 8px; overflow-x: auto; white-space: pre; }
.muted { color: var(--vscode-descriptionForeground); }
a { color: var(--vscode-textLink-foreground); }
</style>
</head>
<body>
<h1>${escapeHtml(f.title || "Untitled finding")}</h1>
<p><span class="badge">${escapeHtml(severityLabel(f.severity))}</span></p>
<table>${rows}</table>
${link ? `<p><a href="${escapeHtml(link)}">Open in PATHOS</a></p>` : ""}
<h2>Description</h2>
<div class="text">${f.description ? escapeHtml(f.description) : '<span class="muted">No description provided by the scanner.</span>'}</div>
<h2>Remediation</h2>
<div class="text">${fix ? escapeHtml(fix) : '<span class="muted">See the description and PATHOS for remediation guidance.</span>'}</div>
${snippet}
</body>
</html>`;
}

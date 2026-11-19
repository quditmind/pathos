import { Link } from "@tanstack/react-router";
import { ExternalLink } from "lucide-react";
import { SeverityBadge } from "@/components/data/Severity";
import { Badge } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { humanize } from "../shared";
import type { ReviewDetail } from "../types";
import { KV, Panel } from "./section";
import { findingCheckLabel } from "@/lib/checkKinds";

const cweUrl = (c: string) => `https://cwe.mitre.org/data/definitions/${c.replace(/^CWE-/i, "")}.html`;

export function OverviewTab({ d, openSource }: { d: ReviewDetail; openSource: (path: string, line?: number) => void }) {
  const f = d.finding;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel title="Finding" className="lg:col-span-2">
        <KV
          rows={[
            ["Finding ID", <span className="font-mono text-[12px]">{d.review_key} · {f.id}</span>],
            ["Vulnerability", f.title],
            ["Rule", <span className="font-mono text-[12px]">{f.rule_id}</span>],
            ["Category", f.category.toUpperCase()],
            ["Kind of check", findingCheckLabel(f)],
            ["Detected severity", <span className="flex items-center gap-2"><SeverityBadge value={d.original.severity} />{d.original.cvss != null && <span className="tabular text-[12px]">CVSS {d.original.cvss.toFixed(1)}</span>}</span>],
            ["Human-assessed severity", d.assessed_severity ? <span className="flex items-center gap-2"><SeverityBadge value={d.assessed_severity} />{d.assessed_cvss != null && <span className="tabular text-[12px]">CVSS {d.assessed_cvss.toFixed(1)}</span>}</span> : "Not assessed yet"],
            ["CWE", f.cwe.length ? <span className="flex flex-wrap gap-1.5">{f.cwe.map((c) => <a key={c} href={cweUrl(c)} target="_blank" rel="noreferrer noopener" className="text-primary hover:underline">{c}</a>)}</span> : "—"],
            ["CVE", f.cve ? <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve)}`} target="_blank" rel="noreferrer noopener" className="text-primary hover:underline">{f.cve}</a> : "—"],
            ["OWASP Top 10", f.owasp.length ? <span className="flex flex-wrap gap-1">{f.owasp.map((o) => <Badge key={o}>{o}</Badge>)}<span className="text-[11px] text-muted-foreground">(derived from CWE)</span></span> : "—"],
            ...(f.package_name ? ([["Package", `${f.package_name}@${f.package_version}${f.fixed_version ? ` (fixed in ${f.fixed_version})` : ""}`]] as [string, React.ReactNode][]) : []),
          ]}
        />
        {f.description && <p className="mt-3 whitespace-pre-wrap text-[13px] leading-relaxed">{f.description}</p>}
      </Panel>

      <Panel title="Location (as scanned)">
        <KV
          rows={[
            ["Repository", <span>{d.repository_name} <span className="font-mono text-[11px] text-muted-foreground">{d.repository_key} · {d.repository_id}</span></span>],
            ["Application", d.application_name ?? "—"],
            ["Branch", <span className="font-mono text-[12px]">{d.branch || "—"}</span>],
            ["Commit", <span className="font-mono text-[12px]">{d.commit_sha || (d.source_type === "upload" ? "uploaded snapshot" : "not recorded")}</span>],
            [
              "File",
              d.file_path ? (
                <button type="button" className="text-left font-mono text-[12px] text-primary hover:underline" onClick={() => openSource(d.file_path, d.start_line ?? undefined)}>
                  {d.file_path}{d.start_line ? `:${d.start_line}` : ""}
                </button>
              ) : "—",
            ],
            ["Detected", formatDateTime(f.first_seen_at)],
            ["Last seen", formatDateTime(f.last_seen_at)],
            ["Scan", d.scan_job_id ? <Link to="/scans/$id" params={{ id: d.scan_job_id }} className="font-mono text-[12px] text-primary hover:underline">{d.scan_key ?? d.scan_job_id}</Link> : "—"],
          ]}
        />
      </Panel>

      <Panel title="Review">
        <KV
          rows={[
            ["Added", `${formatDateTime(d.created_at)} · ${d.source === "automatic" ? "automatically" : `manually by ${d.created_by_name ?? "—"}`}`],
            ["Reason", d.source_reason || "—"],
            ["Finding status", humanize(d.finding_status)],
            ["Finding assignee", f.assignee_name ?? "—"],
            ["Remediation SLA", formatDateTime(f.sla_due_at)],
            ["Evidence items", d.evidence_count],
          ]}
        />
      </Panel>

      <Panel title="Automated triage">
        <KV
          rows={[
            ["Finding status", humanize(d.triage.status)],
            ["Last change by", d.triage.source ? humanize(d.triage.source) : "—"],
            ["Reason", d.triage.reason || "—"],
            ["When", formatDateTime(d.triage.changed_at)],
          ]}
        />
      </Panel>

      <Panel title="AI review summary">
        {d.ai_review ? (
          <div className="space-y-2 text-[13px]">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="primary">AI suggestion</Badge>
              <span>Verdict: <strong>{humanize(d.ai_review.verdict)}</strong></span>
              <span className="tabular text-muted-foreground">confidence {Math.round(d.ai_review.confidence * 100)}%</span>
              {d.ai_review.suggested_severity && <SeverityBadge value={d.ai_review.suggested_severity as never} />}
            </div>
            <p className="whitespace-pre-wrap">{d.ai_review.rationale}</p>
            <p className="text-[11.5px] text-muted-foreground">
              {d.ai_review.model} · {humanize(d.ai_review.status)} · {formatDateTime(d.ai_review.created_at)}
            </p>
          </div>
        ) : (
          <p className="text-[12.5px] text-muted-foreground">No AI review of this finding is available.</p>
        )}
      </Panel>

      <Panel title="Original scanner output" className="lg:col-span-2" actions={<span className="text-[11px] text-muted-foreground">Preserved independently of human decisions · secrets redacted</span>}>
        {d.original.output ? (
          <div className="space-y-2">
            <pre className="max-h-96 overflow-auto rounded-md bg-surface-muted p-3 font-mono text-[11.5px] leading-relaxed">{JSON.stringify(d.original.output, null, 2)}</pre>
            {d.original.rule != null && (
              <details>
                <summary className="cursor-pointer text-[12px] text-muted-foreground">Rule definition</summary>
                <pre className="mt-1 max-h-72 overflow-auto rounded-md bg-surface-muted p-3 font-mono text-[11.5px]">{JSON.stringify(d.original.rule, null, 2)}</pre>
              </details>
            )}
            <p className="text-[11px] text-muted-foreground">Captured {formatDateTime(d.original.captured_at)}</p>
          </div>
        ) : (
          <p className="flex items-center gap-1 text-[12.5px] text-muted-foreground">
            {d.original.capture_error ? `Unavailable: ${d.original.capture_error}.` : "Not captured yet."}
            {d.scan_job_id && (
              <Link to="/scans/$id" params={{ id: d.scan_job_id }} className="inline-flex items-center gap-0.5 text-primary hover:underline">
                Open the scan <ExternalLink className="size-3" />
              </Link>
            )}
          </p>
        )}
      </Panel>
    </div>
  );
}

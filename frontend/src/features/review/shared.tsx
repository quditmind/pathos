import { useState, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { ChevronLeft, ChevronRight, Search, X } from "lucide-react";
import { api } from "@/api/client";
import type { Page, Repository, Severity } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Combobox, type ComboOption } from "@/components/ui/combobox";
import { Badge, Input, Select } from "@/components/ui/primitives";
import { useApplications } from "@/features/repos/api";
import { CHECK_KINDS, kindOfTool, toolKeysOfKind } from "@/lib/checkKinds";
import { cn } from "@/lib/utils";
import { useReviewers } from "./api";
import type { Disposition, Priority, RemediationStatus, ReviewFilters, ReviewStatus } from "./types";

export const severities: Severity[] = ["critical", "high", "medium", "low", "info"];

export const statusLabel: Record<ReviewStatus, string> = {
  pending: "Pending",
  assigned: "Assigned",
  in_progress: "In progress",
  awaiting_information: "Awaiting information",
  awaiting_independent_review: "Awaiting independent review",
  completed: "Completed",
  reopened: "Reopened",
};

export const dispositionLabel: Record<Disposition, string> = {
  confirmed: "Confirmed",
  false_positive: "False positive",
  duplicate: "Duplicate",
  not_exploitable: "Not exploitable",
  accepted_risk: "Accepted risk",
  mitigated: "Mitigated",
  needs_more_information: "Needs more information",
  out_of_scope: "Out of scope",
};

export const remediationLabel: Record<RemediationStatus, string> = {
  not_required: "Not required",
  open: "Open",
  in_progress: "In progress",
  fixed: "Fixed",
  pending_verification: "Pending verification",
  verified: "Verified",
  reopened: "Reopened",
};

export const priorityLabel: Record<Priority, string> = { p1: "P1 · Urgent", p2: "P2 · High", p3: "P3 · Normal", p4: "P4 · Low" };

export const aiKindLabel: Record<string, string> = {
  explanation: "Explain the vulnerability",
  code_summary: "Summarize the code",
  code_paths: "Identify vulnerable code paths",
  investigation_questions: "Suggest investigation questions",
  false_positive_indicators: "False-positive indicators",
  evidence_suggestions: "Suggest evidence to collect",
  remediation: "Suggest remediation",
  secure_code: "Secure code example",
  references: "CWE / OWASP references",
  assessment_summary: "Draft an assessment summary",
  patch: "Propose a patch (reviewed by you, never applied)",
  risk_explanation: "Explain the risk score",
  duplicate_candidates: "Find possible duplicates",
};

export const evidenceTypeLabel: Record<string, string> = {
  screenshot: "Screenshot",
  code_snippet: "Source code snippet",
  http_request: "HTTP request",
  http_response: "HTTP response",
  command_output: "Command output",
  application_log: "Application log",
  security_log: "Security log",
  reproduction_result: "Reproduction result",
  document: "Supporting document",
  other: "Other",
};

export const humanize = (s: string) => s.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

const statusTone: Record<ReviewStatus, "neutral" | "primary" | "warning" | "success" | "danger"> = {
  pending: "neutral",
  assigned: "neutral",
  in_progress: "primary",
  awaiting_information: "warning",
  awaiting_independent_review: "warning",
  completed: "success",
  reopened: "danger",
};

export function StatusBadge({ status }: { status: ReviewStatus }) {
  return <Badge tone={statusTone[status]}>{statusLabel[status]}</Badge>;
}

const dispositionTone: Record<Disposition, "neutral" | "primary" | "warning" | "success" | "danger"> = {
  confirmed: "danger",
  false_positive: "success",
  duplicate: "neutral",
  not_exploitable: "success",
  accepted_risk: "warning",
  mitigated: "primary",
  needs_more_information: "warning",
  out_of_scope: "neutral",
};

export function DispositionBadge({ value }: { value: Disposition | null | undefined }) {
  if (!value) return <span className="text-[12px] text-muted-foreground">—</span>;
  return <Badge tone={dispositionTone[value]}>{dispositionLabel[value]}</Badge>;
}

export function PriorityBadge({ value }: { value: Priority }) {
  const tone = value === "p1" ? "danger" : value === "p2" ? "warning" : "neutral";
  return (
    <Badge tone={tone} className="font-mono uppercase">
      {value}
    </Badge>
  );
}

export function ReviewKeyLink({ id, reviewKey, className }: { id: string; reviewKey: string; className?: string }) {
  return (
    <Link
      to="/human-review/reviews/$id"
      params={{ id }}
      onClick={(e) => e.stopPropagation()}
      className={cn("whitespace-nowrap font-mono text-[12px] text-primary hover:underline", className)}
    >
      {reviewKey}
    </Link>
  );
}

export const fmtHours = (h: number | null | undefined) => {
  if (h == null) return "—";
  if (h < 1) return `${Math.round(h * 60)} min`;
  if (h < 48) return `${h.toFixed(1)} h`;
  return `${(h / 24).toFixed(1)} d`;
};

export function RepoFilter({ value, onChange }: { value?: string; onChange: (v?: string) => void }) {
  const [picked, setPicked] = useState<ComboOption | null>(null);
  const current = value ? (picked?.value === value ? picked : { value, label: "Selected repository" }) : null;
  return (
    <Combobox
      ariaLabel="Filter by repository"
      className="w-52"
      placeholder="Repository…"
      queryKey="hr-filter-repo"
      value={current}
      load={(q, signal) => {
        const p = new URLSearchParams({ limit: "20" });
        if (q) p.set("q", q);
        return api<Page<Repository>>(`/api/v1/repositories?${p}`, { signal }).then((r) =>
          r.items.map((x) => ({ value: x.id, label: x.full_name, description: x.repository_key })),
        );
      }}
      onChange={(o) => {
        setPicked(o);
        onChange(o?.value);
      }}
    />
  );
}

/** Shared filter row (queue, assessments, overview, reports). */
export function ReviewFilterBar({
  values,
  onChange,
  onReset,
  show,
  trailing,
}: {
  values: ReviewFilters;
  onChange: (k: keyof ReviewFilters, v?: string) => void;
  onReset: () => void;
  show: ("q" | "date" | "repository" | "application" | "scanner" | "severity" | "reviewer" | "status" | "disposition" | "priority" | "overdue")[];
  trailing?: ReactNode;
}) {
  const reviewers = useReviewers();
  const apps = (useApplications().data ?? []).map((a) => ({ value: a.id, label: a.name }));
  const [q, setQ] = useState(values.q ?? "");
  const has = (k: (typeof show)[number]) => show.includes(k);
  const active = Object.entries(values).some(([k, v]) => v && !["sort", "order", "page", "page_size"].includes(k));
  return (
    <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filters">
      {has("q") && (
        <form
          className="relative"
          onSubmit={(e) => {
            e.preventDefault();
            onChange("q", q.trim() || undefined);
          }}
        >
          <Search className="pointer-events-none absolute left-2 top-2 size-4 text-muted-foreground" aria-hidden />
          <Input
            aria-label="Search by review or finding ID, vulnerability, repository or file path"
            placeholder="ID, vulnerability, repository, file…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onBlur={() => onChange("q", q.trim() || undefined)}
            className="w-64 pl-7"
          />
        </form>
      )}
      {has("date") && (
        <>
          <Input type="date" aria-label="From date" value={values.from ?? ""} onChange={(e) => onChange("from", e.target.value || undefined)} className="w-36" />
          <span className="text-[12px] text-muted-foreground">to</span>
          <Input type="date" aria-label="To date" value={values.to ?? ""} onChange={(e) => onChange("to", e.target.value || undefined)} className="w-36" />
        </>
      )}
      {has("repository") && <RepoFilter value={values.repository_id} onChange={(v) => onChange("repository_id", v)} />}
      {has("application") && (
        <Select aria-label="Application" value={values.application_id ?? ""} onChange={(e) => onChange("application_id", e.target.value || undefined)} className="max-w-44">
          <option value="">All applications</option>
          {apps.map((a) => (
            <option key={a.value} value={a.value}>{a.label}</option>
          ))}
        </Select>
      )}
      {has("scanner") && (
        <Select
          aria-label="Kind of check"
          value={values.scanner ? kindOfTool(values.scanner.split(",")[0]!) : ""}
          onChange={(e) => onChange("scanner", e.target.value ? toolKeysOfKind(e.target.value).join(",") : undefined)}
          className="max-w-48"
        >
          <option value="">All kinds of check</option>
          {CHECK_KINDS.filter((k) => toolKeysOfKind(k.id).length > 0).map((k) => (
            <option key={k.id} value={k.id}>{k.name}</option>
          ))}
        </Select>
      )}
      {has("severity") && (
        <Select aria-label="Severity" value={values.severity ?? ""} onChange={(e) => onChange("severity", e.target.value || undefined)}>
          <option value="">All severities</option>
          {severities.map((s) => (
            <option key={s} value={s}>{humanize(s)}</option>
          ))}
        </Select>
      )}
      {has("reviewer") && (
        <Select aria-label="Reviewer" value={values.reviewer ?? ""} onChange={(e) => onChange("reviewer", e.target.value || undefined)} className="max-w-44">
          <option value="">All reviewers</option>
          <option value="me">Assigned to me</option>
          <option value="none">Unassigned</option>
          {(reviewers.data ?? []).filter((r) => r.can_assess).map((r) => (
            <option key={r.id} value={r.id}>{r.name}</option>
          ))}
        </Select>
      )}
      {has("status") && (
        <Select aria-label="Review status" value={values.status ?? ""} onChange={(e) => onChange("status", e.target.value || undefined)} className="max-w-48">
          <option value="">All statuses</option>
          <option value="open">Open (not completed)</option>
          {(Object.keys(statusLabel) as ReviewStatus[]).map((s) => (
            <option key={s} value={s}>{statusLabel[s]}</option>
          ))}
        </Select>
      )}
      {has("disposition") && (
        <Select aria-label="Final disposition" value={values.disposition ?? ""} onChange={(e) => onChange("disposition", e.target.value || undefined)} className="max-w-44">
          <option value="">All dispositions</option>
          {(Object.keys(dispositionLabel) as Disposition[]).map((d) => (
            <option key={d} value={d}>{dispositionLabel[d]}</option>
          ))}
        </Select>
      )}
      {has("priority") && (
        <Select aria-label="Priority" value={values.priority ?? ""} onChange={(e) => onChange("priority", e.target.value || undefined)}>
          <option value="">All priorities</option>
          {(Object.keys(priorityLabel) as Priority[]).map((p) => (
            <option key={p} value={p}>{priorityLabel[p]}</option>
          ))}
        </Select>
      )}
      {has("overdue") && (
        <label className="flex items-center gap-1.5 text-[12.5px]">
          <input
            type="checkbox"
            className="size-3.5 accent-[var(--primary)]"
            checked={values.overdue === "true"}
            onChange={(e) => onChange("overdue", e.target.checked ? "true" : undefined)}
          />
          Overdue only
        </label>
      )}
      {active && (
        <Button variant="ghost" size="sm" onClick={() => { setQ(""); onReset(); }}>
          <X /> Clear filters
        </Button>
      )}
      {trailing && <div className="ml-auto flex items-center gap-2">{trailing}</div>}
    </div>
  );
}

export function Pagination({ page, pageSize, total, onPage, onPageSize }: { page: number; pageSize: number; total: number; onPage: (p: number) => void; onPageSize: (n: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <nav className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2 text-[12px] text-muted-foreground" aria-label="Pagination">
      <span className="tabular">
        {from}–{to} of {total}
      </span>
      <div className="flex items-center gap-2">
        <Select aria-label="Rows per page" value={pageSize} onChange={(e) => onPageSize(Number(e.target.value))}>
          {[25, 50, 100].map((n) => (
            <option key={n} value={n}>{n} per page</option>
          ))}
        </Select>
        <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
          <ChevronLeft />
        </Button>
        <span className="tabular">
          Page {page} of {pages}
        </span>
        <Button variant="ghost" size="sm" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page">
          <ChevronRight />
        </Button>
      </div>
    </nav>
  );
}

/** Reads ReviewFilters from router search params (strings only). */
export function filtersFromSearch(s: Record<string, unknown>, keys: (keyof ReviewFilters)[]): ReviewFilters {
  const out: ReviewFilters = {};
  for (const k of keys) {
    const v = s[k];
    if (typeof v === "string" && v.length <= 200) out[k] = v;
    else if (typeof v === "number") out[k] = String(v);
  }
  return out;
}

export const allFilterKeys: (keyof ReviewFilters)[] = [
  "q", "status", "disposition", "remediation_status", "severity", "priority", "scanner", "category", "repository_id", "application_id",
  "reviewer", "independent_reviewer", "overdue", "source", "branch", "from", "to", "sort", "order", "page", "page_size",
];

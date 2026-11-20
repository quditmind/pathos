import { RelatedFindings } from "@/features/vuln/RelatedFindings";
import { CreateRemediationItems } from "@/features/remediation/CreateItems";
import { categoryLabel } from "@/lib/findingCategories";
import { FindingDependencyPaths } from "@/features/posture/DependencyPanel";
import { IntroducedBy } from "./IntroducedBy";
import { SecretStatusBadge, SecretValidationPanel, secretStatusLabel } from "./SecretValidation";
import { FindingRuntime } from "@/features/runtime/FindingRuntime";
import { ReachabilitySection } from "./Reachability";
import { useDeferredValue, useEffect, useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Bot, Search, ShieldCheck, X } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { FindingTickets } from "@/features/integrations/IntegrationsPage";
import { FindingFixPR } from "@/features/fixprs/FixPRPanel";
import { FindingAIFix } from "@/features/aifix/AIFixPanel";
import { AIEvidencePanel } from "@/features/ai/AIEvidencePanel";
import { CorrelationSection } from "@/features/ai/CorrelationSection";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { useSession } from "@/features/auth/session";
import { useAIMutation, useFindingReviews } from "@/features/ai/api";
import { ReviewCard } from "@/features/ai/ReviewCard";
import type { Finding, Severity } from "@/api/types";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { FilterBar, type FilterDef } from "@/components/data/FilterBar";
import { severityColor, SeverityBadge } from "@/components/data/Severity";
import { useRepositories } from "@/features/repos/api";
import { cn, formatDateTime } from "@/lib/utils";
import { useFinding, useFindings, useFindingSummary } from "@/features/scans/api";
import { CHECK_KINDS, findingCheckLabel, toolCheckLabel } from "@/lib/checkKinds";
import { LifecyclePanel, slaState } from "@/features/vuln/LifecyclePanel";
import { needsReason, statusLabel, useVulnMutation } from "@/features/vuln/api";
import { reviewApi } from "@/features/review/api";
import { dispositionLabel, statusLabel as reviewStatusLabel } from "@/features/review/shared";
import type { Disposition, ReviewStatus } from "@/features/review/types";
import { KevBadge, MaliciousBadge, LifecycleBadge, lifecycleLabel, pct, RiskBadge, RiskPanel } from "@/features/vuln/intel";
import { ErrorPanel } from "@/components/ui/error-panel";

/** Human Eye outcome of a finding (link to the assessment workspace). */
function HumanReviewCell({ f }: { f: Finding }) {
  if (!f.human_review_id) return <span className="text-muted-foreground">—</span>;
  const label = f.human_disposition ? dispositionLabel[f.human_disposition as Disposition] : reviewStatusLabel[f.human_review_status as ReviewStatus] ?? f.human_review_status;
  return (
    <Link to="/human-review/reviews/$id" params={{ id: f.human_review_id }} onClick={(e) => e.stopPropagation()} className="whitespace-nowrap text-[12px] text-primary hover:underline" title={f.human_review_key ?? undefined}>
      {label}
    </Link>
  );
}

type FindingSearch = { application_id?: string; control?: string; malicious?: string; deployed?: string; internet_exposed?: string; status?: string; severity?: string; category?: string; kind?: string; scanner?: string; repository_id?: string; assignee?: string; sla?: string; human_review?: string; lifecycle?: string; kev?: string; risk_min?: string; sort?: string; q?: string; finding?: string; target_kind?: string; scan_target_id?: string; secret_validation?: string; reachability?: string; reachability_method?: string };
export const validateFindingSearch = (s: Record<string, unknown>): FindingSearch => {
  const out: FindingSearch = {};
  for (const k of ["application_id", "control", "malicious", "deployed", "internet_exposed", "status", "severity", "category", "kind", "scanner", "repository_id", "assignee", "sla", "human_review", "lifecycle", "kev", "risk_min", "sort", "q", "finding", "target_kind", "scan_target_id", "secret_validation", "reachability", "reachability_method"] as const) if (typeof s[k] === "string") out[k] = s[k] as string;
  return out;
};


function location(f: Finding) {
  if ((f.category === "sca" || f.category === "container") && f.package_name) return `${f.package_name}@${f.package_version}`;
  if (f.category === "eol" && f.package_name) return `${f.package_name} ${f.package_version}${f.file_path ? ` (${f.file_path})` : ""}`;
  return f.file_path ? `${f.file_path}${f.start_line ? `:${f.start_line}` : ""}` : "—";
}

const columns: Column<Finding>[] = [
  { id: "severity", header: "Severity", required: true, cell: (f) => <SeverityBadge value={f.severity} />, csv: (f) => f.severity },
  { id: "risk", header: "Risk", cell: (f) => <span className="flex items-center gap-1"><RiskBadge score={f.risk_score} />{f.malicious && <MaliciousBadge />}{f.kev && <KevBadge />}{f.secret_validation?.status === "active" && <SecretStatusBadge status="active" />}</span>, csv: (f) => f.risk_score ?? "" },
  { id: "runtime", header: "Runtime", defaultHidden: true, exportAlways: true, className: "whitespace-nowrap text-[12px]", cell: (f) => f.runtime_status === "deployed" ? (f.runtime_exposed ? "Deployed · exposed" : "Deployed") : f.runtime_status === "not_deployed" ? "Not deployed" : "—", csv: (f) => f.runtime_status ? `${f.runtime_status}${f.runtime_exposed ? ";internet_exposed" : ""}` : "" },
  {
    id: "title",
    header: "Finding",
    required: true,
    cell: (f) => (
      <div className="min-w-0 max-w-xl">
        <div className="truncate font-medium">{f.title}</div>
        <div className="truncate text-[12px] text-muted-foreground">
          {f.repository_name}
          {f.repository_key && <span className="ml-1 font-mono text-[11px]">({f.repository_key})</span>}
          {f.scan_target_name && <span> · {f.scan_target_name}</span>} · <span className="font-mono">{location(f)}</span>
        </div>
      </div>
    ),
    csv: (f) => f.title,
  },
  { id: "repository", header: "Repository", defaultHidden: true, exportAlways: true, className: "text-[12px]", cell: (f) => f.repository_name, csv: (f) => f.repository_name },
  { id: "repository_key", header: "Repository ID", defaultHidden: true, exportAlways: true, className: "whitespace-nowrap font-mono text-[11.5px]", cell: (f) => f.repository_key || "—", csv: (f) => f.repository_key },
  { id: "category", header: "Type", cell: (f) => <span className="whitespace-nowrap text-[12px]">{f.category === "sca" ? "SCA" : f.category === "sast" ? "SAST" : f.category === "iac" ? "IaC" : f.category === "dast" ? "DAST" : categoryLabel[f.category] ?? f.category}</span>, csv: (f) => f.category },
  { id: "rule", header: "Rule / CVE", cell: (f) => <span className="whitespace-nowrap font-mono text-[11.5px]">{f.cve || f.rule_id}</span>, csv: (f) => f.cve || f.rule_id },
  { id: "scanners", header: "Kind of check", defaultHidden: true, cell: (f) => <span className="text-[12px]">{findingCheckLabel(f)}</span>, csv: (f) => findingCheckLabel(f) },
  { id: "status", header: "Status", cell: (f) => f.lifecycle_status ? <LifecycleBadge value={f.lifecycle_status} /> : <span className="whitespace-nowrap text-[12px]">{statusLabel[f.status] ?? f.status}</span>, csv: (f) => f.lifecycle_status ?? f.status },
  { id: "epss", header: "EPSS", defaultHidden: true, exportAlways: true, className: "tabular text-[12px]", cell: (f) => (f.epss != null ? <span title={`percentile ${pct(f.epss_percentile)}`}>{pct(f.epss)}</span> : "—"), csv: (f) => f.epss ?? "" },
  { id: "kev", header: "KEV", defaultHidden: true, exportAlways: true, cell: (f) => (f.kev ? "Yes" : "—"), csv: (f) => (f.kev ? "yes" : "no") },
  { id: "secret_validation", header: "Secret check", defaultHidden: true, exportAlways: true, className: "text-[12px]",
    cell: (f) => (f.secret_validation ? secretStatusLabel[f.secret_validation.status] : "—"), csv: (f) => f.secret_validation?.status ?? "" },
  { id: "confidence", header: "Confidence", defaultHidden: true, exportAlways: true, className: "text-[12px] capitalize", cell: (f) => f.confidence ?? "—", csv: (f) => f.confidence },
  { id: "application", header: "Application", defaultHidden: true, exportAlways: true, className: "text-[12px]", cell: (f) => f.application_name ?? "—", csv: (f) => f.application_name },
  {
    id: "sla", header: "SLA",
    cell: (f) => { const s = slaState(f); return s ? <Badge tone={s.tone}>{s.label.replace("SLA ", "")}</Badge> : <span className="text-muted-foreground">—</span>; },
    csv: (f) => f.sla_due_at,
  },
  { id: "assignee", header: "Assignee", cell: (f) => <span className="whitespace-nowrap text-[12px]">{f.assignee_name ?? <span className="text-muted-foreground">—</span>}</span>, csv: (f) => f.assignee_name },
  { id: "first", header: "First seen", className: "tabular whitespace-nowrap text-[12px] text-muted-foreground", cell: (f) => formatDateTime(f.first_seen_at), csv: (f) => f.first_seen_at },
  { id: "fix", header: "Fixed version", defaultHidden: true, className: "text-[12px]", cell: (f) => f.fixed_version || "—", csv: (f) => f.fixed_version },
  { id: "path", header: "Location", defaultHidden: true, className: "font-mono text-[11.5px]", cell: location, csv: location },
  { id: "human_review", header: "Human Eye", cell: (f) => <HumanReviewCell f={f} />, csv: (f) => f.human_disposition ?? f.human_review_status ?? "" },
];

export function FindingsPage() {
  const search = useSearch({ strict: false }) as FindingSearch;
  const navigate = useNavigate();
  const set = (n: Partial<FindingSearch>) => void navigate({ to: "/findings", search: { ...search, ...n } as never, replace: true });
  const [q, setQ] = useState(search.q ?? "");
  const dq = useDeferredValue(q.trim());
  useEffect(() => setQ(search.q ?? ""), [search.q]);
  const { finding, ...rest } = search;
  const filters = { ...rest, q: dq || undefined };
  const findings = useFindings(filters);
  const summary = useFindingSummary({ ...filters, severity: undefined });
  const repos = useRepositories({});
  const rows = findings.data?.pages.flatMap((p) => p.items) ?? [];

  const filterDefs: FilterDef[] = [
    { key: "status", label: "Status", allLabel: "Open", options: [...["in_progress", "needs_review", "fixed", "false_positive", "accepted_risk"].map((value) => ({ value, label: statusLabel[value]! })), { value: "all", label: "All statuses" }] },
    { key: "assignee", label: "Assignee", allLabel: "Anyone", options: [{ value: "me", label: "Assigned to me" }, { value: "none", label: "Unassigned" }] },
    { key: "lifecycle", label: "Lifecycle", allLabel: "Any lifecycle", options: Object.entries(lifecycleLabel).map(([value, label]) => ({ value, label })) },
    { key: "kev", label: "Exploited (KEV)", allLabel: "Any exploit status", options: [{ value: "true", label: "In CISA KEV" }] },
    { key: "secret_validation", label: "Secret check", allLabel: "Any secret check", options: (["active", "inactive", "error", "not_checked"] as const).map((value) => ({ value, label: `Secrets: ${secretStatusLabel[value].toLowerCase()}` })) },
    { key: "malicious", label: "Malicious packages", allLabel: "Any package", options: [{ value: "true", label: "Malicious packages only" }] },
    { key: "deployed", label: "Deployed", allLabel: "Any deployment", options: [{ value: "true", label: "Deployed (running in a cluster)" }, { value: "false", label: "Not deployed" }] },
    { key: "internet_exposed", label: "Internet-exposed", allLabel: "Any exposure", options: [{ value: "true", label: "Internet-exposed in a cluster" }] },
    { key: "risk_min", label: "Risk", allLabel: "Any risk", options: [{ value: "75", label: "Critical risk (≥ 75)" }, { value: "50", label: "High risk or more (≥ 50)" }, { value: "25", label: "Medium risk or more (≥ 25)" }] },
    { key: "sort", label: "Order", options: [{ value: "", label: "Order by severity" }, { value: "risk", label: "Order by contextual risk" }] },
    { key: "human_review", label: "Human Eye", allLabel: "Any review state", options: [{ value: "none", label: "Not reviewed" }, { value: "open", label: "Review in progress" }, ...Object.entries(dispositionLabel).filter(([k]) => k !== "needs_more_information").map(([value, label]) => ({ value, label: `Reviewed: ${label}` }))] },
    { key: "sla", label: "SLA", allLabel: "Any SLA", options: [{ value: "breached", label: "Breached" }, { value: "due_soon", label: "Due within 7 days" }] },
    { key: "reachability", label: "Reachability", allLabel: "Any reachability", options: [{ value: "reachable", label: "Reachable" }, { value: "not_reachable", label: "Not reachable" }, { value: "unknown", label: "Unknown" }] },
    { key: "reachability_method", label: "Reachability method", allLabel: "Any method", options: [{ value: "call_graph", label: "Function level: call graph" }, { value: "symbol_calls", label: "Function level: calls in the code" }, { value: "import", label: "Package level: imports" }, { value: "none", label: "Not analysed" }] },
    { key: "target_kind", label: "Asset", allLabel: "All assets", options: [{ value: "repository", label: "Source code" }, { value: "image", label: "Container images" }, { value: "url", label: "Web applications" }, { value: "api", label: "APIs" }, { value: "sbom", label: "Imported SBOMs" }, { value: "artifact", label: "Build artifacts" }, { value: "endpoints", label: "Declared public endpoints" }, { value: "mobile-app", label: "Mobile apps" }, { value: "llm-endpoint", label: "LLM endpoints" }] },
    { key: "category", label: "Type", allLabel: "All types", options: Object.entries(categoryLabel).map(([value, label]) => ({ value, label })) },
    { key: "kind", label: "Kind of check", allLabel: "All kinds of check", options: CHECK_KINDS.map((k) => ({ value: k.id, label: k.name })) },
    { key: "repository_id", label: "Repository", allLabel: "All repositories", options: (repos.data?.pages.flatMap((p) => p.items) ?? []).map((r) => ({ value: r.id, label: r.repository_key ? `${r.full_name} · ${r.repository_key}` : r.full_name })) },
  ];
  const sevs: Severity[] = ["critical", "high", "medium", "low", "info"];
  const active = search.severity?.split(",") ?? [];
  const { can } = useSession();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  useEffect(() => setSelected(new Set()), [JSON.stringify(filters)]);

  return (
    <>
      <PageHeader title="Findings" description="Normalized, de-duplicated results from every scanner. Select rows for bulk triage; open a finding for its lifecycle, risk acceptance and history." />
      <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-5">
        {sevs.map((s) => (
          <button key={s} onClick={() => set({ severity: active.length === 1 && active[0] === s ? undefined : s })}
            className={cn("rounded-lg border bg-surface p-3 text-left transition-colors", active.includes(s) ? "border-[color:var(--ring)] ring-1 ring-[color:var(--ring)]" : "border-border hover:border-primary/40")}>
            <div className="flex items-center gap-1.5 text-[12px] font-medium capitalize text-muted-foreground">
              <span className="size-2 rounded-full" style={{ backgroundColor: severityColor[s] }} />{s}
            </div>
            <div className="tabular mt-1 text-xl font-semibold">{summary.data ? summary.data[s] ?? 0 : "…"}</div>
          </button>
        ))}
      </div>
      {search.control && (
        <div className="mb-3">
          <Alert tone="warning">
            Showing findings mapped to compliance control <strong className="font-mono">{search.control.replace(":", " ")}</strong>.{" "}
            <button type="button" className="underline" onClick={() => set({ control: undefined })}>Clear</button>
          </Alert>
        </div>
      )}
      <Card className="mb-3 p-3">
        <FilterBar filters={filterDefs} values={rest as Record<string, string | undefined>} onChange={(k, v) => set({ [k]: v })}
          onReset={() => { setQ(""); void navigate({ to: "/findings", search: {} as never, replace: true }); }} />
        {search.scan_target_id && (
          <div className="mt-2 flex items-center gap-2 text-[12px]">
            <span className="rounded-full border border-border bg-surface-muted px-2 py-0.5">
              Scan target: {rows.find((r) => r.scan_target_id === search.scan_target_id)?.scan_target_name ?? "selected target"}
            </span>
            <button type="button" className="text-primary hover:underline" onClick={() => set({ scan_target_id: undefined })}>Show all</button>
          </div>
        )}
      </Card>
      {(can("findings.triage") || can("reviews.assign")) && selected.size > 0 && <BulkBar ids={[...selected]} onDone={() => setSelected(new Set())} />}
      <Card>
        <DataTable
          tableId="findings-v2"
          selection={can("findings.triage") || can("reviews.assign") ? selected : undefined}
          onSelectionChange={can("findings.triage") || can("reviews.assign") ? setSelected : undefined}
          exportName="pathos-findings"
          columns={columns}
          rows={rows}
          rowKey={(f) => f.id}
          isPending={findings.isPending}
          error={findings.error}
          hasMore={findings.hasNextPage}
          loadingMore={findings.isFetchingNextPage}
          onLoadMore={() => void findings.fetchNextPage()}
          onRowClick={(f) => set({ finding: f.id })}
          empty={<EmptyState icon={<ShieldCheck />} title="No findings match these filters">Findings appear here after repositories are scanned.</EmptyState>}
          toolbar={
            <div className="relative w-full max-w-sm">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input aria-label="Search findings" placeholder="Search title, rule, CVE, file or package" className="pl-8" value={q}
                onChange={(e) => setQ(e.target.value)} onBlur={() => set({ q: q.trim() || undefined })} />
            </div>
          }
        />
      </Card>
      <FindingDrawer id={finding} onClose={() => set({ finding: undefined })} />
    </>
  );
}

function FindingDrawer({ id, onClose }: { id?: string; onClose: () => void }) {
  const f = useFinding(id);
  const d = f.data;
  return (
    <Dialog side open={!!id} onOpenChange={(o) => !o && onClose()} title={d?.title ?? "Finding"} description={d ? `${d.repository_name}${d.repository_key ? ` · ${d.repository_key}` : ""}` : undefined}>
      {f.isError ? <ErrorPanel error={f.error} /> : !d ? <Skeleton className="h-40" /> : (
        <div className="space-y-5 text-[13px]">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge value={d.severity} />
            {d.lifecycle_status ? <LifecycleBadge value={d.lifecycle_status} /> : <span className="text-[12px] text-muted-foreground">{statusLabel[d.status] ?? d.status}</span>}
            {d.cvss != null && <span className="tabular text-[12px] text-muted-foreground">CVSS {d.cvss.toFixed(1)}</span>}
          </div>
          <LifecyclePanel f={d} />
          <SecretValidationPanel f={d} />
          <RiskPanel findingId={d.id} />
          <FindingRuntime findingId={d.id} />
          {(d.category === "sca" || d.category === "container") && d.package_name && !d.scan_target_id && (
            <div className="rounded-md border border-border p-3">
              <h3 className="mb-1 text-[12px] font-semibold">How the package gets in</h3>
              <FindingDependencyPaths findingId={d.id} />
            </div>
          )}
          {d.human_review_id && (
            <div className="rounded-md border border-border p-3 text-[12.5px]">
              <span className="font-medium">Human Eye review {d.human_review_key}: </span>
              {d.human_disposition ? dispositionLabel[d.human_disposition as Disposition] : reviewStatusLabel[d.human_review_status as ReviewStatus]}
              {d.human_severity && <span className="text-muted-foreground"> · assessed severity {d.human_severity}</span>}
              <Link to="/human-review/reviews/$id" params={{ id: d.human_review_id }} className="ml-2 text-primary hover:underline">Open assessment →</Link>
            </div>
          )}
          {d.malicious && (
            <Alert>
              This is a known <strong>malicious package</strong>: its code runs when it is installed. Remove it, rotate any credentials on machines and
              CI runners that installed it, and check them for compromise.
            </Alert>
          )}
          {d.description && <p className="whitespace-pre-wrap break-words text-muted-foreground">{d.description}</p>}
          <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
            <div><dt className="text-[12px] text-muted-foreground">Type</dt><dd>{categoryLabel[d.category] ?? d.category}</dd></div>
            <div><dt className="text-[12px] text-muted-foreground">Rule</dt><dd className="break-all font-mono text-[12px]">{d.rule_id}</dd></div>
            {d.cve && (
              <div>
                <dt className="text-[12px] text-muted-foreground">CVE</dt>
                <dd className="font-mono text-[12px]"><Link to="/vulnerabilities/$id" params={{ id: d.cve }} className="text-primary hover:underline">{d.cve}</Link></dd>
              </div>
            )}
            {d.cwe.length > 0 && <div><dt className="text-[12px] text-muted-foreground">CWE</dt><dd className="font-mono text-[12px]">{d.cwe.join(", ")}</dd></div>}
            {d.package_name && <div><dt className="text-[12px] text-muted-foreground">Package</dt><dd className="font-mono text-[12px]">{d.package_name}@{d.package_version}</dd></div>}
            {d.fixed_version && <div><dt className="text-[12px] text-muted-foreground">Fixed in</dt><dd className="font-mono text-[12px] text-success">{d.fixed_version}</dd></div>}
            <div className="col-span-2"><dt className="text-[12px] text-muted-foreground">Location</dt><dd className="break-all font-mono text-[12px]">{location(d)}</dd></div>
            <div><dt className="text-[12px] text-muted-foreground">Kind of check</dt><dd>{findingCheckLabel(d)}</dd></div>
            <div><dt className="text-[12px] text-muted-foreground">First seen</dt><dd className="tabular">{formatDateTime(d.first_seen_at)}</dd></div>
            {d.introduced_commit && (
              <div title="Commit of the first scan that detected it: the finding was introduced at or before this commit">
                <dt className="text-[12px] text-muted-foreground">First detected at commit</dt>
                <dd className="font-mono text-[12px]">{d.introduced_commit.slice(0, 12)}</dd>
              </div>
            )}
            <IntroducedBy f={d} />
            <div><dt className="text-[12px] text-muted-foreground">Last seen</dt><dd className="tabular">{formatDateTime(d.last_seen_at)}</dd></div>
            {d.resolved_at && <div><dt className="text-[12px] text-muted-foreground">Resolved</dt><dd className="tabular">{formatDateTime(d.resolved_at)}</dd></div>}
            {d.category === "sca" && <ReachabilitySection f={d} />}
            {d.suppression_rule_id && (
              <div className="col-span-2">
                <dt className="text-[12px] text-muted-foreground">Decided by</dt>
                <dd><Link to="/suppression-rules" className="text-primary hover:underline">an approved suppression rule</Link></dd>
              </div>
            )}
          </dl>
          <FindingPolicies findingId={d.id} />
          <FindingTickets findingId={d.id} />
          {!d.scan_target_id && <FindingFixPR findingId={d.id} category={d.category} />}
          {!d.scan_target_id && <FindingAIFix findingId={d.id} category={d.category} />}
          <RelatedFindings findingId={d.id} />
          {d.snippet && (
            <div>
              <h3 className="mb-2 text-[13px] font-semibold">Code</h3>
              <pre className="max-h-72 overflow-auto rounded-md border border-border bg-muted/40 p-2 font-mono text-[11.5px] leading-5">
                {d.snippet.split("\n").map((l, i) => {
                  const n = (d.snippet_start_line ?? 1) + i;
                  const hit = d.start_line != null && n === d.start_line;
                  return <div key={i} className={cn("px-1", hit && "bg-warning/15")}><span className="mr-3 inline-block w-8 select-none text-right text-muted-foreground">{n}</span>{l}</div>;
                })}
              </pre>
            </div>
          )}
          <AISection id={d.id} />
          <CorrelationSection findingId={d.id} />
          <AIEvidencePanel findingId={d.id} />
          <div>
            <h3 className="mb-2 text-[13px] font-semibold">Sightings</h3>
            <ul className="divide-y divide-border rounded-md border border-border">
              {(d.occurrences ?? []).map((o, i) => (
                <li key={i} className="flex items-center justify-between gap-3 px-3 py-2 text-[12px]">
                  <span>{toolCheckLabel(o.scanner_key)}{o.commit_sha && <span className="font-mono text-muted-foreground"> @ {o.commit_sha.slice(0, 8)}</span>}</span>
                  <Link to="/scans" search={{ job: o.scan_job_id } as never} className="tabular text-primary hover:underline">{formatDateTime(o.seen_at)}</Link>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </Dialog>
  );
}

function AISection({ id }: { id: string }) {
  const { can } = useSession();
  const reviews = useFindingReviews(id);
  const request = useAIMutation(() => api(`/api/v1/findings/${id}/ai-review`, { method: "POST" }));
  const queued = reviews.data?.ai_status === "queued";
  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-[13px] font-semibold">AI review</h3>
        {can("ai.review") && (
          <Button size="sm" variant="secondary" disabled={request.isPending || queued} onClick={() => request.mutate(undefined)}>
            <Bot /> {queued ? "Queued…" : "Request AI review"}
          </Button>
        )}
      </div>
      {request.isError && <ErrorPanel error={request.error} />}
      {reviews.data?.items.length ? (
        <div className="space-y-2">{reviews.data.items.slice(0, 3).map((r) => <ReviewCard key={r.id} review={r} />)}</div>
      ) : (
        <p className="text-[12px] text-muted-foreground">{reviews.data?.ai_status === "failed" ? "The last AI review failed; see AI settings." : "Not reviewed yet."}</p>
      )}
    </div>
  );
}

function BulkBar({ ids, onDone }: { ids: string[]; onDone: () => void }) {
  const { me, can } = useSession();
  const [hrReason, setHrReason] = useState("");
  const [hrOpen, setHrOpen] = useState(false);
  const sendToReview = useVulnMutation(() => reviewApi.create({ finding_ids: ids, reason: hrReason }));
  const [status, setStatus] = useState("");
  const [reason, setReason] = useState("");
  const bulk = useVulnMutation((body: unknown) => api<{ updated: number }>("/api/v1/findings/bulk", { method: "POST", body: { finding_ids: ids, ...(body as object) } }));
  const done = { onSuccess: () => { setStatus(""); setReason(""); onDone(); } };
  return (
    <Card className="mb-3 flex flex-wrap items-center gap-2 border-primary/40 p-2.5">
      <span className="text-[13px] font-medium">{ids.length} selected</span>
      {can("reviews.assign") && (
        <>
          {hrOpen ? (
            <>
              <Input aria-label="Reason for human review" className="max-w-xs" placeholder="Why does this need human review?" value={hrReason} onChange={(e) => setHrReason(e.target.value)} />
              <Button size="sm" disabled={sendToReview.isPending || hrReason.trim().length < 5}
                onClick={() => sendToReview.mutate(undefined, { onSuccess: () => { setHrOpen(false); setHrReason(""); onDone(); } })}>
                Add to review queue
              </Button>
            </>
          ) : (
            <Button size="sm" variant="secondary" onClick={() => setHrOpen(true)}><ShieldCheck /> Send to Human Eye</Button>
          )}
          {sendToReview.data && <span className="text-[12px] text-muted-foreground">{sendToReview.data.created.length} added, {sendToReview.data.existing.length} already queued</span>}
          {can("findings.triage") && <span className="mx-1 h-5 w-px bg-border" />}
        </>
      )}
      {can("findings.triage") && <>
      <Select aria-label="Bulk status" value={status} onChange={(e) => setStatus(e.target.value)}>
        <option value="">Set status…</option>
        {["open", "in_progress", "needs_review", "false_positive", "fixed"].map((s) => <option key={s} value={s}>{statusLabel[s]}</option>)}
      </Select>
      {status && <Input aria-label="Bulk reason" className="max-w-xs" placeholder={needsReason(status) ? "Reason (required)" : "Reason (optional)"} value={reason} onChange={(e) => setReason(e.target.value)} />}
      {status && <Button size="sm" disabled={bulk.isPending || (needsReason(status) && reason.trim().length < 5)} onClick={() => bulk.mutate({ action: "status", status, reason }, done)}>Apply</Button>}
      <span className="mx-1 h-5 w-px bg-border" />
      <Button size="sm" variant="secondary" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "assign", assignee_id: me.user.id }, done)}>Assign to me</Button>
      <Button size="sm" variant="ghost" disabled={bulk.isPending} onClick={() => bulk.mutate({ action: "assign", assignee_id: null }, done)}>Unassign</Button>
      </>}
      <CreateRemediationItems findingIds={ids} onDone={onDone} />
      <Button size="sm" variant="ghost" className="ml-auto" aria-label="Clear selection" onClick={onDone}><X /></Button>
      {bulk.isError && <div className="w-full"><ErrorPanel error={bulk.error} /></div>}
      {sendToReview.isError && <div className="w-full"><ErrorPanel error={sendToReview.error} /></div>}
    </Card>
  );
}

/** Security policies the finding violates (and what they do). */
function FindingPolicies({ findingId }: { findingId: string }) {
  const q = useQuery({
    queryKey: ["finding-policies", findingId],
    queryFn: () => api<{ items: { id: string; name: string; actions: { block?: boolean; require_review?: boolean; sla_days?: number; notify?: boolean } }[] }>(`/api/v1/findings/${findingId}/policies`).then((r) => r.items),
    retry: false,
  });
  if (!q.data?.length) return null;
  return (
    <div className="rounded-md border border-border p-3 text-[12.5px]">
      <h3 className="mb-1 text-[12px] font-semibold">Violates security polic{q.data.length === 1 ? "y" : "ies"}</h3>
      <ul className="space-y-0.5">
        {q.data.map((p) => (
          <li key={p.id} className="flex flex-wrap items-center gap-1.5">
            <Link to="/admin/policies" search={{ policy: p.id } as never} className="text-primary hover:underline">{p.name}</Link>
            {p.actions.block && <Badge tone="danger">blocks gates</Badge>}
            {p.actions.require_review && <Badge tone="primary">review required</Badge>}
            {p.actions.sla_days != null && <Badge tone="warning">SLA {p.actions.sla_days} d</Badge>}
          </li>
        ))}
      </ul>
    </div>
  );
}

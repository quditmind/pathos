import { useState } from "react";
import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { ArrowLeft, Bot, Play, RotateCcw, Scale, ShieldCheck, UserPlus, X } from "lucide-react";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { Alert, PageHeader, Skeleton } from "@/components/ui/primitives";
import { Tabs } from "@/features/scans/shared";
import { cn, formatDateTime } from "@/lib/utils";
import { reviewApi, useReview, useReviewMutation } from "../api";
import { DispositionBadge, PriorityBadge, remediationLabel, StatusBadge } from "../shared";
import { AssignDialog, DecisionDialog, IndependentDialog, ReopenDialog, StatusDialog } from "./actions";
import { AIPanel } from "./AIPanel";
import { DataFlowTab } from "./DataFlowTab";
import { EvidenceTab } from "./EvidenceTab";
import { ExploitabilityTab } from "./ExploitabilityTab";
import { HistoryTab } from "./HistoryTab";
import { OverviewTab } from "./OverviewTab";
import { RemediationTab } from "./RemediationTab";
import { RiskTab } from "./RiskTab";
import { SourceTab } from "./SourceTab";
import { ErrorPanel } from "@/components/ui/error-panel";

export const workspaceTabs = [
  ["overview", "Overview"],
  ["source", "Source code"],
  ["dataflow", "Data flow"],
  ["exploitability", "Exploitability"],
  ["evidence", "Evidence"],
  ["risk", "Risk assessment"],
  ["remediation", "Remediation"],
  ["history", "History"],
] as const;
export type WorkspaceTab = (typeof workspaceTabs)[number][0];
export type WorkspaceSearch = { tab?: WorkspaceTab; path?: string; line?: number };

export const validateWorkspaceSearch = (s: Record<string, unknown>): WorkspaceSearch => {
  const out: WorkspaceSearch = {};
  if (workspaceTabs.some(([k]) => k === s.tab)) out.tab = s.tab as WorkspaceTab;
  if (typeof s.path === "string" && s.path.length <= 1000) out.path = s.path;
  const n = Number(s.line);
  if (Number.isInteger(n) && n > 0) out.line = n;
  return out;
};

export function WorkspacePage() {
  const { id } = useParams({ strict: false }) as { id: string };
  return <Workspace id={id} />;
}

/** The assessment workspace: everything an analyst needs on one page. */
export function Workspace({ id }: { id: string }) {
  const search = validateWorkspaceSearch(useSearch({ strict: false }) as Record<string, unknown>);
  const tab: WorkspaceTab = search.tab ?? "overview";
  const navigate = useNavigate();
  const q = useReview(id);
  const d = q.data;
  const start = useReviewMutation(() => reviewApi.start(id));
  const [dialog, setDialog] = useState<null | "assign" | "decision" | "independent" | "reopen" | "status">(null);
  const [aiOpen, setAiOpen] = useState(false);
  const setTab = (t: WorkspaceTab, extra: Partial<WorkspaceSearch> = {}) =>
    void navigate({ to: ".", search: { ...(t === "overview" ? {} : { tab: t }), ...extra } as never, replace: true });
  const openSource = (path: string, line?: number) => setTab("source", { path, line });

  if (q.isError) {
    return (
      <>
        <BackLink />
        <ErrorPanel error={q.error} title="Could not load the review" />
      </>
    );
  }
  if (!d) {
    return (
      <>
        <BackLink />
        <Skeleton className="h-48" />
      </>
    );
  }
  const can = d.can;
  const pendingDecision = d.decisions.findLast((x) => x.outcome === "pending_approval" && x.approvals.every((a) => a.outcome === "approved"));
  const firstApproval = pendingDecision?.approvals.find((a) => (a.level ?? 1) === 1 && a.outcome === "approved");

  return (
    <>
      <BackLink />
      <PageHeader
        title={d.title}
        description={`${d.review_key} · ${d.repository_name}${d.file_path ? ` · ${d.file_path}${d.start_line ? `:${d.start_line}` : ""}` : ""}`}
        actions={
          <div className="flex flex-wrap items-center justify-end gap-2">
            {can.start && (
              <Button onClick={() => start.mutate(undefined)} disabled={start.isPending}>
                <Play /> {d.reviewer_id ? "Start review" : "Assign to me & start"}
              </Button>
            )}
            {can.assess && (
              <>
                <Button variant="secondary" onClick={() => setDialog("status")}>{d.status === "awaiting_information" ? "Resume review" : "Awaiting info…"}</Button>
                <Button onClick={() => setDialog("decision")}>
                  <Scale /> Submit decision
                </Button>
              </>
            )}
            {can.approve && (
              <Button onClick={() => setDialog("independent")}>
                <ShieldCheck /> {can.final_approval ? "Final approval" : "Independent review"}
              </Button>
            )}
            {can.assign && (
              <Button variant="secondary" onClick={() => setDialog("assign")}>
                <UserPlus /> Assign
              </Button>
            )}
            {can.reopen && (
              <Button variant="secondary" onClick={() => setDialog("reopen")}>
                <RotateCcw /> Reopen
              </Button>
            )}
            <Button variant={aiOpen ? "primary" : "secondary"} onClick={() => setAiOpen(!aiOpen)} aria-pressed={aiOpen} title="AI suggestions (advisory)">
              <Bot /> AI assist
            </Button>
          </div>
        }
      />
      {start.error && <div className="mb-3"><ErrorPanel error={start.error} /></div>}

      <dl className="mb-4 grid grid-cols-2 gap-x-4 gap-y-2 rounded-lg border border-border bg-surface p-3 text-[12.5px] sm:grid-cols-4 lg:grid-cols-8">
        <Fact label="Review status"><StatusBadge status={d.status} /></Fact>
        <Fact label="Disposition"><DispositionBadge value={d.disposition} /></Fact>
        <Fact label="Remediation">{d.remediation_status ? remediationLabel[d.remediation_status] : "—"}</Fact>
        <Fact label="Scanner severity"><SeverityBadge value={d.original.severity} /></Fact>
        <Fact label="Assessed severity">{d.assessed_severity ? <SeverityBadge value={d.assessed_severity} /> : <span className="text-muted-foreground">Not assessed</span>}</Fact>
        <Fact label="Priority"><PriorityBadge value={d.priority} /></Fact>
        <Fact label="Reviewer">{d.reviewer_name ?? <span className="text-muted-foreground">Unassigned</span>}</Fact>
        <Fact label="Due">
          <span className={cn(d.overdue && "font-semibold text-danger")}>{d.due_at ? formatDateTime(d.due_at) : "—"}</span>
        </Fact>
      </dl>
      {d.status === "awaiting_independent_review" && pendingDecision && (
        <div className="mb-3">
          <Alert tone="warning">
            {pendingDecision.decided_by_name} proposed <strong>{pendingDecision.disposition.replace(/_/g, " ")}</strong>.{" "}
            {firstApproval ? (
              <>{firstApproval.reviewer_name} approved it as independent reviewer; a <strong>final approval</strong> by a third person is now required.</>
            ) : (
              <>The assessment is locked until an independent reviewer{d.independent_reviewer_name ? ` (${d.independent_reviewer_name})` : ""} approves, rejects or asks for more information.</>
            )}
          </Alert>
        </div>
      )}
      {d.round > 1 && <p className="mb-2 text-[12px] text-muted-foreground">Review round {d.round}: earlier rounds remain in the history.</p>}

      <div className={cn("grid gap-4", aiOpen && "xl:grid-cols-[minmax(0,1fr)_380px]")}>
        <div className="min-w-0">
          <Tabs tabs={workspaceTabs} value={tab} onChange={(t) => setTab(t)} label="Assessment sections" idPrefix="hr" />
          <div role="tabpanel" id={`hr-panel-${tab}`} aria-labelledby={`hr-tab-${tab}`} className="pt-4">
            {tab === "overview" && <OverviewTab d={d} openSource={openSource} />}
            {tab === "source" && <SourceTab d={d} path={search.path} line={search.line} />}
            {tab === "dataflow" && <DataFlowTab d={d} openSource={openSource} />}
            {tab === "exploitability" && <ExploitabilityTab d={d} />}
            {tab === "evidence" && <EvidenceTab d={d} />}
            {tab === "risk" && <RiskTab d={d} />}
            {tab === "remediation" && <RemediationTab d={d} />}
            {tab === "history" && <HistoryTab d={d} />}
          </div>
        </div>
        {aiOpen && (
          <aside className="min-w-0" aria-label="AI assistant">
            <div className="sticky top-0">
              <div className="mb-2 flex items-center justify-between">
                <h2 className="text-[13px] font-semibold">AI assistant</h2>
                <Button variant="ghost" size="icon" onClick={() => setAiOpen(false)} aria-label="Close AI assistant">
                  <X />
                </Button>
              </div>
              <AIPanel d={d} />
            </div>
          </aside>
        )}
      </div>

      <AssignDialog d={d} open={dialog === "assign"} onOpenChange={(o) => setDialog(o ? "assign" : null)} />
      <DecisionDialog d={d} open={dialog === "decision"} onOpenChange={(o) => setDialog(o ? "decision" : null)} onGoto={(t) => { setDialog(null); setTab(t); }} />
      <IndependentDialog d={d} open={dialog === "independent"} onOpenChange={(o) => setDialog(o ? "independent" : null)} />
      <ReopenDialog d={d} open={dialog === "reopen"} onOpenChange={(o) => setDialog(o ? "reopen" : null)} />
      <StatusDialog d={d} open={dialog === "status"} onOpenChange={(o) => setDialog(o ? "status" : null)} />
    </>
  );
}

function BackLink() {
  return (
    <Link to="/human-review/queue" className="mb-3 inline-flex items-center gap-1 text-[12px] text-muted-foreground hover:text-foreground">
      <ArrowLeft className="size-3.5" /> Review queue
    </Link>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 truncate">{children}</dd>
    </div>
  );
}

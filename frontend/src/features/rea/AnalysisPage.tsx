import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { ApiError } from "@/api/client";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Alert, Badge, PageHeader } from "@/components/ui/primitives";
import { FeatureDisabled, LoadingSkeleton, PermissionDenied } from "@/components/ui/states";
import { useFeatureFlags } from "@/features/shell/meta";
import { formatDateTime } from "@/lib/utils";
import { analysisReady, hideToolNames, kindOf, useAnalysis, type Analysis } from "./api";
import { AnalysisStatusBadge } from "./badges";
import { reaTabs, type ReaAnalysisSearch, type ReaTab } from "./search";
import { CallGraphTab, DiffTab, FunctionsTab, HistoryTab, RuntimeTab, StringsImportsTab } from "./tabs";

export const tabLabel: Record<ReaTab, string> = {
  functions: "Functions",
  "call-graph": "Call graph",
  strings: "Strings & imports",
  runtime: "Runtime behaviour",
  diff: "Source ↔ binary",
  history: "History",
};

const trustLabel: Record<string, string> = {
  signature: "From our own builds (verified signature)",
  provenance: "From our own builds (verified provenance)",
  authorization: "Untrusted artifact, authorised with a reason",
};

/** The tool runs of an analysis, named by the kind of analysis (rule 3). */
function ToolRuns({ a }: { a: Analysis }) {
  const runs = Object.entries(a.tools ?? {});
  if (!runs.length) return null;
  return (
    <ul className="flex flex-wrap gap-2 text-[12px]" aria-label="Analyses run">
      {runs.map(([tool, r]) => (
        <li key={tool} title={hideToolNames(r.detail)}>
          <Badge tone={r.status === "succeeded" ? "success" : r.status === "skipped" ? "neutral" : "danger"}>
            {kindOf(tool)}: {r.status.replaceAll("_", " ")}
          </Badge>
        </li>
      ))}
    </ul>
  );
}

/** The reverse-engineering workspace of one analysis (wireframe 4). */
export function AnalysisView({ analysis, counts, search, onNavigate }: { analysis: Analysis; counts: Record<string, number | undefined>; search: ReaAnalysisSearch; onNavigate: (s: ReaAnalysisSearch) => void }) {
  const tab = search.tab ?? "functions";
  const ready = analysisReady(analysis);
  // Runtime behaviour and History do not need a finished analysis.
  const needsData = tab !== "runtime" && tab !== "history";
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[12px] text-muted-foreground">
        <AnalysisStatusBadge status={analysis.status} />
        <span>{trustLabel[analysis.trust_basis ?? ""] ?? "Trust not recorded"}</span>
        {analysis.commit_sha && (
          <span>
            Commit <code>{analysis.commit_sha.slice(0, 12)}</code>
          </span>
        )}
        {(analysis.format || analysis.arch) && (
          <span>
            {[analysis.format, analysis.arch, analysis.language].filter(Boolean).join(" · ")}
          </span>
        )}
        {counts.functions != null && <span>{counts.functions} functions · {counts.imports ?? 0} imports · {counts.strings ?? 0} strings</span>}
        <span>Started {formatDateTime(analysis.created_at)}</span>
      </div>
      <ToolRuns a={analysis} />
      {(analysis.status === "queued" || analysis.status === "running") && (
        <div role="status" className="rounded-md bg-surface-muted px-3 py-2 text-[13px]">
          The analysis is {analysis.status}. It runs in the isolated reverse-engineering worker (no network, read-only, never runs the artifact). This page
          refreshes on its own.
        </div>
      )}
      {analysis.status === "failed" && (
        <Alert>
          The analysis failed{analysis.error_code ? ` (${analysis.error_code})` : ""}: {hideToolNames(analysis.error) || "no reason recorded"}. See Troubleshooting in the
          reverse-engineering help.
        </Alert>
      )}
      {analysis.status === "partial" && <Alert tone="warning">Partial analysis: some analyses did not finish or the results were cut at their size limits.</Alert>}
      <div role="tablist" aria-label="Binary analysis sections" className="flex flex-wrap gap-1 border-b border-border">
        {reaTabs.map((t) => (
          <button
            key={t}
            type="button"
            role="tab"
            id={`rea-tab-${t}`}
            aria-selected={t === tab}
            aria-controls={`rea-panel-${t}`}
            onClick={() => onNavigate({ tab: t === "functions" ? undefined : t })}
            className={"-mb-px border-b-2 px-3 py-1.5 text-[13px] " + (t === tab ? "border-primary font-medium text-foreground" : "border-transparent text-muted-foreground hover:text-foreground")}
          >
            {tabLabel[t]}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`rea-panel-${tab}`} aria-labelledby={`rea-tab-${tab}`}>
        {needsData && !ready ? (
          <p className="text-[13px] text-muted-foreground">{tabLabel[tab]} appear when the analysis has finished.</p>
        ) : (
          <>
            {tab === "functions" && <FunctionsTab analysis={analysis} selected={search.fn} onSelect={(fn) => onNavigate({ ...search, fn })} />}
            {tab === "call-graph" && <CallGraphTab analysis={analysis} node={search.node} onNode={(node) => onNavigate({ ...search, node })} />}
            {tab === "strings" && <StringsImportsTab analysis={analysis} />}
            {tab === "runtime" && <RuntimeTab />}
            {tab === "diff" && <DiffTab analysis={analysis} />}
            {tab === "history" && <HistoryTab analysis={analysis} />}
          </>
        )}
      </div>
    </div>
  );
}

/** /reverse-engineering/analyses/$analysisId */
export function AnalysisPage() {
  const { analysisId } = useParams({ strict: false }) as { analysisId: string };
  const search = useSearch({ strict: false }) as ReaAnalysisSearch;
  const navigate = useNavigate();
  const { flags, isPending } = useFeatureFlags();
  const enabled = flags.reverse_engineering === true;
  const q = useAnalysis(enabled ? analysisId : "");
  const a = q.data?.analysis;
  const crumbs = (
    <nav aria-label="Breadcrumb" className="mb-2 text-[12px] text-muted-foreground">
      <ol className="flex flex-wrap items-center gap-1">
        <li>5 · Reverse engineering /</li>
        <li>
          <Link to="/reverse-engineering" className="hover:underline">
            Binary analysis
          </Link>{" "}
          /
        </li>
        {a?.repository_name && <li>{a.repository_name} /</li>}
        <li aria-current="page" className="font-semibold text-foreground">
          {a?.artifact_name ?? "Analysis"}
        </li>
      </ol>
    </nav>
  );
  const header = (
    <PageHeader
      title={a ? `Binary analysis: ${a.artifact_name}` : "Binary analysis"}
      description="Functions, call graph, strings and imports of a shipped binary, compared with its source code. Every fact carries its offset in the binary."
    />
  );
  if (isPending) return <>{crumbs}{header}<LoadingSkeleton rows={4} /></>;
  if (!enabled) return <>{crumbs}{header}<FeatureDisabled flag="reverse_engineering" feature="Reverse engineering" /></>;
  if (q.isError) {
    if (q.error instanceof ApiError && q.error.status === 403) return <>{crumbs}{header}<PermissionDenied permission="findings.read" what="Viewing binary analyses" /></>;
    return <>{crumbs}{header}<ErrorPanel error={q.error} title="Could not load the analysis" onVerify={() => q.refetch()} /></>;
  }
  if (q.isPending || !a) return <>{crumbs}{header}<LoadingSkeleton rows={6} label="Loading the analysis" /></>;
  return (
    <>
      {crumbs}
      {header}
      <AnalysisView
        analysis={a}
        counts={q.data.counts}
        search={search}
        onNavigate={(s) =>
          void navigate({ to: "/reverse-engineering/analyses/$analysisId", params: { analysisId }, search: s as never, replace: s.tab === search.tab })
        }
      />
    </>
  );
}

import { useCallback, useMemo, useState } from "react";
import { GitCommitHorizontal, RefreshCw, Waypoints } from "lucide-react";
import { api, ApiError } from "@/api/client";
import { GraphExplorer, SnapshotPicker, type GraphData, type GraphDiff } from "@/components/graph";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Alert, Card } from "@/components/ui/primitives";
import { EmptyStateCard, FeatureDisabled, LoadingSkeleton, PermissionDenied } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useFeatureFlags, useMeta } from "@/features/shell/meta";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { downloadJson, exportFileName } from "@/components/graph/export";
import { exportUrl, fetchNodeDetail, fetchPaths, useCodeGraphViews, useDiff, useGraph, useRebuild, useSnapshots, type BuildAnswer, type CodeGraphSnapshot } from "./api";
import { codegraphViews, viewInfo, type CodeGraphView } from "./views";

/** URL or local state of the CodeGraph screen. */
export interface CodeGraphState {
  view: CodeGraphView;
  snapshot?: string;
  compare?: string;
  focus?: string;
  node?: string;
}

export function relativeTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "";
  const s = Math.round((now - new Date(iso).getTime()) / 1000);
  if (!Number.isFinite(s)) return "";
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

/** change_impact marks nodes with attrs.change (added, changed, removed); turn that into a diff for the colours. */
export function diffFromChangeAttrs(g: GraphData): GraphDiff {
  const d: GraphDiff = { added: { nodes: [], edges: [] }, removed: { nodes: [], edges: [] }, changed: { nodes: [], edges: [] } };
  for (const n of g.nodes) {
    const c = n.attrs?.change;
    if (c === "added" || c === "removed" || c === "changed") d[c].nodes.push(n);
  }
  return d;
}

const usable = (s: CodeGraphSnapshot) => s.status === "ready" || s.status === "partial";

/**
 * The 15 views as a toggle group. With the server's view catalogue
 * (GET /api/v1/codegraph/views) only the views it serves are offered.
 */
export function ViewSwitcher({ value, onChange, available }: { value: CodeGraphView; onChange: (v: CodeGraphView) => void; available?: readonly string[] }) {
  const shown = available?.length ? codegraphViews.filter((v) => available.includes(v) || v === value) : codegraphViews;
  return (
    <div className="flex gap-1 overflow-x-auto pb-1" role="group" aria-label="CodeGraph views">
      {shown.map((v) => (
        <button
          key={v}
          type="button"
          aria-pressed={v === value}
          title={viewInfo[v].description}
          onClick={() => onChange(v)}
          className={
            "h-7 shrink-0 rounded-md border px-2 text-[12px] whitespace-nowrap focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring " +
            (v === value ? "border-foreground bg-foreground text-background" : "border-border bg-surface text-foreground hover:bg-surface-muted")
          }
        >
          {viewInfo[v].label}
        </button>
      ))}
    </div>
  );
}

function BuildStatus({ snap }: { snap: CodeGraphSnapshot }) {
  if (snap.status === "queued" || snap.status === "building") {
    return (
      <div role="status" className="rounded-md bg-surface-muted px-3 py-2 text-[13px]">
        A CodeGraph build is {snap.status === "queued" ? "queued" : "running"} (started {relativeTime(snap.started_at ?? snap.created_at)}). This page refreshes on its own.
      </div>
    );
  }
  if (snap.status === "failed") {
    return (
      <Alert>
        The last CodeGraph build failed{snap.error_code ? ` (${snap.error_code})` : ""}: {snap.error || "no reason recorded"}. Fix the cause and select Rebuild; see
        Troubleshooting in the CodeGraph help.
      </Alert>
    );
  }
  return null;
}

/**
 * CodeGraph of one application: snapshot header (commit, build time,
 * Rebuild), the 15 views and the shared graph component. Embeddable in the
 * application hub tab; the standalone route keeps its state in the URL.
 */
export function CodeGraphPanel({
  applicationId,
  applicationName,
  state: controlled,
  onStateChange,
}: {
  applicationId: string;
  applicationName?: string;
  state?: CodeGraphState;
  onStateChange?: (s: CodeGraphState) => void;
}) {
  const [local, setLocal] = useState<CodeGraphState>({ view: "architecture" });
  const state = controlled ?? local;
  const setState = useCallback(
    (patch: Partial<CodeGraphState>) => {
      const next = { ...state, ...patch };
      if (onStateChange) onStateChange(next);
      else setLocal(next);
    },
    [state, onStateChange],
  );
  const { flags, isPending: flagsPending } = useFeatureFlags();
  const enabled = flags.codegraph === true;
  const meta = useMeta();
  const { can } = useSession();
  // No dead buttons: building needs scans.run, the JSON export findings.export (as on the API).
  const canBuild = can("scans.run");
  const canExport = can("findings.export");
  const viewCatalogue = useCodeGraphViews(enabled);
  const snaps = useSnapshots(applicationId, enabled);
  const rebuild = useRebuild(applicationId);
  const [buildErrors, setBuildErrors] = useState<NonNullable<BuildAnswer["errors"]>>([]);

  const list = useMemo(() => [...(snaps.data ?? [])].sort((a, b) => b.created_at.localeCompare(a.created_at)), [snaps.data]);
  const latest = list[0];
  const ready = list.filter(usable);
  const current = (state.snapshot && list.find((s) => s.id === state.snapshot)) || ready[0];
  const compare = state.compare && state.compare !== current?.id ? state.compare : undefined;
  const isChangeImpact = state.view === "change_impact";
  // Change impact: the server compares with `compare` or the previous
  // snapshot of the same repository and marks nodes (attrs.change). Other
  // views with a compare snapshot use the diff endpoint.
  const graph = useGraph(applicationId, current && usable(current) ? current.id : undefined, { view: state.view, focus: state.focus, compare: isChangeImpact ? compare : undefined });
  const base = isChangeImpact ? undefined : compare;
  const diffQ = useDiff(applicationId, base, current?.id);
  const changeDiff = useMemo(() => (isChangeImpact && graph.data ? diffFromChangeAttrs(graph.data) : undefined), [isChangeImpact, graph.data]);
  const diff = isChangeImpact ? { data: changeDiff, isError: false, isPending: false, error: null, refetch: () => undefined } : diffQ;

  const loadDetail = useCallback((nid: string) => fetchNodeDetail(applicationId, current!.id, nid), [applicationId, current]);
  const loadPaths = useCallback((from: string, dir: "in" | "out") => fetchPaths(applicationId, current!.id, from, dir), [applicationId, current]);
  const comparedWith = graph.data?.base_snapshot_id ? list.find((s) => s.id === graph.data!.base_snapshot_id) : undefined;
  const onExpand = useCallback((id: string) => setState({ focus: id }), [setState]);
  const onExportJson = useCallback(async () => {
    const data = await api<unknown>(exportUrl(applicationId, current!.id));
    downloadJson(data, exportFileName(`codegraph-${applicationName ?? applicationId}-${state.view}`, "json", meta.data?.version));
  }, [applicationId, current, applicationName, state.view, meta.data?.version]);

  if (flagsPending) return <LoadingSkeleton rows={4} label="Loading CodeGraph" />;
  if (!enabled) return <FeatureDisabled flag="codegraph" feature="CodeGraph" />;
  if (snaps.isPending) return <LoadingSkeleton rows={6} label="Loading CodeGraph snapshots" />;
  if (snaps.isError) {
    if (snaps.error instanceof ApiError && snaps.error.status === 403) return <PermissionDenied permission="findings.read" what="Viewing the CodeGraph" />;
    return <ErrorPanel error={snaps.error} title="Could not load the CodeGraph snapshots" onVerify={() => snaps.refetch()} />;
  }

  const doRebuild = () =>
    rebuild.mutate(undefined, {
      onSuccess: (r) => {
        setBuildErrors(r?.errors ?? []);
        if (!r?.errors?.length || r.snapshots?.length) toast.success("CodeGraph build queued. The graph appears when the build finishes.");
      },
    });
  const rebuildBtn = canBuild ? (
    <Button size="sm" onClick={doRebuild} disabled={rebuild.isPending || latest?.status === "queued" || latest?.status === "building"}>
      <RefreshCw /> {list.length ? "Rebuild" : "Build CodeGraph"}
    </Button>
  ) : null;

  if (!list.length) {
    return (
      <div className="space-y-3">
        {rebuild.isError && <ErrorPanel error={rebuild.error} title="Could not start the CodeGraph build" />}
        <EmptyStateCard icon={<Waypoints />} title="No CodeGraph yet" action={rebuildBtn}>
          The CodeGraph is built from the application's repositories by the graph worker: files, functions, routes, data stores, components and the edges between them,
          each with its evidence. {canBuild ? "Build it now, or it is built after the next scan." : "It is built after the next scan, or by someone who can run scans."}
        </EmptyStateCard>
      </div>
    );
  }

  const graphData: GraphData | undefined = graph.data;
  const info = viewInfo[state.view];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[12px] text-muted-foreground">
        {current ? (
          <>
            <span className="inline-flex items-center gap-1" data-testid="codegraph-commit">
              <GitCommitHorizontal className="size-3.5" aria-hidden />
              {current.ref ? `${current.ref} @ ` : ""}
              <code>{current.commit_sha ? current.commit_sha.slice(0, 12) : "no commit"}</code>
            </span>
            <span title={formatDateTime(current.finished_at ?? current.created_at)}>Graph built {relativeTime(current.finished_at ?? current.created_at)}</span>
            {current.node_count != null && (
              <span>
                {current.node_count} nodes · {current.edge_count ?? 0} edges
              </span>
            )}
            {current.status === "partial" && <span className="text-warning">Partial build: the repository exceeded the discovery limits; the graph shows what was found.</span>}
          </>
        ) : (
          <span>No finished graph yet.</span>
        )}
        {rebuildBtn && <span className="ml-auto">{rebuildBtn}</span>}
      </div>
      {rebuild.isError && <ErrorPanel error={rebuild.error} title="Could not start the CodeGraph build" />}
      {buildErrors.length > 0 && (
        <Alert tone="warning">
          Some repositories were not queued:{" "}
          {buildErrors.map((e) => `${e.message}${e.code ? ` (${e.code})` : ""}`).join("; ")}
        </Alert>
      )}
      {latest && <BuildStatus snap={latest} />}
      <ViewSwitcher
        value={state.view}
        available={viewCatalogue.data?.views?.map((v) => v.name)}
        onChange={(view) => setState({ view, focus: undefined, node: undefined })}
      />
      <p className="text-[12px] text-muted-foreground">
        {info.description}
        {isChangeImpact && comparedWith && (
          <>
            {" "}
            Compared with the snapshot of <code>{comparedWith.commit_sha ? comparedWith.commit_sha.slice(0, 12) : comparedWith.id}</code>.
          </>
        )}
      </p>
      {state.focus && (
        <div className="flex items-center gap-2 text-[12px]">
          <span>Showing an expanded group.</span>
          <Button size="sm" variant="ghost" onClick={() => setState({ focus: undefined })}>
            Back to the full view
          </Button>
        </div>
      )}
      {!current ? null : graph.isError ? (
        <ErrorPanel error={graph.error} title={`Could not load the ${info.label} view`} onVerify={() => graph.refetch()} />
      ) : diff.isError ? (
        <ErrorPanel error={diff.error} title="Could not compare the snapshots" onVerify={() => diff.refetch()} />
      ) : isChangeImpact && (ready.length < 2 || graph.data?.base_snapshot_id === null) ? (
        <EmptyStateCard icon={<Waypoints />} title="Nothing to compare yet">
          Change impact needs two finished snapshots. Rebuild after the next commit, or choose a snapshot to compare with.
        </EmptyStateCard>
      ) : !graphData || (base && diff.isPending) ? (
        <Card className="p-4">
          <LoadingSkeleton rows={8} label="Loading the graph" />
        </Card>
      ) : graphData.nodes.length + (graphData.aggregated?.length ?? 0) === 0 ? (
        <EmptyStateCard icon={<Waypoints />} title={`Nothing in the ${info.label} view`}>
          The graph of this snapshot has no {info.label.toLowerCase()} elements. Try another view, or rebuild after adding the repositories that hold them.
        </EmptyStateCard>
      ) : (
        <GraphExplorer
          key={`${current.id}:${state.view}:${state.focus ?? ""}`}
          data={graphData}
          diff={base || isChangeImpact ? diff.data : undefined}
          title={`CodeGraph${applicationName ? ` of ${applicationName}` : ""}, ${info.label} view`}
          initialSelected={state.node}
          onSelect={(node) => setState({ node })}
          onExpand={onExpand}
          loadDetail={loadDetail}
          detailKey={["codegraph", applicationId, current.id]}
          loadPaths={loadPaths}
          onExportJson={canExport ? onExportJson : undefined}
          jsonExport={canExport}
          exportName={`codegraph-${applicationName ?? applicationId}-${state.view}`}
          version={meta.data?.version}
          toolbar={
            <SnapshotPicker
              snapshots={ready}
              value={current.id}
              compareTo={compare}
              onChange={(snapshot) => setState({ snapshot, focus: undefined })}
              onCompare={(c) => setState({ compare: c })}
            />
          }
        />
      )}
    </div>
  );
}

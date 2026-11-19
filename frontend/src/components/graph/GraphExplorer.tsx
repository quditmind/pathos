import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Background, Controls, MarkerType, MiniMap, ReactFlow, ReactFlowProvider, useReactFlow, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import * as Popover from "@radix-ui/react-popover";
import * as DM from "@radix-ui/react-dropdown-menu";
import { ChevronDown, Download, Filter, LayoutList, Maximize, Network, Search, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, Input, Select, Skeleton } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import { flowEdgeTypes, flowNodeTypes, NODE_H, NODE_W, AGG_H, type Emphasis, type FlowNode, type EvidenceFlowEdge } from "./GraphElements";
import { GraphListView } from "./GraphListView";
import { Inspector, type InspectorProps } from "./Inspector";
import { GraphLegend } from "./Legend";
import { exportFileName, exportImage, downloadJson } from "./export";
import { layoutGraph, type LayoutEdge, type LayoutNode, type Placed } from "./layout";
import {
  diffIndex,
  edgeAriaLabel,
  evidenceStyle,
  filterGraph,
  layerLabel,
  mergeDiff,
  neighbourInDirection,
  nodeAriaLabel,
  nodeTypeLabel,
  searchNodes,
  technologies,
  traceFromPaths,
  tracePaths,
  diffStyle,
  type TraceResult,
} from "./model";
import { emptyFilters, evidenceKinds, layers as allLayers, severities, type GraphData, type GraphDiff, type GraphFilters, type Layer, type NodeType, type TraceDirection } from "./types";

/** Timings of the first render, reported once per data set (ADR-005 measurement). */
export interface RenderMetrics {
  nodes: number;
  edges: number;
  layoutMs: number;
  totalMs: number;
  engine: string;
}

export interface GraphExplorerProps {
  data: GraphData;
  /** Accessible name of the graph ("CodeGraph of payments-api, architecture view"). */
  title: string;
  /** Compare mode: colours added, removed and changed elements. */
  diff?: GraphDiff;
  /** Expand an aggregate (lazy: the caller requests focus on its id). */
  onExpand?: (aggregateId: string) => void;
  /** Server path tracing; falls back to the loaded edges. Returns edge-id paths. */
  loadPaths?: (from: string, direction: TraceDirection) => Promise<string[][]>;
  loadDetail?: InspectorProps["loadDetail"];
  detailKey?: readonly unknown[];
  refHref?: InspectorProps["refHref"];
  /** JSON export through the API; without it the loaded graph is downloaded. */
  onExportJson?: () => void | Promise<void>;
  /** Layers on at start; all by default. */
  initialLayers?: Layer[];
  /** Node to select at start (deep links). */
  initialSelected?: string;
  onSelect?: (id: string | undefined) => void;
  /** Extra toolbar content (snapshots, compare). */
  toolbar?: ReactNode;
  exportName?: string;
  version?: string;
  onRendered?: (m: RenderMetrics) => void;
  /** Canvas height in px (default 640). */
  height?: number;
  /** What node `finding_counts` count, in the inspector and filters (default "findings"; threat models: "threats"). */
  countsNoun?: string;
}

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(() => typeof window !== "undefined" && !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches);
  useEffect(() => {
    const m = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    if (!m) return;
    const on = () => setReduced(m.matches);
    m.addEventListener?.("change", on);
    return () => m.removeEventListener?.("change", on);
  }, []);
  return reduced;
}

/** The app theme is a "dark" class on <html> (AppShell). */
function useDarkTheme() {
  const [dark, setDark] = useState(() => typeof document !== "undefined" && document.documentElement.classList.contains("dark"));
  useEffect(() => {
    if (typeof MutationObserver === "undefined") return;
    const o = new MutationObserver(() => setDark(document.documentElement.classList.contains("dark")));
    o.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => o.disconnect();
  }, []);
  return dark;
}

function Toggle({ pressed, onClick, children, label }: { pressed: boolean; onClick: () => void; children: ReactNode; label?: string }) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      aria-label={label}
      onClick={onClick}
      className={cn(
        "h-7 rounded-md border px-2 text-[12px] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
        pressed ? "border-foreground bg-foreground text-background" : "border-border bg-surface text-foreground hover:bg-surface-muted",
      )}
    >
      {children}
    </button>
  );
}

function CheckList<T extends string>({ legend, options, value, onChange, label }: { legend: string; options: readonly T[]; value: T[]; onChange: (v: T[]) => void; label: (v: T) => string }) {
  if (!options.length) return null;
  return (
    <fieldset className="space-y-1">
      <legend className="mb-1 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">{legend}</legend>
      <div className="max-h-40 space-y-0.5 overflow-y-auto">
        {options.map((o) => (
          <label key={o} className="flex items-center gap-2 text-[12px]">
            <input type="checkbox" checked={value.includes(o)} onChange={(e) => onChange(e.target.checked ? [...value, o] : value.filter((x) => x !== o))} />
            {label(o)}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

export function activeFilterCount(f: GraphFilters): number {
  return f.types.length + f.technologies.length + f.evidence.length + (f.hasFindings ? 1 : 0) + (f.minSeverity ? 1 : 0) + (f.internetExposed ? 1 : 0);
}

function FiltersPanel({ filters, setFilters, types, techs, countsNoun = "findings" }: { filters: GraphFilters; setFilters: (f: GraphFilters) => void; types: NodeType[]; techs: string[]; countsNoun?: string }) {
  const n = activeFilterCount(filters);
  return (
    <Popover.Root>
      <Popover.Trigger asChild>
        <Button variant="secondary" size="sm" aria-label={`Filters${n ? `, ${n} active` : ""}`}>
          <Filter /> Filters{n ? ` (${n})` : ""} <ChevronDown />
        </Button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content align="start" sideOffset={4} className="z-50 w-80 space-y-3 rounded-md border border-border bg-surface p-3 shadow-lg" aria-label="Graph filters">
          <fieldset className="space-y-1.5">
            <legend className="mb-1 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">Security status</legend>
            <label className="flex items-center gap-2 text-[12px]">
              <input type="checkbox" checked={filters.hasFindings} onChange={(e) => setFilters({ ...filters, hasFindings: e.target.checked })} />
              Has open {countsNoun}
            </label>
            <label className="flex items-center gap-2 text-[12px]">
              <input type="checkbox" checked={filters.internetExposed} onChange={(e) => setFilters({ ...filters, internetExposed: e.target.checked })} />
              Internet-exposed
            </label>
            <label className="flex items-center gap-2 text-[12px]">
              Severity at least
              <Select aria-label="Minimum severity" value={filters.minSeverity} onChange={(e) => setFilters({ ...filters, minSeverity: e.target.value as GraphFilters["minSeverity"] })} className="h-7 w-28">
                <option value="">Any</option>
                {severities.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            </label>
          </fieldset>
          <CheckList legend="Type" options={types} value={filters.types} onChange={(types) => setFilters({ ...filters, types })} label={(t) => nodeTypeLabel[t] ?? t} />
          <CheckList legend="Technology" options={techs} value={filters.technologies} onChange={(technologies) => setFilters({ ...filters, technologies })} label={(t) => t} />
          <CheckList legend="Evidence" options={evidenceKinds} value={filters.evidence} onChange={(evidence) => setFilters({ ...filters, evidence })} label={(e) => evidenceStyle[e].label} />
          <Button variant="ghost" size="sm" onClick={() => setFilters({ ...emptyFilters, query: filters.query })} disabled={!n}>
            Clear filters
          </Button>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

type LayoutState = { key: string; positions: Map<string, Placed>; engine: string; ms: number };

function Explorer(props: GraphExplorerProps) {
  const { data, diff, onExpand, loadPaths, title } = props;
  const rf = useReactFlow();
  const reduced = usePrefersReducedMotion();
  const dark = useDarkTheme();
  const duration = reduced ? 0 : 300;
  const wrapRef = useRef<HTMLDivElement>(null);
  const [filters, setFilters] = useState<GraphFilters>(emptyFilters);
  const [activeLayers, setActiveLayers] = useState<Set<Layer>>(() => new Set(props.initialLayers ?? allLayers));
  const [selectedId, setSelectedId] = useState<string | undefined>(props.initialSelected);
  const [trace, setTrace] = useState<{ from: string; direction: TraceDirection; result: TraceResult; note?: string } | null>(null);
  const [mode, setMode] = useState<"graph" | "list">("graph");
  const [matchIdx, setMatchIdx] = useState(0);
  const [layout, setLayout] = useState<LayoutState | null>(null);
  const [exportError, setExportError] = useState<string>();
  const t0 = useRef(performance.now());
  useEffect(() => {
    t0.current = performance.now();
  }, [data]);

  const select = useCallback(
    (id: string | undefined) => {
      setSelectedId(id);
      props.onSelect?.(id);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [props.onSelect],
  );

  const merged = useMemo(() => (diff ? mergeDiff(data, diff) : data), [data, diff]);
  const dIdx = useMemo(() => (diff ? diffIndex(diff) : undefined), [diff]);
  const visible = useMemo(() => filterGraph(merged, filters, activeLayers), [merged, filters, activeLayers]);
  const labels = useMemo(() => {
    const m = new Map<string, string>();
    for (const n of merged.nodes) m.set(n.id, n.label);
    for (const a of merged.aggregated ?? []) m.set(a.id, a.label);
    return m;
  }, [merged]);
  const labelOf = useCallback((id: string) => labels.get(id) ?? id, [labels]);
  const presentTypes = useMemo(() => [...new Set(merged.nodes.map((n) => n.type))].filter((t) => t !== "trust_boundary").sort() as NodeType[], [merged]);
  const presentLayers = useMemo(() => new Set(merged.nodes.map((n) => n.layer)), [merged]);
  const techs = useMemo(() => technologies(merged.nodes), [merged]);
  const matches = useMemo(() => searchNodes(visible.nodes.filter((n) => n.type !== "trust_boundary"), filters.query), [visible, filters.query]);
  const matchSet = useMemo(() => new Set(matches.map((m) => m.id)), [matches]);

  // Layout input: only what is visible.
  const layoutInput = useMemo(() => {
    const boundaryIds = new Set(visible.nodes.filter((n) => n.type === "trust_boundary").map((n) => n.id));
    const nodes: LayoutNode[] = [
      ...visible.nodes.map((n) =>
        n.type === "trust_boundary"
          ? { id: n.id, width: 0, height: 0, container: true }
          : { id: n.id, width: NODE_W, height: NODE_H, parent: n.parent && boundaryIds.has(n.parent) ? n.parent : undefined },
      ),
      ...visible.aggregated.map((a) => ({ id: a.id, width: NODE_W, height: AGG_H, parent: a.parent && boundaryIds.has(a.parent) ? a.parent : undefined })),
    ];
    const edges: LayoutEdge[] = visible.edges.map((e) => ({ id: e.id, source: e.source, target: e.target }));
    return { nodes, edges, key: `${nodes.map((n) => n.id).join(",")}|${edges.length}` };
  }, [visible]);

  useEffect(() => {
    let live = true;
    void layoutGraph(layoutInput.nodes, layoutInput.edges).then((r) => {
      if (live) setLayout({ key: layoutInput.key, positions: r.positions, engine: r.engine, ms: r.ms });
    });
    return () => {
      live = false;
    };
  }, [layoutInput]);

  const ready = layout?.key === layoutInput.key;

  // Absolute positions (for keyboard navigation and centring).
  const absolute = useMemo(() => {
    const m = new Map<string, { x: number; y: number; w: number; h: number }>();
    if (!layout) return m;
    for (const n of layoutInput.nodes) {
      const p = layout.positions.get(n.id);
      if (!p) continue;
      const par = n.parent ? layout.positions.get(n.parent) : undefined;
      m.set(n.id, { x: p.x + (par?.x ?? 0), y: p.y + (par?.y ?? 0), w: p.width, h: p.height });
    }
    return m;
  }, [layout, layoutInput]);

  const emphasisOf = useCallback(
    (id: string): Emphasis => {
      if (trace) return trace.result.nodes.has(id) ? "trace" : "dim";
      if (filters.query.trim()) return matchSet.has(id) ? "match" : "none";
      return "none";
    },
    [trace, filters.query, matchSet],
  );

  const flowNodes = useMemo((): FlowNode[] => {
    if (!layout || !ready) return [];
    const pos = (id: string) => layout.positions.get(id) ?? { x: 0, y: 0, width: NODE_W, height: NODE_H };
    const boundaryIds = new Set(visible.nodes.filter((n) => n.type === "trust_boundary").map((n) => n.id));
    const out: FlowNode[] = [];
    for (const n of visible.nodes) {
      if (n.type !== "trust_boundary") continue;
      const p = pos(n.id);
      out.push({
        id: n.id,
        type: "boundary",
        position: { x: p.x, y: p.y },
        data: { node: n, diff: dIdx?.nodes.get(n.id) },
        style: { width: p.width, height: p.height },
        width: p.width,
        height: p.height,
        selectable: false,
        focusable: false,
        draggable: false,
        zIndex: -1,
        ariaLabel: `Trust boundary ${n.label}`,
      });
    }
    for (const n of visible.nodes) {
      if (n.type === "trust_boundary") continue;
      const p = pos(n.id);
      const diffS = dIdx?.nodes.get(n.id);
      out.push({
        id: n.id,
        type: "entity",
        position: { x: p.x, y: p.y },
        parentId: n.parent && boundaryIds.has(n.parent) ? n.parent : undefined,
        data: { node: n, diff: diffS, emphasis: emphasisOf(n.id) },
        width: NODE_W,
        height: NODE_H,
        selected: n.id === selectedId,
        draggable: false,
        ariaLabel: nodeAriaLabel(n, diffS),
        ariaRole: "button",
      });
    }
    for (const a of visible.aggregated) {
      const p = pos(a.id);
      out.push({
        id: a.id,
        type: "aggregate",
        position: { x: p.x, y: p.y },
        parentId: a.parent && boundaryIds.has(a.parent) ? a.parent : undefined,
        data: { aggregate: a, emphasis: emphasisOf(a.id), onExpand },
        width: NODE_W,
        height: AGG_H,
        selected: a.id === selectedId,
        draggable: false,
        ariaLabel: `${a.label}, group of ${a.count} nodes${onExpand ? ", press Enter to expand" : ""}`,
        ariaRole: "button",
      });
    }
    return out;
  }, [layout, ready, visible, dIdx, emphasisOf, selectedId, onExpand]);

  const flowEdges = useMemo((): EvidenceFlowEdge[] => {
    if (!ready) return [];
    return visible.edges.map((e) => {
      const diffS = dIdx?.edges.get(e.id);
      const emphasis: Emphasis = trace ? (trace.result.edges.has(e.id) ? "trace" : "dim") : "none";
      const color = diffS && diffS !== "unchanged" ? diffStyle[diffS].color : evidenceStyle[e.evidence].color;
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        type: "evidence",
        data: { evidence: e.evidence, diff: diffS, emphasis },
        markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
        ariaLabel: edgeAriaLabel(e, labelOf, diffS),
        focusable: true,
        selectable: true,
      };
    });
  }, [ready, visible, dIdx, trace, labelOf]);

  // Fit once per laid-out data set and report the first-render timing.
  const fittedKey = useRef<string>("");
  useEffect(() => {
    if (!ready || !layout || fittedKey.current === layout.key) return;
    fittedKey.current = layout.key;
    requestAnimationFrame(() => {
      void rf.fitView({ duration: 0, padding: 0.08 });
      requestAnimationFrame(() => {
        props.onRendered?.({ nodes: flowNodes.length, edges: flowEdges.length, layoutMs: layout.ms, totalMs: performance.now() - t0.current, engine: layout.engine });
      });
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, layout]);

  const focusNode = useCallback(
    (id: string) => {
      const find = () => wrapRef.current?.querySelector<HTMLElement>(`.react-flow__node[data-id="${CSS.escape(id)}"]`);
      const el = find();
      // Rendered: focus it (React Flow pans to a focused node). Culled
      // (outside the viewport): centre on it first, then focus once rendered.
      if (el) {
        el.focus();
        return;
      }
      const p = absolute.get(id);
      if (p) void rf.setCenter(p.x + p.w / 2, p.y + p.h / 2, { zoom: Math.max(rf.getZoom(), 0.8), duration });
      const retry = (n: number) => {
        const e = find();
        if (e) e.focus();
        else if (n > 0) requestAnimationFrame(() => retry(n - 1));
      };
      requestAnimationFrame(() => retry(20));
    },
    [absolute, rf, duration],
  );

  const runTrace = useCallback(
    async (direction: TraceDirection, from = selectedId) => {
      if (!from) return;
      if (loadPaths) {
        try {
          const paths = await loadPaths(from, direction);
          setTrace({ from, direction, result: traceFromPaths(merged.edges, paths, from) });
          return;
        } catch {
          setTrace({ from, direction, result: tracePaths(merged.edges, from, direction), note: "The server path search failed; showing paths over the loaded graph." });
          return;
        }
      }
      setTrace({ from, direction, result: tracePaths(merged.edges, from, direction) });
    },
    [selectedId, loadPaths, merged.edges],
  );

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const nodeEl = (e.target as HTMLElement).closest?.(".react-flow__node");
    const id = nodeEl?.getAttribute("data-id") ?? undefined;
    if (e.key === "Escape") {
      if (trace) setTrace(null);
      else select(undefined);
      return;
    }
    if (!id) return;
    if (e.key === "ArrowUp" || e.key === "ArrowDown" || e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      e.stopPropagation();
      const pts = new Map([...absolute].filter(([k]) => !k.startsWith("__")).map(([k, v]) => [k, { x: v.x + v.w / 2, y: v.y + v.h / 2 }]));
      for (const n of visible.nodes) if (n.type === "trust_boundary") pts.delete(n.id);
      const next = neighbourInDirection(pts, id, e.key);
      if (next) focusNode(next);
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      if (onExpand && visible.aggregated.some((a) => a.id === id)) onExpand(id);
      else select(id);
    }
  };

  const gotoMatch = (dir: 1 | -1) => {
    if (!matches.length) return;
    const i = (matchIdx + dir + matches.length) % matches.length;
    setMatchIdx(i);
    const m = matches[i]!;
    select(m.id);
    if (mode === "graph") focusNode(m.id);
  };

  const selectedNode = merged.nodes.find((n) => n.id === selectedId);
  const selectedAgg = (merged.aggregated ?? []).find((a) => a.id === selectedId);

  const doExport = async (format: "png" | "svg" | "json") => {
    setExportError(undefined);
    const name = exportFileName(props.exportName ?? title, format, props.version);
    try {
      if (format === "json") {
        if (props.onExportJson) await props.onExportJson();
        else downloadJson({ exported_at: new Date().toISOString(), pathos_version: props.version, ...visible }, name);
        return;
      }
      if (mode !== "graph") setMode("graph");
      await rf.fitView({ duration: 0 });
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
      await exportImage(wrapRef.current!, rf.getNodes() as Node[], format, name);
    } catch (err) {
      setExportError(`Export failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const hiddenCount = merged.nodes.length + (merged.aggregated?.length ?? 0) - visible.nodes.length - visible.aggregated.length;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2" role="toolbar" aria-label="Graph tools">
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            type="search"
            aria-label="Search nodes"
            placeholder="Search nodes, files, technology…"
            className="h-8 w-64 pl-7"
            value={filters.query}
            onChange={(e) => {
              setFilters({ ...filters, query: e.target.value });
              setMatchIdx(-1);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                gotoMatch(e.shiftKey ? -1 : 1);
              }
            }}
          />
        </div>
        {filters.query.trim() && (
          <span className="text-[12px] text-muted-foreground" aria-live="polite">
            {matches.length} match{matches.length === 1 ? "" : "es"}
            {matches.length > 0 && " · Enter for next"}
          </span>
        )}
        <FiltersPanel filters={filters} setFilters={setFilters} types={presentTypes} techs={techs} countsNoun={props.countsNoun} />
        <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Layers">
          {allLayers.map((l) => (
            <Toggle
              key={l}
              pressed={activeLayers.has(l)}
              label={`${layerLabel[l]} layer${presentLayers.has(l) ? "" : " (empty in this view)"}`}
              onClick={() => {
                const next = new Set(activeLayers);
                if (next.has(l)) next.delete(l);
                else next.add(l);
                setActiveLayers(next);
              }}
            >
              {layerLabel[l]}
            </Toggle>
          ))}
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-1">
          {props.toolbar}
          <div className="flex rounded-md border border-border" role="group" aria-label="Display">
            <Toggle pressed={mode === "graph"} onClick={() => setMode("graph")} label="Graph view">
              <Network className="inline size-3.5" aria-hidden /> Graph
            </Toggle>
            <Toggle pressed={mode === "list"} onClick={() => setMode("list")} label="List view">
              <LayoutList className="inline size-3.5" aria-hidden /> List
            </Toggle>
          </div>
          <Button variant="secondary" size="sm" onClick={() => void rf.fitView({ duration, padding: 0.08 })} disabled={mode !== "graph"}>
            <Maximize /> Fit
          </Button>
          <DM.Root>
            <DM.Trigger asChild>
              <Button variant="secondary" size="sm">
                <Download /> Export <ChevronDown />
              </Button>
            </DM.Trigger>
            <DM.Portal>
              <DM.Content align="end" sideOffset={4} className="z-50 min-w-40 rounded-md border border-border bg-surface p-1 shadow-lg">
                {(["png", "svg", "json"] as const).map((f) => (
                  <DM.Item key={f} onSelect={() => void doExport(f)} className="cursor-pointer rounded px-2 py-1.5 text-[13px] outline-none data-[highlighted]:bg-surface-muted">
                    {f === "png" ? "PNG image" : f === "svg" ? "SVG image" : "JSON (graph data)"}
                  </DM.Item>
                ))}
              </DM.Content>
            </DM.Portal>
          </DM.Root>
        </div>
      </div>
      {(trace || hiddenCount > 0 || merged.truncated || exportError) && (
        <div className="flex flex-wrap items-center gap-3 text-[12px] text-muted-foreground" aria-live="polite">
          {trace && (
            <span className="inline-flex items-center gap-1 rounded bg-primary/10 px-2 py-0.5 text-primary">
              Tracing {trace.direction === "in" ? "into" : "out of"} {labelOf(trace.from)}: {trace.result.nodes.size - 1} nodes, {trace.result.edges.size} edges
              <button type="button" aria-label="Clear the path trace" onClick={() => setTrace(null)} className="ml-1">
                <X className="size-3.5" />
              </button>
            </span>
          )}
          {trace?.note && <span>{trace.note}</span>}
          {hiddenCount > 0 && <span>{hiddenCount} nodes hidden by filters or layers.</span>}
          {merged.truncated && <span>The server truncated this view; expand groups or narrow the view to see more.</span>}
          {exportError && <span className="text-danger">{exportError}</span>}
        </div>
      )}
      <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_320px]">
        <Card className="min-w-0 overflow-hidden">
          {mode === "list" ? (
            <div className="max-h-[720px] overflow-auto p-3">
              <GraphListView graph={visible} labelOf={labelOf} selectedId={selectedId} onSelect={select} diff={dIdx} highlight={trace?.result.nodes} />
            </div>
          ) : (
            <div
              ref={wrapRef}
              className="pathos-graph relative"
              style={{ height: props.height ?? 640 }}
              onKeyDown={onKeyDown}
              data-testid="graph-canvas"
              data-layout-engine={layout?.engine}
              data-node-count={flowNodes.length}
            >
              {!ready && (
                <div className="absolute inset-0 z-10 flex flex-col gap-2 p-4" aria-busy="true" aria-label="Laying out the graph">
                  <Skeleton className="h-8 w-48" />
                  <Skeleton className="h-full w-full" />
                </div>
              )}
              <ReactFlow
                nodes={flowNodes}
                edges={flowEdges}
                nodeTypes={flowNodeTypes}
                edgeTypes={flowEdgeTypes}
                onNodeClick={(_, n) => select(n.type === "boundary" ? undefined : n.id)}
                onNodeDoubleClick={(_, n) => n.type === "aggregate" && onExpand?.(n.id)}
                onPaneClick={() => select(undefined)}
                nodesDraggable={false}
                nodesConnectable={false}
                nodesFocusable
                edgesFocusable
                elementsSelectable
                deleteKeyCode={null}
                selectionKeyCode={null}
                multiSelectionKeyCode={null}
                onlyRenderVisibleElements
                minZoom={0.02}
                maxZoom={2.5}
                proOptions={{ hideAttribution: true }}
                aria-label={title}
                ariaLabelConfig={{ "node.a11yDescription.default": "Graph node. Use the arrow keys to move to a neighbouring node, Enter to inspect it, Escape to clear." }}
                colorMode={dark ? "dark" : "light"}
              >
                <Background gap={16} size={1} color="var(--border)" />
                <Controls showInteractive={false} position="bottom-right" />
                {flowNodes.length <= 1500 && <MiniMap pannable zoomable position="bottom-left" ariaLabel="Mini map" nodeColor="var(--surface-muted)" maskColor="color-mix(in srgb, var(--background) 60%, transparent)" />}
              </ReactFlow>
            </div>
          )}
        </Card>
        <Card className="max-h-[720px] min-w-0 overflow-y-auto" aria-label="Node inspector">
          <Inspector
            node={selectedNode}
            aggregate={selectedAgg}
            edges={merged.edges}
            labelOf={labelOf}
            loadDetail={props.loadDetail}
            detailKey={props.detailKey}
            refHref={props.refHref}
            onTrace={(d) => void runTrace(d)}
            onExpand={onExpand}
            onClose={() => select(undefined)}
            countsNoun={props.countsNoun}
          />
        </Card>
      </div>
      <GraphLegend diffCounts={dIdx?.counts} />
    </div>
  );
}

/** The shared graph component (ADR-005): React Flow with ELK in a web worker. */
export function GraphExplorer(props: GraphExplorerProps) {
  return (
    <ReactFlowProvider>
      <Explorer {...props} />
    </ReactFlowProvider>
  );
}

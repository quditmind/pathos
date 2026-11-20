import { memo } from "react";
import { BaseEdge, getBezierPath, Handle, Position, useStore, type Edge, type EdgeProps, type Node, type NodeProps } from "@xyflow/react";
import { Globe, Layers } from "lucide-react";
import { severityColor } from "@/components/data/Severity";
import { cn } from "@/lib/utils";
import { aggregateSummary, diffStyle, evidenceStyle, findingTotal, isInternetExposed, nodeTypeLabel, technologyOf, topSeverity, trustBoundaryStyle } from "./model";
import type { AggregateNode, DiffStatus, Evidence, GraphNode } from "./types";

/** Visual emphasis from search, path tracing and selection. */
export type Emphasis = "none" | "match" | "trace" | "dim";

export type EntityData = { node: GraphNode; diff?: DiffStatus; emphasis: Emphasis };
export type AggregateData = { aggregate: AggregateNode; emphasis: Emphasis; onExpand?: (id: string) => void };
export type BoundaryData = { node: GraphNode; diff?: DiffStatus };
export type EvidenceEdgeData = { evidence: Evidence; diff?: DiffStatus; emphasis: Emphasis; /** Stored edges a lifted or aggregated edge stands for. */ count?: number };

export type EntityFlowNode = Node<EntityData, "entity">;
export type AggregateFlowNode = Node<AggregateData, "aggregate">;
export type BoundaryFlowNode = Node<BoundaryData, "boundary">;
export type FlowNode = EntityFlowNode | AggregateFlowNode | BoundaryFlowNode;
export type EvidenceFlowEdge = Edge<EvidenceEdgeData, "evidence">;

export const NODE_W = 200;
export const NODE_H = 52;
export const AGG_H = 60;

// Below this zoom nodes render as plain boxes (ADR-005 mitigation 2).
const zoomedOut = (s: { transform: [number, number, number] }) => s.transform[2] < 0.45;

const handleCls = "!size-1.5 !min-h-0 !min-w-0 !border-0 !bg-transparent";

function emphasisCls(e: Emphasis) {
  return e === "dim" ? "opacity-25" : e === "match" ? "ring-2 ring-warning ring-offset-1 ring-offset-surface" : e === "trace" ? "ring-2 ring-primary" : "";
}

export const EntityNode = memo(function EntityNode({ data, selected }: NodeProps<EntityFlowNode>) {
  const far = useStore(zoomedOut);
  const n = data.node;
  const sev = topSeverity(n);
  const diffColor = data.diff && data.diff !== "unchanged" ? diffStyle[data.diff].color : undefined;
  const border = diffColor ?? (sev ? severityColor[sev] : "var(--border)");
  const tech = technologyOf(n);
  return (
    <div
      className={cn(
        "relative flex h-[52px] w-[200px] flex-col justify-center rounded-md border bg-surface px-2.5 text-left shadow-sm",
        selected && "bg-primary/10",
        emphasisCls(data.emphasis),
        data.diff === "removed" && "border-dashed",
      )}
      style={{ borderColor: border, borderWidth: diffColor || sev ? 2 : 1 }}
      data-diff={data.diff}
      data-evidence-node={n.type}
    >
      <Handle type="target" position={Position.Left} className={handleCls} isConnectable={false} />
      {far ? (
        <span className="truncate text-[12px] font-semibold text-foreground">{n.label}</span>
      ) : (
        <>
          <span className="truncate text-[12px] font-semibold text-foreground" title={n.label}>
            {n.label}
          </span>
          <span className="flex items-center gap-1 truncate text-[10.5px] text-muted-foreground">
            {nodeTypeLabel[n.type] ?? n.type}
            {tech && <> · {tech}</>}
            {isInternetExposed(n) && <Globe className="size-3 text-danger" aria-hidden />}
          </span>
          {sev && (
            <span
              className="absolute top-1 right-1 rounded-full px-1 text-[10px] font-semibold text-white"
              style={{ backgroundColor: severityColor[sev] }}
              aria-hidden
            >
              {findingTotal(n)}
            </span>
          )}
        </>
      )}
      <Handle type="source" position={Position.Right} className={handleCls} isConnectable={false} />
    </div>
  );
});

export const AggregateNodeView = memo(function AggregateNodeView({ data, selected }: NodeProps<AggregateFlowNode>) {
  const a = data.aggregate;
  const sev = topSeverity(a);
  const findings = findingTotal(a);
  return (
    <div
      className={cn(
        "flex h-[60px] w-[200px] items-center gap-2 rounded-md border-2 border-double border-border bg-surface-muted px-2.5",
        selected && "bg-primary/10",
        emphasisCls(data.emphasis),
      )}
      style={sev ? { borderColor: severityColor[sev] } : undefined}
    >
      <Handle type="target" position={Position.Left} className={handleCls} isConnectable={false} />
      <Layers className="size-4 shrink-0 text-muted-foreground" aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="truncate text-[12px] font-semibold text-foreground">{a.label}</div>
        <div className="truncate text-[10.5px] text-muted-foreground">
          {a.count} nodes{aggregateSummary(a) ? ` · ${aggregateSummary(a)}` : ""}
        </div>
        {findings > 0 && (
          <div className="truncate text-[10.5px] font-medium" style={{ color: severityColor[sev!] }}>
            {findings} open finding{findings === 1 ? "" : "s"}, highest {sev}
          </div>
        )}
      </div>
      {data.onExpand && (
        <button
          type="button"
          tabIndex={-1}
          className="nodrag rounded border border-border bg-surface px-1.5 text-[11px] text-foreground hover:bg-surface-muted"
          onClick={(e) => {
            e.stopPropagation();
            data.onExpand?.(a.id);
          }}
        >
          Expand
        </button>
      )}
      <Handle type="source" position={Position.Right} className={handleCls} isConnectable={false} />
    </div>
  );
});

export const BoundaryNode = memo(function BoundaryNode({ data }: NodeProps<BoundaryFlowNode>) {
  return (
    <div
      className="pointer-events-none size-full rounded-[10px] border-[1.5px] border-dashed"
      style={{ borderColor: trustBoundaryStyle.color }}
      data-trust-boundary
    >
      <span className="absolute top-2 left-3 text-[10.5px] font-semibold tracking-wide uppercase" style={{ color: trustBoundaryStyle.color }}>
        Trust boundary · {data.node.label}
      </span>
    </div>
  );
});

export const EvidenceEdge = memo(function EvidenceEdge(props: EdgeProps<EvidenceFlowEdge>) {
  const { sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, markerEnd, selected } = props;
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  const count = data?.count ?? 1;
  const ev = evidenceStyle[data?.evidence ?? "verified"];
  const diffColor = data?.diff && data.diff !== "unchanged" ? diffStyle[data.diff].color : undefined;
  const emphasis = data?.emphasis ?? "none";
  return (
    <BaseEdge
      id={props.id}
      path={path}
      markerEnd={markerEnd}
      interactionWidth={12}
      label={count > 1 ? `×${count}` : undefined}
      labelX={labelX}
      labelY={labelY}
      labelStyle={{ fontSize: 10, fill: "var(--foreground)" }}
      labelBgStyle={{ fill: "var(--surface)" }}
      labelShowBg
      style={{
        stroke: diffColor ?? ev.color,
        strokeWidth: emphasis === "trace" || selected ? 3 : 1.8,
        strokeDasharray: ev.dash || undefined,
        opacity: emphasis === "dim" ? 0.15 : 1,
      }}
      className="pathos-evidence-edge"
      data-evidence={data?.evidence}
    />
  );
});

export const flowNodeTypes = { entity: EntityNode, aggregate: AggregateNodeView, boundary: BoundaryNode };
export const flowEdgeTypes = { evidence: EvidenceEdge };

import { useState } from "react";
import { Table, Td, Th } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import { EvidenceChip } from "./Legend";
import { aggregateSummary, diffStyle, edgeTypeLabel, findingTotal, isInternetExposed, layerLabel, nodeTypeLabel, technologyOf, topSeverity } from "./model";
import type { DiffIndex, VisibleGraph } from "./model";
import { SeverityBadge } from "@/components/data/Severity";

const PAGE = 200;

/**
 * Accessible alternative to the canvas: the same (filtered) nodes and edges as
 * two tables, with the same selection.
 */
export function GraphListView({
  graph,
  labelOf,
  selectedId,
  onSelect,
  diff,
  highlight,
}: {
  graph: VisibleGraph;
  labelOf: (id: string) => string;
  selectedId?: string;
  onSelect: (id: string) => void;
  diff?: DiffIndex;
  highlight?: Set<string>;
}) {
  const [nodeLimit, setNodeLimit] = useState(PAGE);
  const [edgeLimit, setEdgeLimit] = useState(PAGE);
  const nodes = graph.nodes.filter((n) => n.type !== "trust_boundary");
  const boundaries = graph.nodes.filter((n) => n.type === "trust_boundary");
  const DiffCell = ({ id, edge }: { id: string; edge?: boolean }) => {
    const s = (edge ? diff?.edges : diff?.nodes)?.get(id);
    return s && s !== "unchanged" ? <span style={{ color: diffStyle[s].color }} className="font-semibold">{diffStyle[s].label}</span> : <span className="text-muted-foreground">—</span>;
  };
  return (
    <div className="space-y-4" data-testid="graph-list-view">
      <section aria-labelledby="graph-list-nodes">
        <h3 id="graph-list-nodes" className="mb-1 text-[13px] font-semibold">
          Nodes ({nodes.length + graph.aggregated.length})
        </h3>
        <Table>
          <thead>
            <tr>
              <Th>Name</Th>
              <Th>Type</Th>
              <Th>Layer</Th>
              <Th>Technology</Th>
              <Th>Findings</Th>
              <Th>Exposure</Th>
              <Th>Location</Th>
              <Th>Trust boundary</Th>
              {diff && <Th>Change</Th>}
            </tr>
          </thead>
          <tbody>
            {graph.aggregated.map((a) => (
              <tr key={a.id} className={cn(selectedId === a.id && "bg-primary/10")}>
                <Td>
                  <button type="button" className="text-left font-medium text-primary underline" onClick={() => onSelect(a.id)}>
                    {a.label}
                  </button>
                </Td>
                <Td>Group of {a.count}</Td>
                <Td>{a.layer ? layerLabel[a.layer] : "—"}</Td>
                <Td>{aggregateSummary(a) || "—"}</Td>
                <Td>—</Td>
                <Td>—</Td>
                <Td>—</Td>
                <Td>{a.parent ? labelOf(a.parent) : "—"}</Td>
                {diff && <Td>—</Td>}
              </tr>
            ))}
            {nodes.slice(0, nodeLimit).map((n) => {
              const sev = topSeverity(n);
              return (
                <tr key={n.id} className={cn(selectedId === n.id && "bg-primary/10", highlight?.has(n.id) && "outline outline-1 outline-primary")} aria-selected={selectedId === n.id}>
                  <Td>
                    <button type="button" className="text-left font-medium text-primary underline" onClick={() => onSelect(n.id)} aria-label={`Inspect ${n.label}`}>
                      {n.label}
                    </button>
                  </Td>
                  <Td>{nodeTypeLabel[n.type] ?? n.type}</Td>
                  <Td>{layerLabel[n.layer] ?? n.layer}</Td>
                  <Td>{technologyOf(n) ?? "—"}</Td>
                  <Td>{sev ? <span className="inline-flex items-center gap-1"><SeverityBadge value={sev} /> {findingTotal(n)}</span> : "—"}</Td>
                  <Td>{isInternetExposed(n) ? <span className="font-semibold text-danger">Internet</span> : "—"}</Td>
                  <Td>{n.attrs?.file ? <code className="break-all">{String(n.attrs.file)}{n.attrs.line ? `:${n.attrs.line}` : ""}</code> : "—"}</Td>
                  <Td>{n.parent ? labelOf(n.parent) : "—"}</Td>
                  {diff && <Td><DiffCell id={n.id} /></Td>}
                </tr>
              );
            })}
          </tbody>
        </Table>
        {nodes.length > nodeLimit && (
          <button type="button" className="mt-1 text-[12px] text-primary underline" onClick={() => setNodeLimit((l) => l + PAGE)}>
            Show {Math.min(PAGE, nodes.length - nodeLimit)} more nodes
          </button>
        )}
        {boundaries.length > 0 && (
          <p className="mt-1 text-[12px] text-muted-foreground">Trust boundaries: {boundaries.map((b) => b.label).join(", ")}</p>
        )}
      </section>
      <section aria-labelledby="graph-list-edges">
        <h3 id="graph-list-edges" className="mb-1 text-[13px] font-semibold">
          Relationships ({graph.edges.length})
        </h3>
        <Table>
          <thead>
            <tr>
              <Th>From</Th>
              <Th>Relationship</Th>
              <Th>To</Th>
              <Th>Evidence</Th>
              <Th>Evidence references</Th>
              {diff && <Th>Change</Th>}
            </tr>
          </thead>
          <tbody>
            {graph.edges.slice(0, edgeLimit).map((e) => (
              <tr key={e.id}>
                <Td>{labelOf(e.source)}</Td>
                <Td>
                  {edgeTypeLabel[e.type] ?? e.type}
                  {(e.count ?? 1) > 1 && <span className="text-muted-foreground"> ({e.count} connections)</span>}
                </Td>
                <Td>{labelOf(e.target)}</Td>
                <Td><EvidenceChip evidence={e.evidence} /></Td>
                <Td>
                  <span className="text-[12px] break-all">{e.evidence_refs.map((r) => `${r.kind}: ${r.ref}`).join("; ") || "—"}</span>
                </Td>
                {diff && <Td><DiffCell id={e.id} edge /></Td>}
              </tr>
            ))}
          </tbody>
        </Table>
        {graph.edges.length > edgeLimit && (
          <button type="button" className="mt-1 text-[12px] text-primary underline" onClick={() => setEdgeLimit((l) => l + PAGE)}>
            Show {Math.min(PAGE, graph.edges.length - edgeLimit)} more relationships
          </button>
        )}
      </section>
    </div>
  );
}

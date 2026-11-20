import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowLeftToLine, ArrowRightFromLine, Expand, X } from "lucide-react";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Skeleton } from "@/components/ui/primitives";
import { splitHref } from "@/lib/utils";
import { EvidenceChip } from "./Legend";
import { aggregateSummary, edgeTypeLabel, isInternetExposed, layerLabel, nodeTypeLabel, safeDetail } from "./model";
import type { AggregateNode, EvidenceRef, GraphEdge, GraphNode, NodeDetail } from "./types";
import { severities } from "./types";

/** Attribute keys whose values are never shown (secrets are referenced, never displayed). */
const hiddenAttr = /(^value$|secret|password|passwd|token|credential|private[_-]?key)/i;

/** Where an evidence reference links to inside PATHOS, if anywhere. */
export function defaultRefHref(r: EvidenceRef): string | undefined {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (r.kind === "scan" && uuid.test(r.ref)) return `/scans/${r.ref}`;
  if (r.kind === "sbom") return "/sbom";
  return undefined;
}

const refKindLabel: Record<EvidenceRef["kind"], string> = {
  file_line: "Source",
  sbom: "SBOM",
  scan: "Scan",
  registry: "Inventory record",
  runtime: "Runtime",
  ai_record: "AI evidence record",
  binary: "Binary offset",
};

function RefLine({ r, refHref }: { r: EvidenceRef; refHref: (r: EvidenceRef) => string | undefined }) {
  const href = refHref(r);
  const detail = safeDetail(r.kind, r.detail);
  const text = <code className="break-all">{r.ref}</code>;
  return (
    <li className="text-[12px]">
      <span className="text-muted-foreground">{refKindLabel[r.kind] ?? r.kind}: </span>
      {href ? (
        href.startsWith("/") ? (
          <Link {...splitHref(href)} className="text-primary underline">
            {text}
          </Link>
        ) : (
          <a href={href} className="text-primary underline" target="_blank" rel="noreferrer noopener">
            {text}
          </a>
        )
      ) : (
        text
      )}
      {detail && <span className="text-muted-foreground"> · {detail}</span>}
    </li>
  );
}

function EdgeList({ title, edges, labelOf, refHref, end }: { title: string; edges: GraphEdge[]; labelOf: (id: string) => string; refHref: (r: EvidenceRef) => string | undefined; end: "source" | "target" }) {
  if (!edges.length) return null;
  return (
    <section>
      <h4 className="mb-1 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">
        {title} ({edges.length})
      </h4>
      <ul className="space-y-2">
        {edges.slice(0, 50).map((e) => (
          <li key={e.id} className="rounded border border-border p-1.5">
            <div className="flex flex-wrap items-center gap-1.5 text-[12px]">
              <span>{edgeTypeLabel[e.type] ?? e.type}</span>
              <span className="font-medium">{labelOf(e[end])}</span>
              <EvidenceChip evidence={e.evidence} />
            </div>
            <ul className="mt-1 space-y-0.5">
              {e.evidence_refs.map((r, i) => (
                <RefLine key={i} r={r} refHref={refHref} />
              ))}
            </ul>
          </li>
        ))}
      </ul>
      {edges.length > 50 && <p className="mt-1 text-[11px] text-muted-foreground">Showing 50 of {edges.length}. Use the list view for all.</p>}
    </section>
  );
}

export interface InspectorProps {
  node?: GraphNode;
  aggregate?: AggregateNode;
  edges: GraphEdge[];
  labelOf: (id: string) => string;
  /** Loads the full inspector payload (findings, source links); optional. */
  loadDetail?: (id: string) => Promise<NodeDetail>;
  detailKey?: readonly unknown[];
  refHref?: (r: EvidenceRef) => string | undefined;
  onTrace?: (direction: "in" | "out") => void;
  onExpand?: (id: string) => void;
  onClose: () => void;
  extra?: ReactNode;
  /** What `finding_counts` count (default "findings"). */
  countsNoun?: string;
}

export function Inspector({ node, aggregate, edges, labelOf, loadDetail, detailKey = [], refHref = defaultRefHref, onTrace, onExpand, onClose, extra, countsNoun = "findings" }: InspectorProps) {
  const id = node?.id ?? aggregate?.id;
  const detail = useQuery({
    queryKey: ["graph-node-detail", ...detailKey, id],
    queryFn: () => loadDetail!(id!),
    enabled: !!loadDetail && !!node,
  });
  if (!id) {
    return <p className="p-3 text-[12px] text-muted-foreground">Select a node to see its attributes, findings and evidence. Use Tab and the arrow keys to move between nodes.</p>;
  }
  const close = (
    <Button variant="ghost" size="icon" aria-label="Close the inspector" onClick={onClose}>
      <X />
    </Button>
  );
  if (aggregate) {
    return (
      <div className="space-y-3 p-3" aria-live="polite">
        <div className="flex items-start justify-between gap-2">
          <div>
            <div className="text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">Group</div>
            <h3 className="text-[14px] font-semibold">{aggregate.label}</h3>
          </div>
          {close}
        </div>
        <p className="text-[12px] text-muted-foreground">
          {aggregate.count} nodes grouped by the server{aggregateSummary(aggregate) ? `: ${aggregateSummary(aggregate)}` : ""}.
        </p>
        {severities.some((s) => (aggregate.finding_counts?.[s] ?? 0) > 0) && (
          <div>
            <div className="mb-1 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">Open findings in the group</div>
            <div className="flex flex-wrap gap-2">
              {severities
                .filter((s) => (aggregate.finding_counts?.[s] ?? 0) > 0)
                .map((s) => (
                  <span key={s} className="inline-flex items-center gap-1 text-[12px]">
                    <SeverityBadge value={s} /> {aggregate.finding_counts![s]}
                  </span>
                ))}
            </div>
          </div>
        )}
        {onExpand && (
          <Button size="sm" onClick={() => onExpand(aggregate.id)}>
            <Expand /> Expand group
          </Button>
        )}
      </div>
    );
  }
  const n = node!;
  // The server's edge list is complete (it reaches nodes outside this view).
  const all = detail.data?.edges?.length ? detail.data.edges : edges;
  const outgoing = all.filter((e) => e.source === n.id);
  const incoming = all.filter((e) => e.target === n.id);
  const nameOf = (id: string) => detail.data?.labels?.[id] ?? labelOf(id);
  const attrs = Object.entries(n.attrs ?? {}).filter(([, v]) => v !== undefined && v !== null && v !== "");
  const findings = detail.data?.findings ?? [];
  return (
    <div className="space-y-3 p-3" aria-live="polite">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">
            {nodeTypeLabel[n.type] ?? n.type} · {layerLabel[n.layer] ?? n.layer}
          </div>
          <h3 className="text-[14px] font-semibold break-words">{n.label}</h3>
          {isInternetExposed(n) && <span className="text-[11px] font-semibold text-danger">Internet-exposed</span>}
        </div>
        {close}
      </div>
      {onTrace && (
        <div className="flex flex-wrap gap-1.5">
          <Button size="sm" variant="secondary" onClick={() => onTrace("in")}>
            <ArrowLeftToLine /> Trace in
          </Button>
          <Button size="sm" variant="secondary" onClick={() => onTrace("out")}>
            <ArrowRightFromLine /> Trace out
          </Button>
        </div>
      )}
      {attrs.length > 0 && (
        <dl className="grid grid-cols-[96px_minmax(0,1fr)] gap-x-2 gap-y-1 text-[12px]">
          {attrs.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted-foreground">{k}</dt>
              <dd className="break-words">
                {hiddenAttr.test(k) || (n.type === "secret_ref" && !["file", "line", "name", "source", "kind"].includes(k)) ? (
                  <span className="text-muted-foreground italic">value never shown</span>
                ) : (
                  <code>{typeof v === "object" ? JSON.stringify(v) : String(v)}</code>
                )}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {n.attrs?.file && (
        <p className="text-[12px]">
          <span className="text-muted-foreground">Defined at </span>
          <code className="break-all">
            {String(n.attrs.file)}
            {n.attrs.line ? `:${n.attrs.line}` : ""}
          </code>
        </p>
      )}
      <section>
        <h4 className="mb-1 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">Open {countsNoun}</h4>
        <div className="flex flex-wrap gap-1">
          {severities.filter((s) => (n.finding_counts?.[s] ?? 0) > 0).map((s) => (
            <span key={s} className="inline-flex items-center gap-1 text-[12px]">
              <SeverityBadge value={s} /> {n.finding_counts![s]}
            </span>
          ))}
          {!severities.some((s) => (n.finding_counts?.[s] ?? 0) > 0) && <span className="text-[12px] text-muted-foreground">None</span>}
        </div>
        {loadDetail && detail.isPending && <Skeleton className="mt-2 h-10" />}
        {detail.isError && (
          <div className="mt-2">
            <ErrorPanel error={detail.error} title="Could not load the node details" onVerify={() => detail.refetch()} />
          </div>
        )}
        {findings.length > 0 && (
          <ul className="mt-2 space-y-1">
            {findings.slice(0, 20).map((f) => (
              <li key={f.id} className="flex items-center gap-2 rounded border border-border px-2 py-1 text-[12px]">
                <SeverityBadge value={f.severity} />
                {f.href ? (
                  <Link {...splitHref(f.href)} className="truncate text-primary underline">
                    {f.title}
                  </Link>
                ) : (
                  <span className="truncate">{f.title}</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
      {(detail.data?.source_links?.length ?? 0) > 0 && (
        <section>
          <h4 className="mb-1 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">Source links</h4>
          <ul className="space-y-0.5">
            {detail.data!.source_links!.map((l, i) => (
              <li key={i} className="text-[12px]">
                {!l.href ? (
                  <code className="break-all">{l.label}</code>
                ) : l.href.startsWith("/") ? (
                  <Link {...splitHref(l.href)} className="text-primary underline">
                    {l.label}
                  </Link>
                ) : /^https?:\/\//.test(l.href) ? (
                  <a href={l.href} target="_blank" rel="noreferrer noopener" className="text-primary underline">
                    {l.label}
                  </a>
                ) : (
                  <code>{l.label}</code>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}
      <EdgeList title="Outgoing" edges={outgoing} labelOf={nameOf} refHref={refHref} end="target" />
      <EdgeList title="Incoming" edges={incoming} labelOf={nameOf} refHref={refHref} end="source" />
      {extra}
    </div>
  );
}

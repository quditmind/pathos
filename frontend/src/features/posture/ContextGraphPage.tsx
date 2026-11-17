import { useMemo } from "react";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Network } from "lucide-react";
import { api } from "@/api/client";
import { severityColor } from "@/components/data/Severity";
import { Alert, Card, EmptyState, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { useApplications } from "@/features/repos/api";
import type { ContextGraph, GraphNode } from "./api";

type GraphSearch = { node?: string };
export const validateGraphSearch = (s: Record<string, unknown>): GraphSearch =>
  typeof s.node === "string" && /^(application|repository):[0-9a-f-]{36}$/.test(s.node) ? { node: s.node } : {};

// Column of each node type, left to right: who owns it, what it is, what
// is scanned, what it depends on, what is wrong.
const column: Record<GraphNode["type"], number> = {
  business_unit: 0, owner: 0, team: 0, application: 1, repository: 2, target: 3, component: 4, finding: 5,
};
const columnTitle = ["Ownership", "Application", "Repositories", "Scan targets", "Components", "Riskiest open findings"];
const typeLabel: Record<GraphNode["type"], string> = {
  business_unit: "Business unit", owner: "Owner", team: "Team", application: "Application", repository: "Repository",
  target: "Scan target", component: "Component", finding: "Finding",
};
const W = 210, H = 48, COL = 260, ROW = 58, TOP = 28;

/** Splits a node link ("/findings?finding=…") into a route and its search. */
function target(link: string) {
  const u = new URL(link, "https://pathos.invalid");
  return { to: u.pathname, search: Object.fromEntries(u.searchParams) };
}

function clip(s: string, n: number) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

export function ContextGraphPage() {
  const search = useSearch({ strict: false }) as GraphSearch;
  const navigate = useNavigate();
  const apps = useApplications();
  const q = useQuery({
    queryKey: ["posture", "graph", search.node],
    queryFn: () => api<ContextGraph>(`/api/v1/posture/context-graph?node=${encodeURIComponent(search.node!)}`),
    enabled: !!search.node,
  });
  const layout = useMemo(() => {
    if (!q.data) return null;
    const cols: GraphNode[][] = [[], [], [], [], [], []];
    for (const n of q.data.nodes) cols[column[n.type]]!.push(n);
    const pos = new Map<string, { x: number; y: number }>();
    const used = cols.map((c, i) => ({ c, i })).filter(({ c }) => c.length);
    used.forEach(({ c }, ci) => c.forEach((n, ri) => pos.set(n.id, { x: ci * COL, y: TOP + ri * ROW })));
    const rows = Math.max(...used.map(({ c }) => c.length));
    return { pos, titles: used.map(({ i }) => columnTitle[i]!), width: used.length * COL - (COL - W) + 2, height: TOP + rows * ROW };
  }, [q.data]);
  const appId = search.node?.startsWith("application:") ? search.node.slice(12) : "";
  return (
    <>
      <PageHeader
        title="Context graph"
        description="Everything connected to an application or repository: who owns it, its repositories and scan targets, the vulnerable components and the riskiest open findings. Select a node to open it."
      />
      <div className="mb-3">
        <Select aria-label="Application" value={appId} onChange={(e) => e.target.value && void navigate({ to: "/posture/graph", search: { node: `application:${e.target.value}` } as never })}>
          <option value="">{search.node?.startsWith("repository:") ? "Repository selected — choose an application…" : "Choose an application…"}</option>
          {(apps.data ?? []).map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
        </Select>
      </div>
      <Card className="overflow-x-auto p-3">
        {!search.node ? (
          <EmptyState icon={<Network />} title="Choose an application">Or open the graph from Application posture or Blast radius.</EmptyState>
        ) : q.isError ? (
          <Alert>{q.error.message}</Alert>
        ) : q.isPending || !layout ? (
          <Skeleton className="h-64" />
        ) : (
          <svg width={layout.width} height={layout.height} role="img" aria-label={`Context graph with ${q.data.nodes.length} nodes`} className="block">
            {layout.titles.map((t, i) => (
              <text key={t} x={i * COL} y={14} className="fill-[var(--muted-foreground)] text-[11px] font-semibold uppercase tracking-wide">{t}</text>
            ))}
            {q.data.edges.map((e, i) => {
              const a = layout.pos.get(e.from), b = layout.pos.get(e.to);
              if (!a || !b) return null;
              const x1 = a.x + W, y1 = a.y + H / 2, x2 = b.x, y2 = b.y + H / 2;
              const mx = (x1 + x2) / 2;
              return <path key={i} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none" className="stroke-[var(--border)]" strokeWidth={1.5} />;
            })}
            {q.data.nodes.map((n) => {
              const p = layout.pos.get(n.id)!;
              const sev = n.type === "finding" && n.severity ? severityColor[n.severity as keyof typeof severityColor] : undefined;
              const root = n.id === q.data.root;
              return (
                <g
                  key={n.id}
                  transform={`translate(${p.x},${p.y})`}
                  className={n.link ? "cursor-pointer outline-none [&:focus-visible>rect:first-of-type]:stroke-[var(--ring)]" : undefined}
                  onClick={() => n.link && void navigate(target(n.link) as never)}
                  onKeyDown={(e) => n.link && (e.key === "Enter" || e.key === " ") && (e.preventDefault(), void navigate(target(n.link) as never))}
                  tabIndex={n.link ? 0 : undefined}
                  role={n.link ? "link" : undefined}
                  aria-label={`${typeLabel[n.type]}: ${n.label}`}
                >
                  <title>{`${typeLabel[n.type]}: ${n.label}${n.sub ? `\n${n.sub}` : ""}${n.risk != null ? `\nRisk ${n.risk.toFixed(0)}` : ""}`}</title>
                  <rect width={W} height={H} rx={6} className={root ? "fill-[var(--surface)] stroke-[var(--primary)]" : "fill-[var(--surface)] stroke-[var(--border)]"} strokeWidth={root ? 2 : 1} />
                  {sev && <rect width={4} height={H} rx={2} fill={sev} />}
                  <text x={10} y={19} className="fill-[var(--foreground)] text-[12px] font-medium">{clip(n.label, 30)}</text>
                  <text x={10} y={36} className="fill-[var(--muted-foreground)] text-[10.5px]">
                    {clip([typeLabel[n.type], n.type === "finding" ? n.severity : n.sub, n.risk != null ? `risk ${n.risk.toFixed(0)}` : ""].filter(Boolean).join(" · "), 33)}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
      </Card>
    </>
  );
}

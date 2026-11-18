import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronRight, Package } from "lucide-react";
import { api } from "@/api/client";
import { SeverityBadge } from "@/components/data/Severity";
import type { Severity } from "@/api/types";
import { Alert, Badge, EmptyState, Input, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { type DepComponent, type PathNode, relationLabel, useDependencyGraph } from "./api";
import { EOLBadge } from "./EndOfLifePanel";

export function relationOf(depth: number | null) {
  return depth == null ? "unknown" : depth === 0 ? "root" : depth === 1 ? "direct" : "transitive";
}

/** A dependency path: root → … → component. */
export function DependencyPath({ path }: { path: PathNode[] }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-0.5 font-mono text-[11.5px]">
      {path.map((n, i) => (
        <span key={n.ref + i} className="inline-flex items-center gap-0.5">
          {i > 0 && <ChevronRight className="size-3 text-muted-foreground" aria-label="depends on" />}
          <span className={i === path.length - 1 ? "font-semibold" : undefined}>
            {n.name}
            {n.version && <span className="text-muted-foreground">@{n.version}</span>}
          </span>
        </span>
      ))}
    </span>
  );
}

function Paths({ repoId, c }: { repoId: string; c: DepComponent }) {
  const q = useQuery({
    queryKey: ["dependency-paths", repoId, c.ref],
    queryFn: () => api<{ paths: PathNode[][] }>(`/api/v1/repositories/${repoId}/dependencies/paths?ref=${encodeURIComponent(c.ref)}`),
  });
  if (q.isPending) return <Skeleton className="h-5 w-64" />;
  if (q.isError) return <span className="text-danger">{q.error.message}</span>;
  if (!q.data.paths.length) return <span className="text-muted-foreground">No path recorded in the SBOM.</span>;
  return (
    <ul className="space-y-0.5">
      {q.data.paths.map((p, i) => <li key={i}><DependencyPath path={p} /></li>)}
    </ul>
  );
}

/** Package health from deps.dev: deprecated version, newer release, OpenSSF Scorecard. */
function Health({ c }: { c: DepComponent }) {
  if (!c.latest_version && c.scorecard == null && !c.provenance && !c.eol_status) return <span className="text-muted-foreground" title="Package health not fetched yet (deps.dev feed)">—</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {c.eol_status && c.eol_status !== "supported" && (
        <span className="inline-flex items-center gap-1" title={c.eol_cycle}>
          <EOLBadge status={c.eol_status} date={c.eol_date} />
        </span>
      )}
      {c.deprecated && <Badge tone="danger">Deprecated</Badge>}
      {c.outdated ? <span title="Latest release">latest {c.latest_version}</span> : c.latest_version && <span className="text-muted-foreground">Up to date</span>}
      {c.scorecard != null && <span className="text-muted-foreground" title="OpenSSF Scorecard of the source repository (0–10)">· Scorecard {c.scorecard.toFixed(1)}</span>}
      {c.provenance === "verified" && <Badge tone="success"><span title={`Built from ${c.provenance_source}; SLSA provenance verified`}>Provenance</span></Badge>}
      {c.provenance === "unverified" && <Badge tone="warning"><span title={`Provenance claims ${c.provenance_source}; not verified`}>Unverified provenance</span></Badge>}
      {c.provenance === "none" && <span className="text-muted-foreground" title="The registry has no build provenance for this version">· no provenance</span>}
    </span>
  );
}

export function DependencyPanel({ repoId }: { repoId: string }) {
  const g = useDependencyGraph(repoId);
  const [q, setQ] = useState("");
  const [rel, setRel] = useState("");
  const [vulnOnly, setVulnOnly] = useState(false);
  const [health, setHealth] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase();
    return (g.data?.components ?? []).filter(
      (c) => (!t || c.name.toLowerCase().includes(t)) && (!rel || relationOf(c.depth) === rel) && (!vulnOnly || c.open_vulnerabilities > 0) &&
        (!health || (health === "outdated" ? c.outdated : health === "eol" ? c.eol_status === "eol" || c.eol_status === "approaching" : c.deprecated)),
    );
  }, [g.data, q, rel, vulnOnly, health]);
  if (g.isError) return <Alert>{g.error.message}</Alert>;
  if (g.isPending) return <Skeleton className="h-40" />;
  const st = g.data.stats;
  if (!st.components) return <EmptyState icon={<Package />} title="No SBOM yet">Run a scan with SBOM generation or import an SBOM.</EmptyState>;
  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-4 gap-2 sm:grid-cols-8">
        {(
          [
            ["components", "Components"],
            ["direct", "Direct"],
            ["transitive", "Transitive"],
            ["unknown", "No graph data"],
            ["vulnerable", "Vulnerable"],
            ["vulnerable_transitive", "Vulnerable, transitive"],
            ["outdated", "Outdated"],
            ["deprecated", "Deprecated"],
          ] as const
        ).map(([k, l]) => (
          <div key={k} className="rounded-md border border-border px-2 py-1.5">
            <dt className="text-[11px] text-muted-foreground">{l}</dt>
            <dd className="tabular text-[15px] font-semibold">{st[k] ?? 0}</dd>
          </div>
        ))}
      </dl>
      {!st.edges && <Alert tone="warning">This SBOM has no dependency relationships, so direct and transitive dependencies cannot be told apart.</Alert>}
      <div className="flex flex-wrap items-center gap-2">
        <Input aria-label="Search components" placeholder="Package…" value={q} onChange={(e) => setQ(e.target.value)} className="w-48" />
        <Select aria-label="Relation" value={rel} onChange={(e) => setRel(e.target.value)}>
          <option value="">All dependencies</option>
          {["root", "direct", "transitive", "unknown"].map((r) => <option key={r} value={r}>{relationLabel[r]}</option>)}
        </Select>
        <Select aria-label="Package health" value={health} onChange={(e) => setHealth(e.target.value)}>
          <option value="">Any health</option>
          <option value="outdated">Outdated</option>
          <option value="deprecated">Deprecated version</option>
          <option value="eol">End of life (or within six months)</option>
        </Select>
        <label className="flex items-center gap-1.5 text-[12.5px]">
          <input type="checkbox" className="accent-[var(--primary)]" checked={vulnOnly} onChange={(e) => setVulnOnly(e.target.checked)} /> Vulnerable only
        </label>
        <span className="ml-auto text-[12px] text-muted-foreground">{rows.length} shown</span>
      </div>
      <Table>
        <thead>
          <tr>
            <Th>Package</Th>
            <Th>Dependency</Th>
            <Th>Licences</Th>
            <Th>Health</Th>
            <Th>Open vulnerabilities</Th>
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 500).map((c) => (
            <>
              <tr key={c.ref || c.name + c.version}>
                <Td>
                  <button
                    type="button"
                    className="text-left font-mono text-[12px] hover:underline disabled:no-underline"
                    disabled={!c.ref || !st.edges}
                    aria-expanded={open === c.ref}
                    onClick={() => setOpen(open === c.ref ? null : c.ref)}
                    title={c.ref && st.edges ? "Show why this package is here" : undefined}
                  >
                    {c.name}<span className="text-muted-foreground">@{c.version}</span>
                  </button>
                </Td>
                <Td className="text-[12px]">{relationLabel[relationOf(c.depth)]}{c.depth != null && c.depth > 1 && <span className="text-muted-foreground"> (depth {c.depth})</span>}</Td>
                <Td className="max-w-40 truncate text-[11.5px] text-muted-foreground">{c.licenses.join(", ") || "—"}</Td>
                <Td className="text-[11.5px]"><Health c={c} /></Td>
                <Td>{c.open_vulnerabilities ? <span className="inline-flex items-center gap-1"><SeverityBadge value={c.max_severity as Severity} /> {c.open_vulnerabilities}</span> : <span className="text-[12px] text-muted-foreground">0</span>}</Td>
              </tr>
              {open === c.ref && (
                <tr key={c.ref + "-paths"}>
                  <Td className="bg-surface-muted/40" />
                  <td colSpan={4} className="bg-surface-muted/40 px-3 py-2 text-[12px]">
                    <div className="mb-1 text-[11px] font-medium text-muted-foreground">How it gets here</div>
                    <Paths repoId={repoId} c={c} />
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </Table>
      {rows.length > 500 && <p className="text-[12px] text-muted-foreground">Showing 500 of {rows.length}; search to narrow down.</p>}
    </div>
  );
}

/** For a dependency finding: direct or transitive, and how it gets in. */
export function FindingDependencyPaths({ findingId }: { findingId: string }) {
  const q = useQuery({
    queryKey: ["finding-dependency-paths", findingId],
    queryFn: () =>
      api<{ components: { component: DepComponent; relation: string; paths: PathNode[][] }[]; reason?: string }>(`/api/v1/findings/${findingId}/dependency-paths`),
  });
  if (q.isPending) return <Skeleton className="h-6" />;
  if (q.isError) return <span className="text-[12px] text-danger">{q.error.message}</span>;
  if (!q.data.components.length) return <span className="text-[12px] text-muted-foreground">{q.data.reason ?? "No dependency data."}</span>;
  return (
    <ul className="space-y-1.5 text-[12px]">
      {q.data.components.map((m) => (
        <li key={m.component.ref || m.component.version}>
          <span className="font-medium">{relationLabel[m.relation]} dependency</span>
          {m.paths.length ? m.paths.map((p, i) => <div key={i}><DependencyPath path={p} /></div>) : <div className="text-muted-foreground">No path recorded in the SBOM.</div>}
        </li>
      ))}
    </ul>
  );
}

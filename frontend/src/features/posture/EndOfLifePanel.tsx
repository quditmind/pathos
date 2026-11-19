import { useQuery } from "@tanstack/react-query";
import { CalendarX } from "lucide-react";
import { api } from "@/api/client";
import { Badge, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { ErrorPanel } from "@/components/ui/error-panel";

export interface EOLItem {
  source: "sbom" | "runtime" | "image";
  component: string;
  version: string;
  purl?: string;
  path?: string;
  scan_target_id?: string;
  product: string;
  product_label: string;
  cycle: string;
  eol_date: string | null;
  status: "eol" | "approaching" | "supported";
  latest_in_cycle?: string;
}

export interface RepositoryEOL {
  feed_loaded: boolean;
  feed_as_of: string;
  eol: number;
  approaching: number;
  supported: number;
  computed_at: string | null;
  items: EOLItem[];
}

export function useRepositoryEOL(repoId: string) {
  return useQuery({ queryKey: ["repository-eol", repoId], queryFn: () => api<RepositoryEOL>(`/api/v1/repositories/${repoId}/eol`) });
}

const sourceLabel: Record<EOLItem["source"], string> = { sbom: "Dependency", runtime: "Declared runtime", image: "Image target" };

/** End-of-life status badge (eol, approaching, supported). */
export function EOLBadge({ status, date }: { status: string; date?: string | null }) {
  const d = date ? date.slice(0, 10) : "";
  if (status === "eol") return <Badge tone="danger"><span title={d ? `Support ended on ${d}` : "No longer supported"}>End of life</span></Badge>;
  if (status === "approaching") return <Badge tone="warning"><span title={d ? `Support ends on ${d}` : undefined}>EOL {d || "soon"}</span></Badge>;
  return <Badge tone="success">Supported</Badge>;
}

/**
 * End-of-life dates (endoflife.date) of the repository's frameworks,
 * declared runtimes, base images and image targets.
 */
export function EndOfLifePanel({ repoId }: { repoId: string }) {
  const q = useRepositoryEOL(repoId);
  if (q.isPending) return <Skeleton className="h-16" />;
  if (q.isError) return <ErrorPanel error={q.error} />;
  const d = q.data;
  const relevant = d.items.filter((i) => i.status !== "supported");
  return (
    <section aria-labelledby="eol-heading" className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-2">
        <h3 id="eol-heading" className="flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
          <CalendarX className="size-3.5" /> End of life
        </h3>
        {d.feed_loaded && (
          <span className="text-[12px] text-muted-foreground">
            {d.eol} end-of-life · {d.approaching} within six months · {d.supported} supported
            {d.feed_as_of && <> · endoflife.date data of {d.feed_as_of}</>}
          </span>
        )}
      </div>
      {!d.feed_loaded ? (
        <p className="text-[12.5px] text-muted-foreground">
          No end-of-life data yet. An administrator enables the endoflife.date feed (or imports it from a file) under Risk &amp; intelligence.
        </p>
      ) : !d.items.length ? (
        <p className="text-[12.5px] text-muted-foreground">No tracked runtime, framework or base image found{d.computed_at ? "" : " yet; run a scan"}.</p>
      ) : !relevant.length ? (
        <p className="text-[12.5px] text-muted-foreground">All {d.items.length} tracked runtimes, frameworks and images are supported.</p>
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Component</Th>
              <Th>Release</Th>
              <Th>Status</Th>
              <Th>Found in</Th>
            </tr>
          </thead>
          <tbody>
            {relevant.map((i) => (
              <tr key={`${i.source}|${i.component}|${i.version}|${i.path}|${i.product}|${i.cycle}|${i.scan_target_id ?? ""}`}>
                <Td className="font-mono text-[12px]">
                  {i.component}
                  {i.version && i.source !== "image" && <span className="text-muted-foreground">@{i.version}</span>}
                </Td>
                <Td className="text-[12px]">
                  {i.product_label} {i.cycle}
                  {i.latest_in_cycle && <span className="text-muted-foreground"> (latest {i.latest_in_cycle})</span>}
                </Td>
                <Td><EOLBadge status={i.status} date={i.eol_date} /></Td>
                <Td className="text-[12px] text-muted-foreground">
                  {sourceLabel[i.source]}
                  {i.path && <span className="font-mono"> · {i.path}</span>}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {d.computed_at && <p className="text-[11px] text-muted-foreground">Updated {formatDateTime(d.computed_at)}; end-of-life releases are also findings (category "End of life").</p>}
    </section>
  );
}

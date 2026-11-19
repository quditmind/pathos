import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { SeverityBadge } from "@/components/data/Severity";
import type { Severity } from "@/api/types";
import { Skeleton } from "@/components/ui/primitives";
import { keysCheckLabel } from "@/lib/checkKinds";

interface Related {
  id: string;
  relation: "same_location" | "same_vulnerability";
  title: string;
  severity: Severity;
  status: string;
  scanner_keys: string[];
  file_path: string;
  start_line: number | null;
  scan_target_name: string | null;
  risk_score: number | null;
}

const relationLabel = { same_location: "Same location, another engine", same_vulnerability: "Same vulnerability elsewhere in the repository" };

/** Findings other engines report at the same place, or the same CVE elsewhere (never merged). */
export function RelatedFindings({ findingId }: { findingId: string }) {
  const q = useQuery({
    queryKey: ["finding-related", findingId],
    queryFn: () => api<{ items: Related[]; cve: string; other_repositories: number }>(`/api/v1/findings/${findingId}/related`),
  });
  if (q.isPending) return <Skeleton className="h-6" />;
  if (q.isError || (!q.data.items.length && !q.data.other_repositories)) return null;
  return (
    <div className="rounded-md border border-border p-3">
      <h3 className="mb-1 text-[12px] font-semibold">Related findings</h3>
      <ul className="space-y-1 text-[12px]">
        {q.data.items.map((r) => (
          <li key={r.id} className="flex flex-wrap items-center gap-1.5">
            <SeverityBadge value={r.severity} />
            <Link to="/findings" search={{ finding: r.id } as never} className="text-primary hover:underline">{r.title}</Link>
            <span className="text-muted-foreground">
              · {relationLabel[r.relation]} · {keysCheckLabel(r.scanner_keys)}
              {r.scan_target_name ? ` · ${r.scan_target_name}` : r.file_path ? ` · ${r.file_path}${r.start_line ? `:${r.start_line}` : ""}` : ""}
              {r.status !== "open" && ` · ${r.status.replace("_", " ")}`}
            </span>
          </li>
        ))}
      </ul>
      {q.data.other_repositories > 0 && (
        <Link to="/posture/blast-radius" search={{ cve: q.data.cve } as never} className="mt-1 inline-block text-[12px] text-primary hover:underline">
          {q.data.cve} is open in {q.data.other_repositories} other repositor{q.data.other_repositories === 1 ? "y" : "ies"} →
        </Link>
      )}
    </div>
  );
}

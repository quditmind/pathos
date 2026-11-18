import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { GitCompareArrows } from "lucide-react";
import { Alert, Badge, Card, EmptyState, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { materialCategories, useRepoMaterialChanges, useScanMaterialChanges, type MaterialChange, type MaterialRun } from "./api";

const levelTone = { high: "danger", medium: "warning", low: "neutral" } as const;

const short = (sha: string) => sha.slice(0, 10);

function location(c: MaterialChange): string {
  if (!c.file_path) return c.detail || "—";
  if (!c.start_line) return c.file_path;
  const lines = c.end_line && c.end_line !== c.start_line ? `${c.start_line}-${c.end_line}` : `${c.start_line}`;
  return `${c.file_path}:${lines}`;
}

const sideLabel: Record<string, string> = { added: "added lines", removed: "removed lines", file: "file changed" };

/** One sentence on how the comparison went. */
export function RunSummary({ run }: { run: MaterialRun | null }) {
  if (!run) {
    return (
      <Alert tone="warning">
        No change comparison was recorded for this scan. Comparisons run for branch scans of Git repositories (not pull request checks, uploads or scan
        targets) by workers of this PATHOS version.
      </Alert>
    );
  }
  const range = run.base_sha ? `${short(run.base_sha)} → ${short(run.head_sha)}` : short(run.head_sha);
  switch (run.status) {
    case "computed":
      return (
        <p className="text-[12.5px] text-muted-foreground">
          Compared commits <span className="font-mono">{range}</span>: {run.files_changed} changed file{run.files_changed === 1 ? "" : "s"},{" "}
          {run.change_count} material change{run.change_count === 1 ? "" : "s"}.
          {run.truncated && " The diff was too large to analyze completely; only its first part was checked."}
          {run.dependency_status === "baseline" && " Dependencies: this is the first SBOM, so it becomes the baseline."}
          {run.dependency_status === "none" && " Dependencies were not compared (this scan produced no SBOM)."}
          {run.reason && ` ${run.reason}`}
        </p>
      );
    case "baseline":
      return <p className="text-[12.5px] text-muted-foreground">Baseline: {run.reason || "there is no earlier scanned commit to compare with."}</p>;
    case "unchanged":
      return <p className="text-[12.5px] text-muted-foreground">The commit is the same as in the previous scan; nothing changed.</p>;
    default:
      return <Alert tone="warning">Change comparison unavailable: {run.reason || "unknown reason"}</Alert>;
  }
}

function ChangesTable({ items, showScan }: { items: MaterialChange[]; showScan?: boolean }) {
  const showAuthor = items.some((c) => c.author_name);
  return (
    <Table>
      <thead>
        <tr>
          <Th>Level</Th>
          <Th>Change</Th>
          <Th>Location</Th>
          <Th>Matched</Th>
          {showAuthor && <Th>Last author</Th>}
          {showScan && <Th>Scan</Th>}
        </tr>
      </thead>
      <tbody>
        {items.map((c) => (
          <tr key={c.id} className="align-top">
            <Td><Badge tone={levelTone[c.level] ?? "neutral"}>{c.level}</Badge></Td>
            <Td className="max-w-sm">
              <div className="font-medium">{c.rule_title || c.rule_id}</div>
              <div className="text-[11.5px] text-muted-foreground">{c.category_label} · rule <span className="font-mono">{c.rule_id}</span></div>
              <details className="mt-1 text-[12px]">
                <summary className="cursor-pointer text-primary">Why this is material</summary>
                <p className="mt-1 text-muted-foreground">{c.explanation}</p>
              </details>
            </Td>
            <Td className="max-w-xs">
              <div className="break-all font-mono text-[11.5px]">{location(c)}</div>
              <div className="text-[11px] text-muted-foreground">{c.change_type ? `${c.change_type} file, ` : ""}{sideLabel[c.side] ?? c.side}{c.match_count > 1 ? ` (${c.match_count} matches)` : ""}</div>
            </Td>
            <Td className="max-w-md"><code className="block whitespace-pre-wrap break-all text-[11.5px]">{c.snippet || "—"}</code></Td>
            {showAuthor && <Td className="whitespace-nowrap text-[12px]">{c.author_name || "—"}</Td>}
            {showScan && (
              <Td className="whitespace-nowrap text-[12px]">
                <Link to="/scans/$id" params={{ id: c.scan_job_id }} search={{ tab: "material" } as never} className="text-primary hover:underline">
                  {formatDateTime(c.created_at)}
                </Link>
                {c.commit_sha && <div className="font-mono text-[11px] text-muted-foreground">{short(c.commit_sha)}</div>}
              </Td>
            )}
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

const disclaimer =
  "Material changes are found by deterministic, explainable rules on the diff between the previous and this scanned commit and on the two SBOMs. They prompt a closer look; they are not findings and never change a finding.";

/** The "Material changes" tab of a scan execution. */
export function ScanMaterialChanges({ jobId }: { jobId: string }) {
  const q = useScanMaterialChanges(jobId);
  const [cat, setCat] = useState("");
  if (q.isError) return <Alert>Could not load material changes: {q.error.message}</Alert>;
  if (!q.data) return <Skeleton className="h-32" />;
  const items = q.data.items.filter((c) => !cat || c.category === cat);
  return (
    <Card className="space-y-3 p-4">
      <RunSummary run={q.data.run} />
      <p className="text-[12px] text-muted-foreground">{disclaimer}</p>
      {q.data.items.length > 0 && (
        <CategoryFilter value={cat} onChange={setCat} counts={countBy(q.data.items)} />
      )}
      {items.length === 0 ? (
        <EmptyState icon={<GitCompareArrows />} title="No material changes">
          {q.data.items.length ? "No change in the selected category." : "Nothing security-material changed between the compared commits."}
        </EmptyState>
      ) : (
        <ChangesTable items={items} />
      )}
    </Card>
  );
}

function countBy(items: MaterialChange[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const c of items) out[c.category] = (out[c.category] ?? 0) + 1;
  return out;
}

function CategoryFilter({ value, onChange, counts }: { value: string; onChange: (v: string) => void; counts?: Record<string, number> }) {
  return (
    <label className="flex items-center gap-2 text-[12.5px]">
      Category
      <Select aria-label="Category" value={value} onChange={(e) => onChange(e.target.value)} className="w-64">
        <option value="">All categories</option>
        {materialCategories.map(([k, l]) => (
          <option key={k} value={k}>
            {l}{counts ? ` (${counts[k] ?? 0})` : ""}
          </option>
        ))}
      </Select>
    </label>
  );
}

/** The "Material changes" tab of a repository. */
export function RepositoryMaterialChanges({ repoId }: { repoId: string }) {
  const [cat, setCat] = useState("");
  const [days, setDays] = useState(90);
  const q = useRepoMaterialChanges(repoId, { category: cat || undefined, days });
  return (
    <div className="space-y-3">
      <p className="text-[12px] text-muted-foreground">{disclaimer}</p>
      <div className="flex flex-wrap items-center gap-3">
        <CategoryFilter value={cat} onChange={setCat} />
        <label className="flex items-center gap-2 text-[12.5px]">
          Period
          <Select aria-label="Period" value={String(days)} onChange={(e) => setDays(Number(e.target.value))} className="w-36">
            <option value="30">Last 30 days</option>
            <option value="90">Last 90 days</option>
            <option value="365">Last year</option>
          </Select>
        </label>
      </div>
      {q.isError ? (
        <Alert>Could not load material changes: {q.error.message}</Alert>
      ) : !q.data ? (
        <Skeleton className="h-32" />
      ) : (
        <>
          {q.data.runs[0] && <RunSummary run={q.data.runs[0]} />}
          {q.data.items.length === 0 ? (
            <EmptyState icon={<GitCompareArrows />} title="No material changes">
              {q.data.runs.length ? "No security-material change in this period." : "No branch scan of this repository has been compared yet. The first scan sets the baseline."}
            </EmptyState>
          ) : (
            <ChangesTable items={q.data.items} showScan />
          )}
          {q.data.truncated && <p className="text-[12px] text-muted-foreground">Showing the most recent changes only; narrow the category or period.</p>}
        </>
      )}
    </div>
  );
}

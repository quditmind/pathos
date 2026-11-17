import { useState } from "react";
import { BarChart3 } from "lucide-react";
import { Alert, Card, EmptyState, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import { type Benchmark, type BenchmarkMetric, type Dimension, dimensionLabel, useBenchmark } from "./api";
import { daysOptions } from "./shared";

function value(b: Benchmark, m: BenchmarkMetric): number | null {
  const v = b[m.key];
  return typeof v === "number" ? v : null;
}

function median(vs: number[]): number | null {
  if (!vs.length) return null;
  const s = [...vs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

const fmt = (v: number | null, key: string) => (v == null ? "—" : key === "sla_compliance" || key === "coverage" ? `${v.toFixed(v % 1 ? 1 : 0)}%` : v.toFixed(v % 1 ? 1 : 0));

export function BenchmarkPage() {
  const [by, setBy] = useState<Dimension>("application");
  const [days, setDays] = useState(90);
  const q = useBenchmark(by, days);
  const items = q.data?.items ?? [];
  const metrics = q.data?.metrics ?? [];
  // Column extremes and medians, over groups that have a value.
  const stats = Object.fromEntries(
    metrics.map((m) => {
      const vs = items.map((b) => value(b, m)).filter((v): v is number => v != null);
      return [m.key, { max: Math.max(0, ...vs), best: vs.length ? (m.lower_is_better ? Math.min(...vs) : Math.max(...vs)) : null,
        worst: vs.length ? (m.lower_is_better ? Math.max(...vs) : Math.min(...vs)) : null, median: median(vs) }];
    }),
  ) as Record<string, { max: number; best: number | null; worst: number | null; median: number | null }>;
  return (
    <>
      <PageHeader
        title="Benchmarking"
        description="Compare applications, business units, teams, owners or regions on normalised metrics, so large and small groups compare fairly. Rows are ordered by risk; the best and worst value in each column are marked."
      />
      <div className="mb-3 flex flex-wrap gap-2">
        <Select aria-label="Compare" value={by} onChange={(e) => setBy(e.target.value as Dimension)}>
          {(Object.keys(dimensionLabel) as Dimension[]).map((d) => <option key={d} value={d}>Compare {dimensionLabel[d].toLowerCase()}s</option>)}
        </Select>
        <Select aria-label="Remediation window" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {daysOptions.map((d) => <option key={d} value={d}>Remediation over {d} days</option>)}
        </Select>
      </div>
      <Card>
        {q.isError ? (
          <div className="p-4"><Alert>{q.error.message}</Alert></div>
        ) : q.isPending ? (
          <Skeleton className="m-4 h-40" />
        ) : items.length < 1 ? (
          <EmptyState icon={<BarChart3 />} title="Nothing to compare" />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>#</Th>
                <Th>{dimensionLabel[by]}</Th>
                <Th>Repositories</Th>
                {metrics.map((m) => (
                  <Th key={m.key}>
                    {m.label}
                    <span className="block text-[10.5px] font-normal text-muted-foreground">{m.lower_is_better ? "lower is better" : "higher is better"}</span>
                  </Th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((b) => (
                <tr key={b.id ?? "none"}>
                  <Td className="tabular text-[12px] text-muted-foreground">{b.rank}</Td>
                  <Td className={cn("font-medium", !b.id && "text-muted-foreground")}>{b.label}</Td>
                  <Td className="tabular text-[12px]">{b.repositories}</Td>
                  {metrics.map((m) => {
                    const v = value(b, m);
                    const st = stats[m.key]!;
                    const mark = v != null && items.length > 1 && st.best !== st.worst ? (v === st.best ? "best" : v === st.worst ? "worst" : "") : "";
                    return (
                      <Td key={m.key} className="min-w-28">
                        <div className="tabular flex items-baseline gap-1.5 text-[12px]">
                          {fmt(v, m.key)}
                          {mark && <span className={cn("text-[10.5px]", mark === "best" ? "text-success" : "text-danger")}>{mark}</span>}
                        </div>
                        {v != null && st.max > 0 && (
                          <div className="mt-0.5 h-1.5 w-full rounded-sm bg-surface-muted" aria-hidden>
                            <div className="h-full rounded-sm bg-primary/70" style={{ width: `${(v / (m.key === "sla_compliance" || m.key === "coverage" ? 100 : st.max)) * 100}%` }} />
                          </div>
                        )}
                      </Td>
                    );
                  })}
                </tr>
              ))}
              <tr className="bg-surface-muted/40">
                <Td />
                <Td className="text-[12px] font-medium">Median</Td>
                <Td />
                {metrics.map((m) => <Td key={m.key} className="tabular text-[12px] text-muted-foreground">{fmt(stats[m.key]!.median, m.key)}</Td>)}
              </tr>
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}

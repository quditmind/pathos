import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import { api } from "@/api/client";
import { Card, EmptyState, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { ErrorPanel } from "@/components/ui/error-panel";

interface Row {
  key: string;
  label?: string;
  requests: number;
  input_tokens: number;
  output_tokens: number;
}
interface Usage {
  days: number;
  by_feature: Row[];
  by_model: Row[];
  by_day: Row[];
  by_user: Row[];
}

const featureLabel: Record<string, string> = {
  finding_review: "Automated finding reviews",
  human_eye_suggestion: "Human Eye suggestions",
  analyst: "AI Security Analyst",
  report: "AI reports",
};
const n = (x: number) => x.toLocaleString();

function UsageTable({ title, rows, label }: { title: string; rows: Row[]; label: (r: Row) => string }) {
  const max = Math.max(1, ...rows.map((r) => r.input_tokens + r.output_tokens));
  return (
    <Card>
      <h2 className="border-b border-border px-4 py-2.5 text-[13px] font-semibold">{title}</h2>
      {!rows.length ? <p className="p-4 text-[12px] text-muted-foreground">No AI requests in this period.</p> : (
        <Table>
          <thead><tr><Th>{title.split(" ").pop()}</Th><Th className="text-right">Requests</Th><Th className="text-right">Input tokens</Th><Th className="text-right">Output tokens</Th><Th>Share</Th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key}>
                <Td className="text-[12.5px]">{label(r)}</Td>
                <Td className="tabular text-right text-[12px]">{n(r.requests)}</Td>
                <Td className="tabular text-right text-[12px]">{n(r.input_tokens)}</Td>
                <Td className="tabular text-right text-[12px]">{n(r.output_tokens)}</Td>
                <Td className="w-40">
                  <div className="h-1.5 rounded-sm bg-surface-muted" title={`${n(r.input_tokens + r.output_tokens)} tokens`}>
                    <div className="h-full rounded-sm bg-primary/70" style={{ width: `${((r.input_tokens + r.output_tokens) / max) * 100}%` }} />
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

export function AIUsagePage() {
  const [days, setDays] = useState(30);
  const q = useQuery({ queryKey: ["ai-usage", days], queryFn: () => api<Usage>(`/api/v1/ai/usage?days=${days}`) });
  const total = q.data?.by_feature.reduce((a, r) => ({ req: a.req + r.requests, tok: a.tok + r.input_tokens + r.output_tokens }), { req: 0, tok: 0 });
  return (
    <>
      <PageHeader title="AI usage" description="Requests and tokens used by every AI feature, model and person. Use it to watch costs of hosted providers and the load on self-hosted models." />
      <div className="mb-3 flex items-center gap-3">
        <Select aria-label="Period" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {[7, 30, 90].map((d) => <option key={d} value={d}>Last {d} days</option>)}
        </Select>
        {total && <span className="text-[12.5px] text-muted-foreground">{n(total.req)} requests · {n(total.tok)} tokens</span>}
      </div>
      {q.isError ? <ErrorPanel error={q.error} /> : q.isPending ? <Skeleton className="h-48" /> : !q.data.by_feature.length ? (
        <Card><EmptyState icon={<Activity />} title="No AI usage in this period" /></Card>
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          <UsageTable title="By feature" rows={q.data.by_feature} label={(r) => featureLabel[r.key] ?? r.key} />
          <UsageTable title="By model" rows={q.data.by_model} label={(r) => r.key} />
          <UsageTable title="By person" rows={q.data.by_user} label={(r) => r.label || r.key} />
          <UsageTable title="By day" rows={q.data.by_day} label={(r) => r.key} />
        </div>
      )}
    </>
  );
}

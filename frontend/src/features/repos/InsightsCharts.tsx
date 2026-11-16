import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { InsightBucket, RepositoryInsights } from "@/api/types";
import { Card } from "@/components/ui/primitives";
import { isHexColor } from "@/lib/color";

const axis = { fontSize: 11, fill: "var(--muted-foreground)" };
const tooltipStyle = {
  background: "var(--surface)",
  border: "1px solid var(--border)",
  borderRadius: 6,
  fontSize: 12,
  color: "var(--foreground)",
};

export type InsightKey = Exclude<keyof RepositoryInsights, "totals">;

export const insightCharts: { key: InsightKey; title: string; filter?: string }[] = [
  { key: "by_provider", title: "By source / provider", filter: "provider" },
  { key: "by_business_region", title: "By business region", filter: "business_region_id" },
  { key: "by_business_unit", title: "By business unit", filter: "business_unit_id" },
  { key: "by_data_classification", title: "By data classification", filter: "data_classification" },
  { key: "by_criticality", title: "By criticality", filter: "criticality" },
  { key: "by_environment", title: "By environment", filter: "environment" },
  { key: "by_compliance", title: "By compliance scope", filter: "compliance" },
  { key: "by_lifecycle", title: "By lifecycle status", filter: "lifecycle_status" },
  { key: "by_business_owner", title: "Top business owners", filter: "business_owner_id" },
];

function BucketChart({ buckets, onSelect }: { buckets: InsightBucket[]; onSelect?: (b: InsightBucket) => void }) {
  if (!buckets.length || buckets.every((b) => b.count === 0)) {
    return <div className="flex h-[200px] items-center justify-center text-[13px] text-muted-foreground">No repositories</div>;
  }
  const data = buckets.slice(0, 10).map((b) => ({ ...b, label: b.key === "" ? "Not set" : b.label || b.key }));
  const height = Math.max(120, data.length * 26 + 24);
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, bottom: 0, left: 8 }}>
        <CartesianGrid stroke="var(--border)" horizontal={false} />
        <XAxis type="number" allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
        <YAxis
          type="category"
          dataKey="label"
          tick={axis}
          tickLine={false}
          axisLine={false}
          width={140}
          tickFormatter={(v: string) => (v.length > 22 ? `${v.slice(0, 21)}…` : v)}
        />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-muted)" }} />
        <Bar
          dataKey="count"
          name="Repositories"
          radius={[0, 4, 4, 0]}
          barSize={14}
          cursor={onSelect ? "pointer" : undefined}
          onClick={onSelect ? (d: unknown) => onSelect((d as { payload: InsightBucket }).payload) : undefined}
        >
          {data.map((b) => (
            <Cell key={b.key || "unset"} fill={b.key === "" ? "var(--sev-info)" : isHexColor(b.color) ? b.color : "var(--primary)"} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Insights view: one breakdown per dimension. Lazy-loaded so Recharts stays out of the main bundle. */
export default function InsightsCharts({ insights, onDrill }: { insights: RepositoryInsights; onDrill: (filter: string, key: string) => void }) {
  return (
    <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
      {insightCharts.map((c) => {
        const buckets = insights[c.key] ?? [];
        return (
          <Card key={c.key} className="p-4">
            <h3 className="mb-2 text-[13px] font-semibold">{c.title}</h3>
            <BucketChart buckets={buckets} onSelect={c.filter ? (b) => onDrill(c.filter!, b.key) : undefined} />
            {buckets.length > 0 && (
              <details className="mt-2 text-[12px]">
                <summary className="cursor-pointer text-muted-foreground">Show as table</summary>
                <table className="mt-1 w-full">
                  <tbody>
                    {buckets.map((b) => (
                      <tr key={b.key || "unset"} className="border-t border-border">
                        <td className="py-1">{b.key === "" ? "Not set" : b.label || b.key}</td>
                        <td className="tabular py-1 text-right">{b.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>
            )}
          </Card>
        );
      })}
    </div>
  );
}

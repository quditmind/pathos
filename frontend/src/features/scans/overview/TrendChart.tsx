import { Bar, CartesianGrid, ComposedChart, Legend, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ScanOverview } from "@/api/types";

const axis = { fontSize: 11, fill: "var(--muted-foreground)" };
const tooltipStyle = {
  background: "var(--surface)",
  border: "1px solid var(--border)",
  borderRadius: 6,
  fontSize: 12,
  color: "var(--foreground)",
};

function shortDate(d: string) {
  const dt = new Date(`${d.slice(0, 10)}T00:00:00`);
  return dt.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** Executions per day (stacked by outcome) with new findings as a line. Lazy-loaded with Recharts. */
export default function TrendChart({ trend }: { trend: ScanOverview["trend"] }) {
  const total = trend.reduce((n, d) => n + d.completed + d.failed + d.cancelled + d.new_findings, 0);
  if (!trend.length || total === 0) {
    return <div className="flex h-[240px] items-center justify-center text-[13px] text-muted-foreground">No executions in this period</div>;
  }
  return (
    <ResponsiveContainer width="100%" height={240}>
      <ComposedChart data={trend} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
        <CartesianGrid stroke="var(--border)" vertical={false} />
        <XAxis dataKey="day" tickFormatter={shortDate} tick={axis} tickLine={false} axisLine={false} minTickGap={24} />
        <YAxis yAxisId="runs" allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
        <YAxis yAxisId="findings" orientation="right" allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} labelFormatter={(l) => shortDate(String(l))} cursor={{ fill: "var(--surface-muted)" }} />
        <Legend iconType="square" wrapperStyle={{ fontSize: 12 }} />
        <Bar yAxisId="runs" dataKey="completed" name="Completed" stackId="a" fill="var(--success)" maxBarSize={18} />
        <Bar yAxisId="runs" dataKey="failed" name="Failed" stackId="a" fill="var(--danger)" maxBarSize={18} />
        <Bar yAxisId="runs" dataKey="cancelled" name="Cancelled" stackId="a" fill="var(--muted-foreground)" maxBarSize={18} />
        <Line yAxisId="findings" type="monotone" dataKey="new_findings" name="New findings" stroke="var(--primary)" strokeWidth={2} dot={false} />
      </ComposedChart>
    </ResponsiveContainer>
  );
}

import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { TrendPoint } from "./api";

const axis = { fontSize: 11, fill: "var(--muted-foreground)" };
const tooltipStyle = { background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12, color: "var(--foreground)" };

function shortDate(d: string) {
  return new Date(`${d}T00:00:00`).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** Findings introduced vs fixed per week. Lazy-loaded with Recharts. */
export default function AttributionTrendChart({ points }: { points: TrendPoint[] }) {
  if (!points.some((p) => p.introduced || p.fixed)) {
    return <div className="flex h-[240px] items-center justify-center text-[13px] text-muted-foreground">No attributed findings in this period</div>;
  }
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={points} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
        <CartesianGrid stroke="var(--border)" vertical={false} />
        <XAxis dataKey="week" tickFormatter={shortDate} tick={axis} tickLine={false} axisLine={false} minTickGap={24} />
        <YAxis allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} labelFormatter={(l) => `Week of ${shortDate(String(l))}`} cursor={{ fill: "var(--surface-muted)" }} />
        <Legend iconType="square" wrapperStyle={{ fontSize: 12 }} />
        <Bar dataKey="introduced" name="Introduced" fill="var(--danger)" maxBarSize={18} />
        <Bar dataKey="fixed" name="Fixed" fill="var(--success)" maxBarSize={18} />
      </BarChart>
    </ResponsiveContainer>
  );
}

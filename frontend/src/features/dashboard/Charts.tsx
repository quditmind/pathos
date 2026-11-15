import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Chart } from "@/api/types";

const palette = ["var(--primary)", "var(--danger)", "var(--sev-medium)", "var(--sev-low)"];

const axis = { fontSize: 11, fill: "var(--muted-foreground)" };
const tooltipStyle = {
  background: "var(--surface)",
  border: "1px solid var(--border)",
  borderRadius: 6,
  fontSize: 12,
  color: "var(--foreground)",
};

function shortDate(d: string) {
  const dt = new Date(`${d}T00:00:00`);
  return dt.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** Renders an available chart. Kept in its own module so Recharts is lazy-loaded. */
export default function ChartBody({ chart }: { chart: Chart }) {
  if ((chart.kind === "line" || chart.kind === "stacked_bar") && chart.series?.length) {
    // Pivot series into rows keyed by date.
    const dates = chart.series[0]!.points.map((p) => p.date);
    const data = dates.map((date, i) => {
      const row: Record<string, string | number> = { date };
      for (const s of chart.series!) row[s.name] = s.points[i]?.value ?? 0;
      return row;
    });
    const total = data.reduce((n, r) => n + chart.series!.reduce((m, s) => m + Number(r[s.name] ?? 0), 0), 0);
    if (total === 0) return <Empty />;
    return (
      <ResponsiveContainer width="100%" height={220}>
        <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
          <CartesianGrid stroke="var(--border)" vertical={false} />
          <XAxis dataKey="date" tickFormatter={shortDate} tick={axis} tickLine={false} axisLine={false} minTickGap={24} />
          <YAxis allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
          <Tooltip contentStyle={tooltipStyle} labelFormatter={(l) => shortDate(String(l))} />
          <Legend iconType="plainline" wrapperStyle={{ fontSize: 12 }} />
          {chart.series.map((s, i) => (
            <Line key={s.name} type="monotone" dataKey={s.name} stroke={palette[i % palette.length]} strokeWidth={2} dot={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    );
  }
  if (chart.kind === "bar" && chart.categories) {
    if (!chart.categories.length) return <Empty />;
    return (
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chart.categories} layout="vertical" margin={{ top: 4, right: 16, bottom: 0, left: 8 }}>
          <CartesianGrid stroke="var(--border)" horizontal={false} />
          <XAxis type="number" allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
          <YAxis type="category" dataKey="label" tick={axis} tickLine={false} axisLine={false} width={110} />
          <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-muted)" }} />
          <Bar dataKey="value" name="Changes" fill="var(--primary)" radius={[0, 3, 3, 0]} barSize={14} />
        </BarChart>
      </ResponsiveContainer>
    );
  }
  return <Empty />;
}

function Empty() {
  return <div className="flex h-[220px] items-center justify-center text-[13px] text-muted-foreground">No activity in this period</div>;
}

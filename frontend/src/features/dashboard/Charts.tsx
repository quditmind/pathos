import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Chart } from "@/api/types";

const palette = ["var(--primary)", "var(--danger)", "var(--sev-medium)", "var(--sev-low)"];
const severityColors: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

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

function colorFor(name: string, i: number) {
  return severityColors[name] ?? palette[i % palette.length]!;
}

/** Renders an available chart. Kept in its own module so Recharts is lazy-loaded. */
export default function ChartBody({ chart }: { chart: Chart }) {
  if ((chart.kind === "line" || chart.kind === "stacked_bar") && chart.series?.length) {
    const dates = chart.series[0]!.points.map((p) => p.date);
    const data = dates.map((date, i) => {
      const row: Record<string, string | number> = { date };
      for (const s of chart.series!) row[s.name] = s.points[i]?.value ?? 0;
      return row;
    });
    const total = data.reduce((n, r) => n + chart.series!.reduce((m, s) => m + Number(r[s.name] ?? 0), 0), 0);
    if (total === 0) return <Empty />;
    if (chart.kind === "stacked_bar") {
      return (
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
            <CartesianGrid stroke="var(--border)" vertical={false} />
            <XAxis dataKey="date" tickFormatter={shortDate} tick={axis} tickLine={false} axisLine={false} minTickGap={24} />
            <YAxis allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={tooltipStyle} labelFormatter={(l) => shortDate(String(l))} cursor={{ fill: "var(--surface-muted)" }} />
            <Legend iconType="square" wrapperStyle={{ fontSize: 12, textTransform: "capitalize" }} />
            {chart.series.map((s, i) => (
              <Bar key={s.name} dataKey={s.name} stackId="a" fill={colorFor(s.name, i)} maxBarSize={18} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      );
    }
    return (
      <ResponsiveContainer width="100%" height={220}>
        <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
          <CartesianGrid stroke="var(--border)" vertical={false} />
          <XAxis dataKey="date" tickFormatter={shortDate} tick={axis} tickLine={false} axisLine={false} minTickGap={24} />
          <YAxis allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
          <Tooltip contentStyle={tooltipStyle} labelFormatter={(l) => shortDate(String(l))} />
          <Legend iconType="plainline" wrapperStyle={{ fontSize: 12 }} />
          {chart.series.map((s, i) => (
            <Line key={s.name} type="monotone" dataKey={s.name} stroke={colorFor(s.name, i)} strokeWidth={2} dot={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    );
  }
  if (chart.kind === "donut" && chart.categories) {
    if (!chart.categories.length) return <Empty />;
    const total = chart.categories.reduce((n, c) => n + c.value, 0);
    return (
      <div className="flex h-[220px] items-center gap-6">
        <ResponsiveContainer width="55%" height={220}>
          <PieChart>
            <Pie data={chart.categories} dataKey="value" nameKey="label" innerRadius={58} outerRadius={88} paddingAngle={2} stroke="var(--surface)">
              {chart.categories.map((c, i) => <Cell key={c.label} fill={colorFor(c.label, i)} />)}
            </Pie>
            <Tooltip contentStyle={tooltipStyle} />
          </PieChart>
        </ResponsiveContainer>
        <ul className="space-y-1.5 text-[12px]">
          {chart.categories.map((c, i) => (
            <li key={c.label} className="flex items-center gap-2">
              <span className="size-2.5 rounded-sm" style={{ background: colorFor(c.label, i) }} />
              <span className="w-16 capitalize">{c.label}</span>
              <span className="tabular font-medium">{c.value}</span>
              <span className="tabular text-muted-foreground">{Math.round((100 * c.value) / total)}%</span>
            </li>
          ))}
        </ul>
      </div>
    );
  }
  if (chart.kind === "bar" && chart.categories) {
    if (!chart.categories.length) return <Empty />;
    const severityLike = chart.categories.every((c) => c.label in severityColors);
    return (
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chart.categories} layout="vertical" margin={{ top: 4, right: 16, bottom: 0, left: 8 }}>
          <CartesianGrid stroke="var(--border)" horizontal={false} />
          <XAxis type="number" allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
          <YAxis type="category" dataKey="label" tick={axis} tickLine={false} axisLine={false} width={140}
            tickFormatter={(v: string) => (v.length > 22 ? `…${v.slice(-21)}` : v)} />
          <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-muted)" }} />
          <Bar dataKey="value" name={chart.key === "top_repositories" ? "Risk points" : "Count"} radius={[0, 3, 3, 0]} barSize={14}>
            {chart.categories.map((c, i) => <Cell key={c.label} fill={severityLike ? colorFor(c.label, i) : "var(--primary)"} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    );
  }
  return <Empty />;
}

function Empty() {
  return <div className="flex h-[220px] items-center justify-center text-[13px] text-muted-foreground">No data in this period</div>;
}

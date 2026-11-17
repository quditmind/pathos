import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Severity } from "@/api/types";
import { severityColor } from "@/components/data/Severity";
import { Card } from "@/components/ui/primitives";
import { dispositionLabel, humanize, statusLabel } from "./shared";
import type { Count, Disposition, Overview, ReviewStatus } from "./types";

// Lazy-loaded (Recharts). One axis per chart; identity is carried by the
// axis label, so single-measure distributions use one hue.
const axis = { fontSize: 11, fill: "var(--muted-foreground)" };
const tooltipStyle = { background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12, color: "var(--foreground)" };
const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

function Empty() {
  return <div className="flex h-full min-h-40 items-center justify-center text-[13px] text-muted-foreground">No reviews match the filters</div>;
}

function ChartCard({ title, children, table }: { title: string; children: React.ReactNode; table: { label: string; value: number | string }[] }) {
  return (
    <Card className="p-4">
      <h2 className="mb-2 text-[13px] font-semibold">{title}</h2>
      {children}
      <details className="mt-2 text-[12px]">
        <summary className="cursor-pointer text-muted-foreground">Show as table</summary>
        <table className="mt-1 w-full">
          <tbody>
            {table.map((r) => (
              <tr key={r.label} className="border-b border-border last:border-0">
                <td className="py-1">{r.label}</td>
                <td className="tabular py-1 text-right">{r.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </Card>
  );
}

/** Horizontal single-hue bars (names on the axis, value on hover and in the table). */
function HBars({ rows, color, height }: { rows: { name: string; count: number; fill?: string }[]; color: string; height?: number }) {
  if (!rows.length || rows.every((r) => r.count === 0)) return <Empty />;
  return (
    <ResponsiveContainer width="100%" height={height ?? Math.max(120, rows.length * 30 + 30)}>
      <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 16, bottom: 0, left: 8 }} barCategoryGap={6}>
        <CartesianGrid stroke="var(--border)" horizontal={false} />
        <XAxis type="number" allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
        <YAxis type="category" dataKey="name" width={150} tick={axis} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-muted)" }} formatter={(v) => [v, "Reviews"]} />
        <Bar dataKey="count" name="Reviews" fill={color} radius={[0, 4, 4, 0]} maxBarSize={14}>
          {rows.map((r) => (
            <Cell key={r.name} fill={r.fill ?? color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

const shortDate = (d: string) => new Date(`${d}T00:00:00`).toLocaleDateString(undefined, { month: "short", day: "numeric" });

export default function OverviewCharts({ data }: { data: Overview }) {
  const sev = severityOrder.map((s) => ({ name: humanize(s), count: data.by_severity.find((c) => c.key === s)?.count ?? 0, fill: severityColor[s] }));
  const byLabel = (rows: Count[], label: (k: string) => string) => rows.map((c) => ({ name: label(c.key), count: c.count }));
  const status = byLabel(data.by_status, (k) => statusLabel[k as ReviewStatus] ?? k);
  const disp = byLabel(data.by_disposition.filter((c) => c.key !== "none"), (k) => dispositionLabel[k as Disposition] ?? k);
  const scanners = byLabel(data.by_scanner, (k) => (k === "none" || !k ? "Unknown" : k));
  const workload = data.workload.filter((w) => w.reviewer_id).map((w) => ({ name: w.reviewer_name, Pending: w.pending, "In progress": w.in_progress, Overdue: w.overdue }));
  const trendTotal = data.trend.reduce((n, d) => n + d.created + d.completed, 0);

  return (
    <div className="space-y-4">
      <ChartCard title="Review completion trend" table={data.trend.map((d) => ({ label: d.day, value: `${d.created} added · ${d.completed} completed` }))}>
        {trendTotal === 0 ? (
          <Empty />
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={data.trend} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid stroke="var(--border)" vertical={false} />
              <XAxis dataKey="day" tickFormatter={shortDate} tick={axis} tickLine={false} axisLine={false} minTickGap={24} />
              <YAxis allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} labelFormatter={(l) => shortDate(String(l))} />
              <Legend iconType="plainline" wrapperStyle={{ fontSize: 12 }} />
              <Line type="monotone" dataKey="created" name="Added to queue" stroke="var(--muted-foreground)" strokeDasharray="4 3" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
              <Line type="monotone" dataKey="completed" name="Completed" stroke="var(--primary)" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </ChartCard>
      <div className="grid gap-4 lg:grid-cols-2">
        <ChartCard title="Findings by severity" table={sev.map((r) => ({ label: r.name, value: r.count }))}>
          <HBars rows={sev} color="var(--primary)" />
        </ChartCard>
        <ChartCard title="Review status" table={status.map((r) => ({ label: r.name, value: r.count }))}>
          <HBars rows={status} color="var(--primary)" />
        </ChartCard>
        <ChartCard title="Final disposition" table={disp.map((r) => ({ label: r.name, value: r.count }))}>
          <HBars rows={disp} color="var(--primary)" />
        </ChartCard>
        <ChartCard title="Findings by scanner" table={scanners.map((r) => ({ label: r.name, value: r.count }))}>
          <HBars rows={scanners} color="var(--primary)" />
        </ChartCard>
      </div>
      <ChartCard title="Analyst workload (open reviews)" table={workload.map((w) => ({ label: w.name, value: `${w.Pending} pending · ${w["In progress"]} in progress · ${w.Overdue} overdue` }))}>
        {workload.length === 0 ? (
          <Empty />
        ) : (
          <ResponsiveContainer width="100%" height={Math.max(140, workload.length * 32 + 50)}>
            <BarChart data={workload} layout="vertical" margin={{ top: 4, right: 16, bottom: 0, left: 8 }} barCategoryGap={6}>
              <CartesianGrid stroke="var(--border)" horizontal={false} />
              <XAxis type="number" allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="name" width={150} tick={axis} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-muted)" }} />
              <Legend iconType="square" wrapperStyle={{ fontSize: 12 }} />
              <Bar dataKey="Pending" stackId="w" fill="color-mix(in srgb, var(--primary) 40%, var(--surface))" stroke="var(--surface)" strokeWidth={2} maxBarSize={14} />
              <Bar dataKey="In progress" stackId="w" fill="var(--primary)" stroke="var(--surface)" strokeWidth={2} radius={[0, 4, 4, 0]} maxBarSize={14} />
            </BarChart>
          </ResponsiveContainer>
        )}
        <p className="mt-1 text-[11.5px] text-muted-foreground">Overdue counts are in the table view and on the Assignments page.</p>
      </ChartCard>
    </div>
  );
}

import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { severityColor } from "@/components/data/Severity";
import type { ComparedScan } from "./model";
import { severities } from "../shared";

const axis = { fontSize: 11, fill: "var(--muted-foreground)" };
const tooltipStyle = {
  background: "var(--surface)",
  border: "1px solid var(--border)",
  borderRadius: 6,
  fontSize: 12,
  color: "var(--foreground)",
};

/** Trend charts across the compared executions (lazy-loaded with Recharts). */
export default function CompareCharts({ scans }: { scans: ComparedScan[] }) {
  const data = scans.map((s) => ({
    scan: s.scan_key || s.id.slice(0, 8),
    total: s.findings_total ?? 0,
    ...Object.fromEntries(severities.map((k) => [k, s.severity?.[k] ?? 0])),
  }));
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <figure className="rounded-lg border border-border bg-surface p-4" aria-label="Total findings per scan">
        <figcaption className="mb-2 text-[13px] font-semibold">Total findings</figcaption>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
            <CartesianGrid stroke="var(--border)" vertical={false} />
            <XAxis dataKey="scan" tick={axis} tickLine={false} axisLine={false} minTickGap={16} />
            <YAxis allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={tooltipStyle} />
            <Line type="monotone" dataKey="total" name="Total" stroke="var(--primary)" strokeWidth={2} dot />
          </LineChart>
        </ResponsiveContainer>
      </figure>
      <figure className="rounded-lg border border-border bg-surface p-4" aria-label="Findings per severity per scan">
        <figcaption className="mb-2 text-[13px] font-semibold">By severity</figcaption>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
            <CartesianGrid stroke="var(--border)" vertical={false} />
            <XAxis dataKey="scan" tick={axis} tickLine={false} axisLine={false} minTickGap={16} />
            <YAxis allowDecimals={false} tick={axis} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={tooltipStyle} />
            <Legend iconType="plainline" wrapperStyle={{ fontSize: 12, textTransform: "capitalize" }} />
            {severities.filter((k) => k !== "info").map((k) => (
              <Line key={k} type="monotone" dataKey={k} stroke={severityColor[k]} strokeWidth={2} dot />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </figure>
    </div>
  );
}

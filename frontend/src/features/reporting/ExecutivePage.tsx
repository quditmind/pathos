import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Printer } from "lucide-react";
import { api } from "@/api/client";
import type { Severity } from "@/api/types";
import { SeverityBadge, severityColor } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { Card, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { ErrorPanel } from "@/components/ui/error-panel";

interface GroupRisk { id: string | null; name: string; critical: number; high: number; open: number; kev: number; max_risk: number | null }
interface Executive {
  generated_at: string;
  days: number;
  scope: string;
  open_by_severity: Record<string, number>;
  open_actively_exploited: number;
  open_critical_risk: number;
  open_past_sla: number;
  new_in_period: number;
  fixed_in_period: number;
  mean_days_to_fix: Record<string, number | null>;
  fixed_within_sla_percent: number | null;
  repositories: number;
  repositories_scanned_30_days: number;
  trend: { week: string; new: number; fixed: number; open_at_end: number }[];
  top_applications: GroupRisk[];
  business_units: GroupRisk[];
}

const axis = { fontSize: 11, fill: "var(--muted-foreground)" };
const tooltipStyle = { background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 6, fontSize: 12, color: "var(--foreground)" };
const sevs: Severity[] = ["critical", "high", "medium", "low"];
const short = (d: string) => new Date(d + "T00:00:00Z").toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });

function Tile({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: "danger" | "warning" | "success" }) {
  const color = tone === "danger" ? "text-danger" : tone === "warning" ? "text-warning" : tone === "success" ? "text-success" : "";
  return (
    <Card className="p-3 print:break-inside-avoid">
      <div className="text-[12px] text-muted-foreground">{label}</div>
      <div className={`tabular mt-1 text-2xl font-semibold ${color}`}>{value}</div>
      {hint && <div className="text-[11.5px] text-muted-foreground">{hint}</div>}
    </Card>
  );
}

function GroupTable({ title, rows }: { title: string; rows: GroupRisk[] }) {
  return (
    <Card className="print:break-inside-avoid">
      <h2 className="border-b border-border px-4 py-2.5 text-[13px] font-semibold">{title}</h2>
      {!rows.length ? <p className="p-4 text-[12px] text-muted-foreground">No open findings.</p> : (
        <Table>
          <thead><tr><Th>Name</Th><Th className="text-right">Critical</Th><Th className="text-right">High</Th><Th className="text-right">Open</Th><Th className="text-right">KEV</Th><Th className="text-right">Max risk</Th></tr></thead>
          <tbody>
            {rows.map((g) => (
              <tr key={g.id ?? g.name}>
                <Td className="text-[12.5px]">{g.name}</Td>
                <Td className="tabular text-right text-[12px]">{g.critical}</Td>
                <Td className="tabular text-right text-[12px]">{g.high}</Td>
                <Td className="tabular text-right text-[12px]">{g.open}</Td>
                <Td className="tabular text-right text-[12px]">{g.kev || "—"}</Td>
                <Td className="tabular text-right text-[12px]">{g.max_risk ?? "—"}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

export function ExecutivePage() {
  const [days, setDays] = useState(90);
  const q = useQuery({ queryKey: ["executive", days], queryFn: () => api<Executive>(`/api/v1/executive?days=${days}`) });
  const e = q.data;
  const fmt = (n: number | null | undefined, unit = "") => (n == null ? "—" : `${n.toLocaleString()}${unit}`);
  return (
    <>
      <PageHeader
        title="Executive overview"
        description="Security posture for leadership: what is open and how dangerous, how fast it is fixed, and where the risk sits. Every figure is computed from findings in your scope."
        actions={<Button variant="secondary" onClick={() => window.print()}><Printer /> Print</Button>}
      />
      <div className="mb-3 flex items-center gap-3 print:hidden">
        <Select aria-label="Period" value={days} onChange={(ev) => setDays(Number(ev.target.value))}>
          {[30, 90, 180, 365].map((d) => <option key={d} value={d}>Last {d} days</option>)}
        </Select>
        {e && <span className="text-[12px] text-muted-foreground">{e.scope} · computed {formatDateTime(e.generated_at)}</span>}
      </div>
      {q.isError ? <ErrorPanel error={q.error} /> : q.isPending || !e ? <Skeleton className="h-96" /> : (
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Tile label="Open critical and high" value={fmt((e.open_by_severity.critical ?? 0) + (e.open_by_severity.high ?? 0))}
              hint={`${e.open_by_severity.critical ?? 0} critical · ${e.open_by_severity.high ?? 0} high`} tone={(e.open_by_severity.critical ?? 0) > 0 ? "danger" : undefined} />
            <Tile label="Actively exploited (CISA KEV)" value={fmt(e.open_actively_exploited)} hint={`${e.open_critical_risk} with critical contextual risk`} tone={e.open_actively_exploited ? "danger" : "success"} />
            <Tile label="Fixed within SLA" value={fmt(e.fixed_within_sla_percent, "%")} hint={`${e.open_past_sla} open findings past their deadline`} tone={e.open_past_sla ? "warning" : undefined} />
            <Tile label={`New vs fixed (${e.days} days)`} value={`${e.new_in_period} / ${e.fixed_in_period}`}
              hint={`${e.repositories_scanned_30_days} of ${e.repositories} repositories scanned in 30 days`} />
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            <Card className="p-4 print:break-inside-avoid">
              <h2 className="mb-2 text-[13px] font-semibold">Findings found and fixed per week</h2>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={e.trend} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
                    <CartesianGrid stroke="var(--border)" vertical={false} />
                    <XAxis dataKey="week" tick={axis} tickFormatter={short} />
                    <YAxis tick={axis} allowDecimals={false} />
                    <Tooltip contentStyle={tooltipStyle} labelFormatter={(l) => `Week of ${short(String(l))}`} cursor={{ fill: "var(--surface-muted)" }} />
                    <Legend iconType="square" wrapperStyle={{ fontSize: 12 }} />
                    <Bar dataKey="new" name="New" fill="var(--danger)" maxBarSize={14} radius={[4, 4, 0, 0]} />
                    <Bar dataKey="fixed" name="Fixed" fill="var(--success)" maxBarSize={14} radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
            <Card className="p-4 print:break-inside-avoid">
              <h2 className="mb-2 text-[13px] font-semibold">Open findings at the end of each week</h2>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={e.trend} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
                    <CartesianGrid stroke="var(--border)" vertical={false} />
                    <XAxis dataKey="week" tick={axis} tickFormatter={short} />
                    <YAxis tick={axis} allowDecimals={false} />
                    <Tooltip contentStyle={tooltipStyle} labelFormatter={(l) => `Week of ${short(String(l))}`} />
                    <Line type="monotone" dataKey="open_at_end" name="Open" stroke="var(--primary)" strokeWidth={2} dot={{ r: 3 }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </Card>
          </div>
          <Card className="p-4 print:break-inside-avoid">
            <h2 className="mb-2 text-[13px] font-semibold">Mean time to fix ({e.days} days)</h2>
            <div className="grid gap-3 sm:grid-cols-4">
              {sevs.map((s) => (
                <div key={s} className="flex items-center gap-2">
                  <span className="size-2 rounded-full" style={{ backgroundColor: severityColor[s] }} aria-hidden />
                  <SeverityBadge value={s} />
                  <span className="tabular text-[15px] font-semibold">{e.mean_days_to_fix[s] == null ? "—" : `${e.mean_days_to_fix[s]} days`}</span>
                </div>
              ))}
            </div>
          </Card>
          <div className="grid gap-4 xl:grid-cols-2">
            <GroupTable title="Applications with the most critical findings" rows={e.top_applications} />
            <GroupTable title="Business units" rows={e.business_units} />
          </div>
        </div>
      )}
    </>
  );
}

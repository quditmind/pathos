import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { CalendarClock, History, Pause, Play, Plus, Trash2, Zap } from "lucide-react";
import type { Schedule } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Badge, Card, EmptyState, PageHeader, Skeleton } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import {
  deleteSchedule,
  describePlanEntry,
  describeSchedule,
  describeWindow,
  kindLabel,
  pauseSchedule,
  runSchedule,
  useScheduleMutation,
  useSchedulerStatus,
  useSchedules,
  type RunResult,
} from "./api";
import { emptyForm, formFromSchedule, type ScheduleForm } from "./form";
import { ScheduleDialog } from "./ScheduleDialog";
import { RunHistory } from "./RunHistory";
import { ErrorPanel } from "@/components/ui/error-panel";

function runSummary(r: RunResult) {
  const parts = [`queued ${r.queued}`];
  if (r.coalesced) parts.push(`${r.coalesced} already queued`);
  if (r.deferred) parts.push(`${r.deferred} deferred`);
  if (r.skipped) parts.push(`${r.skipped} skipped`);
  if (r.failed) parts.push(`${r.failed} failed`);
  return `Manual run: ${parts.join(", ")}`;
}

function planEntries(s: Schedule) {
  if (s.plan?.length) return s.plan;
  return [{ target_type: s.target_type === "profile" ? "organization" : s.target_type, target_id: s.target_id, target_name: s.target_name, profile_id: s.target_type === "profile" ? s.target_id : null, profile_name: s.target_type === "profile" ? s.target_name : undefined }] as Schedule["plan"];
}

function relative(iso: string | null) {
  if (!iso) return "—";
  const d = (new Date(iso).getTime() - Date.now()) / 60000;
  const abs = Math.abs(d);
  const txt = abs < 60 ? `${Math.round(abs)} min` : abs < 48 * 60 ? `${Math.round(abs / 60)} h` : `${Math.round(abs / 1440)} days`;
  return d >= 0 ? `in ${txt}` : `${txt} ago`;
}

function StatusCard() {
  const st = useSchedulerStatus();
  const s = st.data;
  if (!s) return <Skeleton className="mb-3 h-20" />;
  const items = [
    { label: "Scheduler", value: s.healthy ? "Running" : s.heartbeat_at ? "Not responding" : "Not started", tone: s.healthy ? "text-success" : "text-danger",
      hint: s.heartbeat_at ? `${s.leader} · heartbeat ${relative(s.heartbeat_at)}` : "Start the scheduler service" },
    { label: "Workers online", value: String(s.workers_online), tone: s.workers_online ? "" : "text-danger", hint: s.workers_offline ? `${s.workers_offline} offline` : "All registered workers polling" },
    { label: "Queue", value: `${s.queued} queued · ${s.running} running`, tone: "", hint: s.oldest_queued_at ? `oldest queued ${relative(s.oldest_queued_at)}` : "Queue empty" },
    { label: "Active schedules", value: String(s.schedules), tone: "", hint: s.missed_runs ? `${s.missed_runs} missed runs recorded` : "No missed runs" },
  ];
  return (
    <Card className="mb-3 grid grid-cols-2 divide-border p-0 lg:grid-cols-4 lg:divide-x">
      {items.map((it) => (
        <div key={it.label} className="p-3">
          <div className="text-[12px] font-medium text-muted-foreground">{it.label}</div>
          <div className={`mt-0.5 text-[15px] font-semibold ${it.tone}`}>{it.value}</div>
          <div className="truncate text-[11.5px] text-muted-foreground">{it.hint}</div>
        </div>
      ))}
    </Card>
  );
}

export function SchedulesPage() {
  const { can } = useSession();
  const list = useSchedules();
  const [form, setForm] = useState<ScheduleForm | null>(null);
  const [history, setHistory] = useState<Schedule | null>(null);
  const [deleting, setDeleting] = useState<Schedule | null>(null);
  const [ran, setRan] = useState<Record<string, string>>({});
  const run = useScheduleMutation(runSchedule);
  const toggle = useScheduleMutation(pauseSchedule);
  const del = useScheduleMutation(deleteSchedule);
  const error = run.error ?? toggle.error;

  const columns: Column<Schedule>[] = [
    {
      id: "name", header: "Schedule", required: true,
      cell: (s) => {
        const plan = planEntries(s);
        return (
          <div className="min-w-48">
            <div className="flex items-center gap-2 font-medium">{s.name}{!s.enabled && <Badge tone="warning">paused</Badge>}</div>
            <div className="text-[12px] text-muted-foreground" title={plan.map(describePlanEntry).join("\n")}>
              {plan.length === 1 ? describePlanEntry(plan[0]!) : `${plan.length} plan rows: ${plan.slice(0, 2).map(describePlanEntry).join("; ")}${plan.length > 2 ? "; …" : ""}`}
            </div>
          </div>
        );
      },
      csv: (s) => s.name,
    },
    { id: "plan", header: "Plan", defaultHidden: true, exportAlways: true, cell: (s) => planEntries(s).map(describePlanEntry).join("; "), csv: (s) => planEntries(s).map(describePlanEntry).join("; ") },
    {
      id: "cadence", header: "Kind / cadence",
      cell: (s) => (
        <div>
          <div className="text-[12.5px]">{describeSchedule(s)}</div>
          <div className="text-[11px] text-muted-foreground">
            {kindLabel[s.kind] ?? s.kind}{s.kind === "cron" && <span className="font-mono"> · {s.cron}</span>} · {s.timezone}
          </div>
        </div>
      ),
      csv: (s) => `${s.kind} ${s.kind === "cron" ? s.cron : s.kind === "interval" ? `${s.interval_minutes}m` : s.run_at ?? ""} ${s.timezone}`,
    },
    { id: "next", header: "Next run", className: "whitespace-nowrap text-[12px]", cell: (s) => s.enabled && s.next_run_at ? <span title={formatDateTime(s.next_run_at)}>{relative(s.next_run_at)}</span> : <span className="text-muted-foreground">{s.enabled ? "—" : "Paused"}</span>, csv: (s) => s.next_run_at },
    { id: "window", header: "Window", className: "whitespace-nowrap text-[12px]", cell: (s) => describeWindow(s) || <span className="text-muted-foreground">Any time</span>, csv: (s) => describeWindow(s) },
    {
      id: "last", header: "Last run",
      cell: (s) => s.last_run_at ? (
        <div className="text-[12px]">
          <Link to="/scans" search={{ schedule_id: s.id } as never} className="hover:underline" onClick={(e) => e.stopPropagation()}>{relative(s.last_run_at)}</Link>
          <div className="max-w-xs truncate text-muted-foreground" title={s.last_status}>{ran[s.id] ?? s.last_status}</div>
        </div>
      ) : <span className="text-[12px] text-muted-foreground">{ran[s.id] ?? "Never"}</span>,
      csv: (s) => s.last_run_at,
    },
    {
      id: "policy", header: "Retries / concurrency", defaultHidden: true, className: "text-[12px]",
      cell: (s) => `${s.retry_max} × ${s.retry_delay_minutes} min · ${s.max_concurrent ? `max ${s.max_concurrent}` : "unlimited"}`,
      csv: (s) => `${s.retry_max}/${s.retry_delay_minutes}/${s.max_concurrent}`,
    },
    { id: "prio", header: "Priority", className: "tabular text-[12px]", cell: (s) => s.priority, csv: (s) => s.priority },
    { id: "missed", header: "Missed", className: "tabular", cell: (s) => s.missed_runs ? <Badge tone="warning">{s.missed_runs}</Badge> : <span className="text-muted-foreground">0</span>, csv: (s) => s.missed_runs },
    {
      id: "actions", header: "", required: true,
      cell: (s) => (
        <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          <Button size="sm" variant="ghost" aria-label="Run history" title="Run history" onClick={() => setHistory(s)}><History /></Button>
          {s.can_manage && (
            <>
              <Button size="sm" variant="secondary" disabled={run.isPending} title="Queue scans now"
                onClick={() => run.mutate(s.id, { onSuccess: (r) => setRan((x) => ({ ...x, [s.id]: runSummary(r) })) })}><Zap /> Run now</Button>
              <Button size="sm" variant="ghost" aria-label={s.enabled ? "Pause" : "Resume"} title={s.enabled ? "Pause" : "Resume"} disabled={toggle.isPending} onClick={() => toggle.mutate(s)}>{s.enabled ? <Pause /> : <Play />}</Button>
              <Button size="sm" variant="ghost" className="text-danger" aria-label="Delete" title="Delete" onClick={() => { del.reset(); setDeleting(s); }}><Trash2 /></Button>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Scan schedules" description="One-time, recurring and interval scans with execution plans (assets × scan profiles), approved scan windows, retries and concurrency limits. A leader-elected scheduler queues them; missed runs are caught up once and reported."
        actions={can("schedules.manage") && <Button onClick={() => setForm(emptyForm())}><Plus /> New schedule</Button>} />
      <StatusCard />
      {error && <div className="mb-3"><ErrorPanel error={error} /></div>}
      <Card>
        <DataTable tableId="schedules-v2" exportName="pathos-schedules" columns={columns} rows={list.data ?? []} rowKey={(s) => s.id}
          isPending={list.isPending} error={list.error}
          onRowClick={(s) => (s.can_manage ? setForm(formFromSchedule(s)) : setHistory(s))}
          empty={<EmptyState icon={<CalendarClock />} title="No schedules yet">Create a schedule to scan repositories regularly, e.g. nightly for production applications.</EmptyState>} />
      </Card>
      <ScheduleDialog initial={form} onClose={() => setForm(null)} />
      <RunHistory schedule={history} onClose={() => setHistory(null)} />
      <ConfirmDialog open={!!deleting} onOpenChange={(o) => !o && setDeleting(null)} title="Delete schedule" confirmLabel="Delete schedule"
        pending={del.isPending} error={del.error?.message}
        onConfirm={() => deleting && del.mutate(deleting.id, { onSuccess: () => setDeleting(null) })}>
        <p>Delete the schedule <strong>{deleting?.name}</strong>? Executions it already queued are not affected.</p>
      </ConfirmDialog>
    </>
  );
}

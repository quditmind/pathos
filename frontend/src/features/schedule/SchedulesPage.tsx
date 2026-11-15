import { useEffect, useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import { CalendarClock, Pause, Play, Plus, Trash2, Zap } from "lucide-react";
import { api } from "@/api/client";
import type { Schedule, ScheduleTarget } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { useSession } from "@/features/auth/session";
import { useRepositories } from "@/features/repos/api";
import { useProfiles } from "@/features/scans/api";
import { useBusinessUnits, useRegions } from "@/features/users/api";
import { formatDateTime } from "@/lib/utils";
import { describeCron, presets, useScheduleMutation, useSchedulerStatus, useSchedules } from "./api";

const targetLabel: Record<ScheduleTarget, string> = {
  organization: "All repositories",
  region: "Region",
  business_unit: "Business unit",
  repository: "Repository",
  profile: "Scan profile",
};

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

type Draft = { id?: string; name: string; cron: string; timezone: string; target_type: ScheduleTarget; target_id: string; priority: number; enabled: boolean };

const browserZone = (() => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
})();

const empty: Draft = { name: "", cron: "0 2 * * *", timezone: browserZone, target_type: "organization", target_id: "", priority: 30, enabled: true };

function ScheduleDialog({ draft, onClose }: { draft: Draft | null; onClose: () => void }) {
  const [d, setD] = useState<Draft>(empty);
  useEffect(() => { if (draft) setD(draft); }, [draft]);
  const regions = useRegions();
  const bus = useBusinessUnits();
  const repos = useRepositories({});
  const profiles = useProfiles();
  const zones = useMemo(() => {
    try {
      return (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.("timeZone") ?? ["UTC"];
    } catch {
      return ["UTC"];
    }
  }, []);
  const body = { name: d.name, cron: d.cron, timezone: d.timezone, target_type: d.target_type, target_id: d.target_type === "organization" ? null : d.target_id || null, priority: d.priority, enabled: d.enabled };
  const [preview, setPreview] = useState<{ next_runs: string[]; repositories: number } | null>(null);
  const [previewErr, setPreviewErr] = useState("");
  useEffect(() => {
    if (!draft) return;
    const t = setTimeout(() => {
      if (d.target_type !== "organization" && !d.target_id) { setPreview(null); setPreviewErr(""); return; }
      api<{ next_runs: string[]; repositories: number }>("/api/v1/schedules/preview", { method: "POST", body: { ...body, name: d.name || "preview" } })
        .then((r) => { setPreview(r); setPreviewErr(""); })
        .catch((e: Error) => { setPreview(null); setPreviewErr(e.message); });
    }, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [d.cron, d.timezone, d.target_type, d.target_id, draft]);
  const save = useScheduleMutation(() => (d.id ? api(`/api/v1/schedules/${d.id}`, { method: "PUT", body }) : api("/api/v1/schedules", { method: "POST", body })));
  const targets: { id: string; name: string }[] =
    d.target_type === "region" ? (regions.data ?? []).map((r) => ({ id: r.id, name: r.name }))
      : d.target_type === "business_unit" ? (bus.data ?? []).map((b) => ({ id: b.id, name: b.name }))
        : d.target_type === "repository" ? (repos.data?.pages.flatMap((p) => p.items) ?? []).map((r) => ({ id: r.id, name: r.full_name }))
          : d.target_type === "profile" ? (profiles.data ?? []).map((p) => ({ id: p.id, name: p.name + (p.is_default ? " (default)" : "") })) : [];

  return (
    <Dialog open={!!draft} onOpenChange={(o) => !o && onClose()} title={d.id ? "Edit schedule" : "New schedule"}
      description="Schedules queue a scan for every scan-enabled repository in the target. Webhooks still trigger scans on push."
      footer={<>
        <Button variant="secondary" onClick={onClose}>Cancel</Button>
        <Button disabled={!d.name.trim() || save.isPending || !!previewErr} onClick={() => save.mutate(undefined, { onSuccess: onClose })}>{d.id ? "Save" : "Create schedule"}</Button>
      </>}>
      <div className="space-y-3">
        {save.isError && <Alert>{save.error.message}</Alert>}
        <div>
          <Label htmlFor="s-name">Name</Label>
          <Input id="s-name" value={d.name} placeholder="Nightly EMEA" onChange={(e) => setD({ ...d, name: e.target.value })} />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <Label htmlFor="s-tt">Target</Label>
            <Select id="s-tt" className="w-full" value={d.target_type} onChange={(e) => setD({ ...d, target_type: e.target.value as ScheduleTarget, target_id: "" })}>
              {(Object.keys(targetLabel) as ScheduleTarget[]).map((k) => <option key={k} value={k}>{targetLabel[k]}</option>)}
            </Select>
          </div>
          {d.target_type !== "organization" && (
            <div>
              <Label htmlFor="s-tid">{targetLabel[d.target_type]}</Label>
              <Select id="s-tid" className="w-full" value={d.target_id} onChange={(e) => setD({ ...d, target_id: e.target.value })}>
                <option value="">Choose…</option>
                {targets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
              </Select>
            </div>
          )}
        </div>
        <div>
          <Label htmlFor="s-cron" hint="minute hour day-of-month month day-of-week; at most once per hour">Cadence</Label>
          <div className="flex gap-2">
            <Select aria-label="Preset" value={presets.some((p) => p.cron === d.cron) ? d.cron : ""} onChange={(e) => e.target.value && setD({ ...d, cron: e.target.value })}>
              <option value="">Custom</option>
              {presets.map((p) => <option key={p.cron} value={p.cron}>{p.label}</option>)}
            </Select>
            <Input id="s-cron" className="font-mono" value={d.cron} onChange={(e) => setD({ ...d, cron: e.target.value })} />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <Label htmlFor="s-tz">Time zone</Label>
            <Select id="s-tz" className="w-full" value={d.timezone} onChange={(e) => setD({ ...d, timezone: e.target.value })}>
              {!zones.includes(d.timezone) && <option value={d.timezone}>{d.timezone}</option>}
              {zones.map((z) => <option key={z} value={z}>{z}</option>)}
            </Select>
          </div>
          <div>
            <Label htmlFor="s-prio" hint="0–90; manual scans are 70">Priority</Label>
            <Input id="s-prio" type="number" min={0} max={90} value={d.priority} onChange={(e) => setD({ ...d, priority: Number(e.target.value) })} />
          </div>
        </div>
        <label className="flex items-center gap-2 text-[13px]"><input type="checkbox" checked={d.enabled} onChange={(e) => setD({ ...d, enabled: e.target.checked })} /> Enabled</label>
        <div className="rounded-md border border-border bg-surface-muted/50 p-3 text-[12.5px]">
          {previewErr ? <span className="text-danger">{previewErr}</span> : preview ? (
            <>
              <div className="font-medium">{describeCron(d.cron)} · {preview.repositories} repositor{preview.repositories === 1 ? "y" : "ies"} today</div>
              <div className="mt-1 text-muted-foreground">Next: {preview.next_runs.slice(0, 3).map((r) => formatDateTime(r)).join(" · ")}</div>
            </>
          ) : <span className="text-muted-foreground">Choose a target to preview.</span>}
        </div>
      </div>
    </Dialog>
  );
}

export function SchedulesPage() {
  const { can } = useSession();
  const list = useSchedules();
  const [draft, setDraft] = useState<Draft | null>(null);
  const [ran, setRan] = useState<Record<string, string>>({});
  const run = useScheduleMutation((id: string) => api<{ queued: number; coalesced: number; skipped: number }>(`/api/v1/schedules/${id}/run`, { method: "POST" }));
  const toggle = useScheduleMutation((s: Schedule) => api(`/api/v1/schedules/${s.id}`, { method: "PUT", body: { name: s.name, cron: s.cron, timezone: s.timezone, target_type: s.target_type, target_id: s.target_id, priority: s.priority, enabled: !s.enabled } }));
  const del = useScheduleMutation((id: string) => api(`/api/v1/schedules/${id}`, { method: "DELETE" }));
  const error = run.error ?? toggle.error ?? del.error;

  const columns: Column<Schedule>[] = [
    {
      id: "name", header: "Schedule", required: true,
      cell: (s) => (
        <div>
          <div className="flex items-center gap-2 font-medium">{s.name}{!s.enabled && <Badge>paused</Badge>}</div>
          <div className="text-[12px] text-muted-foreground">{targetLabel[s.target_type]}{s.target_type !== "organization" && `: ${s.target_name}`}</div>
        </div>
      ),
      csv: (s) => s.name,
    },
    { id: "cadence", header: "Cadence", cell: (s) => <div><div className="text-[12.5px]">{describeCron(s.cron)}</div><div className="font-mono text-[11px] text-muted-foreground">{s.cron} · {s.timezone}</div></div>, csv: (s) => `${s.cron} ${s.timezone}` },
    { id: "next", header: "Next run", className: "whitespace-nowrap text-[12px]", cell: (s) => s.enabled && s.next_run_at ? <span title={formatDateTime(s.next_run_at)}>{relative(s.next_run_at)}</span> : <span className="text-muted-foreground">—</span>, csv: (s) => s.next_run_at },
    {
      id: "last", header: "Last run",
      cell: (s) => s.last_run_at ? (
        <div className="text-[12px]">
          <Link to="/scans" search={{ schedule_id: s.id } as never} className="hover:underline">{relative(s.last_run_at)}</Link>
          <div className="max-w-xs truncate text-muted-foreground" title={s.last_status}>{ran[s.id] ?? s.last_status}</div>
        </div>
      ) : <span className="text-[12px] text-muted-foreground">Never</span>,
      csv: (s) => s.last_run_at,
    },
    { id: "prio", header: "Priority", className: "tabular text-[12px]", cell: (s) => s.priority, csv: (s) => s.priority },
    { id: "missed", header: "Missed", className: "tabular", cell: (s) => s.missed_runs ? <Badge tone="warning">{s.missed_runs}</Badge> : <span className="text-muted-foreground">0</span>, csv: (s) => s.missed_runs },
    {
      id: "actions", header: "", required: true,
      cell: (s) => s.can_manage && (
        <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          <Button size="sm" variant="secondary" disabled={run.isPending} title="Queue scans now"
            onClick={() => run.mutate(s.id, { onSuccess: (r) => setRan({ ...ran, [s.id]: `manual run: queued ${r.queued}${r.coalesced ? `, ${r.coalesced} already queued` : ""}` }) })}><Zap /> Run now</Button>
          <Button size="sm" variant="ghost" aria-label={s.enabled ? "Pause" : "Resume"} title={s.enabled ? "Pause" : "Resume"} onClick={() => toggle.mutate(s)}>{s.enabled ? <Pause /> : <Play />}</Button>
          <Button size="sm" variant="ghost" className="text-danger" aria-label="Delete" onClick={() => confirm(`Delete schedule "${s.name}"?`) && del.mutate(s.id)}><Trash2 /></Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Scan schedules" description="Recurring scans by organization, region, business unit, repository or scan profile. A leader-elected scheduler queues them; missed runs are caught up once and reported."
        actions={can("schedules.manage") && <Button onClick={() => setDraft({ ...empty })}><Plus /> New schedule</Button>} />
      <StatusCard />
      {error && <div className="mb-3"><Alert>{error.message}</Alert></div>}
      <Card>
        <DataTable tableId="schedules" exportName="pathos-schedules" columns={columns} rows={list.data ?? []} rowKey={(s) => s.id}
          isPending={list.isPending} error={list.error}
          onRowClick={(s) => s.can_manage && setDraft({ id: s.id, name: s.name, cron: s.cron, timezone: s.timezone, target_type: s.target_type, target_id: s.target_id ?? "", priority: s.priority, enabled: s.enabled })}
          empty={<EmptyState icon={<CalendarClock />} title="No schedules yet">Create a schedule to scan repositories regularly, e.g. nightly for production applications.</EmptyState>} />
      </Card>
      <ScheduleDialog draft={draft} onClose={() => setDraft(null)} />
    </>
  );
}

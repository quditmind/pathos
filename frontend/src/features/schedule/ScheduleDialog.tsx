import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input, Label, Select, Spinner } from "@/components/ui/primitives";
import { useDebounced } from "@/lib/useDebounced";
import { cn, formatDateTime } from "@/lib/utils";
import { describeCron, previewSchedule, saveSchedule, useScheduleMutation } from "./api";
import { buildRequest, emptyForm, formErrors, presetCron, timeZones, weekdayNames, weekdayShort, type IntervalUnit, type ScheduleForm, type ScheduleMode } from "./form";
import { PlanEditor } from "./PlanEditor";
import { ErrorPanel } from "@/components/ui/error-panel";

const modes: [ScheduleMode, string][] = [
  ["once", "One-time"],
  ["daily", "Daily"],
  ["weekly", "Weekly"],
  ["monthly", "Monthly"],
  ["cron", "Custom cron"],
  ["interval", "Custom interval"],
];

function Section({ title, hint, children }: { title: string; hint?: string; children: ReactNode }) {
  return (
    <fieldset className="space-y-2 rounded-md border border-border p-3">
      <legend className="px-1 text-[12.5px] font-semibold">{title}</legend>
      {hint && <p className="-mt-1 text-[12px] text-muted-foreground">{hint}</p>}
      {children}
    </fieldset>
  );
}

function DayToggles({ value, onChange, label }: { value: number[]; onChange: (v: number[]) => void; label: string }) {
  return (
    <div className="flex flex-wrap gap-1" role="group" aria-label={label}>
      {weekdayShort.map((d, i) => {
        const on = value.includes(i);
        return (
          <button key={d} type="button" aria-pressed={on} title={weekdayNames[i]}
            onClick={() => onChange(on ? value.filter((x) => x !== i) : [...value, i].sort((a, b) => a - b))}
            className={cn("h-7 rounded-md border px-2 text-[12px]", on ? "border-primary bg-primary/10 font-medium text-primary" : "border-border text-muted-foreground hover:bg-surface-muted")}>
            {d}
          </button>
        );
      })}
    </div>
  );
}

export function ScheduleDialog({ initial, onClose }: { initial: ScheduleForm | null; onClose: () => void }) {
  const [f, setF] = useState<ScheduleForm>(() => initial ?? emptyForm());
  useEffect(() => {
    if (initial) setF(initial);
  }, [initial]);
  const up = (patch: Partial<ScheduleForm>) => setF((x) => ({ ...x, ...patch }));
  const zones = useMemo(timeZones, []);
  const errors = formErrors(f);
  const body = buildRequest(f);
  // Preview errors other than a missing name are shown; the name is optional for the preview.
  const previewable = !!initial && formErrors({ ...f, name: f.name || "preview" }).length === 0;
  const key = useDebounced(previewable ? JSON.stringify(body) : "", 400);
  const preview = useQuery({
    queryKey: ["schedule-preview", key],
    queryFn: ({ signal }) => previewSchedule(JSON.parse(key), signal),
    enabled: !!key,
    retry: false,
    staleTime: 30_000,
  });
  const save = useScheduleMutation(() => saveSchedule(f.id, body));

  return (
    <Dialog open={!!initial} onOpenChange={(o) => !o && onClose()} size="xl" title={f.id ? "Edit schedule" : "New schedule"}
      description="Schedules queue one execution per repository and plan row. Push webhooks still trigger scans independently."
      footer={<>
        <Button variant="secondary" onClick={onClose}>Cancel</Button>
        <Button disabled={errors.length > 0 || save.isPending} title={errors[0]} onClick={() => save.mutate(undefined, { onSuccess: onClose })}>
          {save.isPending ? "Saving…" : f.id ? "Save" : "Create schedule"}
        </Button>
      </>}>
      <div className="space-y-3 text-[13px]">
        {save.isError && <ErrorPanel error={save.error} />}
        <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
          <div>
            <Label htmlFor="s-name">Name</Label>
            <Input id="s-name" value={f.name} maxLength={120} placeholder="Nightly EMEA" onChange={(e) => up({ name: e.target.value })} />
          </div>
          <label className="flex items-center gap-2 self-end pb-1.5"><input type="checkbox" checked={f.enabled} onChange={(e) => up({ enabled: e.target.checked })} /> Enabled</label>
        </div>

        <Section title="When">
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label htmlFor="s-kind">Schedule type</Label>
              <Select id="s-kind" className="w-full" value={f.mode}
                onChange={(e) => {
                  const mode = e.target.value as ScheduleMode;
                  // Switching to custom cron starts from the current preset.
                  up(mode === "cron" && f.mode !== "cron" && f.mode !== "once" && f.mode !== "interval" ? { mode, cron: presetCron(f) } : { mode });
                }}>
                {modes.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
              </Select>
            </div>
            <div>
              <Label htmlFor="s-tz">Time zone</Label>
              <Select id="s-tz" className="w-full" value={f.timezone} onChange={(e) => up({ timezone: e.target.value })}>
                {!zones.includes(f.timezone) && <option value={f.timezone}>{f.timezone}</option>}
                {zones.map((z) => <option key={z} value={z}>{z}</option>)}
              </Select>
            </div>
          </div>
          {f.mode === "once" && (
            <div className="max-w-xs">
              <Label htmlFor="s-runat">Run at</Label>
              <Input id="s-runat" type="datetime-local" value={f.runAt} onChange={(e) => up({ runAt: e.target.value })} />
            </div>
          )}
          {(f.mode === "daily" || f.mode === "weekly" || f.mode === "monthly") && (
            <div className="flex flex-wrap items-end gap-3">
              <div>
                <Label htmlFor="s-time">Time of day</Label>
                <Input id="s-time" type="time" className="w-32" value={f.time} onChange={(e) => up({ time: e.target.value || "00:00" })} />
              </div>
              {f.mode === "weekly" && (
                <div>
                  <span className="mb-1 block text-[12px] font-medium">Weekdays</span>
                  <DayToggles label="Weekdays" value={f.weekdays} onChange={(weekdays) => up({ weekdays })} />
                </div>
              )}
              {f.mode === "monthly" && (
                <div>
                  <Label htmlFor="s-dom" hint="1–31; skipped in shorter months">Day of month</Label>
                  <Input id="s-dom" type="number" min={1} max={31} className="w-24" value={f.monthDay}
                    onChange={(e) => up({ monthDay: Math.min(31, Math.max(1, Number(e.target.value) || 1)) })} />
                </div>
              )}
              <span className="pb-1.5 font-mono text-[11.5px] text-muted-foreground">{presetCron(f)}</span>
            </div>
          )}
          {f.mode === "cron" && (
            <div>
              <Label htmlFor="s-cron" hint="minute hour day-of-month month day-of-week; at most once per hour">Cron expression</Label>
              <Input id="s-cron" className="font-mono" value={f.cron} onChange={(e) => up({ cron: e.target.value })} />
              {f.cron.trim() && <p className="mt-1 text-[12px] text-muted-foreground">{describeCron(f.cron.trim())}</p>}
            </div>
          )}
          {f.mode === "interval" && (
            <div className="flex flex-wrap items-end gap-3">
              <div>
                <Label htmlFor="s-every" hint="at least 1 hour">Every</Label>
                <div className="flex gap-2">
                  <Input id="s-every" type="number" min={1} className="w-24" value={f.intervalValue} onChange={(e) => up({ intervalValue: Number(e.target.value) })} />
                  <Select aria-label="Interval unit" value={f.intervalUnit} onChange={(e) => up({ intervalUnit: e.target.value as IntervalUnit })}>
                    <option value="hours">hours</option>
                    <option value="days">days</option>
                    {f.intervalUnit === "minutes" && <option value="minutes">minutes</option>}
                  </Select>
                </div>
              </div>
              <div>
                <Label htmlFor="s-first" hint="optional">First run</Label>
                <Input id="s-first" type="datetime-local" value={f.firstRun} onChange={(e) => up({ firstRun: e.target.value })} />
              </div>
            </div>
          )}
        </Section>

        <Section title="Approved scan window" hint="Optional. Activations outside the window wait for it to open. A start later than the end spans midnight.">
          <div className="flex flex-wrap items-end gap-3">
            <div>
              <Label htmlFor="s-ws">Start</Label>
              <Input id="s-ws" type="time" className="w-32" value={f.windowStart} onChange={(e) => up({ windowStart: e.target.value })} />
            </div>
            <div>
              <Label htmlFor="s-we">End</Label>
              <Input id="s-we" type="time" className="w-32" value={f.windowEnd} onChange={(e) => up({ windowEnd: e.target.value })} />
            </div>
            <div>
              <span className="mb-1 block text-[12px] font-medium">Days <span className="font-normal text-muted-foreground">none = every day</span></span>
              <DayToggles label="Window days" value={f.windowDays} onChange={(windowDays) => up({ windowDays })} />
            </div>
            {(f.windowStart || f.windowEnd) && <Button type="button" variant="ghost" size="sm" onClick={() => up({ windowStart: "", windowEnd: "", windowDays: [] })}>Clear window</Button>}
          </div>
        </Section>

        <Section title="Execution">
          <div className="grid gap-3 sm:grid-cols-4">
            <div>
              <Label htmlFor="s-retry" hint="0–5">Retries</Label>
              <Input id="s-retry" type="number" min={0} max={5} value={f.retryMax} onChange={(e) => up({ retryMax: Math.min(5, Math.max(0, Number(e.target.value) || 0)) })} />
            </div>
            <div>
              <Label htmlFor="s-delay" hint="minutes">Retry delay</Label>
              <Input id="s-delay" type="number" min={5} max={1440} value={f.retryDelay} disabled={f.retryMax === 0} onChange={(e) => up({ retryDelay: Number(e.target.value) })} />
            </div>
            <div>
              <Label htmlFor="s-conc" hint="0 = unlimited">Max concurrent</Label>
              <Input id="s-conc" type="number" min={0} value={f.maxConcurrent} onChange={(e) => up({ maxConcurrent: Math.max(0, Number(e.target.value) || 0) })} />
            </div>
            <div>
              <Label htmlFor="s-prio" hint="0–90">Priority</Label>
              <Input id="s-prio" type="number" min={0} max={90} value={f.priority} onChange={(e) => up({ priority: Number(e.target.value) })} />
            </div>
          </div>
          <div className="flex flex-wrap gap-4">
            <span className="text-[12px] font-medium">Notify</span>
            <label className="flex items-center gap-2"><input type="checkbox" checked={f.notifyCompleted} onChange={(e) => up({ notifyCompleted: e.target.checked })} /> On completion</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={f.notifyFailed} onChange={(e) => up({ notifyFailed: e.target.checked })} /> On failure</label>
          </div>
        </Section>

        <Section title="Execution plan" hint="Each row selects assets and the scan profile to run on them. Profiles are managed in Configurations.">
          <PlanEditor rows={f.plan} onChange={(plan) => up({ plan })} />
        </Section>

        <div className="rounded-md border border-border bg-surface-muted/50 p-3 text-[12.5px]" aria-live="polite" data-testid="schedule-preview">
          {!previewable ? (
            <span className="text-muted-foreground">{formErrors({ ...f, name: f.name || "preview" })[0] ?? "Complete the form to preview."}</span>
          ) : preview.isError ? (
            <span className="text-danger">{preview.error.message}</span>
          ) : !preview.data ? (
            <span className="flex items-center gap-2 text-muted-foreground"><Spinner /> Previewing…</span>
          ) : (
            <>
              <div className="font-medium">
                {preview.data.executions} execution{preview.data.executions === 1 ? "" : "s"} per activation · {preview.data.repositories} repositor{preview.data.repositories === 1 ? "y" : "ies"}
                {preview.data.window && ` · window ${preview.data.window}`}
              </div>
              <div className="mt-1 text-muted-foreground">
                Next: {preview.data.next_runs.length ? preview.data.next_runs.map((r) => formatDateTime(r)).join(" · ") : "never"}
              </div>
            </>
          )}
        </div>
        {errors.length > 0 && f.name && <ul className="list-disc pl-5 text-[12px] text-danger">{errors.map((e) => <li key={e}>{e}</li>)}</ul>}
      </div>
    </Dialog>
  );
}

import { useEffect, useId, useMemo, useState, type ReactNode } from "react";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { ArrowRight, BellRing, Download, GitCompareArrows, RadioTower } from "lucide-react";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Badge, Input, Label, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { EmptyStateCard, FeatureDisabled, LoadingSkeleton, PermissionDenied } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useSession } from "@/features/auth/session";
import { useApplications } from "@/features/repos/api";
import { useFeatureFlags } from "@/features/shell/meta";
import { cn, formatDateTime } from "@/lib/utils";
import {
  driftCategories,
  driftCategoryLabel,
  FLAG,
  feedCsvUrl,
  isFeatureDisabled,
  rangePresets,
  severities,
  shortSha,
  sinceFor,
  useDrift,
  useDrifts,
  useEvents,
  useEventTypes,
  useMonitoringSettings,
  useSaveMonitoringSettings,
  useSummary,
  type Drift,
  type DriftItem,
  type FeedFilters,
} from "./api";
import { AppLink, codegraphCompareHref, EventCard, EvidenceBadge } from "./shared";
import type { MonitoringSearch } from "./search";

const title = "Continuous monitoring";

/**
 * /monitoring (PATHOS 3.0 M9, flag `continuous_monitoring`): the feed of the
 * seven feedback loops (new commit → rediscovery … new findings → AI triage
 * queue) and architecture drift between CodeGraph snapshots. Real events
 * only; every event carries its evidence label and references.
 */
export function MonitoringPage() {
  const search = useSearch({ strict: false }) as MonitoringSearch;
  const navigate = useNavigate();
  const { flags, isPending } = useFeatureFlags();
  const { can } = useSession();
  const on = flags[FLAG] === true;
  const allowed = can("findings.read");
  const tab = search.tab ?? "feed";
  const [disabledByApi, setDisabledByApi] = useState(false);
  const set = (patch: Partial<MonitoringSearch>) => {
    const merge = (prev: Record<string, unknown>) => {
      const next: Record<string, unknown> = { ...prev };
      for (const [k, v] of Object.entries(patch)) {
        if (v) next[k] = v;
        else delete next[k];
      }
      return next;
    };
    void navigate({ to: "/monitoring", search: ((prev: Record<string, unknown>) => merge(prev)) as never, replace: true });
  };

  const header = (actions?: ReactNode) => (
    <>
      <nav aria-label="Breadcrumb" className="mb-1 text-[12px] text-muted-foreground">
        9 · Report &amp; monitor / <span className="text-foreground">{title}</span>
      </nav>
      <PageHeader
        title={title}
        description="What changed and what PATHOS did about it: the seven feedback loops from a new commit to verified fixes, and how each application's architecture drifts between snapshots."
        actions={actions}
      />
    </>
  );
  if (isPending) return <LoadingSkeleton rows={4} label="Loading continuous monitoring" />;
  if (!on || disabledByApi) {
    return (
      <>
        {header()}
        <FeatureDisabled flag={FLAG} feature="Continuous monitoring" />
      </>
    );
  }
  if (!allowed) {
    return (
      <>
        {header()}
        <PermissionDenied permission="findings.read" what={title} />
      </>
    );
  }
  return (
    <>
      {header(<HeaderActions search={search} tab={tab} />)}
      <div className="mb-3 flex gap-1 border-b border-border" role="tablist" aria-label="Monitoring views">
        {(
          [
            ["feed", "Feed"],
            ["drift", "Architecture drift"],
          ] as const
        ).map(([k, label]) => (
          <button
            key={k}
            type="button"
            role="tab"
            aria-selected={tab === k}
            aria-controls={`mon-panel-${k}`}
            id={`mon-tab-${k}`}
            onClick={() => set({ tab: k === "feed" ? undefined : k, drift: undefined })}
            className={cn(
              "-mb-px border-b-2 px-3 py-2 text-[13px] font-medium",
              tab === k ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {label}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`mon-panel-${tab}`} aria-labelledby={`mon-tab-${tab}`}>
        {tab === "feed" ? <FeedTab search={search} set={set} onDisabled={() => setDisabledByApi(true)} /> : <DriftTab search={search} set={set} onDisabled={() => setDisabledByApi(true)} />}
      </div>
    </>
  );
}

/** Feed filters sent to the API: the URL filters with the time range resolved. */
export function useFeedFilters(search: MonitoringSearch): FeedFilters {
  const { range, since: rawSince, until: rawUntil } = search;
  // A preset is resolved once per change (a moving "now" would refetch on every render).
  const since = useMemo(() => (range === "custom" ? rawSince : sinceFor(range ?? "")), [range, rawSince]);
  const until = range === "custom" ? rawUntil : undefined;
  return {
    application_id: search.application_id,
    repository_id: search.repository_id,
    type: search.type,
    severity: search.severity,
    loop: search.loop,
    since,
    until,
  };
}

function HeaderActions({ search, tab }: { search: MonitoringSearch; tab: "feed" | "drift" }) {
  const { can } = useSession();
  const [open, setOpen] = useState(false);
  const filters = useFeedFilters(search);
  return (
    <>
      {tab === "feed" && can("findings.export") && (
        <Button variant="secondary" size="sm" asChild>
          <a href={feedCsvUrl(filters)} download title="Download the feed with the current filters as CSV (stamped with the PATHOS version and build)">
            <Download /> Export CSV
          </a>
        </Button>
      )}
      {can("settings.manage") && (
        <>
          <Button variant="secondary" size="sm" onClick={() => setOpen(true)}>
            <BellRing /> Drift alerts
          </Button>
          {open && <DriftAlertsDialog open={open} onOpenChange={setOpen} />}
        </>
      )}
    </>
  );
}

// --- feed ------------------------------------------------------------------------

function ApplicationSelect({ value, onChange, id }: { value?: string; onChange: (v?: string) => void; id?: string }) {
  const apps = useApplications();
  const known = apps.data?.some((a) => a.id === value);
  return (
    <Select id={id} aria-label="Application" value={value ?? ""} onChange={(e) => onChange(e.target.value || undefined)} className="max-w-56">
      <option value="">All applications</option>
      {value && !known && <option value={value}>Selected application</option>}
      {(apps.data ?? []).map((a) => (
        <option key={a.id} value={a.id}>
          {a.name}
        </option>
      ))}
    </Select>
  );
}

const toLocalInput = (iso?: string) => {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
};
const fromLocalInput = (v: string) => (v ? new Date(v).toISOString() : undefined);

function FeedFiltersBar({ search, set }: { search: MonitoringSearch; set: (p: Partial<MonitoringSearch>) => void }) {
  const types = useEventTypes();
  const ids = useId();
  return (
    <div className="mb-3 flex flex-wrap items-end gap-2" role="group" aria-label="Feed filters">
      <ApplicationSelect value={search.application_id} onChange={(v) => set({ application_id: v })} />
      <Select aria-label="Event type" value={search.type ?? ""} onChange={(e) => set({ type: e.target.value || undefined })}>
        <option value="">All event types</option>
        {(types.data ?? []).map((t) => (
          <option key={t.type} value={t.type}>
            {t.loop ? `Loop ${t.loop} · ` : ""}
            {t.label}
          </option>
        ))}
        {search.type && !types.data?.some((t) => t.type === search.type) && <option value={search.type}>Selected types</option>}
      </Select>
      <Select aria-label="Severity" value={search.severity ?? ""} onChange={(e) => set({ severity: e.target.value || undefined })}>
        <option value="">Any severity</option>
        {severities.map((s) => (
          <option key={s} value={s} className="capitalize">
            {s}
          </option>
        ))}
        {search.severity && !severities.includes(search.severity as never) && <option value={search.severity}>Selected severities</option>}
      </Select>
      <Select aria-label="Time range" value={search.range ?? ""} onChange={(e) => set({ range: e.target.value || undefined, since: undefined, until: undefined })}>
        <option value="">Any time</option>
        {rangePresets.map((p) => (
          <option key={p.key} value={p.key}>
            {p.label}
          </option>
        ))}
        <option value="custom">Custom range</option>
      </Select>
      {search.range === "custom" && (
        <>
          <div>
            <Label htmlFor={`${ids}-since`}>From</Label>
            <Input id={`${ids}-since`} type="datetime-local" className="w-48" value={toLocalInput(search.since)} onChange={(e) => set({ since: fromLocalInput(e.target.value) })} />
          </div>
          <div>
            <Label htmlFor={`${ids}-until`}>To</Label>
            <Input id={`${ids}-until`} type="datetime-local" className="w-48" value={toLocalInput(search.until)} onChange={(e) => set({ until: fromLocalInput(e.target.value) })} />
          </div>
        </>
      )}
      {search.repository_id && (
        <span className="inline-flex h-8 items-center gap-1 rounded-md border border-border px-2 text-[12.5px]">
          One repository only
          <button type="button" className="text-primary hover:underline" onClick={() => set({ repository_id: undefined })}>
            Clear
          </button>
        </span>
      )}
      {search.loop && (
        <span className="inline-flex h-8 items-center gap-1 rounded-md border border-border px-2 text-[12.5px]">
          Loop {search.loop} only
          <button type="button" className="text-primary hover:underline" onClick={() => set({ loop: undefined })}>
            Clear
          </button>
        </span>
      )}
    </div>
  );
}

function SummaryStat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="rounded-md border border-border bg-surface p-3">
      <div className="text-[11.5px] text-muted-foreground">{label}</div>
      <div className="mt-0.5 text-lg font-semibold tabular-nums">{value}</div>
      {hint && <div className="text-[11px] text-muted-foreground">{hint}</div>}
    </div>
  );
}

function SummaryCards({ applicationId }: { applicationId?: string }) {
  const s = useSummary(applicationId, 30);
  if (s.isPending) return <Skeleton className="mb-3 h-20" />;
  if (s.isError) return isFeatureDisabled(s.error) ? null : <div className="mb-3"><ErrorPanel error={s.error} title="The monitoring summary could not be loaded" onVerify={() => s.refetch()} /></div>;
  const d = s.data;
  const sev = d.by_severity ?? {};
  return (
    <section aria-label={`Summary of the last ${d.days} days`} className="mb-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
      <SummaryStat label={`Events (last ${d.days} days)`} value={d.total} hint={d.latest_at ? `Latest ${formatDateTime(d.latest_at)}` : "No events yet"} />
      <SummaryStat label="Critical and high" value={(sev.critical ?? 0) + (sev.high ?? 0)} hint={`${sev.critical ?? 0} critical · ${sev.high ?? 0} high`} />
      <SummaryStat label="Architecture drift with changes" value={d.drift?.with_changes ?? 0} hint={`${d.drift?.total ?? 0} snapshot comparison(s)`} />
      <SummaryStat label="Latest drift" value={<span className="text-[13px]">{d.drift?.latest_at ? formatDateTime(d.drift.latest_at) : "None yet"}</span>} />
    </section>
  );
}

function FeedTab({ search, set, onDisabled }: { search: MonitoringSearch; set: (p: Partial<MonitoringSearch>) => void; onDisabled: () => void }) {
  const filters = useFeedFilters(search);
  const [cursor, setCursor] = useState<string | undefined>();
  const [cursors, setCursors] = useState<string[]>([]);
  const key = JSON.stringify(filters);
  useEffect(() => {
    setCursor(undefined);
    setCursors([]);
  }, [key]);
  const list = useEvents(filters, cursor);
  const disabled = isFeatureDisabled(list.error);
  useEffect(() => {
    if (disabled) onDisabled();
  }, [disabled, onDisabled]);
  const filtered = !!(search.application_id || search.repository_id || search.type || search.severity || search.loop || search.range);
  return (
    <>
      <SummaryCards applicationId={search.application_id} />
      <FeedFiltersBar search={search} set={set} />
      {list.isError ? (
        <ErrorPanel error={list.error} title="The monitoring feed could not be loaded" onVerify={() => list.refetch()} />
      ) : list.isPending ? (
        <LoadingSkeleton rows={6} label="Loading the monitoring feed" />
      ) : !list.data.items.length ? (
        <EmptyStateCard icon={<RadioTower />} title={filtered ? "No events match these filters" : "No monitoring events yet"}>
          {filtered
            ? "Clear a filter or widen the time range to see more events."
            : "Events appear here as PATHOS reacts to change: a new commit queues a CodeGraph rediscovery, a dependency change triggers reassessment, an architecture change updates the threat model draft, new intelligence re-scores risk, a merged fix is verified, a failed gate gives developer feedback and new findings join the AI triage queue. Connect a repository and run a scan to start."}
        </EmptyStateCard>
      ) : (
        <>
          <ol className="space-y-2" aria-label="Monitoring events">
            {list.data.items.map((e) => (
              <li key={e.id}>
                <EventCard e={e} />
              </li>
            ))}
          </ol>
          {(list.data.next_cursor || cursors.length > 0) && (
            <div className="mt-2 flex justify-end gap-2">
              <Button
                size="sm"
                variant="secondary"
                disabled={!cursors.length}
                onClick={() => {
                  const prev = cursors[cursors.length - 1];
                  setCursors((c) => c.slice(0, -1));
                  setCursor(prev || undefined);
                }}
              >
                Previous
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!list.data.next_cursor}
                onClick={() => {
                  setCursors((c) => [...c, cursor ?? ""]);
                  setCursor(list.data.next_cursor ?? undefined);
                }}
              >
                Next
              </Button>
            </div>
          )}
        </>
      )}
    </>
  );
}

// --- drift -----------------------------------------------------------------------

function countText(d: Drift): { label: string; text: string }[] {
  const out: { label: string; text: string }[] = [];
  for (const c of driftCategories) {
    const a = d.counts?.[c.added] ?? 0;
    const r = d.counts?.[c.removed] ?? 0;
    const ch = c.changed ? (d.counts?.[c.changed] ?? 0) : 0;
    if (!a && !r && !ch) continue;
    const parts = [a ? `+${a}` : "", r ? `−${r}` : "", ch ? `~${ch}` : ""].filter(Boolean);
    out.push({ label: c.label, text: parts.join(" ") });
  }
  return out;
}

function CommitRange({ d }: { d: Pick<Drift, "from_commit" | "to_commit" | "from_snapshot_id" | "to_snapshot_id"> }) {
  return (
    <span className="font-mono text-[11.5px]">
      {d.from_snapshot_id ? shortSha(d.from_commit) || d.from_snapshot_id.slice(0, 8) : "baseline"} → {shortSha(d.to_commit) || d.to_snapshot_id.slice(0, 8)}
    </span>
  );
}

function DriftTab({ search, set, onDisabled }: { search: MonitoringSearch; set: (p: Partial<MonitoringSearch>) => void; onDisabled: () => void }) {
  const showUnchanged = search.unchanged === "true";
  const [cursor, setCursor] = useState<string | undefined>();
  const [cursors, setCursors] = useState<string[]>([]);
  useEffect(() => {
    setCursor(undefined);
    setCursors([]);
  }, [search.application_id, showUnchanged]);
  const list = useDrifts(search.application_id, !showUnchanged, cursor);
  const disabled = isFeatureDisabled(list.error);
  useEffect(() => {
    if (disabled) onDisabled();
  }, [disabled, onDisabled]);
  return (
    <>
      <div className="mb-3 flex flex-wrap items-center gap-3" role="group" aria-label="Drift filters">
        <ApplicationSelect value={search.application_id} onChange={(v) => set({ application_id: v })} />
        <label className="flex items-center gap-1.5 text-[13px]">
          <input type="checkbox" className="accent-[var(--primary)]" checked={showUnchanged} onChange={(e) => set({ unchanged: e.target.checked ? "true" : undefined })} />
          Show snapshots without changes
        </label>
      </div>
      {list.isError ? (
        <ErrorPanel error={list.error} title="Architecture drift could not be loaded" onVerify={() => list.refetch()} />
      ) : list.isPending ? (
        <LoadingSkeleton rows={5} label="Loading architecture drift" />
      ) : !list.data.items.length ? (
        <EmptyStateCard icon={<GitCompareArrows />} title={search.application_id || showUnchanged ? "No drift for this selection" : "No architecture drift yet"}>
          Each new CodeGraph snapshot of an application is compared with the previous one: new or removed routes, external services, data stores, internet
          exposure, trust boundary crossings and components appear here. Enable CodeGraph and let a second snapshot build after the next commit.
        </EmptyStateCard>
      ) : (
        <>
          <ol className="relative ml-2 space-y-3 border-l border-border pl-5" aria-label="Architecture drift timeline">
            {list.data.items.map((d) => {
              const counts = countText(d);
              return (
                <li key={d.id} className="relative" data-testid="drift-entry">
                  <span
                    className={cn("absolute -left-[27px] top-3 size-3 rounded-full border-2 border-surface", d.has_changes ? "bg-primary" : "bg-surface-muted")}
                    aria-hidden
                  />
                  <button
                    type="button"
                    onClick={() => set({ drift: d.id })}
                    className="w-full rounded-md border border-border bg-surface p-3 text-left text-[12.5px] hover:bg-surface-muted/60 focus-visible:outline-2 focus-visible:outline-ring"
                    aria-label={`Open drift of ${d.application_name || "the application"} ${d.repository_name ? `(${d.repository_name}) ` : ""}from ${formatDateTime(d.created_at)}`}
                  >
                    <div className="mb-1 flex flex-wrap items-center gap-1.5">
                      <span className="font-medium">{d.application_name || "Application"}</span>
                      {d.repository_name && <span className="text-muted-foreground">· {d.repository_name}</span>}
                      {d.has_changes ? <SeverityBadge value={d.severity} /> : <Badge>{d.from_snapshot_id ? "No changes" : "Baseline"}</Badge>}
                      <time dateTime={d.created_at} className="ml-auto text-[11.5px] text-muted-foreground">
                        {formatDateTime(d.created_at)}
                      </time>
                    </div>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-muted-foreground">
                      <CommitRange d={d} />
                      {counts.length ? (
                        counts.map((c) => (
                          <span key={c.label}>
                            {c.label} <span className="font-medium text-foreground tabular-nums">{c.text}</span>
                          </span>
                        ))
                      ) : (
                        <span>{d.from_snapshot_id ? "Same architecture as the previous snapshot" : "First snapshot: the baseline later snapshots are compared with"}</span>
                      )}
                    </div>
                  </button>
                </li>
              );
            })}
          </ol>
          {(list.data.next_cursor || cursors.length > 0) && (
            <div className="mt-2 flex justify-end gap-2">
              <Button
                size="sm"
                variant="secondary"
                disabled={!cursors.length}
                onClick={() => {
                  const prev = cursors[cursors.length - 1];
                  setCursors((c) => c.slice(0, -1));
                  setCursor(prev || undefined);
                }}
              >
                Previous
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={!list.data.next_cursor}
                onClick={() => {
                  setCursors((c) => [...c, cursor ?? ""]);
                  setCursor(list.data.next_cursor ?? undefined);
                }}
              >
                Next
              </Button>
            </div>
          )}
        </>
      )}
      <DriftDrawer id={search.drift} onClose={() => set({ drift: undefined })} />
    </>
  );
}

const changeTone = { added: "primary", removed: "neutral", changed: "warning" } as const;
const changeLabel = { added: "Added", removed: "Removed", changed: "Changed" } as const;

function DriftItemRow({ i }: { i: DriftItem }) {
  return (
    <li className="rounded border border-border px-2 py-1.5" data-testid="drift-item">
      <div className="flex flex-wrap items-center gap-1.5">
        <Badge tone={changeTone[i.change] ?? "neutral"}>{changeLabel[i.change] ?? i.change}</Badge>
        <span className="font-medium">{i.label || i.key}</span>
        <EvidenceBadge label={i.evidence_label} />
      </div>
      {i.detail && <p className="text-[12px] text-muted-foreground">{i.detail}</p>}
      {i.evidence.length > 0 && (
        <ul className="mt-0.5 space-y-0.5 text-[11.5px] text-muted-foreground" aria-label={`Evidence for ${i.label || i.key}`}>
          {i.evidence.map((e, n) => (
            <li key={n}>
              <span className="mr-1">{e.kind.replace(/_/g, " ")}:</span>
              {e.file ? (
                <code className="font-mono">
                  {e.file}
                  {e.line ? `:${e.line}` : ""}
                </code>
              ) : (
                <code className="font-mono">{e.ref}</code>
              )}
              {e.detail && ` — ${e.detail}`}
            </li>
          ))}
        </ul>
      )}
      {!i.evidence.length && i.file && <p className="font-mono text-[11.5px] text-muted-foreground">{i.file}</p>}
    </li>
  );
}

/** Drift detail drawer: added, removed and changed items grouped by category, each with evidence and its label. */
export function DriftDrawer({ id, onClose }: { id?: string; onClose: () => void }) {
  const q = useDrift(id);
  const d = q.data;
  const groups = useMemo(() => {
    const m = new Map<string, DriftItem[]>();
    for (const i of d?.items ?? []) m.set(i.category, [...(m.get(i.category) ?? []), i]);
    return [...m.entries()];
  }, [d]);
  const cg = d ? codegraphCompareHref(d.application_id, d.from_snapshot_id, d.to_snapshot_id) : undefined;
  return (
    <Dialog
      open={!!id}
      onOpenChange={(o) => !o && onClose()}
      side
      size="lg"
      title={d ? `Architecture drift · ${d.application_name || "application"}` : "Architecture drift"}
      description={d ? `${d.repository_name ? `${d.repository_name} · ` : ""}${formatDateTime(d.created_at)}` : undefined}
    >
      {q.isPending ? (
        <LoadingSkeleton rows={6} label="Loading the drift" />
      ) : q.isError ? (
        <ErrorPanel error={q.error} title="The drift could not be loaded" onVerify={() => q.refetch()} />
      ) : d ? (
        <div className="space-y-4 text-[13px]" data-testid="drift-detail">
          <div className="flex flex-wrap items-center gap-2">
            {d.has_changes ? <SeverityBadge value={d.severity} /> : <Badge>{d.from_snapshot_id ? "No changes" : "Baseline"}</Badge>}
            <CommitRange d={d} />
            {cg && (
              <AppLink href={cg} className="inline-flex items-center gap-1 text-primary hover:underline">
                Compare the snapshots in CodeGraph <ArrowRight className="size-3.5" aria-hidden />
              </AppLink>
            )}
          </div>
          {!groups.length ? (
            <p className="text-muted-foreground">
              {d.from_snapshot_id ? "Nothing was added, removed or changed between the two snapshots." : "This is the first snapshot of the repository; later snapshots are compared with it."}
            </p>
          ) : (
            groups.map(([cat, items]) => (
              <section key={cat} className="space-y-1.5" aria-label={driftCategoryLabel[cat as keyof typeof driftCategoryLabel] ?? cat}>
                <h3 className="text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">
                  {driftCategoryLabel[cat as keyof typeof driftCategoryLabel] ?? cat} ({items.length})
                </h3>
                <ul className="space-y-1">
                  {items.map((i) => (
                    <DriftItemRow key={`${i.change}:${i.key}`} i={i} />
                  ))}
                </ul>
              </section>
            ))
          )}
          {d.truncated && <p className="text-[12px] text-warning">The list is shortened; open the CodeGraph comparison for every change.</p>}
        </div>
      ) : null}
    </Dialog>
  );
}

// --- settings --------------------------------------------------------------------

function DriftAlertsDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const q = useMonitoringSettings(open);
  const save = useSaveMonitoringSettings();
  const ids = useId();
  const [on, setOn] = useState(false);
  const [min, setMin] = useState("high");
  useEffect(() => {
    if (q.data) {
      setOn(q.data.drift_alerts);
      setMin(q.data.drift_alert_min_severity || "high");
    }
  }, [q.data]);
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Drift alerts"
      description="Send architecture drift through the notification channels (in-app, e-mail and outbound webhooks). Off by default."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            disabled={!q.data || save.isPending}
            onClick={() =>
              save.mutate(
                { drift_alerts: on, drift_alert_min_severity: min as never },
                {
                  onSuccess: () => {
                    toast.success(on ? `Drift alerts on for ${min} severity and above` : "Drift alerts off");
                    onOpenChange(false);
                  },
                },
              )
            }
          >
            Save
          </Button>
        </>
      }
    >
      {q.isPending ? (
        <LoadingSkeleton rows={2} label="Loading the drift alert settings" />
      ) : q.isError ? (
        <ErrorPanel error={q.error} title="The drift alert settings could not be loaded" onVerify={() => q.refetch()} />
      ) : (
        <div className="space-y-3 text-[13px]">
          <label className="flex items-center gap-2">
            <input type="checkbox" className="accent-[var(--primary)]" checked={on} onChange={(e) => setOn(e.target.checked)} />
            Alert on architecture drift
          </label>
          <div>
            <Label htmlFor={`${ids}-min`}>Minimum severity</Label>
            <Select id={`${ids}-min`} value={min} disabled={!on} onChange={(e) => setMin(e.target.value)}>
              {severities.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
            <p className="mt-1 text-[11.5px] text-muted-foreground">
              Drift at or above this severity is sent as the notification event <code>architecture.drift</code>; who receives it follows the rules under
              Administration › Notifications.
            </p>
          </div>
          {q.data?.updated_at && (
            <p className="text-[11.5px] text-muted-foreground">
              Last changed {formatDateTime(q.data.updated_at)}
              {q.data.updated_by && ` by ${q.data.updated_by}`}
            </p>
          )}
          {save.error && <ErrorPanel error={save.error} title="The drift alert settings were not saved" />}
        </div>
      )}
    </Dialog>
  );
}

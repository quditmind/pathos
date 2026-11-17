import { useEffect, useState, type ReactNode } from "react";
import type { Severity } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Card, Input, Label, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { useCatalog as useScannerCatalog } from "@/features/scans/api";
import { reviewApi, useCatalog, useReviewers, useReviewMutation, useSettings } from "./api";
import { dispositionLabel, humanize, priorityLabel, severities } from "./shared";
import type { Disposition, Priority, Settings } from "./types";

function Section({ title, description, children }: { title: string; description?: string; children: ReactNode }) {
  return (
    <Card className="p-4">
      <h2 className="text-[13px] font-semibold">{title}</h2>
      {description && <p className="mb-3 mt-0.5 text-[12.5px] text-muted-foreground">{description}</p>}
      <div className="space-y-3">{children}</div>
    </Card>
  );
}

function Toggle({ id, label, checked, onChange, disabled, hint }: { id: string; label: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; hint?: string }) {
  return (
    <label htmlFor={id} className="flex items-start gap-2 text-[13px]">
      <input id={id} type="checkbox" className="mt-0.5 size-3.5 accent-[var(--primary)]" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>
        {label}
        {hint && <span className="block text-[12px] text-muted-foreground">{hint}</span>}
      </span>
    </label>
  );
}

function Checks<T extends string>({ legend, options, value, onChange, disabled, label }: { legend: string; options: readonly T[]; value: T[]; onChange: (v: T[]) => void; disabled?: boolean; label?: (v: T) => string }) {
  return (
    <fieldset>
      <legend className="mb-1 text-[12px] font-medium">{legend}</legend>
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        {options.map((o) => (
          <label key={o} className="flex items-center gap-1.5 text-[12.5px]">
            <input
              type="checkbox"
              className="size-3.5 accent-[var(--primary)]"
              disabled={disabled}
              checked={value.includes(o)}
              onChange={(e) => onChange(e.target.checked ? [...value, o] : value.filter((x) => x !== o))}
            />
            {label ? label(o) : humanize(o)}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

const triggers = ["needs_review", "ai_needs_review", "ai_false_positive", "new_findings"] as const;
const triggerLabel: Record<string, string> = {
  needs_review: "Automated triage marks a finding as needing review",
  ai_needs_review: "AI review cannot decide (needs review)",
  ai_false_positive: "AI review suggests a false positive (human confirms)",
  new_findings: "Every new finding matching the filters",
};
const categories = ["sast", "sca", "secrets", "iac", "container", "license", "other"] as const;
const finalDispositions = (Object.keys(dispositionLabel) as Disposition[]).filter((d) => d !== "needs_more_information");

export function ConfigurationsPage() {
  const { canOrgWide } = useSession();
  const editable = canOrgWide("reviews.configure");
  const settings = useSettings();
  const catalog = useCatalog();
  const scanners = useScannerCatalog();
  const reviewers = useReviewers();
  const [s, setS] = useState<Settings | null>(null);
  const save = useReviewMutation(reviewApi.saveSettings);
  useEffect(() => {
    if (settings.data) setS(settings.data);
  }, [settings.data]);
  if (settings.isError) return <Alert>Could not load the configuration: {settings.error.message}</Alert>;
  if (!s || !catalog.data) return <Skeleton className="h-96" />;
  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setS({ ...s, [k]: v });
  const requiredKeys = [...catalog.data.questions.map((q) => ({ key: q.key, label: q.label })), ...catalog.data.assessment_fields.map((f) => ({ key: f.key, label: f.label }))];
  const dis = !editable;
  return (
    <>
      <PageHeader
        title="Review configurations"
        description={editable ? "Workflow rules for Human Eye. Nothing here is hard-coded." : "Read-only: managing the configuration requires reviews.configure."}
        actions={
          editable && (
            <Button disabled={save.isPending} onClick={() => save.mutate(s)}>
              {save.isPending ? "Saving…" : "Save configuration"}
            </Button>
          )
        }
      />
      <div className="mb-3 space-y-2">
        {save.error && <Alert>{save.error.message}</Alert>}
        {save.isSuccess && <Alert tone="success">Configuration saved.</Alert>}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Automatic review queue" description="Which findings enter the queue on their own. Ingestion runs after every scan and every few minutes; findings are never queued twice.">
          <Toggle id="auto" label="Create reviews automatically" checked={s.auto_queue} disabled={dis} onChange={(v) => set("auto_queue", v)} />
          <Checks legend="Queue a finding when" options={triggers} value={s.auto_triggers as (typeof triggers)[number][]} disabled={dis || !s.auto_queue} onChange={(v) => set("auto_triggers", v)} label={(v) => triggerLabel[v]!} />
          <Checks legend="Finding categories" options={categories} value={s.auto_categories as (typeof categories)[number][]} disabled={dis || !s.auto_queue} onChange={(v) => set("auto_categories", v)} label={(v) => v.toUpperCase()} />
          <div>
            <Label htmlFor="minsev">Minimum severity</Label>
            <Select id="minsev" value={s.auto_min_severity} disabled={dis} onChange={(e) => set("auto_min_severity", e.target.value as Severity)}>
              {severities.map((x) => <option key={x} value={x}>{humanize(x)} and above</option>)}
            </Select>
          </div>
          <Checks
            legend="Scanners that may send findings (none selected = all scanners)"
            options={(scanners.data ?? []).map((x) => x.key)}
            value={s.auto_scanners}
            disabled={dis}
            onChange={(v) => set("auto_scanners", v)}
            label={(k) => scanners.data?.find((x) => x.key === k)?.name ?? k}
          />
        </Section>

        <Section title="Severity-based rules and review SLA" description="Priority and due date given to new reviews by scanner severity (0 days = no due date).">
          <div className="grid grid-cols-[auto_1fr_auto] items-center gap-2 text-[12.5px]">
            {severities.map((sv) => (
              <div key={sv} className="contents">
                <span className="capitalize">{sv}</span>
                <Select aria-label={`Priority for ${sv}`} disabled={dis} value={s.priority_by_severity[sv] ?? "p3"} onChange={(e) => set("priority_by_severity", { ...s.priority_by_severity, [sv]: e.target.value as Priority })}>
                  {(Object.keys(priorityLabel) as Priority[]).map((p) => <option key={p} value={p}>{priorityLabel[p]}</option>)}
                </Select>
                <span className="flex items-center gap-1">
                  <Input aria-label={`Review SLA days for ${sv}`} type="number" min={0} max={365} className="w-20" disabled={dis} value={s.sla_days[sv] ?? 0}
                    onChange={(e) => set("sla_days", { ...s.sla_days, [sv]: Math.max(0, Math.min(365, Number(e.target.value) || 0)) })} />
                  days
                </span>
              </div>
            ))}
          </div>
        </Section>

        <Section title="Assignment rules">
          <div>
            <Label htmlFor="strategy">Assignment of new reviews</Label>
            <Select id="strategy" className="w-full" disabled={dis} value={s.assignment_strategy} onChange={(e) => set("assignment_strategy", e.target.value as Settings["assignment_strategy"])}>
              <option value="manual">Manual (review managers assign)</option>
              <option value="round_robin">Round robin across the pool</option>
              <option value="least_loaded">Least loaded analyst in the pool</option>
            </Select>
          </div>
          {s.assignment_strategy !== "manual" && (
            <Checks
              legend="Assignment pool (analysts must hold reviews.assess on the repository)"
              options={(reviewers.data ?? []).filter((r) => r.can_assess).map((r) => r.id)}
              value={s.assignment_pool}
              disabled={dis}
              onChange={(v) => set("assignment_pool", v)}
              label={(id) => reviewers.data?.find((r) => r.id === id)?.name ?? id}
            />
          )}
          <Toggle id="selfassign" label="Analysts may assign unassigned reviews to themselves" checked={s.allow_self_assign} disabled={dis} onChange={(v) => set("allow_self_assign", v)} />
          <Toggle id="unassigned" label="Any analyst may work on a review, not only its assignee" checked={s.unassigned_can_assess} disabled={dis} onChange={(v) => set("unassigned_can_assess", v)}
            hint="Review permissions: off keeps assessments with the assigned analyst (review managers can always step in)." />
        </Section>

        <Section title="Independent review" description="A second analyst must approve these decisions before closure. Accepted risk always needs approval by someone holding findings.accept_risk.">
          <Checks legend="Require for findings of severity (scanner or assessed)" options={severities} value={s.independent_review_severities} disabled={dis} onChange={(v) => set("independent_review_severities", v)} />
          <Checks legend="Require for dispositions" options={finalDispositions} value={s.independent_review_dispositions} disabled={dis} onChange={(v) => set("independent_review_dispositions", v)} label={(d) => dispositionLabel[d]} />
        </Section>

        <Section title="Required evidence and assessment fields">
          <Checks legend="At least one evidence item for dispositions" options={finalDispositions} value={s.evidence_required_dispositions} disabled={dis} onChange={(v) => set("evidence_required_dispositions", v)} label={(d) => dispositionLabel[d]} />
          <Checks legend="At least one evidence item for severities" options={severities} value={s.evidence_required_severities} disabled={dis} onChange={(v) => set("evidence_required_severities", v)} />
          <Checks legend="Assessment fields required before a final decision" options={requiredKeys.map((k) => k.key)} value={s.required_fields} disabled={dis} onChange={(v) => set("required_fields", v)}
            label={(k) => requiredKeys.find((x) => x.key === k)?.label ?? k} />
          <div>
            <Label htmlFor="maxmb">Maximum evidence file size (MB)</Label>
            <Input id="maxmb" type="number" min={1} max={100} className="w-24" disabled={dis} value={s.evidence_max_mb} onChange={(e) => set("evidence_max_mb", Math.max(1, Math.min(100, Number(e.target.value) || 1)))} />
          </div>
        </Section>

        <Section title="Notifications" description="Delivered through the notification rules under Administration → Notifications.">
          <Toggle id="n1" label="Notify analysts when a review is assigned to them" checked={s.notify_assignment} disabled={dis} onChange={(v) => set("notify_assignment", v)} />
          <Toggle id="n2" label="Notify independent reviewers when a decision needs approval" checked={s.notify_independent_review} disabled={dis} onChange={(v) => set("notify_independent_review", v)} />
          <Toggle id="n3" label="Notify analysts when a review becomes overdue" checked={s.notify_overdue} disabled={dis} onChange={(v) => set("notify_overdue", v)} />
        </Section>

        <Section title="AI assistance" description="Suggestions use the default provider under AI settings. AI never finalizes a review, approves accepted risk or marks a false positive.">
          <Toggle id="ai" label="Offer AI suggestions in the assessment workspace" checked={s.ai_assist} disabled={dis} onChange={(v) => set("ai_assist", v)} />
          <Toggle id="aicode" label="Send redacted source code from the scanned commit with requests" checked={s.ai_send_code} disabled={dis || !s.ai_assist} onChange={(v) => set("ai_send_code", v)}
            hint="Code around secret findings is never sent. The AI configuration's own setting also applies." />
        </Section>
      </div>
      {s.updated_at && <p className="mt-3 text-[12px] text-muted-foreground">Last changed {new Date(s.updated_at).toLocaleString()}{s.updated_by ? ` by ${s.updated_by}` : ""}.</p>}
    </>
  );
}

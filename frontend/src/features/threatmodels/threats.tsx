import { useId, useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import { ShieldHalf } from "lucide-react";
import { SeverityBadge } from "@/components/data/Severity";
import { defaultRefHref, EvidenceChip } from "@/components/graph";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Badge, Card, Input, Label, Select, Table, Td, Th } from "@/components/ui/primitives";
import { EmptyStateCard, LoadingSkeleton } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { formatDateTime } from "@/lib/utils";
import {
  categoryLabel,
  changeStates,
  methodLabel,
  patchProblem,
  threatCategories,
  threatMethods,
  threatSeverities,
  threatStatuses,
  threatStatusLabel,
  useDeleteThreat,
  useThreat,
  useUpdateThreat,
  type Threat,
  type ThreatModel,
  type ThreatPatch,
  type ThreatSeverity,
  type ThreatStatus,
} from "./api";
import { ChangeBadge, confidenceText, EvidenceLabel } from "./badges";
import { parseElementKeys, parseIds } from "./dialogs";

export interface ThreatFilters {
  category: string;
  severity: string;
  status: string;
  change_state: string;
  method: string;
  q: string;
}
export const emptyThreatFilters: ThreatFilters = { category: "", severity: "", status: "", change_state: "", method: "", q: "" };

const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function filterThreats(ts: Threat[], f: ThreatFilters): Threat[] {
  const q = f.q.trim().toLowerCase();
  return ts
    .filter(
      (t) =>
        (!f.category || t.category === f.category) &&
        (!f.severity || t.severity === f.severity) &&
        (!f.status || t.status === f.status) &&
        (!f.change_state || (t.change_state ?? "") === f.change_state) &&
        (!f.method || t.method === f.method) &&
        (!q || t.title.toLowerCase().includes(q) || (t.rule_id ?? "").toLowerCase().includes(q)),
    )
    .sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9) || a.title.localeCompare(b.title));
}

function FilterSelect({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: [string, string][] }) {
  return (
    <label className="flex items-center gap-1.5 text-[12px]">
      {label}
      <Select aria-label={label} value={value} onChange={(e) => onChange(e.target.value)} className="h-7 w-auto">
        <option value="">All</option>
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </Select>
    </label>
  );
}

export function ThreatsTable({ threats, onOpen, selected }: { threats: Threat[]; onOpen: (id: string) => void; selected?: string }) {
  const [f, setF] = useState<ThreatFilters>(emptyThreatFilters);
  const shown = useMemo(() => filterThreats(threats, f), [threats, f]);
  const set = (k: keyof ThreatFilters) => (v: string) => setF({ ...f, [k]: v });
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-3" role="group" aria-label="Threat filters">
        <Input aria-label="Search threats" placeholder="Search title or rule" value={f.q} onChange={(e) => set("q")(e.target.value)} className="h-7 w-52" />
        <FilterSelect label="Category" value={f.category} onChange={set("category")} options={threatCategories.map((c) => [c, categoryLabel[c]])} />
        <FilterSelect label="Severity" value={f.severity} onChange={set("severity")} options={threatSeverities.map((s) => [s, s])} />
        <FilterSelect label="Status" value={f.status} onChange={set("status")} options={threatStatuses.map((s) => [s, threatStatusLabel[s]])} />
        <FilterSelect label="Change" value={f.change_state} onChange={set("change_state")} options={changeStates.map((s) => [s, s])} />
        <FilterSelect label="Method" value={f.method} onChange={set("method")} options={threatMethods.filter((m) => m !== "ai").map((m) => [m, methodLabel[m]])} />
        <span className="text-[12px] text-muted-foreground" aria-live="polite">
          {shown.length} of {threats.length} threats
        </span>
      </div>
      {shown.length === 0 ? (
        <EmptyStateCard icon={<ShieldHalf />} title={threats.length ? "No threat matches the filters" : "No threats yet"}>
          {threats.length ? "Change or clear the filters." : "Generate the model from the CodeGraph, or add a manual threat."}
        </EmptyStateCard>
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Threat</Th>
              <Th>Category</Th>
              <Th>Severity</Th>
              <Th>Confidence</Th>
              <Th>Evidence</Th>
              <Th>Method</Th>
              <Th>Status</Th>
              <Th>Change</Th>
            </tr>
          </thead>
          <tbody>
            {shown.map((t) => (
              <tr key={t.id} className={t.id === selected ? "bg-primary/5" : undefined} data-testid="threat-row">
                <Td>
                  <button type="button" className="text-left text-primary underline" onClick={() => onOpen(t.id)}>
                    {t.title}
                  </button>
                  {!t.mitigation?.trim() && (t.status === "open" || t.status === "accepted") && <div className="text-[11px] text-warning">No mitigation yet</div>}
                </Td>
                <Td>{categoryLabel[t.category] ?? t.category}</Td>
                <Td>
                  <SeverityBadge value={t.severity} />
                  {t.severity_overridden && <span className="sr-only"> (changed by a person)</span>}
                </Td>
                <Td>{confidenceText(t.confidence)}</Td>
                <Td>
                  <EvidenceLabel threat={t} />
                </Td>
                <Td>
                  {methodLabel[t.method] ?? t.method}
                  {t.rule_id && <div className="font-mono text-[11px] text-muted-foreground">{t.rule_id}</div>}
                </Td>
                <Td>{threatStatusLabel[t.status] ?? t.status}</Td>
                <Td>
                  <ChangeBadge state={t.change_state} />
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-1.5">
      <h3 className="text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">{title}</h3>
      {children}
    </section>
  );
}

/** Link into the CodeGraph page for an evidence node. */
export function codegraphHref(appId: string | undefined, snapshot: string | undefined, nodeId: string) {
  if (!appId) return undefined;
  const p = new URLSearchParams();
  if (snapshot) p.set("snapshot", snapshot);
  p.set("node", nodeId);
  return `/codegraph/${appId}?${p}`;
}

function SmartLink({ href, children }: { href: string; children: React.ReactNode }) {
  if (href.startsWith("/")) {
    const [to, qs] = href.split("?");
    const search = Object.fromEntries(new URLSearchParams(qs ?? ""));
    return (
      <Link to={to as never} search={search as never} className="text-primary underline">
        {children}
      </Link>
    );
  }
  if (/^https?:\/\//.test(href))
    return (
      <a href={href} target="_blank" rel="noreferrer noopener" className="text-primary underline">
        {children}
      </a>
    );
  return <span>{children}</span>;
}

function EditPanel({ threat, editable }: { threat: Threat; editable: boolean }) {
  const ids = useId();
  const [severity, setSeverity] = useState<ThreatSeverity>(threat.severity);
  const [status, setStatus] = useState<ThreatStatus>(threat.status);
  const [reason, setReason] = useState("");
  const [mitigation, setMitigation] = useState(threat.mitigation);
  const [problem, setProblem] = useState<string>();
  const upd = useUpdateThreat(threat.id);
  const save = () => {
    const p: ThreatPatch = {};
    if (severity !== threat.severity) p.severity = severity;
    if (status !== threat.status) p.status = status;
    if (mitigation !== threat.mitigation) p.mitigation = mitigation;
    if (reason.trim()) p.reason = reason.trim();
    const err = patchProblem(p, threat);
    setProblem(err);
    if (err || Object.keys(p).length === 0) return;
    upd.mutate(p, { onSuccess: () => (toast.success("Threat updated."), setReason("")) });
  };
  if (!editable) return null;
  const needsReason = severity !== threat.severity || status !== threat.status;
  return (
    <Section title="Change">
      <div className="grid gap-2 sm:grid-cols-2">
        <div>
          <Label htmlFor={`${ids}-sev`}>Severity</Label>
          <Select id={`${ids}-sev`} value={severity} onChange={(e) => setSeverity(e.target.value as ThreatSeverity)}>
            {threatSeverities.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor={`${ids}-st`}>Status</Label>
          <Select id={`${ids}-st`} value={status} onChange={(e) => setStatus(e.target.value as ThreatStatus)}>
            {threatStatuses.map((s) => (
              <option key={s} value={s}>
                {threatStatusLabel[s]}
              </option>
            ))}
          </Select>
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor={`${ids}-r`} hint={needsReason ? "(required for a severity or status change)" : "(optional)"}>
            Reason
          </Label>
          <Input id={`${ids}-r`} value={reason} maxLength={2000} aria-required={needsReason} onChange={(e) => setReason(e.target.value)} />
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor={`${ids}-m`}>Mitigation</Label>
          <textarea id={`${ids}-m`} className="min-h-20 w-full rounded-md border border-border bg-surface px-2 py-1 text-[13px]" value={mitigation} maxLength={8000} onChange={(e) => setMitigation(e.target.value)} />
        </div>
      </div>
      {problem && (
        <p role="alert" className="text-[12px] text-danger">
          {problem}
        </p>
      )}
      {upd.isError && <ErrorPanel error={upd.error} title="Could not update the threat" />}
      <Button size="sm" onClick={save} disabled={upd.isPending}>
        Save changes
      </Button>
    </Section>
  );
}

function LinkPanel({ threat, editable, defaultRepo }: { threat: Threat; editable: boolean; defaultRepo?: string }) {
  const ids = useId();
  const [keys, setKeys] = useState("");
  const [findings, setFindings] = useState("");
  const upd = useUpdateThreat(threat.id);
  if (!editable) return null;
  const elementKeys = parseElementKeys(keys, defaultRepo ?? threat.evidence?.repository_id);
  const fids = parseIds(findings);
  return (
    <Section title="Link evidence">
      <p className="text-[12px] text-muted-foreground">A link to CodeGraph elements or findings that exist makes a manual or imported threat verified.</p>
      <div className="grid gap-2 sm:grid-cols-2">
        <div>
          <Label htmlFor={`${ids}-k`} hint="(one per line)">
            CodeGraph keys
          </Label>
          <textarea id={`${ids}-k`} className="min-h-14 w-full rounded-md border border-border bg-surface px-2 py-1 font-mono text-[12px]" value={keys} onChange={(e) => setKeys(e.target.value)} />
        </div>
        <div>
          <Label htmlFor={`${ids}-f`}>Finding ids</Label>
          <textarea id={`${ids}-f`} className="min-h-14 w-full rounded-md border border-border bg-surface px-2 py-1 font-mono text-[12px]" value={findings} onChange={(e) => setFindings(e.target.value)} />
        </div>
      </div>
      {upd.isError && <ErrorPanel error={upd.error} title="Could not link the evidence" />}
      <Button
        size="sm"
        variant="secondary"
        disabled={upd.isPending || (!elementKeys.length && !fids.length) || elementKeys.some((k) => !k.repository_id)}
        onClick={() =>
          upd.mutate(
            { link: { element_keys: elementKeys.length ? elementKeys : undefined, finding_ids: fids.length ? fids : undefined } },
            { onSuccess: () => (toast.success("Evidence linked."), setKeys(""), setFindings("")) },
          )
        }
      >
        Link
      </Button>
    </Section>
  );
}

/** Threat detail drawer: evidence with links into CodeGraph and findings, reasons, mappings, edits, history. */
export function ThreatDetail({ threatId, model, onClose }: { threatId?: string; model: ThreatModel; onClose: () => void }) {
  const q = useThreat(threatId);
  const del = useDeleteThreat();
  const t = q.data?.threat;
  const editable = !!model.can_edit && model.status === "draft";
  const ev = t?.evidence;
  const appId = ev?.application_id ?? model.application_id;
  return (
    <Dialog open={!!threatId} onOpenChange={(o) => !o && onClose()} side size="lg" title={t?.title ?? "Threat"} description={t ? `${categoryLabel[t.category] ?? t.category} · ${methodLabel[t.method] ?? t.method}${t.rule_id ? ` · ${t.rule_id} v${t.rule_version}` : ""}` : undefined}>
      {q.isPending ? (
        <LoadingSkeleton rows={6} label="Loading the threat" />
      ) : q.isError ? (
        <ErrorPanel error={q.error} title="Could not load the threat" onVerify={() => q.refetch()} />
      ) : t ? (
        <div className="space-y-4 text-[13px]" data-testid="threat-detail">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge value={t.severity} />
            <EvidenceLabel threat={t} />
            <Badge>{threatStatusLabel[t.status]}</Badge>
            <ChangeBadge state={t.change_state} />
            <span className="text-muted-foreground">Confidence {confidenceText(t.confidence)}</span>
          </div>
          {t.description && <p className="whitespace-pre-wrap">{t.description}</p>}
          <Section title="Why this severity and confidence">
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
              <dt className="text-muted-foreground">Severity</dt>
              <dd>{t.severity_reason || "—"}{t.severity_overridden && " (set by a person)"}</dd>
              <dt className="text-muted-foreground">Confidence</dt>
              <dd>{t.confidence_reason || "—"}</dd>
              {t.status_reason && (
                <>
                  <dt className="text-muted-foreground">Status</dt>
                  <dd>{t.status_reason}</dd>
                </>
              )}
            </dl>
          </Section>
          <Section title="Mitigation">
            <p className="whitespace-pre-wrap">{t.mitigation || <span className="text-warning">No mitigation yet.</span>}</p>
          </Section>
          <Section title="Evidence">
            {ev?.rule && (
              <p>
                Rule <span className="font-mono">{ev.rule.id}</span> v{ev.rule.version}
                {ev.rule.logic && <span className="text-muted-foreground">: {ev.rule.logic}</span>}
              </p>
            )}
            {ev?.exposure && (
              <p>
                Exposure: <strong>{ev.exposure.level}</strong>
                {ev.exposure.reasons?.length ? <span className="text-muted-foreground"> — {ev.exposure.reasons.join("; ")}</span> : null}
              </p>
            )}
            {ev?.nodes?.length ? (
              <ul className="space-y-1" aria-label="Evidence elements">
                {ev.nodes.map((n) => {
                  const href = codegraphHref(appId, ev.snapshot_id, n.id);
                  return (
                    <li key={n.id} className="rounded border border-border px-2 py-1">
                      <span className="mr-1 text-muted-foreground">{n.type}</span>
                      {href ? <SmartLink href={href}>{n.label}</SmartLink> : n.label}
                      {n.file && (
                        <span className="ml-1 font-mono text-[11px] text-muted-foreground">
                          {n.file}
                          {n.line ? `:${n.line}` : ""}
                        </span>
                      )}
                    </li>
                  );
                })}
              </ul>
            ) : null}
            {ev?.edges?.length ? (
              <ul className="space-y-1" aria-label="Evidence edges">
                {ev.edges.map((e) => (
                  <li key={e.id} className="rounded border border-border px-2 py-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <EvidenceChip evidence={e.evidence} />
                      <span className="font-mono text-[11px]">
                        {e.source} —{e.type}→ {e.target}
                      </span>
                    </div>
                    {e.refs?.map((r, i) => {
                      const href = defaultRefHref(r);
                      return (
                        <div key={i} className="text-[12px] text-muted-foreground">
                          {r.kind}: {href ? <SmartLink href={href}>{r.ref}</SmartLink> : <span className="font-mono">{r.ref}</span>}
                          {r.detail && ` — ${r.detail}`}
                        </div>
                      );
                    })}
                  </li>
                ))}
              </ul>
            ) : null}
            {ev?.absent?.length ? (
              <div>
                <p className="text-muted-foreground">Looked for and not found:</p>
                <ul className="list-disc pl-5">
                  {ev.absent.map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {ev?.attack_path?.steps?.length ? (
              <div>
                <p className="text-muted-foreground">Attack path{ev.attack_path.entry ? ` (${ev.attack_path.entry.replaceAll("_", " ")})` : ""}:</p>
                <ol className="flex flex-wrap items-center gap-1 text-[12px]">
                  {ev.attack_path.steps.map((s, i) => (
                    <li key={i} className="flex items-center gap-1">
                      {i > 0 && <span aria-hidden>→</span>}
                      {s.link ? <SmartLink href={s.link}>{s.label}</SmartLink> : s.label}
                    </li>
                  ))}
                </ol>
                {ev.attack_path.reasons?.length ? <p className="text-[12px] text-muted-foreground">{ev.attack_path.reasons.join("; ")}</p> : null}
              </div>
            ) : null}
            {ev?.runtime?.length ? (
              <p>
                Runtime: <span className="text-muted-foreground">{ev.runtime.join("; ")}</span>
              </p>
            ) : null}
            {ev?.links?.length ? (
              <ul className="flex flex-wrap gap-3">
                {ev.links.map((l) => (
                  <li key={l.href}>
                    <SmartLink href={l.href}>{l.label}</SmartLink>
                  </li>
                ))}
              </ul>
            ) : null}
            {t.evidence_type === "unverified" && <p className="text-warning">Not linked to evidence yet: link CodeGraph elements or findings below.</p>}
          </Section>
          {t.findings?.length ? (
            <Section title="Findings">
              <ul className="space-y-1">
                {t.findings.map((f) => (
                  <li key={f.id} className="flex items-center gap-2">
                    <SeverityBadge value={f.severity} />
                    <SmartLink href={f.href ?? `/findings?finding=${f.id}`}>{f.title}</SmartLink>
                    {f.cwe && <span className="text-[11px] text-muted-foreground">{f.cwe}</span>}
                  </li>
                ))}
              </ul>
            </Section>
          ) : null}
          {t.mappings?.length ? (
            <Section title="Framework mappings">
              <ul className="space-y-0.5">
                {t.mappings.map((m) => (
                  <li key={`${m.framework}:${m.id}`}>
                    <span className="mr-1 text-[11px] text-muted-foreground uppercase">{m.framework}</span>
                    {m.url ? <SmartLink href={m.url}>{m.id}</SmartLink> : m.id}
                    {m.name && ` ${m.name}`}
                    <span className="ml-1 text-[11px] text-muted-foreground">({m.source})</span>
                  </li>
                ))}
              </ul>
            </Section>
          ) : null}
          <EditPanel key={`${t.id}:${t.updated_at}`} threat={t} editable={editable} />
          <LinkPanel threat={t} editable={editable} />
          {editable && (t.method === "manual" || t.method === "imported") && (
            <Button
              size="sm"
              variant="danger-outline"
              disabled={del.isPending}
              onClick={() => del.mutate(t.id, { onSuccess: () => (toast.success("Threat deleted."), onClose()) })}
            >
              Delete threat
            </Button>
          )}
          {del.isError && <ErrorPanel error={del.error} title="Could not delete the threat" />}
          <Section title="History">
            {q.data.events.length ? (
              <ol className="space-y-1 text-[12px]">
                {q.data.events.map((e) => (
                  <li key={e.id}>
                    <span className="text-muted-foreground">{formatDateTime(e.at)}</span> {e.actor?.name ?? "PATHOS"} — {e.action.replaceAll("_", " ")}
                    {e.from || e.to ? ` (${e.from ?? ""} → ${e.to ?? ""})` : ""}
                    {e.reason && <span className="text-muted-foreground">: {e.reason}</span>}
                  </li>
                ))}
              </ol>
            ) : (
              <p className="text-[12px] text-muted-foreground">No changes recorded.</p>
            )}
          </Section>
        </div>
      ) : null}
    </Dialog>
  );
}

export function ThreatsCard({ children }: { children: React.ReactNode }) {
  return <Card className="p-4">{children}</Card>;
}

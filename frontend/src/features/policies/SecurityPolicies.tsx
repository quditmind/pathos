import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, ShieldAlert, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import type { Severity } from "@/api/types";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { categoryLabel } from "@/lib/findingCategories";

export interface PolicyConditions {
  min_severity?: string;
  categories?: string[];
  scanners?: string[];
  cwe?: string[];
  min_risk?: number;
  kev?: boolean;
  malicious?: boolean;
  exploit_available?: boolean;
  reachability?: string[];
  min_age_days?: number;
  criticality?: string[];
  internet_exposure?: string[];
  environments?: string[];
  data_classification?: string[];
  compliance_scopes?: string[];
  repository_ids?: string[];
  application_ids?: string[];
}
export interface PolicyActions {
  block?: boolean;
  require_review?: boolean;
  sla_days?: number;
  notify?: boolean;
}
export interface SecurityPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  conditions: PolicyConditions;
  actions: PolicyActions;
  version: number;
  applies_to_pull_requests: boolean;
  open_violations: number;
  created_by: string;
  updated_by: string;
  updated_at: string;
  evaluated_at: string | null;
}
interface Match {
  finding_id: string;
  title: string;
  severity: Severity;
  category: string;
  repository_name: string;
  status: string;
  first_matched_at?: string;
  resolved_at?: string;
}


/** One-line description of a policy's conditions. */
export function describeConditions(c: PolicyConditions): string {
  const p: string[] = [];
  if (c.min_severity) p.push(`severity ${c.min_severity}${c.min_severity === "critical" ? "" : " or above"}`);
  if (c.categories?.length) p.push(c.categories.map((x) => categoryLabel[x] ?? x).join(" or "));
  if (c.kev) p.push("actively exploited (KEV)");
  if (c.malicious) p.push("malicious package");
  if (c.exploit_available) p.push("public exploit");
  if (c.min_risk != null) p.push(`risk ≥ ${c.min_risk}`);
  if (c.reachability?.length) p.push(`reachability ${c.reachability.join(" or ")}`);
  if (c.cwe?.length) p.push(c.cwe.join(", "));
  if (c.scanners?.length) p.push(`from ${c.scanners.join(", ")}`);
  if (c.min_age_days != null) p.push(`open ≥ ${c.min_age_days} days`);
  if (c.criticality?.length) p.push(`${c.criticality.join("/")} criticality`);
  if (c.internet_exposure?.length) p.push(`exposure ${c.internet_exposure.join("/")}`);
  if (c.environments?.length) p.push(`in ${c.environments.join("/")}`);
  if (c.data_classification?.length) p.push(`data ${c.data_classification.join("/")}`);
  if (c.compliance_scopes?.length) p.push(`scope ${c.compliance_scopes.join("/")}`);
  if (c.repository_ids?.length) p.push(`${c.repository_ids.length} selected repositor${c.repository_ids.length === 1 ? "y" : "ies"}`);
  return p.join(" · ") || "—";
}

function ActionBadges({ a }: { a: PolicyActions }) {
  return (
    <span className="flex flex-wrap gap-1">
      {a.block && <Badge tone="danger">Blocks gates</Badge>}
      {a.require_review && <Badge tone="primary">Human Eye review</Badge>}
      {a.sla_days != null && <Badge tone="warning">SLA {a.sla_days} d</Badge>}
      {a.notify && <Badge>Notifies</Badge>}
    </span>
  );
}

const list = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
const toggle = (arr: string[] | undefined, v: string) => (arr?.includes(v) ? arr.filter((x) => x !== v) : [...(arr ?? []), v]);
const tri = (v: boolean | undefined) => (v == null ? "" : v ? "true" : "false");
const fromTri = (v: string) => (v === "" ? undefined : v === "true");

function Checks({ label, options, value, onChange }: { label: string; options: [string, string][]; value?: string[]; onChange: (v: string[]) => void }) {
  return (
    <fieldset>
      <legend className="mb-1 text-[12px] font-medium">{label}</legend>
      <div className="flex flex-wrap gap-x-3 gap-y-1">
        {options.map(([k, l]) => (
          <label key={k} className="flex items-center gap-1 text-[12.5px]">
            <input type="checkbox" className="accent-[var(--primary)]" checked={!!value?.includes(k)} onChange={() => onChange(toggle(value, k))} /> {l}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function PolicyDialog({ open, onClose, policy }: { open: boolean; onClose: () => void; policy: SecurityPolicy | null }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [c, setC] = useState<PolicyConditions>({});
  const [a, setA] = useState<PolicyActions>({ block: true });
  const [cweText, setCweText] = useState("");
  const [scannerText, setScannerText] = useState("");
  useEffect(() => {
    if (!open) return;
    setName(policy?.name ?? "");
    setDescription(policy?.description ?? "");
    setC(policy?.conditions ?? { min_severity: "critical" });
    setA(policy?.actions ?? { block: true, notify: true });
    setCweText((policy?.conditions.cwe ?? []).join(", "));
    setScannerText((policy?.conditions.scanners ?? []).join(", "));
  }, [open, policy]);
  const conditions = useMemo(() => ({ ...c, cwe: list(cweText), scanners: list(scannerText) }), [c, cweText, scannerText]);
  const preview = useQuery({
    queryKey: ["policy-preview", conditions],
    queryFn: () => api<{ matching: number; applies_to_pull_requests: boolean; sample: Match[] }>("/api/v1/security-policies/preview", { method: "POST", body: { conditions } }),
    enabled: open,
    retry: false,
  });
  const save = useMutation({
    mutationFn: () =>
      api<SecurityPolicy>(policy ? `/api/v1/security-policies/${policy.id}` : "/api/v1/security-policies", {
        method: policy ? "PUT" : "POST",
        body: { name, description, conditions, actions: a, enabled: policy?.enabled ?? true },
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["security-policies"] });
      onClose();
    },
  });
  const set = (p: Partial<PolicyConditions>) => setC((x) => ({ ...x, ...p }));
  const num = (v: string) => (v === "" ? undefined : Number(v));
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      size="lg"
      title={policy ? `Edit ${policy.name}` : "New security policy"}
      description="Findings that match every condition get the actions. Policies apply to open findings now and as they change, and to new findings of pull requests."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button disabled={!name.trim() || save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save policy"}</Button>
        </>
      }
    >
      <div className="space-y-4 text-[13px]">
        {save.error && <Alert>{save.error.message}</Alert>}
        <div className="grid gap-3 md:grid-cols-2">
          <div><Label htmlFor="pol-name">Name</Label><Input id="pol-name" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} placeholder="e.g. No exploited vulnerabilities in production" /></div>
          <div><Label htmlFor="pol-desc">Description</Label><Input id="pol-desc" value={description} maxLength={2000} onChange={(e) => setDescription(e.target.value)} /></div>
        </div>
        <fieldset className="space-y-3 rounded-md border border-border p-3">
          <legend className="px-1 text-[12px] font-semibold">Findings</legend>
          <div className="grid gap-3 md:grid-cols-3">
            <div>
              <Label htmlFor="pol-sev">Severity</Label>
              <Select id="pol-sev" value={c.min_severity ?? ""} onChange={(e) => set({ min_severity: e.target.value || undefined })}>
                <option value="">Any</option>
                <option value="critical">Critical</option>
                <option value="high">High or above</option>
                <option value="medium">Medium or above</option>
                <option value="low">Low or above</option>
              </Select>
            </div>
            <div><Label htmlFor="pol-risk" hint="(0–100)">Contextual risk at least</Label><Input id="pol-risk" type="number" min={0} max={100} value={c.min_risk ?? ""} onChange={(e) => set({ min_risk: num(e.target.value) })} /></div>
            <div><Label htmlFor="pol-age">Open for at least (days)</Label><Input id="pol-age" type="number" min={0} max={3650} value={c.min_age_days ?? ""} onChange={(e) => set({ min_age_days: num(e.target.value) })} /></div>
          </div>
          <Checks label="Type" options={Object.entries(categoryLabel)} value={c.categories} onChange={(v) => set({ categories: v })} />
          <div className="grid gap-3 md:grid-cols-3">
            {([["kev", "Actively exploited (KEV)"], ["malicious", "Malicious package"], ["exploit_available", "Public exploit"]] as const).map(([k, l]) => (
              <div key={k}>
                <Label htmlFor={`pol-${k}`}>{l}</Label>
                <Select id={`pol-${k}`} value={tri(c[k])} onChange={(e) => set({ [k]: fromTri(e.target.value) })}>
                  <option value="">Any</option><option value="true">Yes</option><option value="false">No</option>
                </Select>
              </div>
            ))}
          </div>
          <Checks label="Reachability" options={[["reachable", "Reachable"], ["unknown", "Unknown"], ["not_reachable", "Not reachable"]]} value={c.reachability} onChange={(v) => set({ reachability: v })} />
          <div className="grid gap-3 md:grid-cols-2">
            <div><Label htmlFor="pol-cwe" hint="(comma-separated)">CWE</Label><Input id="pol-cwe" value={cweText} onChange={(e) => setCweText(e.target.value)} placeholder="CWE-89, CWE-79" /></div>
            <div><Label htmlFor="pol-scanners" hint="(scanner keys)">Scanners</Label><Input id="pol-scanners" value={scannerText} onChange={(e) => setScannerText(e.target.value)} placeholder="gitleaks, trivy-fs" /></div>
          </div>
        </fieldset>
        <fieldset className="space-y-3 rounded-md border border-border p-3">
          <legend className="px-1 text-[12px] font-semibold">Where (repository context)</legend>
          <Checks label="Business criticality" options={[["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]]} value={c.criticality} onChange={(v) => set({ criticality: v })} />
          <Checks label="Internet exposure" options={[["public", "Public"], ["internal", "Internal"], ["private", "Private"], ["unknown", "Unknown"]]} value={c.internet_exposure} onChange={(v) => set({ internet_exposure: v })} />
          <Checks label="Environment" options={[["production", "Production"], ["staging", "Staging"], ["development", "Development"], ["test", "Test"]]} value={c.environments} onChange={(v) => set({ environments: v })} />
          <Checks label="Compliance scope" options={[["pci_dss", "PCI DSS"], ["iso_27001", "ISO 27001"], ["soc_2", "SOC 2"], ["hipaa", "HIPAA"], ["gdpr", "GDPR"]]} value={c.compliance_scopes} onChange={(v) => set({ compliance_scopes: v })} />
        </fieldset>
        <fieldset className="space-y-2 rounded-md border border-border p-3">
          <legend className="px-1 text-[12px] font-semibold">Actions</legend>
          <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={!!a.block} onChange={(e) => setA({ ...a, block: e.target.checked })} /> Block: fail the scan gate and pull request checks when a new finding matches</label>
          <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={!!a.require_review} onChange={(e) => setA({ ...a, require_review: e.target.checked })} /> Require a Human Eye review</label>
          <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={!!a.notify} onChange={(e) => setA({ ...a, notify: e.target.checked })} /> Notify (event “Security policy violated”)</label>
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={a.sla_days != null} onChange={(e) => setA({ ...a, sla_days: e.target.checked ? 7 : undefined })} /> Remediation deadline at most</label>
            <Input aria-label="SLA days" type="number" min={1} max={365} className="w-20" disabled={a.sla_days == null} value={a.sla_days ?? ""} onChange={(e) => setA({ ...a, sla_days: num(e.target.value) })} /> days after detection
          </div>
        </fieldset>
        <div className="rounded-md bg-surface-muted/50 p-3 text-[12.5px]" aria-live="polite">
          {preview.isError ? <span className="text-danger">{preview.error.message}</span> : preview.isPending ? "Counting matching findings…" : (
            <>
              <strong>{preview.data.matching}</strong> open finding{preview.data.matching === 1 ? "" : "s"} you can see match now.
              {!preview.data.applies_to_pull_requests && <span className="text-muted-foreground"> Conditions on risk, reachability, age or exploits apply to the scan branch only, not to pull requests.</span>}
              {preview.data.sample.length > 0 && (
                <ul className="mt-1 space-y-0.5">{preview.data.sample.slice(0, 5).map((m) => <li key={m.finding_id} className="flex gap-1.5"><SeverityBadge value={m.severity} /> <span className="truncate">{m.title}</span> <span className="text-muted-foreground">· {m.repository_name}</span></li>)}</ul>
              )}
            </>
          )}
        </div>
      </div>
    </Dialog>
  );
}

function Violations({ policy }: { policy: SecurityPolicy }) {
  const [resolved, setResolved] = useState(false);
  const q = useQuery({
    queryKey: ["policy-violations", policy.id, resolved],
    queryFn: () => api<{ items: Match[] }>(`/api/v1/security-policies/${policy.id}/violations${resolved ? "?status=resolved" : ""}`).then((r) => r.items),
  });
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <h3 className="text-[13px] font-semibold">{resolved ? "Resolved" : "Open"} violations of {policy.name}</h3>
        <Button size="sm" variant="ghost" onClick={() => setResolved(!resolved)}>{resolved ? "Show open" : "Show resolved"}</Button>
      </div>
      {q.isError ? <Alert>{q.error.message}</Alert> : q.isPending ? <Skeleton className="h-16" /> : !q.data.length ? <p className="text-[12px] text-muted-foreground">None.</p> : (
        <Table>
          <thead><tr><Th>Severity</Th><Th>Finding</Th><Th>Repository</Th><Th>{resolved ? "Resolved" : "Since"}</Th></tr></thead>
          <tbody>
            {q.data.map((m) => (
              <tr key={m.finding_id}>
                <Td><SeverityBadge value={m.severity} /></Td>
                <Td className="text-[12.5px]"><Link to="/findings" search={{ finding: m.finding_id, status: "all" } as never} className="text-primary hover:underline">{m.title}</Link></Td>
                <Td className="text-[12px]">{m.repository_name}</Td>
                <Td className="whitespace-nowrap text-[11.5px] text-muted-foreground">{formatDateTime((resolved ? m.resolved_at : m.first_matched_at) ?? null)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}

export function SecurityPolicies() {
  const qc = useQueryClient();
  const { can } = useSession();
  const manage = can("settings.manage");
  const search = useSearch({ strict: false }) as { policy?: string };
  const navigate = useNavigate();
  const [dialog, setDialog] = useState<{ policy: SecurityPolicy | null } | null>(null);
  const q = useQuery({ queryKey: ["security-policies"], queryFn: () => api<{ items: SecurityPolicy[] }>("/api/v1/security-policies").then((r) => r.items) });
  const toggleEnabled = useMutation({
    mutationFn: (p: SecurityPolicy) => api(`/api/v1/security-policies/${p.id}`, { method: "PUT", body: { name: p.name, description: p.description, conditions: p.conditions, actions: p.actions, enabled: !p.enabled } }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["security-policies"] }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/api/v1/security-policies/${id}`, { method: "DELETE" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["security-policies"] }),
  });
  const selected = q.data?.find((p) => p.id === search.policy);
  const select = (id: string) => void navigate({ to: "/admin/policies", search: { policy: id } as never });
  return (
    <Card className="mt-4 p-4">
      <div className="mb-3 flex flex-wrap items-start gap-2">
        <div>
          <h2 className="text-[13px] font-semibold">Security policies</h2>
          <p className="text-[12px] text-muted-foreground">Rules on findings and their context: block scan gates and pull requests, require a Human Eye review, tighten deadlines or notify. Evaluated after every scan and every 10 minutes.</p>
        </div>
        {manage && <Button className="ml-auto" onClick={() => setDialog({ policy: null })}><Plus /> New policy</Button>}
      </div>
      {(toggleEnabled.error ?? remove.error) && <div className="mb-2"><Alert>{(toggleEnabled.error ?? remove.error)!.message}</Alert></div>}
      {q.isError ? <Alert>{q.error.message}</Alert> : q.isPending ? <Skeleton className="h-24" /> : !q.data.length ? (
        <EmptyState icon={<ShieldAlert />} title="No security policies">For example: block any new actively exploited vulnerability in internet-facing production repositories.</EmptyState>
      ) : (
        <Table>
          <thead><tr><Th>Policy</Th><Th>When</Th><Th>Actions</Th><Th className="text-right">Open violations</Th><Th className="text-right">Manage</Th></tr></thead>
          <tbody>
            {q.data.map((p) => (
              <tr key={p.id} className={p.enabled ? (selected?.id === p.id ? "bg-primary/5" : undefined) : "opacity-60"}>
                <Td>
                  <div className="flex items-center gap-1.5 font-medium">{p.name}{!p.enabled && <Badge>disabled</Badge>}</div>
                  {p.description && <div className="text-[11.5px] text-muted-foreground">{p.description}</div>}
                  <div className="text-[11px] text-muted-foreground">v{p.version} · {p.updated_by || p.created_by}{!p.applies_to_pull_requests && " · scan branch only"}</div>
                </Td>
                <Td className="max-w-80 text-[12px]">{describeConditions(p.conditions)}</Td>
                <Td><ActionBadges a={p.actions} /></Td>
                <Td className="text-right"><button type="button" className="tabular text-primary hover:underline" onClick={() => select(p.id)}>{p.open_violations}</button></Td>
                <Td className="text-right whitespace-nowrap">
                  {manage && (
                    <>
                      <Button size="sm" variant="ghost" onClick={() => toggleEnabled.mutate(p)} disabled={toggleEnabled.isPending}>{p.enabled ? "Disable" : "Enable"}</Button>
                      <Button size="icon" variant="ghost" aria-label={`Edit ${p.name}`} onClick={() => setDialog({ policy: p })}><Pencil /></Button>
                      <Button size="icon" variant="ghost" aria-label={`Delete ${p.name}`} onClick={() => { if (window.confirm(`Delete the policy “${p.name}” and its violation history?`)) remove.mutate(p.id); }}><Trash2 /></Button>
                    </>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {selected && <div className="mt-4"><Violations policy={selected} /></div>}
      <PolicyDialog open={!!dialog} onClose={() => setDialog(null)} policy={dialog?.policy ?? null} />
    </Card>
  );
}

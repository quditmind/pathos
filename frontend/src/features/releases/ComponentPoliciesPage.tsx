import { useState, type FormEvent } from "react";
import { Pencil, Plus, RefreshCw, Scale, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { usePolicies, useReleasesMutation, useViolations, type ComponentPolicy } from "./api";

const kindLabel: Record<ComponentPolicy["condition_kind"], string> = {
  component_age: "Package age",
  outdated: "Outdated version",
  license: "Licence",
  vulnerability_severity: "Vulnerability severity",
};

const stateTone = { fail: "danger", warn: "warning", info: "neutral" } as const;

function describe(p: ComponentPolicy): string {
  const x = p.params;
  switch (p.condition_kind) {
    case "component_age": return `latest release older than ${x.max_days} days`;
    case "outdated": return x.versions_behind === "major" ? "a newer major version exists" : "a newer version exists";
    case "license": return [x.licenses?.length ? `licence in ${x.licenses.join(", ")}` : "", x.include_unknown ? "no licence declared" : ""].filter(Boolean).join(" or ");
    case "vulnerability_severity": return `open vulnerability of ${x.min_severity} severity or higher`;
  }
}

export function ComponentPoliciesPage() {
  const pols = usePolicies();
  const [editing, setEditing] = useState<ComponentPolicy | "new" | null>(null);
  const [deleting, setDeleting] = useState<ComponentPolicy | null>(null);
  const [policy, setPolicy] = useState("");
  const [state, setState] = useState<"open" | "resolved">("open");
  const viol = useViolations(policy, state);
  const evaluate = useReleasesMutation(() => api<{ violations: number; not_evaluated: number }>("/api/v1/component-policies/evaluate", { method: "POST" }));
  const del = useReleasesMutation((id: string) => api(`/api/v1/component-policies/${id}`, { method: "DELETE" }));
  const manage = pols.data?.can_manage ?? false;
  return (
    <>
      <PageHeader title="Component policies"
        description="Operational policies over the SBOM inventory: package age, outdated versions, licences and known vulnerability severity. Age and outdated conditions use package health from the deps.dev feed (opt-in); without it those components are not evaluated."
        actions={manage && (
          <div className="flex gap-2">
            <Button variant="secondary" disabled={evaluate.isPending} onClick={() => evaluate.mutate(undefined)}><RefreshCw /> {evaluate.isPending ? "Evaluating…" : "Evaluate now"}</Button>
            <Button onClick={() => setEditing("new")}><Plus /> New policy</Button>
          </div>
        )} />
      {evaluate.isError && <Alert>{evaluate.error.message}</Alert>}
      {evaluate.data && <div className="mb-3"><Alert tone="success">Evaluated: {evaluate.data.violations} violation(s); {evaluate.data.not_evaluated} check(s) skipped for missing package health.</Alert></div>}
      <Card className="mb-4">
        {pols.isError ? <Alert>{pols.error.message}</Alert> : pols.isPending ? <Skeleton className="h-24" /> : !pols.data.items.length ? (
          <EmptyState icon={<Scale />} title="No component policies">Define conditions such as "no GPL-3.0 licences" or "no component with a critical vulnerability".</EmptyState>
        ) : (
          <Table>
            <thead><tr><Th>Policy</Th><Th>Condition</Th><Th>State</Th><Th>Open violations</Th><Th>Evaluated</Th>{manage && <Th />}</tr></thead>
            <tbody>
              {pols.data.items.map((p) => (
                <tr key={p.id}>
                  <Td><div className="font-medium">{p.name}{!p.enabled && <Badge className="ml-2">disabled</Badge>}</div>{p.description && <div className="text-[12px] text-muted-foreground">{p.description}</div>}</Td>
                  <Td className="text-[12.5px]"><span className="font-medium">{kindLabel[p.condition_kind]}:</span> {describe(p)}</Td>
                  <Td><Badge tone={stateTone[p.violation_state]}>{p.violation_state}</Badge></Td>
                  <Td className="tabular"><button type="button" className="text-primary hover:underline" onClick={() => { setPolicy(p.id); setState("open"); }}>{p.open_violations}</button></Td>
                  <Td className="text-[12px] text-muted-foreground">{p.evaluated_at ? formatDateTime(p.evaluated_at) : "never"}</Td>
                  {manage && (
                    <Td className="whitespace-nowrap text-right">
                      <Button size="sm" variant="ghost" aria-label={`Edit ${p.name}`} onClick={() => setEditing(p)}><Pencil /></Button>
                      <Button size="sm" variant="ghost" aria-label={`Delete ${p.name}`} onClick={() => setDeleting(p)}><Trash2 /></Button>
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <Card>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-[14px] font-semibold">Violations</h2>
          <div className="flex gap-2">
            <Select aria-label="Policy filter" value={policy} onChange={(e) => setPolicy(e.target.value)}>
              <option value="">All policies</option>
              {(pols.data?.items ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </Select>
            <Select aria-label="Violation state" value={state} onChange={(e) => setState(e.target.value as "open" | "resolved")}>
              <option value="open">Open</option><option value="resolved">Resolved</option>
            </Select>
          </div>
        </div>
        {viol.isError ? <Alert>{viol.error.message}</Alert> : viol.isPending ? <Skeleton className="h-16" /> : !viol.data.length ? (
          <p className="text-[13px] text-muted-foreground">No {state} violations.</p>
        ) : (
          <Table>
            <thead><tr><Th>Policy</Th><Th>Repository</Th><Th>Component</Th><Th>Detail</Th><Th>{state === "open" ? "Since" : "Resolved"}</Th></tr></thead>
            <tbody>
              {viol.data.map((v) => (
                <tr key={v.id}>
                  <Td><Badge tone={stateTone[v.violation_state as keyof typeof stateTone] ?? "neutral"}>{v.violation_state}</Badge> <span className="text-[12.5px]">{v.policy_name}</span></Td>
                  <Td className="text-[12.5px]">{v.repository}</Td>
                  <Td><div className="font-mono text-[12px]">{v.component}{v.component_version && `@${v.component_version}`}</div>{v.purl && <div className="font-mono text-[11px] text-muted-foreground">{v.purl}</div>}</Td>
                  <Td className="text-[12.5px]">{v.detail}</Td>
                  <Td className="text-[12px] text-muted-foreground">{formatDateTime(v.resolved_at ?? v.first_seen_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <PolicyDialog policy={editing} onClose={() => setEditing(null)} />
      <ConfirmDialog open={!!deleting} onOpenChange={(o) => !o && setDeleting(null)} title={`Delete policy "${deleting?.name ?? ""}"?`} confirmLabel="Delete"
        pending={del.isPending} error={del.error?.message ?? null}
        onConfirm={() => deleting && del.mutate(deleting.id, { onSuccess: () => setDeleting(null) })}>
        Its violations are removed with it.
      </ConfirmDialog>
    </>
  );
}

function PolicyDialog({ policy, onClose }: { policy: ComponentPolicy | "new" | null; onClose: () => void }) {
  const existing = policy && policy !== "new" ? policy : null;
  const [f, setF] = useState({ name: "", description: "", enabled: true, kind: "license" as ComponentPolicy["condition_kind"], state: "warn",
    maxDays: "730", behind: "any", licenses: "", unknown: false, minSeverity: "high" });
  const [loadedFor, setLoadedFor] = useState<ComponentPolicy | "new" | null>(null);
  if (policy !== loadedFor) {
    setLoadedFor(policy);
    const x = existing?.params ?? {};
    setF({
      name: existing?.name ?? "", description: existing?.description ?? "", enabled: existing?.enabled ?? true,
      kind: existing?.condition_kind ?? "license", state: existing?.violation_state ?? "warn",
      maxDays: String(x.max_days ?? 730), behind: x.versions_behind ?? "any", licenses: (x.licenses ?? []).join(", "),
      unknown: x.include_unknown ?? false, minSeverity: x.min_severity ?? "high",
    });
  }
  const save = useReleasesMutation((body: unknown) => existing
    ? api<ComponentPolicy>(`/api/v1/component-policies/${existing.id}`, { method: "PUT", body })
    : api<ComponentPolicy>("/api/v1/component-policies", { method: "POST", body }));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const params =
      f.kind === "component_age" ? { max_days: Number(f.maxDays) }
      : f.kind === "outdated" ? { versions_behind: f.behind }
      : f.kind === "license" ? { licenses: f.licenses.split(",").map((s) => s.trim()).filter(Boolean), include_unknown: f.unknown }
      : { min_severity: f.minSeverity };
    save.mutate({ name: f.name, description: f.description, enabled: f.enabled, condition_kind: f.kind, violation_state: f.state, params },
      { onSuccess: () => { save.reset(); onClose(); } });
  };
  return (
    <Dialog open={!!policy} onOpenChange={(o) => { if (!o) { save.reset(); onClose(); } }} title={existing ? "Edit component policy" : "New component policy"}>
      <form onSubmit={submit} className="space-y-3">
        <div><Label htmlFor="cp-name">Name</Label><Input id="cp-name" required maxLength={200} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
        <div><Label htmlFor="cp-desc">Description</Label><Input id="cp-desc" maxLength={2000} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <Label htmlFor="cp-kind">Condition</Label>
            <Select id="cp-kind" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value as ComponentPolicy["condition_kind"] })}>
              {Object.entries(kindLabel).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </Select>
          </div>
          <div>
            <Label htmlFor="cp-state">Violation state</Label>
            <Select id="cp-state" value={f.state} onChange={(e) => setF({ ...f, state: e.target.value })}>
              <option value="fail">Fail</option><option value="warn">Warn</option><option value="info">Info</option>
            </Select>
          </div>
        </div>
        {f.kind === "component_age" && <div><Label htmlFor="cp-days" hint="Flags packages whose latest release is older than this (possibly unmaintained)">Maximum days since the latest release</Label><Input id="cp-days" type="number" min={1} max={36500} value={f.maxDays} onChange={(e) => setF({ ...f, maxDays: e.target.value })} /></div>}
        {f.kind === "outdated" && (
          <div><Label htmlFor="cp-behind">Flag when</Label>
            <Select id="cp-behind" value={f.behind} onChange={(e) => setF({ ...f, behind: e.target.value })}><option value="any">Any newer version exists</option><option value="major">A newer major version exists</option></Select></div>
        )}
        {f.kind === "license" && (
          <>
            <div><Label htmlFor="cp-lic" hint="Comma-separated SPDX identifiers">Licences</Label><Input id="cp-lic" placeholder="GPL-3.0-only, AGPL-3.0-only" value={f.licenses} onChange={(e) => setF({ ...f, licenses: e.target.value })} /></div>
            <label className="flex items-center gap-2 text-[13px]"><input type="checkbox" checked={f.unknown} onChange={(e) => setF({ ...f, unknown: e.target.checked })} /> Also flag components without a declared licence</label>
          </>
        )}
        {f.kind === "vulnerability_severity" && (
          <div><Label htmlFor="cp-sev">Minimum severity</Label>
            <Select id="cp-sev" value={f.minSeverity} onChange={(e) => setF({ ...f, minSeverity: e.target.value })}>
              {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
            </Select></div>
        )}
        <label className="flex items-center gap-2 text-[13px]"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Enabled</label>
        {save.isError && <Alert>{save.error.message}</Alert>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={!f.name.trim() || save.isPending}>{save.isPending ? "Saving…" : "Save"}</Button>
        </div>
      </form>
    </Dialog>
  );
}

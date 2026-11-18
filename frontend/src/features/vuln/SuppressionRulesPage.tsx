import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FilterX, Plus } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { RepoFilter } from "@/features/review/shared";
import { useApplications } from "@/features/repos/api";
import { formatDateTime } from "@/lib/utils";
import { FINDING_CATEGORIES, categoryName } from "@/lib/findingCategories";

export interface SuppressionRule {
  id: string;
  name: string;
  scope_type: "organization" | "application" | "repository";
  scope_id: string | null;
  scope_name: string | null;
  match_rule_id: string;
  match_path: string;
  match_package: string;
  match_cve: string;
  match_scanner: string;
  match_category: string;
  decision: "accepted_risk" | "false_positive";
  justification: string;
  expires_at: string;
  status: "pending" | "active" | "rejected" | "revoked" | "expired" | "withdrawn";
  requested_by: string | null;
  requested_by_id: string;
  requested_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string;
  findings: number;
}

const statusTone: Record<SuppressionRule["status"], "warning" | "success" | "neutral" | "danger"> = {
  pending: "warning", active: "success", rejected: "danger", revoked: "neutral", expired: "neutral", withdrawn: "neutral",
};
const decisionLabel = { accepted_risk: "Accepted risk", false_positive: "False positive" };

function criteria(r: SuppressionRule) {
  return [
    r.match_rule_id && `rule ${r.match_rule_id}`,
    r.match_path && `path ${r.match_path}`,
    r.match_package && `package ${r.match_package}`,
    r.match_cve && r.match_cve,
    r.match_scanner && `scanner ${r.match_scanner}`,
    r.match_category && `type ${r.match_category}`,
  ].filter(Boolean).join(" · ");
}

const in3Months = () => new Date(Date.now() + 90 * 864e5).toISOString().slice(0, 10);

function ProposeDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const apps = useApplications();
  const [f, setF] = useState({ name: "", scope_type: "repository", scope_id: "", match_rule_id: "", match_path: "", match_package: "", match_cve: "",
    match_scanner: "", match_category: "", decision: "false_positive", justification: "", expires: in3Months() });
  const set = (p: Partial<typeof f>) => setF((x) => ({ ...x, ...p }));
  const body = () => ({ ...f, scope_id: f.scope_type === "organization" ? null : f.scope_id || null, expires_at: new Date(f.expires + "T23:59:59Z").toISOString() });
  const preview = useMutation({
    mutationFn: () => api<{ matching_open_findings: number; examples: { id: string; title: string; severity: string; file_path: string; repository_name: string }[] }>(
      "/api/v1/suppression-rules/preview", { method: "POST", body: body() }),
  });
  const save = useMutation({
    mutationFn: () => api<SuppressionRule>("/api/v1/suppression-rules", { method: "POST", body: body() }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["suppression-rules"] });
      onClose();
    },
  });
  const ok = f.name.trim() && (f.scope_type === "organization" || f.scope_id) && (f.match_rule_id || f.match_path || f.match_package || f.match_cve) && f.justification.trim().length >= 20;
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()} size="lg" title="Propose a suppression rule"
      description="The rule takes effect only when someone else approves it. Matching findings keep their evidence and reopen when the rule expires or is revoked."
      footer={
        <>
          <Button variant="secondary" onClick={() => preview.mutate()} disabled={preview.isPending}>Preview matches</Button>
          <Button onClick={() => save.mutate()} disabled={!ok || save.isPending}>{save.isPending ? "Proposing…" : "Propose rule"}</Button>
        </>
      }
    >
      <div className="space-y-3">
        {(save.error || preview.error) && <Alert>{(save.error ?? preview.error)!.message}</Alert>}
        <div className="grid gap-3 md:grid-cols-2">
          <div><Label htmlFor="sr-name">Name</Label><Input id="sr-name" value={f.name} maxLength={200} onChange={(e) => set({ name: e.target.value })} /></div>
          <div>
            <Label htmlFor="sr-decision">Decision</Label>
            <Select id="sr-decision" className="w-full" value={f.decision} onChange={(e) => set({ decision: e.target.value })}>
              <option value="false_positive">False positive</option>
              <option value="accepted_risk">Accepted risk</option>
            </Select>
          </div>
          <div>
            <Label htmlFor="sr-scope">Scope</Label>
            <Select id="sr-scope" className="w-full" value={f.scope_type} onChange={(e) => set({ scope_type: e.target.value, scope_id: "" })}>
              <option value="repository">One repository</option>
              <option value="application">One application</option>
              <option value="organization">Whole organization</option>
            </Select>
          </div>
          <div>
            {f.scope_type === "repository" && (<><span className="mb-1 block text-[12px] font-medium">Repository</span><RepoFilter value={f.scope_id || undefined} onChange={(v) => set({ scope_id: v ?? "" })} /></>)}
            {f.scope_type === "application" && (
              <>
                <Label htmlFor="sr-app">Application</Label>
                <Select id="sr-app" className="w-full" value={f.scope_id} onChange={(e) => set({ scope_id: e.target.value })}>
                  <option value="">Choose…</option>
                  {(apps.data ?? []).map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
                </Select>
              </>
            )}
          </div>
        </div>
        <fieldset className="rounded-md border border-border p-3">
          <legend className="px-1 text-[12px] font-medium">Matches findings with (at least one of the first four)</legend>
          <div className="grid gap-2 md:grid-cols-3">
            <div><Label htmlFor="sr-rule" hint="(* and ? allowed)">Rule ID</Label><Input id="sr-rule" className="font-mono text-[12px]" value={f.match_rule_id} onChange={(e) => set({ match_rule_id: e.target.value })} /></div>
            <div><Label htmlFor="sr-path" hint="(e.g. test/*)">File path</Label><Input id="sr-path" className="font-mono text-[12px]" value={f.match_path} onChange={(e) => set({ match_path: e.target.value })} /></div>
            <div><Label htmlFor="sr-pkg">Package</Label><Input id="sr-pkg" className="font-mono text-[12px]" value={f.match_package} onChange={(e) => set({ match_package: e.target.value })} /></div>
            <div><Label htmlFor="sr-cve">CVE</Label><Input id="sr-cve" className="font-mono text-[12px]" value={f.match_cve} onChange={(e) => set({ match_cve: e.target.value })} /></div>
            <div><Label htmlFor="sr-scanner" hint="(optional)">Scanner</Label><Input id="sr-scanner" className="font-mono text-[12px]" value={f.match_scanner} onChange={(e) => set({ match_scanner: e.target.value })} /></div>
            <div>
              <Label htmlFor="sr-cat" hint="(optional)">Type</Label>
              <Select id="sr-cat" className="w-full" value={f.match_category} onChange={(e) => set({ match_category: e.target.value })}>
                <option value="">Any</option>
                {FINDING_CATEGORIES.map((c) => <option key={c} value={c}>{categoryName(c)}</option>)}
              </Select>
            </div>
          </div>
        </fieldset>
        <div>
          <Label htmlFor="sr-why" hint="(at least 20 characters)">Justification</Label>
          <textarea id="sr-why" value={f.justification} onChange={(e) => set({ justification: e.target.value })} maxLength={4000}
            className="h-20 w-full rounded-md border border-border bg-surface px-3 py-2 text-[13px] focus-visible:outline-2 focus-visible:outline-ring" />
        </div>
        <div className="w-48"><Label htmlFor="sr-exp" hint="(at most one year)">Expires</Label><Input id="sr-exp" type="date" value={f.expires} onChange={(e) => set({ expires: e.target.value })} /></div>
        {preview.data && (
          <Alert tone="warning">
            {preview.data.matching_open_findings} open finding{preview.data.matching_open_findings === 1 ? "" : "s"} match now.
            {preview.data.examples.length > 0 && (
              <ul className="mt-1 list-disc pl-4 text-[12px]">
                {preview.data.examples.slice(0, 5).map((x) => <li key={x.id}>{x.title} — {x.repository_name} {x.file_path}</li>)}
              </ul>
            )}
          </Alert>
        )}
      </div>
    </Dialog>
  );
}

export function SuppressionRulesPage() {
  const { can, me } = useSession();
  const qc = useQueryClient();
  const [status, setStatus] = useState("");
  const [open, setOpen] = useState(false);
  const list = useQuery({
    queryKey: ["suppression-rules", status],
    queryFn: () => api<{ items: SuppressionRule[] }>(`/api/v1/suppression-rules${status ? `?status=${status}` : ""}`).then((r) => r.items),
  });
  const act = useMutation({
    mutationFn: ({ id, action }: { id: string; action: string }) => api(`/api/v1/suppression-rules/${id}/${action}`, { method: "POST", body: {} }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["suppression-rules"] });
      void qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });
  const canPropose = can("findings.triage");
  const canDecide = can("findings.accept_risk");
  return (
    <>
      <PageHeader
        title="Suppression rules"
        description="Decide many findings at once (generated code, test fixtures, an advisory that does not apply) with a justification and an expiry. A rule takes effect only when a second person approves it; findings keep their evidence and reopen when it ends."
        actions={canPropose && <Button onClick={() => setOpen(true)}><Plus /> Propose rule</Button>}
      />
      <div className="mb-3">
        <Select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All rules</option>
          {["pending", "active", "expired", "revoked", "rejected", "withdrawn"].map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
      </div>
      {act.error && <div className="mb-3"><Alert>{act.error.message}</Alert></div>}
      <Card>
        {list.isError ? (
          <div className="p-4"><Alert>{list.error.message}</Alert></div>
        ) : list.isPending ? (
          <Skeleton className="m-4 h-32" />
        ) : !list.data.length ? (
          <EmptyState icon={<FilterX />} title="No suppression rules" />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Rule</Th>
                <Th>Matches</Th>
                <Th>Decision</Th>
                <Th>Status</Th>
                <Th>Findings</Th>
                <Th>Expires</Th>
                <Th className="text-right">Actions</Th>
              </tr>
            </thead>
            <tbody>
              {list.data.map((r) => {
                const mine = r.requested_by_id === me.user.id;
                return (
                  <tr key={r.id}>
                    <Td>
                      <div className="font-medium">{r.name}</div>
                      <div className="max-w-md text-[11.5px] text-muted-foreground" title={r.justification}>{r.justification.slice(0, 140)}</div>
                      <div className="text-[11px] text-muted-foreground">
                        Proposed by {r.requested_by ?? "—"} {formatDateTime(r.requested_at)}
                        {r.decided_by && ` · ${r.status} by ${r.decided_by}`}
                      </div>
                    </Td>
                    <Td className="text-[12px]">
                      <div className="font-mono text-[11.5px]">{criteria(r)}</div>
                      <div className="text-muted-foreground">{r.scope_type === "organization" ? "Whole organization" : `${r.scope_type}: ${r.scope_name ?? "—"}`}</div>
                    </Td>
                    <Td className="text-[12px]">{decisionLabel[r.decision]}</Td>
                    <Td><Badge tone={statusTone[r.status]}>{r.status}</Badge></Td>
                    <Td className="tabular text-[12px]">{r.findings}</Td>
                    <Td className="tabular whitespace-nowrap text-[12px]">{r.expires_at.slice(0, 10)}</Td>
                    <Td className="whitespace-nowrap text-right">
                      {r.status === "pending" && canDecide && !mine && (
                        <>
                          <Button size="sm" onClick={() => act.mutate({ id: r.id, action: "approve" })} disabled={act.isPending}>Approve</Button>{" "}
                          <Button size="sm" variant="secondary" onClick={() => act.mutate({ id: r.id, action: "reject" })} disabled={act.isPending}>Reject</Button>
                        </>
                      )}
                      {r.status === "pending" && mine && (
                        <>
                          <span className="mr-2 text-[11.5px] text-muted-foreground">awaiting another approver</span>
                          <Button size="sm" variant="secondary" onClick={() => act.mutate({ id: r.id, action: "withdraw" })} disabled={act.isPending}>Withdraw</Button>
                        </>
                      )}
                      {r.status === "active" && canDecide && (
                        <Button size="sm" variant="secondary" onClick={() => act.mutate({ id: r.id, action: "revoke" })} disabled={act.isPending}>Revoke</Button>
                      )}
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Card>
      <ProposeDialog open={open} onClose={() => setOpen(false)} />
    </>
  );
}

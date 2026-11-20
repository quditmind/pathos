import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Pencil, PlugZap, Plus, Ticket, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { ErrorPanel } from "@/components/ui/error-panel";

export interface TicketConnection {
  id: string;
  kind: "jira" | "servicenow";
  name: string;
  base_url?: string;
  auth_type?: "basic" | "bearer";
  username?: string;
  config?: { project_key?: string; issue_type?: string; labels?: string[]; table?: string; assignment_group?: string; caller_id?: string };
  allow_private?: boolean;
  /** Private CA bundle (PEM) added to the system trust store for this connection. */
  ca_bundle_pem?: string;
  enabled: boolean;
  tickets?: number;
}
export interface FindingTicket {
  id: string;
  connection_name: string;
  kind: "jira" | "servicenow";
  key: string;
  url: string;
  status: string;
  done: boolean;
  sync_error: string;
  synced_at: string | null;
  created_by: string;
  created_at: string;
}

const kindLabel = { jira: "Jira", servicenow: "ServiceNow" };

export const useTicketConnections = () =>
  useQuery({ queryKey: ["ticket-connections"], queryFn: () => api<{ items: TicketConnection[] }>("/api/v1/ticket-connections").then((r) => r.items), retry: false });

function ConnectionDialog({ open, onClose, conn }: { open: boolean; onClose: () => void; conn: TicketConnection | null }) {
  const qc = useQueryClient();
  const [f, setF] = useState({ kind: "jira" as TicketConnection["kind"], name: "", base_url: "", auth_type: "basic" as "basic" | "bearer", username: "", secret: "",
    project_key: "", issue_type: "Bug", labels: "pathos", table: "incident", assignment_group: "", caller_id: "", allow_private: false, ca_bundle_pem: "" });
  useEffect(() => {
    if (!open) return;
    setF({ kind: conn?.kind ?? "jira", name: conn?.name ?? "", base_url: conn?.base_url ?? "", auth_type: conn?.auth_type ?? "basic", username: conn?.username ?? "", secret: "",
      project_key: conn?.config?.project_key ?? "", issue_type: conn?.config?.issue_type ?? "Bug", labels: (conn?.config?.labels ?? ["pathos"]).join(", "),
      table: conn?.config?.table ?? "incident", assignment_group: conn?.config?.assignment_group ?? "", caller_id: conn?.config?.caller_id ?? "", allow_private: conn?.allow_private ?? false,
      ca_bundle_pem: conn?.ca_bundle_pem ?? "" });
  }, [open, conn]);
  const set = (p: Partial<typeof f>) => setF((x) => ({ ...x, ...p }));
  const save = useMutation({
    mutationFn: () => api(conn ? `/api/v1/ticket-connections/${conn.id}` : "/api/v1/ticket-connections", {
      method: conn ? "PUT" : "POST",
      body: {
        kind: f.kind, name: f.name, base_url: f.base_url, auth_type: f.auth_type, username: f.username, secret: f.secret || undefined, allow_private: f.allow_private, enabled: conn?.enabled ?? true,
        ca_bundle_pem: f.ca_bundle_pem,
        config: f.kind === "jira"
          ? { project_key: f.project_key, issue_type: f.issue_type, labels: f.labels.split(",").map((x) => x.trim()).filter(Boolean) }
          : { table: f.table, assignment_group: f.assignment_group || undefined, caller_id: f.caller_id || undefined },
      },
    }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["ticket-connections"] });
      onClose();
    },
  });
  const jira = f.kind === "jira";
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()} size="lg" title={conn ? `Edit ${conn.name}` : "New ticketing connection"}
      description="People who triage findings can open a ticket for a finding; PATHOS keeps the link and follows the ticket's status. Only the finding's facts and a link are sent, never code."
      footer={<><Button variant="secondary" onClick={onClose}>Cancel</Button><Button disabled={!f.name.trim() || !f.base_url.trim() || (!conn && !f.secret) || (jira && !f.project_key.trim()) || save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save"}</Button></>}>
      <div className="space-y-3 text-[13px]">
        {save.error && <ErrorPanel error={save.error} />}
        <div className="grid gap-3 md:grid-cols-3">
          <div><Label htmlFor="tc-kind">System</Label>
            <Select id="tc-kind" value={f.kind} disabled={!!conn} onChange={(e) => set({ kind: e.target.value as TicketConnection["kind"], auth_type: e.target.value === "jira" ? "basic" : "basic" })}>
              <option value="jira">Jira</option><option value="servicenow">ServiceNow</option>
            </Select></div>
          <div><Label htmlFor="tc-name">Name</Label><Input id="tc-name" value={f.name} maxLength={120} onChange={(e) => set({ name: e.target.value })} placeholder={jira ? "e.g. Jira – Security" : "e.g. ServiceNow incidents"} /></div>
          <div><Label htmlFor="tc-url">Base URL</Label><Input id="tc-url" type="url" value={f.base_url} onChange={(e) => set({ base_url: e.target.value })} placeholder={jira ? "https://acme.atlassian.net" : "https://acme.service-now.com"} /></div>
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          <div><Label htmlFor="tc-auth">Authentication</Label>
            <Select id="tc-auth" value={f.auth_type} onChange={(e) => set({ auth_type: e.target.value as "basic" | "bearer" })}>
              <option value="basic">{jira ? "E-mail + API token (Jira Cloud)" : "User + password"}</option>
              <option value="bearer">{jira ? "Personal access token (Data Center)" : "OAuth bearer token"}</option>
            </Select></div>
          {f.auth_type === "basic" && <div><Label htmlFor="tc-user">{jira ? "E-mail" : "User"}</Label><Input id="tc-user" value={f.username} onChange={(e) => set({ username: e.target.value })} /></div>}
          <div><Label htmlFor="tc-secret" hint={conn ? "(leave empty to keep)" : "(stored encrypted)"}>{f.auth_type === "basic" ? (jira ? "API token" : "Password") : "Token"}</Label>
            <Input id="tc-secret" type="password" autoComplete="new-password" value={f.secret} onChange={(e) => set({ secret: e.target.value })} /></div>
        </div>
        {jira ? (
          <div className="grid gap-3 md:grid-cols-3">
            <div><Label htmlFor="tc-project">Project key</Label><Input id="tc-project" value={f.project_key} onChange={(e) => set({ project_key: e.target.value })} placeholder="SEC" /></div>
            <div><Label htmlFor="tc-type">Issue type</Label><Input id="tc-type" value={f.issue_type} onChange={(e) => set({ issue_type: e.target.value })} /></div>
            <div><Label htmlFor="tc-labels" hint="(comma-separated)">Labels</Label><Input id="tc-labels" value={f.labels} onChange={(e) => set({ labels: e.target.value })} /></div>
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-3">
            <div><Label htmlFor="tc-table">Table</Label><Input id="tc-table" value={f.table} onChange={(e) => set({ table: e.target.value })} /></div>
            <div><Label htmlFor="tc-group" hint="(sys_id or name)">Assignment group</Label><Input id="tc-group" value={f.assignment_group} onChange={(e) => set({ assignment_group: e.target.value })} /></div>
            <div><Label htmlFor="tc-caller" hint="(sys_id)">Caller</Label><Input id="tc-caller" value={f.caller_id} onChange={(e) => set({ caller_id: e.target.value })} /></div>
          </div>
        )}
        <div><Label htmlFor="tc-ca" hint="(optional; PEM certificates of a private CA, added to the system trust store for this connection only)">Private CA bundle</Label>
          <textarea id="tc-ca" className="min-h-20 w-full rounded-md border border-border bg-surface px-2.5 py-1.5 font-mono text-[12px] focus:outline-none focus:ring-1 focus:ring-[color:var(--ring)]"
            value={f.ca_bundle_pem} onChange={(e) => set({ ca_bundle_pem: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" /></div>
        <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={f.allow_private} onChange={(e) => set({ allow_private: e.target.checked })} /> The server is on an internal (private network) address</label>
      </div>
    </Dialog>
  );
}

/** Ticketing integrations. `embedded` renders it inside the Connectors hub (/connectors?manage=integrations). */
export function IntegrationsPage({ embedded = false }: { embedded?: boolean } = {}) {
  const qc = useQueryClient();
  const { can } = useSession();
  const list = useTicketConnections();
  const [dialog, setDialog] = useState<{ conn: TicketConnection | null } | null>(null);
  const [tested, setTested] = useState<Record<string, string>>({});
  const test = useMutation({
    mutationFn: (id: string) => api<{ ok: boolean; identity: string; error?: string }>(`/api/v1/ticket-connections/${id}/test`, { method: "POST" }),
    onSuccess: (r, id) => setTested((t) => ({ ...t, [id]: r.ok ? `Connected as ${r.identity || "the configured user"}` : `Failed: ${r.error}` })),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/api/v1/ticket-connections/${id}`, { method: "DELETE" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["ticket-connections"] }),
  });
  const manage = can("settings.manage");
  return (
    <>
      <PageHeader level={embedded ? 2 : 1} title="Integrations" description="Optional connections to issue trackers. Notification webhooks (SIEM, Slack, Microsoft Teams) are under Notifications → Webhooks; REST API tokens under your user menu."
        actions={manage && <Button onClick={() => setDialog({ conn: null })}><Plus /> New connection</Button>} />
      <Card>
        {(test.error ?? remove.error) && <div className="p-3"><Alert>{(test.error ?? remove.error)!.message}</Alert></div>}
        {list.isError ? <div className="p-3"><ErrorPanel error={list.error} /></div> : list.isPending ? <Skeleton className="m-3 h-20" /> : !list.data.length ? (
          <EmptyState icon={<Ticket />} title="No ticketing connections">Connect Jira or ServiceNow to open tickets for findings.</EmptyState>
        ) : (
          <Table>
            <thead><tr><Th>Connection</Th><Th>Where</Th><Th className="text-right">Tickets</Th><Th className="text-right">Manage</Th></tr></thead>
            <tbody>
              {list.data.map((c) => (
                <tr key={c.id} className={c.enabled ? undefined : "opacity-60"}>
                  <Td>
                    <div className="flex items-center gap-1.5 font-medium">{c.name} <Badge>{kindLabel[c.kind]}</Badge>{!c.enabled && <Badge>disabled</Badge>}</div>
                    {tested[c.id] && <div className="text-[11.5px]">{tested[c.id]}</div>}
                  </Td>
                  <Td className="text-[12px]">{c.base_url}{c.kind === "jira" ? ` · project ${c.config?.project_key}` : ` · table ${c.config?.table}`}</Td>
                  <Td className="tabular text-right text-[12px]">{c.tickets ?? "—"}</Td>
                  <Td className="whitespace-nowrap text-right">
                    {manage && (
                      <>
                        <Button size="sm" variant="ghost" onClick={() => test.mutate(c.id)} disabled={test.isPending}><PlugZap /> Test</Button>
                        <Button size="icon" variant="ghost" aria-label={`Edit ${c.name}`} onClick={() => setDialog({ conn: c })}><Pencil /></Button>
                        <Button size="icon" variant="ghost" aria-label={`Delete ${c.name}`} onClick={() => { if (window.confirm(`Delete “${c.name}”? Links from findings to its tickets are removed; the tickets stay in ${kindLabel[c.kind]}.`)) remove.mutate(c.id); }}><Trash2 /></Button>
                      </>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <ConnectionDialog open={!!dialog} onClose={() => setDialog(null)} conn={dialog?.conn ?? null} />
    </>
  );
}

/** Tickets of a finding, and creating one (people who can triage). */
export function FindingTickets({ findingId }: { findingId: string }) {
  const qc = useQueryClient();
  const { can } = useSession();
  const triage = can("findings.triage");
  const conns = useTicketConnections();
  const tickets = useQuery({ queryKey: ["finding-tickets", findingId], queryFn: () => api<{ items: FindingTicket[] }>(`/api/v1/findings/${findingId}/tickets`).then((r) => r.items), retry: false });
  const [conn, setConn] = useState("");
  const create = useMutation({
    mutationFn: () => api<FindingTicket>(`/api/v1/findings/${findingId}/tickets`, { method: "POST", body: { connection_id: conn } }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["finding-tickets", findingId] }),
  });
  const usable = (conns.data ?? []).filter((c) => c.enabled && !tickets.data?.some((t) => t.connection_name === c.name));
  if (!tickets.data?.length && !(triage && usable.length)) return null;
  return (
    <div className="rounded-md border border-border p-3 text-[12.5px]">
      <h3 className="mb-1 text-[12px] font-semibold">Tickets</h3>
      {tickets.data?.map((t) => (
        <div key={t.id} className="flex flex-wrap items-center gap-1.5">
          <a href={t.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-0.5 font-mono text-primary hover:underline">{t.key}<ExternalLink className="size-3" /></a>
          <span className="text-muted-foreground">{t.connection_name}</span>
          <Badge tone={t.done ? "success" : "neutral"}>{t.status || "open"}</Badge>
          {t.sync_error && <span className="text-[11px] text-danger" title={t.sync_error}>status unavailable</span>}
          <span className="text-[11px] text-muted-foreground">by {t.created_by}, {formatDateTime(t.created_at)}</span>
        </div>
      ))}
      {triage && usable.length > 0 && (
        <div className="mt-2 flex items-center gap-2">
          <Select aria-label="Ticketing connection" value={conn} onChange={(e) => setConn(e.target.value)}>
            <option value="">Open a ticket in…</option>
            {usable.map((c) => <option key={c.id} value={c.id}>{c.name} ({kindLabel[c.kind]})</option>)}
          </Select>
          <Button size="sm" variant="secondary" disabled={!conn || create.isPending} onClick={() => create.mutate()}><Ticket /> {create.isPending ? "Creating…" : "Create ticket"}</Button>
        </div>
      )}
      {create.error && <div className="mt-2"><ErrorPanel error={create.error} /></div>}
    </div>
  );
}

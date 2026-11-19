import { useState, type FormEvent } from "react";
import { Plus, Server } from "lucide-react";
import { api } from "@/api/client";
import type { McpServer } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { useAIMutation, useMcpServers } from "./api";
import { ErrorPanel } from "@/components/ui/error-panel";

const statusTone = { approved: "success", pending: "warning", rejected: "danger", disabled: "neutral" } as const;

export function McpRegistryPage() {
  const { canOrgWide } = useSession();
  const servers = useMcpServers();
  const [requesting, setRequesting] = useState(false);
  const manage = canOrgWide("mcp.manage");
  const decide = useAIMutation(({ id, status }: { id: string; status: string }) => api(`/api/v1/mcp-servers/${id}/decision`, { method: "POST", body: { status, note: "" } }));
  const tools = useAIMutation(({ id, tools }: { id: string; tools: McpServer["tools"] }) => api(`/api/v1/mcp-servers/${id}/tools`, { method: "PUT", body: { tools } }));
  const del = useAIMutation((id: string) => api(`/api/v1/mcp-servers/${id}`, { method: "DELETE" }));
  const error = decide.error ?? tools.error ?? del.error;

  return (
    <>
      <PageHeader title="MCP registry" description="MCP servers approved for use with PATHOS data, and which of their tools are allowed. New requests start pending and with every tool disallowed."
        actions={<Button onClick={() => setRequesting(true)}><Plus /> {manage ? "Register server" : "Request server"}</Button>} />
      {error && <div className="mb-3"><ErrorPanel error={error} /></div>}
      {servers.isPending ? <Skeleton className="h-32" /> : !servers.data?.length ? <Card><EmptyState icon={<Server />} title="No MCP servers" /></Card> : (
        <div className="space-y-3">
          {servers.data.map((s) => (
            <Card key={s.id} className="p-4 text-[13px]">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2 font-semibold">{s.name}<Badge tone={statusTone[s.status]}>{s.status}</Badge>{s.built_in && <Badge tone="primary">built-in</Badge>}</div>
                  {s.description && <p className="text-muted-foreground">{s.description}</p>}
                  <p className="font-mono text-[12px] text-muted-foreground">{s.transport} · {s.endpoint}</p>
                  <p className="text-[12px] text-muted-foreground">Data access: {s.data_access.replace("_", " ")}{s.requested_by && ` · requested by ${s.requested_by}`}{s.decided_by && ` · ${s.status} by ${s.decided_by}`}</p>
                </div>
                {manage && (
                  <div className="flex gap-1">
                    {s.status !== "approved" && <Button size="sm" onClick={() => decide.mutate({ id: s.id, status: "approved" })}>Approve</Button>}
                    {s.status === "pending" && <Button size="sm" variant="secondary" onClick={() => decide.mutate({ id: s.id, status: "rejected" })}>Reject</Button>}
                    {s.status === "approved" && <Button size="sm" variant="danger-outline" onClick={() => decide.mutate({ id: s.id, status: "disabled" })}>Disable</Button>}
                    {!s.built_in && <Button size="sm" variant="ghost" onClick={() => confirm(`Delete ${s.name}?`) && del.mutate(s.id)}>Delete</Button>}
                  </div>
                )}
              </div>
              {s.tools.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-3 border-t border-border pt-3">
                  {s.tools.map((t) => (
                    <label key={t.tool} className="flex items-center gap-1.5 text-[12px]">
                      <input type="checkbox" className="accent-[var(--primary)]" checked={t.allowed} disabled={!manage || tools.isPending}
                        onChange={() => tools.mutate({ id: s.id, tools: s.tools.map((x) => (x.tool === t.tool ? { ...x, allowed: !x.allowed } : x)) })} />
                      <span className="font-mono">{t.tool}</span><Badge tone={t.access === "write" ? "warning" : "neutral"}>{t.access}</Badge>
                    </label>
                  ))}
                </div>
              )}
            </Card>
          ))}
        </div>
      )}
      <RequestDialog open={requesting} onOpenChange={setRequesting} />
    </>
  );
}

function RequestDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const blank = { name: "", description: "", transport: "streamable_http", endpoint: "", data_access: "none", tools: "" };
  const [f, setF] = useState(blank);
  const create = useAIMutation((body: unknown) => api("/api/v1/mcp-servers", { method: "POST", body }));
  const close = () => { setF(blank); create.reset(); onOpenChange(false); };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const tools = f.tools.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => {
      const [tool, access] = l.split(/\s+/);
      return { tool: tool!, access: access === "write" ? "write" : "read", allowed: false };
    });
    create.mutate({ ...f, tools }, { onSuccess: close });
  };
  return (
    <Dialog open={open} onOpenChange={(o) => (o ? onOpenChange(true) : close())} title="Register MCP server" description="The server starts pending; an administrator approves it and allows individual tools."
      footer={<><Button variant="secondary" onClick={close}>Cancel</Button><Button type="submit" form="mcp-form" disabled={create.isPending}>Submit</Button></>}>
      <form id="mcp-form" onSubmit={submit} className="space-y-3 text-[13px]">
        {create.isError && <ErrorPanel error={create.error} />}
        <div className="grid grid-cols-2 gap-3">
          <div><Label htmlFor="m-name">Name</Label><Input id="m-name" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
          <div><Label htmlFor="m-tr">Transport</Label><Select id="m-tr" className="w-full" value={f.transport} onChange={(e) => setF({ ...f, transport: e.target.value })}>
            <option value="streamable_http">Streamable HTTP</option><option value="stdio">stdio (local command)</option></Select></div>
        </div>
        <div><Label htmlFor="m-ep">{f.transport === "stdio" ? "Command" : "URL (https)"}</Label><Input id="m-ep" required value={f.endpoint} onChange={(e) => setF({ ...f, endpoint: e.target.value })} /></div>
        <div><Label htmlFor="m-desc" hint="(why it is needed)">Description</Label><Input id="m-desc" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></div>
        <div><Label htmlFor="m-da">PATHOS data it would receive</Label><Select id="m-da" className="w-full" value={f.data_access} onChange={(e) => setF({ ...f, data_access: e.target.value })}>
          <option value="none">None</option><option value="findings_redacted">Redacted findings</option><option value="findings_full">Full findings</option></Select></div>
        <div><Label htmlFor="m-tools" hint="(one per line: name read|write)">Tools</Label>
          <textarea id="m-tools" rows={3} value={f.tools} onChange={(e) => setF({ ...f, tools: e.target.value })} className="w-full rounded-md border border-border bg-surface p-2 font-mono text-[12px] focus-visible:outline-2 focus-visible:outline-ring" /></div>
      </form>
    </Dialog>
  );
}

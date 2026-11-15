import { useState, type FormEvent } from "react";
import { CheckCircle2, CircleAlert, CircleDashed, Copy, KeyRound, Plug, Plus, RefreshCw, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import type { Provider, ScmConnection } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { useConnections, useRepoMutation } from "@/features/repos/api";
import { formatDateTime } from "@/lib/utils";

const providerLabel: Record<Provider, string> = {
  github: "GitHub",
  github_enterprise: "GitHub Enterprise Server",
  azure_devops: "Azure DevOps Services",
  azure_devops_server: "Azure DevOps Server",
};

export function ScmConnectionsPage() {
  const { canOrgWide } = useSession();
  const conns = useConnections();
  const [creating, setCreating] = useState(false);
  const [secret, setSecret] = useState<{ url: string; secret: string } | null>(null);
  const test = useRepoMutation((id: string) => api<ScmConnection>(`/api/v1/scm-connections/${id}/test`, { method: "POST" }));
  const rotate = useRepoMutation((id: string) => api<{ webhook_url: string; webhook_secret: string }>(`/api/v1/scm-connections/${id}/webhook-secret`, { method: "POST" }));
  const del = useRepoMutation((id: string) => api(`/api/v1/scm-connections/${id}`, { method: "DELETE" }));
  const manage = canOrgWide("scm.manage");
  const error = test.error ?? rotate.error ?? del.error;

  return (
    <>
      <PageHeader
        title="SCM connections"
        description="GitHub and Azure DevOps connections used to discover repositories and receive webhooks. Credentials are encrypted at rest and never shown again."
        actions={manage && <Button onClick={() => setCreating(true)}><Plus /> Add connection</Button>}
      />
      {error && <div className="mb-3"><Alert>{error.message}</Alert></div>}
      {conns.isPending ? (
        <Skeleton className="h-32" />
      ) : !conns.data?.length ? (
        <Card><EmptyState icon={<Plug />} title="No connections yet">Add a GitHub or Azure DevOps connection to start importing repositories.</EmptyState></Card>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {conns.data.map((c) => (
            <Card key={c.id} className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="font-semibold">{c.name}</div>
                  <div className="text-[12px] text-muted-foreground">
                    {providerLabel[c.provider]} · {c.auth_type === "github_app" ? `GitHub App ${c.github_app_id}` : "Personal access token"}
                    {c.owner && ` · ${c.owner}`}
                  </div>
                  <div className="truncate text-[12px] text-muted-foreground">{c.base_url}</div>
                </div>
                <StatusPill c={c} />
              </div>
              {c.status === "error" && <p className="mt-2 text-[12px] text-danger">{c.status_message}</p>}
              {c.status === "ok" && c.status_message && <p className="mt-2 text-[12px] text-muted-foreground">{c.status_message}</p>}
              <div className="mt-3 text-[12px] text-muted-foreground">
                {c.repository_count} repositories · checked {formatDateTime(c.last_checked_at)}
              </div>
              {manage && (
                <>
                  <div className="mt-3 rounded-md bg-surface-muted/60 p-2 text-[12px]">
                    <div className="text-muted-foreground">Webhook URL (push, pull request{c.provider.startsWith("azure") ? ", via service hooks with basic auth" : ""})</div>
                    <code className="break-all">{c.webhook_url}</code>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <Button size="sm" variant="secondary" disabled={test.isPending} onClick={() => test.mutate(c.id)}><RefreshCw /> Test</Button>
                    <Button size="sm" variant="secondary" disabled={rotate.isPending}
                      onClick={() => rotate.mutate(c.id, { onSuccess: (r) => setSecret({ url: r.webhook_url, secret: r.webhook_secret }) })}>
                      <KeyRound /> New webhook secret
                    </Button>
                    <Button size="sm" variant="ghost" className="ml-auto text-danger" disabled={del.isPending || c.repository_count > 0}
                      title={c.repository_count > 0 ? "Archive or delete its repositories first" : "Delete connection"}
                      onClick={() => confirm(`Delete connection "${c.name}"? Its credentials are destroyed.`) && del.mutate(c.id)}>
                      <Trash2 />
                    </Button>
                  </div>
                </>
              )}
            </Card>
          ))}
        </div>
      )}
      <CreateDialog open={creating} onOpenChange={setCreating} />
      <Dialog open={!!secret} onOpenChange={(o) => !o && setSecret(null)} title="Webhook secret" description="Copy it now: it is not shown again."
        footer={<Button onClick={() => setSecret(null)}>Done</Button>}>
        {secret && (
          <div className="space-y-3 text-[13px]">
            <CopyField label="Payload URL" value={secret.url} />
            <CopyField label="Secret (GitHub: webhook secret · Azure DevOps: basic auth password)" value={secret.secret} />
            <p className="text-[12px] text-muted-foreground">GitHub: content type <code>application/json</code>, events "Pushes" and "Pull requests".</p>
          </div>
        )}
      </Dialog>
    </>
  );
}

function StatusPill({ c }: { c: ScmConnection }) {
  if (c.status === "ok") return <span className="flex items-center gap-1 text-[12px] text-success"><CheckCircle2 className="size-4" /> Connected</span>;
  if (c.status === "error") return <span className="flex items-center gap-1 text-[12px] text-danger"><CircleAlert className="size-4" /> Error</span>;
  return <span className="flex items-center gap-1 text-[12px] text-muted-foreground"><CircleDashed className="size-4" /> Untested</span>;
}

function CopyField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="mb-1 text-[12px] text-muted-foreground">{label}</div>
      <div className="flex gap-2">
        <Input readOnly value={value} className="font-mono text-[12px]" onFocus={(e) => e.target.select()} />
        <Button variant="secondary" size="icon" aria-label={`Copy ${label}`} onClick={() => void navigator.clipboard?.writeText(value)}><Copy /></Button>
      </div>
    </div>
  );
}

function CreateDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const empty = { name: "", provider: "github" as Provider, base_url: "", owner: "", auth_type: "pat", token: "", private_key: "", app_id: "", installation_id: "" };
  const [f, setF] = useState(empty);
  const create = useRepoMutation((body: unknown) => api<ScmConnection>("/api/v1/scm-connections", { method: "POST", body }));
  const isGitHub = f.provider === "github" || f.provider === "github_enterprise";
  const close = () => { setF(empty); create.reset(); onOpenChange(false); };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const body: Record<string, unknown> = { name: f.name, provider: f.provider, auth_type: isGitHub ? f.auth_type : "pat", owner: f.owner };
    if (f.base_url) body.base_url = f.base_url;
    if (body.auth_type === "github_app") {
      Object.assign(body, { private_key: f.private_key, github_app_id: Number(f.app_id), github_installation_id: Number(f.installation_id) });
    } else body.token = f.token;
    create.mutate(body, { onSuccess: close });
  };
  const baseHint: Record<Provider, string> = {
    github: "Leave empty for https://api.github.com",
    github_enterprise: "e.g. https://github.example.com/api/v3",
    azure_devops: "Leave empty and set the organization below",
    azure_devops_server: "e.g. https://ado.example.com/DefaultCollection",
  };
  return (
    <Dialog open={open} onOpenChange={(o) => (o ? onOpenChange(true) : close())} title="Add SCM connection"
      description="Use a read-only credential: PATHOS only needs to list repositories and branches and clone code."
      footer={<><Button variant="secondary" onClick={close}>Cancel</Button><Button type="submit" form="conn-form" disabled={create.isPending}>{create.isPending ? "Connecting…" : "Add connection"}</Button></>}>
      <form id="conn-form" onSubmit={submit} className="space-y-3">
        {create.isError && <Alert>{create.error.message}</Alert>}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <Label htmlFor="c-name">Name</Label>
            <Input id="c-name" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="GitHub – Acme" />
          </div>
          <div>
            <Label htmlFor="c-prov">Provider</Label>
            <Select id="c-prov" className="w-full" value={f.provider} onChange={(e) => setF({ ...f, provider: e.target.value as Provider, auth_type: "pat" })}>
              {Object.entries(providerLabel).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </Select>
          </div>
        </div>
        <div>
          <Label htmlFor="c-url" hint={`(${baseHint[f.provider]})`}>API base URL</Label>
          <Input id="c-url" value={f.base_url} onChange={(e) => setF({ ...f, base_url: e.target.value })} required={f.provider === "github_enterprise" || f.provider === "azure_devops_server"} />
        </div>
        <div>
          <Label htmlFor="c-owner" hint={isGitHub ? "(optional: limit discovery to an organization or user)" : f.provider === "azure_devops" ? "(Azure DevOps organization)" : "(optional: limit to a project)"}>
            {isGitHub ? "Owner" : f.provider === "azure_devops" ? "Organization" : "Project"}
          </Label>
          <Input id="c-owner" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} required={f.provider === "azure_devops" && !f.base_url} />
        </div>
        {isGitHub && (
          <div>
            <Label htmlFor="c-auth">Authentication</Label>
            <Select id="c-auth" className="w-full" value={f.auth_type} onChange={(e) => setF({ ...f, auth_type: e.target.value })}>
              <option value="pat">Personal access token</option>
              <option value="github_app">GitHub App (recommended: short-lived tokens)</option>
            </Select>
          </div>
        )}
        {f.auth_type === "github_app" && isGitHub ? (
          <>
            <div className="grid grid-cols-2 gap-3">
              <div><Label htmlFor="c-app">App ID</Label><Input id="c-app" required inputMode="numeric" value={f.app_id} onChange={(e) => setF({ ...f, app_id: e.target.value })} /></div>
              <div><Label htmlFor="c-inst">Installation ID</Label><Input id="c-inst" required inputMode="numeric" value={f.installation_id} onChange={(e) => setF({ ...f, installation_id: e.target.value })} /></div>
            </div>
            <div>
              <Label htmlFor="c-key">Private key (PEM)</Label>
              <textarea id="c-key" required rows={5} value={f.private_key} onChange={(e) => setF({ ...f, private_key: e.target.value })}
                className="w-full rounded-md border border-border bg-surface p-2 font-mono text-[11px] focus-visible:outline-2 focus-visible:outline-ring" />
            </div>
          </>
        ) : (
          <div>
            <Label htmlFor="c-token" hint={isGitHub ? "(fine-grained, Contents: read + Metadata: read)" : "(Code: Read)"}>Access token</Label>
            <Input id="c-token" required type="password" autoComplete="off" value={f.token} onChange={(e) => setF({ ...f, token: e.target.value })} />
          </div>
        )}
      </form>
    </Dialog>
  );
}

import { Fragment, useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Container, Pencil, Plus, RefreshCw, Server, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useApplications } from "@/features/repos/api";
import { cn, formatDateTime } from "@/lib/utils";
import {
  basisLabel, useClusters, useMappings, useRegistries, useRuntimeSummary, useWorkloads,
  type RegistryConnection, type RuntimeAlert, type RuntimeCluster, type SyncRun, type SyncStatus, type Workload, type WorkloadFilters,
} from "./api";

const textareaClass = "min-h-24 w-full rounded-md border border-border bg-surface px-2.5 py-1.5 font-mono text-[12px] focus:outline-none focus:ring-1 focus:ring-[color:var(--ring)]";
const shortDigest = (d: string) => (d ? `${d.slice(0, 19)}…` : "");

function StatusBadge({ status, requested }: { status: SyncStatus; requested?: string | null }) {
  if (requested && status !== "running") return <Badge tone="primary">Sync requested</Badge>;
  switch (status) {
    case "succeeded":
      return <Badge tone="success">Synchronised</Badge>;
    case "partial":
      return <Badge tone="warning">Partial</Badge>;
    case "failed":
      return <Badge tone="danger">Failed</Badge>;
    case "running":
      return <Badge tone="primary">Running</Badge>;
  }
  return <Badge>Not synchronised yet</Badge>;
}

/** How to connect a cluster (empty state; no data is invented). */
function ConnectHelp({ canManage, onAdd }: { canManage: boolean; onAdd: () => void }) {
  return (
    <EmptyState icon={<Container />} title="No Kubernetes cluster connected">
      <div className="mx-auto max-w-2xl space-y-2 text-left text-[12.5px]">
        <p>
          Connect a cluster to see which images run where, which workloads are reachable from the internet, and to rank findings by what is
          actually deployed. PATHOS only reads (get, list, watch); it never reads Secrets or ConfigMaps.
        </p>
        <ol className="list-decimal space-y-1 pl-5">
          <li>Apply the read-only role shipped with PATHOS: <code className="font-mono">kubectl apply -f deploy/kubernetes/pathos-reader-clusterrole.yaml</code></li>
          <li>Copy its token and CA certificate: <code className="font-mono">kubectl -n pathos-reader get secret pathos-reader-token -o jsonpath=&apos;&#123;.data.token&#125;&apos; | base64 -d</code></li>
          <li>{canManage ? "Add the cluster here with the API server URL, the token and the CA certificate (or a kubeconfig with inline credentials)." : "Ask an administrator (settings.manage) to add the cluster."}</li>
          <li>The jobs service reads the cluster on a schedule (hourly by default) and links running images to image scan findings.</li>
        </ol>
        {canManage && <div className="pt-1"><Button onClick={onAdd}><Plus /> Add cluster</Button></div>}
      </div>
    </EmptyState>
  );
}

// --- clusters -------------------------------------------------------------------

function ClusterDialog({ open, onClose, cluster }: { open: boolean; onClose: () => void; cluster: RuntimeCluster | null }) {
  const qc = useQueryClient();
  const blank = { name: "", auth_type: "token" as "token" | "kubeconfig", api_server: "", token: "", ca_cert: "", kubeconfig: "", context: "", namespaces: "",
    allow_private: false, enabled: true, sync_interval_minutes: 60 };
  const [f, setF] = useState(blank);
  useEffect(() => {
    if (!open) return;
    setF(cluster ? { ...blank, name: cluster.name, auth_type: cluster.auth_type, api_server: cluster.api_server, namespaces: cluster.namespaces.join(", "),
      allow_private: cluster.allow_private, enabled: cluster.enabled, sync_interval_minutes: cluster.sync_interval_minutes } : blank);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, cluster]);
  const set = (p: Partial<typeof f>) => setF((x) => ({ ...x, ...p }));
  const save = useMutation({
    mutationFn: () => api(cluster ? `/api/v1/runtime/clusters/${cluster.id}` : "/api/v1/runtime/clusters", {
      method: cluster ? "PUT" : "POST",
      body: {
        name: f.name, auth_type: f.auth_type, api_server: f.api_server, token: f.token || undefined, ca_cert: f.ca_cert || undefined,
        kubeconfig: f.kubeconfig || undefined, context: f.context || undefined, allow_private: f.allow_private, enabled: f.enabled,
        sync_interval_minutes: f.sync_interval_minutes, namespaces: f.namespaces.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean),
      },
    }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["runtime"] });
      onClose();
    },
  });
  const token = f.auth_type === "token";
  const missing = !f.name.trim() || (token ? !f.api_server.trim() || (!cluster && !f.token) : !cluster && !f.kubeconfig.trim());
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()} size="lg" title={cluster ? `Edit ${cluster.name}` : "Add Kubernetes cluster"}
      description="Read-only inventory. The credentials are stored encrypted; the jobs service contacts the API server, never the PATHOS API server."
      footer={<><Button variant="secondary" onClick={onClose}>Cancel</Button><Button disabled={missing || save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save"}</Button></>}>
      <div className="space-y-3 text-[13px]">
        {save.error && <Alert>{save.error.message}</Alert>}
        <div className="grid gap-3 md:grid-cols-2">
          <div><Label htmlFor="rc-name">Name</Label><Input id="rc-name" value={f.name} maxLength={120} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. prod-eu-1" /></div>
          <div><Label htmlFor="rc-auth">Credentials</Label>
            <Select id="rc-auth" value={f.auth_type} onChange={(e) => set({ auth_type: e.target.value as "token" | "kubeconfig" })}>
              <option value="token">Service-account token</option>
              <option value="kubeconfig">Kubeconfig (inline credentials)</option>
            </Select></div>
        </div>
        {token ? (
          <>
            <div><Label htmlFor="rc-server">API server URL</Label><Input id="rc-server" type="url" value={f.api_server} onChange={(e) => set({ api_server: e.target.value })} placeholder="https://k8s.example.com:6443" /></div>
            <div><Label htmlFor="rc-token" hint={cluster ? "(leave empty to keep)" : "(stored encrypted)"}>Token</Label>
              <Input id="rc-token" type="password" autoComplete="new-password" value={f.token} onChange={(e) => set({ token: e.target.value })} /></div>
            <div><Label htmlFor="rc-ca" hint={cluster?.has_ca_cert ? "(a certificate is stored; paste to replace)" : "(PEM; empty = public CA)"}>CA certificate</Label>
              <textarea id="rc-ca" className={textareaClass} value={f.ca_cert} onChange={(e) => set({ ca_cert: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" /></div>
          </>
        ) : (
          <>
            <div><Label htmlFor="rc-kc" hint={cluster ? "(leave empty to keep)" : "(stored encrypted; exec plugins and file references are refused)"}>Kubeconfig</Label>
              <textarea id="rc-kc" className={cn(textareaClass, "min-h-40")} value={f.kubeconfig} onChange={(e) => set({ kubeconfig: e.target.value })} /></div>
            <div><Label htmlFor="rc-ctx" hint="(empty = current-context)">Context</Label><Input id="rc-ctx" value={f.context} onChange={(e) => set({ context: e.target.value })} /></div>
          </>
        )}
        <div className="grid gap-3 md:grid-cols-2">
          <div><Label htmlFor="rc-ns" hint="(comma-separated; empty = all the role can list)">Namespaces</Label><Input id="rc-ns" value={f.namespaces} onChange={(e) => set({ namespaces: e.target.value })} /></div>
          <div><Label htmlFor="rc-int" hint="(15–1440)">Sync every (minutes)</Label>
            <Input id="rc-int" type="number" min={15} max={1440} value={f.sync_interval_minutes} onChange={(e) => set({ sync_interval_minutes: Number(e.target.value) })} /></div>
        </div>
        <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={f.allow_private} onChange={(e) => set({ allow_private: e.target.checked })} /> The API server is on a private network address</label>
        <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={f.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled</label>
      </div>
    </Dialog>
  );
}

function RunsDialog({ path, title, onClose }: { path: string | null; title: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["runtime", "runs", path], queryFn: () => api<{ items: SyncRun[] }>(path!), enabled: !!path });
  return (
    <Dialog open={!!path} onOpenChange={(o) => !o && onClose()} size="lg" title={title} description="The last 30 synchronisations.">
      {q.isError ? <Alert>{q.error.message}</Alert> : q.isPending ? <Skeleton className="h-24" /> : !q.data.items.length ? (
        <p className="text-[12.5px] text-muted-foreground">No synchronisation yet.</p>
      ) : (
        <Table>
          <thead><tr><Th>Started</Th><Th>Status</Th><Th>Result</Th></tr></thead>
          <tbody>
            {q.data.items.map((r) => (
              <tr key={r.id}>
                <Td className="whitespace-nowrap text-[12px]">{formatDateTime(r.started_at)}</Td>
                <Td><StatusBadge status={r.status} /></Td>
                <Td className="text-[12px]">
                  {r.error && <div className="text-danger">{r.error}</div>}
                  <div className="text-muted-foreground">
                    {Object.entries(r.stats).filter(([k]) => k !== "warnings").map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`).join(" · ")}
                  </div>
                  {Array.isArray(r.stats.warnings) && r.stats.warnings.map((w, i) => <div key={i} className="text-warning">{w}</div>)}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Dialog>
  );
}

function ClustersTab() {
  const qc = useQueryClient();
  const list = useClusters();
  const [dialog, setDialog] = useState<{ cluster: RuntimeCluster | null } | null>(null);
  const [runs, setRuns] = useState<RuntimeCluster | null>(null);
  const sync = useMutation({ mutationFn: (id: string) => api(`/api/v1/runtime/clusters/${id}/sync`, { method: "POST" }), onSuccess: () => void qc.invalidateQueries({ queryKey: ["runtime"] }) });
  const remove = useMutation({ mutationFn: (id: string) => api(`/api/v1/runtime/clusters/${id}`, { method: "DELETE" }), onSuccess: () => void qc.invalidateQueries({ queryKey: ["runtime"] }) });
  const manage = !!list.data?.can_manage;
  return (
    <Card>
      <div className="flex items-center border-b border-border px-4 py-2.5">
        <h2 className="text-[13px] font-semibold">Clusters</h2>
        {manage && list.data!.items.length > 0 && <Button size="sm" className="ml-auto" onClick={() => setDialog({ cluster: null })}><Plus /> Add cluster</Button>}
      </div>
      {(sync.error ?? remove.error) && <div className="p-3"><Alert>{(sync.error ?? remove.error)!.message}</Alert></div>}
      {list.isError ? <div className="p-3"><Alert>{list.error.message}</Alert></div> : list.isPending ? <Skeleton className="m-3 h-20" /> : !list.data.items.length ? (
        <ConnectHelp canManage={manage} onAdd={() => setDialog({ cluster: null })} />
      ) : (
        <Table>
          <thead><tr><Th>Cluster</Th><Th>Status</Th><Th className="text-right">Workloads</Th><Th className="text-right">Exposed</Th><Th className="text-right">Privileged</Th>{manage && <Th className="text-right">Manage</Th>}</tr></thead>
          <tbody>
            {list.data.items.map((c) => (
              <tr key={c.id} className={c.enabled ? undefined : "opacity-60"}>
                <Td>
                  <div className="font-medium">{c.name}</div>
                  <div className="text-[11px] text-muted-foreground">
                    {c.api_server && <span className="font-mono">{c.api_server}</span>}
                    {c.namespaces.length > 0 ? ` · namespaces ${c.namespaces.join(", ")}` : ` · ${c.namespace_count} namespaces`}
                  </div>
                </Td>
                <Td>
                  <StatusBadge status={c.last_status} requested={c.sync_requested_at} />
                  <div className="text-[11px] text-muted-foreground">{c.last_sync_at ? `last ${formatDateTime(c.last_sync_at)}` : ""} · every {c.sync_interval_minutes} min</div>
                  {c.last_error && <div className="max-w-md truncate text-[11px] text-danger" title={c.last_error}>{c.last_error}</div>}
                </Td>
                <Td className="tabular text-right">{c.workloads}</Td>
                <Td className="tabular text-right">{c.internet_exposed_workloads}</Td>
                <Td className="tabular text-right">{c.privileged_workloads}</Td>
                {manage && (
                  <Td className="whitespace-nowrap text-right">
                    <Button size="sm" variant="ghost" disabled={!c.enabled || sync.isPending} onClick={() => sync.mutate(c.id)} title="The jobs service synchronises within a minute"><RefreshCw /> Sync now</Button>
                    <Button size="sm" variant="ghost" onClick={() => setRuns(c)}>History</Button>
                    <Button size="icon" variant="ghost" aria-label={`Edit ${c.name}`} onClick={() => setDialog({ cluster: c })}><Pencil /></Button>
                    <Button size="icon" variant="ghost" aria-label={`Delete ${c.name}`} onClick={() => window.confirm(`Delete ${c.name} and its inventory?`) && remove.mutate(c.id)}><Trash2 /></Button>
                  </Td>
                )}
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <ClusterDialog open={!!dialog} cluster={dialog?.cluster ?? null} onClose={() => setDialog(null)} />
      <RunsDialog path={runs ? `/api/v1/runtime/clusters/${runs.id}/runs` : null} title={`Synchronisations of ${runs?.name ?? ""}`} onClose={() => setRuns(null)} />
    </Card>
  );
}

// --- registries -----------------------------------------------------------------

function RegistryDialog({ open, onClose, reg }: { open: boolean; onClose: () => void; reg: RegistryConnection | null }) {
  const qc = useQueryClient();
  const blank = { name: "", base_url: "", repositories: "", auth_type: "none" as RegistryConnection["auth_type"], username: "", secret: "", max_tags: 50,
    allow_private: false, enabled: true, sync_interval_minutes: 360, ca_bundle_pem: "" };
  const [f, setF] = useState(blank);
  useEffect(() => {
    if (!open) return;
    setF(reg ? { ...blank, name: reg.name, base_url: reg.base_url, repositories: reg.repositories.join("\n"), auth_type: reg.auth_type, username: reg.username,
      max_tags: reg.max_tags, allow_private: reg.allow_private, enabled: reg.enabled, sync_interval_minutes: reg.sync_interval_minutes,
      ca_bundle_pem: reg.ca_bundle_pem ?? "" } : blank);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, reg]);
  const set = (p: Partial<typeof f>) => setF((x) => ({ ...x, ...p }));
  const save = useMutation({
    mutationFn: () => api(reg ? `/api/v1/runtime/registries/${reg.id}` : "/api/v1/runtime/registries", {
      method: reg ? "PUT" : "POST",
      body: { ...f, secret: f.secret || undefined, repositories: f.repositories.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean) },
    }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["runtime"] });
      onClose();
    },
  });
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()} size="lg" title={reg ? `Edit ${reg.name}` : "Add container registry"}
      description="Lists tags and digests of the repositories you name (OCI distribution API, read-only) and reads the org.opencontainers.image.source and revision labels."
      footer={<><Button variant="secondary" onClick={onClose}>Cancel</Button><Button disabled={!f.name.trim() || !f.base_url.trim() || !f.repositories.trim() || save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save"}</Button></>}>
      <div className="space-y-3 text-[13px]">
        {save.error && <Alert>{save.error.message}</Alert>}
        <div className="grid gap-3 md:grid-cols-2">
          <div><Label htmlFor="rg-name">Name</Label><Input id="rg-name" value={f.name} maxLength={120} onChange={(e) => set({ name: e.target.value })} /></div>
          <div><Label htmlFor="rg-url">Registry URL</Label><Input id="rg-url" type="url" value={f.base_url} onChange={(e) => set({ base_url: e.target.value })} placeholder="https://ghcr.io" /></div>
        </div>
        <div><Label htmlFor="rg-repos" hint="(one per line, namespace/name)">Repositories</Label>
          <textarea id="rg-repos" className={textareaClass} value={f.repositories} onChange={(e) => set({ repositories: e.target.value })} placeholder="acme/shop" /></div>
        <div className="grid gap-3 md:grid-cols-3">
          <div><Label htmlFor="rg-auth">Authentication</Label>
            <Select id="rg-auth" value={f.auth_type} onChange={(e) => set({ auth_type: e.target.value as RegistryConnection["auth_type"] })}>
              <option value="none">Anonymous</option><option value="basic">User + password or token</option><option value="bearer">Bearer token</option>
            </Select></div>
          {f.auth_type === "basic" && <div><Label htmlFor="rg-user">User</Label><Input id="rg-user" value={f.username} onChange={(e) => set({ username: e.target.value })} /></div>}
          {f.auth_type !== "none" && <div><Label htmlFor="rg-secret" hint={reg ? "(leave empty to keep)" : "(stored encrypted)"}>{f.auth_type === "basic" ? "Password / token" : "Token"}</Label>
            <Input id="rg-secret" type="password" autoComplete="new-password" value={f.secret} onChange={(e) => set({ secret: e.target.value })} /></div>}
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <div><Label htmlFor="rg-tags" hint="(per repository, 1–500)">Tags to read</Label><Input id="rg-tags" type="number" min={1} max={500} value={f.max_tags} onChange={(e) => set({ max_tags: Number(e.target.value) })} /></div>
          <div><Label htmlFor="rg-int" hint="(15–10080)">Sync every (minutes)</Label><Input id="rg-int" type="number" min={15} max={10080} value={f.sync_interval_minutes} onChange={(e) => set({ sync_interval_minutes: Number(e.target.value) })} /></div>
        </div>
        <div><Label htmlFor="rg-ca" hint="(optional; PEM certificates of a private CA, added to the system trust store for this registry only)">Private CA bundle</Label>
          <textarea id="rg-ca" className={textareaClass} value={f.ca_bundle_pem} onChange={(e) => set({ ca_bundle_pem: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" /></div>
        <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={f.allow_private} onChange={(e) => set({ allow_private: e.target.checked })} /> The registry is on a private network address</label>
        <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={f.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled</label>
      </div>
    </Dialog>
  );
}

function RegistryImages({ id }: { id: string }) {
  type Img = { registry: string; repository: string; tag: string; digest: string; source_url: string; revision: string; running: boolean };
  const q = useQuery({ queryKey: ["runtime", "registry-images", id], queryFn: () => api<{ items: Img[] }>(`/api/v1/runtime/registries/${id}/images`).then((r) => r.items) });
  if (q.isError) return <Alert>{q.error.message}</Alert>;
  if (q.isPending) return <Skeleton className="h-12" />;
  if (!q.data.length) return <p className="px-4 py-2 text-[12px] text-muted-foreground">No images listed yet.</p>;
  return (
    <Table>
      <thead><tr><Th>Image</Th><Th>Digest</Th><Th>Source</Th><Th>Running</Th></tr></thead>
      <tbody>
        {q.data.map((i) => (
          <tr key={`${i.repository}:${i.tag}`}>
            <Td className="font-mono text-[11.5px]">{i.registry}/{i.repository}:{i.tag}</Td>
            <Td className="font-mono text-[11px]" ><span title={i.digest}>{shortDigest(i.digest)}</span></Td>
            <Td className="text-[11.5px]">{i.source_url ? <>{i.source_url}{i.revision && <span className="font-mono text-muted-foreground"> @ {i.revision.slice(0, 12)}</span>}</> : <span className="text-muted-foreground">no source label</span>}</Td>
            <Td>{i.running ? <Badge tone="warning">Running</Badge> : <span className="text-[12px] text-muted-foreground">—</span>}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function RegistriesTab() {
  const qc = useQueryClient();
  const list = useRegistries();
  const [dialog, setDialog] = useState<{ reg: RegistryConnection | null } | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [runs, setRuns] = useState<RegistryConnection | null>(null);
  const sync = useMutation({ mutationFn: (id: string) => api(`/api/v1/runtime/registries/${id}/sync`, { method: "POST" }), onSuccess: () => void qc.invalidateQueries({ queryKey: ["runtime"] }) });
  const remove = useMutation({ mutationFn: (id: string) => api(`/api/v1/runtime/registries/${id}`, { method: "DELETE" }), onSuccess: () => void qc.invalidateQueries({ queryKey: ["runtime"] }) });
  const manage = !!list.data?.can_manage;
  return (
    <Card>
      <div className="flex items-center border-b border-border px-4 py-2.5">
        <h2 className="text-[13px] font-semibold">Container registries</h2>
        {manage && <Button size="sm" className="ml-auto" onClick={() => setDialog({ reg: null })}><Plus /> Add registry</Button>}
      </div>
      {(sync.error ?? remove.error) && <div className="p-3"><Alert>{(sync.error ?? remove.error)!.message}</Alert></div>}
      {list.isError ? <div className="p-3"><Alert>{list.error.message}</Alert></div> : list.isPending ? <Skeleton className="m-3 h-20" /> : !list.data.items.length ? (
        <EmptyState icon={<Server />} title="No registry connected">
          Optional. Connect a registry to list which images and digests exist and to read their <code className="font-mono">org.opencontainers.image.source</code> and{" "}
          <code className="font-mono">revision</code> labels, which link a running image to the repository and commit it was built from.
        </EmptyState>
      ) : (
        <Table>
          <thead><tr><Th>Registry</Th><Th>Status</Th><Th className="text-right">Images</Th><Th className="text-right">With source label</Th><Th className="text-right">Manage</Th></tr></thead>
          <tbody>
            {list.data.items.map((r) => (
              <Fragment key={r.id}>
                <tr className={r.enabled ? undefined : "opacity-60"}>
                  <Td>
                    <button type="button" className="flex items-center gap-1 font-medium" onClick={() => setOpen(open === r.id ? null : r.id)} aria-expanded={open === r.id}>
                      {open === r.id ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}{r.name}
                    </button>
                    <div className="text-[11px] text-muted-foreground"><span className="font-mono">{r.base_url}</span> · {r.repositories.join(", ")}</div>
                  </Td>
                  <Td>
                    <StatusBadge status={r.last_status} requested={r.sync_requested_at} />
                    {r.last_error && <div className="max-w-md truncate text-[11px] text-danger" title={r.last_error}>{r.last_error}</div>}
                  </Td>
                  <Td className="tabular text-right">{r.images}</Td>
                  <Td className="tabular text-right">{r.images_with_source}</Td>
                  <Td className="whitespace-nowrap text-right">
                    {manage && <>
                      <Button size="sm" variant="ghost" disabled={!r.enabled || sync.isPending} onClick={() => sync.mutate(r.id)}><RefreshCw /> Sync now</Button>
                      <Button size="sm" variant="ghost" onClick={() => setRuns(r)}>History</Button>
                      <Button size="icon" variant="ghost" aria-label={`Edit ${r.name}`} onClick={() => setDialog({ reg: r })}><Pencil /></Button>
                      <Button size="icon" variant="ghost" aria-label={`Delete ${r.name}`} onClick={() => window.confirm(`Delete ${r.name}?`) && remove.mutate(r.id)}><Trash2 /></Button>
                    </>}
                  </Td>
                </tr>
                {open === r.id && <tr><td colSpan={5} className="bg-surface-muted/40"><RegistryImages id={r.id} /></td></tr>}
              </Fragment>
            ))}
          </tbody>
        </Table>
      )}
      <RegistryDialog open={!!dialog} reg={dialog?.reg ?? null} onClose={() => setDialog(null)} />
      <RunsDialog path={runs ? `/api/v1/runtime/registries/${runs.id}/runs` : null} title={`Synchronisations of ${runs?.name ?? ""}`} onClose={() => setRuns(null)} />
    </Card>
  );
}

// --- workloads ------------------------------------------------------------------

function WorkloadDetail({ w }: { w: Workload }) {
  const q = useQuery({ queryKey: ["runtime", "workload", w.id], queryFn: () => api<{ alerts: RuntimeAlert[] }>(`/api/v1/runtime/workloads/${w.id}`) });
  return (
    <div className="grid gap-3 p-3 text-[12px] md:grid-cols-2">
      <div>
        <h4 className="mb-1 font-semibold">Exposure</h4>
        {!w.exposure.length ? <p className="text-muted-foreground">No Ingress, LoadBalancer or NodePort Service routes to this workload.</p> : (
          <ul className="space-y-0.5">{w.exposure.map((x, i) => <li key={i} className={x.internet ? "text-danger" : undefined}>{x.detail}{x.address ? ` (${x.address})` : ""}</li>)}</ul>
        )}
        <h4 className="mb-1 mt-2 font-semibold">Network policies</h4>
        <p className="text-muted-foreground">{w.network_policies.length ? w.network_policies.join(", ") : "None selects this workload."}</p>
        <h4 className="mb-1 mt-2 font-semibold">Application</h4>
        <p className="text-muted-foreground">{w.application_name ? `${w.application_name} (${w.application_basis})` : "Not mapped. Add a mapping by namespace or label."}</p>
      </div>
      <div>
        <h4 className="mb-1 font-semibold">Images and links</h4>
        <ul className="space-y-1">
          {w.images.map((im) => (
            <li key={`${im.container}-${im.digest}-${im.image}`}>
              <span className="font-mono">{im.container}{im.init ? " (init)" : ""}: {im.image}</span>
              {im.digest && <span className="font-mono text-muted-foreground" title={im.digest}> @ {shortDigest(im.digest)}</span>}
              {!im.links.length ? <div className="text-muted-foreground">Not linked to an image scan or repository.</div> : im.links.map((l, i) => (
                <div key={i} className="text-muted-foreground">
                  ↳ {basisLabel[l.basis]}:{" "}
                  {l.scan_target_id && <Link to="/findings" search={{ scan_target_id: l.scan_target_id } as never} className="text-primary hover:underline">{l.scan_target_name} findings</Link>}
                  {!l.scan_target_id && l.repository_id && <Link to="/findings" search={{ repository_id: l.repository_id, deployed: "true" } as never} className="text-primary hover:underline">{l.repository_name} findings</Link>}
                  <span> — {l.detail}</span>
                </div>
              ))}
            </li>
          ))}
        </ul>
        <h4 className="mb-1 mt-2 font-semibold">Runtime alerts</h4>
        {q.isPending ? <Skeleton className="h-6" /> : q.isError ? <Alert>{q.error.message}</Alert> : !q.data.alerts.length ? (
          <p className="text-muted-foreground">No open Falco, Tetragon or Tracee alert matched this workload.</p>
        ) : (
          <ul>{q.data.alerts.map((a) => <li key={a.finding_id}><Link to="/findings" search={{ finding: a.finding_id } as never} className="text-primary hover:underline">{a.title}</Link> <span className="text-muted-foreground">({a.severity}) {a.location}</span></li>)}</ul>
        )}
      </div>
    </div>
  );
}

function WorkloadsTab() {
  const clusters = useClusters();
  const [f, setF] = useState<WorkloadFilters>({});
  const [open, setOpen] = useState<string | null>(null);
  const list = useWorkloads(f);
  const set = (p: Partial<WorkloadFilters>) => setF((x) => ({ ...x, ...p }));
  if (clusters.data && !clusters.data.items.length) return null;
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5">
        <h2 className="mr-auto text-[13px] font-semibold">Workloads</h2>
        <Input aria-label="Search workloads" placeholder="Name, namespace or image" className="w-56" value={f.q ?? ""} onChange={(e) => set({ q: e.target.value || undefined })} />
        <Select aria-label="Cluster" value={f.cluster_id ?? ""} onChange={(e) => set({ cluster_id: e.target.value || undefined })}>
          <option value="">All clusters</option>
          {clusters.data?.items.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </Select>
        <Select aria-label="Exposure" value={f.exposed ?? ""} onChange={(e) => set({ exposed: e.target.value || undefined })}>
          <option value="">Any exposure</option><option value="true">Internet-exposed</option><option value="false">Not internet-exposed</option>
        </Select>
        <Select aria-label="Security context" value={f.privileged ?? ""} onChange={(e) => set({ privileged: e.target.value || undefined })}>
          <option value="">Any security context</option><option value="true">Privileged / host namespaces</option>
        </Select>
        <Select aria-label="Findings" value={f.with_findings ?? ""} onChange={(e) => set({ with_findings: e.target.value || undefined })}>
          <option value="">With or without findings</option><option value="true">With open findings</option>
        </Select>
      </div>
      {list.isError ? <div className="p-3"><Alert>{list.error.message}</Alert></div> : list.isPending ? <Skeleton className="m-3 h-32" /> : !list.data.items.length ? (
        <EmptyState icon={<Container />} title="No workloads">
          {Object.values(f).some(Boolean) ? "No workload matches the filters." : "The connected clusters have not been synchronised yet, or the role cannot list workloads. See the cluster's history."}
        </EmptyState>
      ) : (
        <Table>
          <thead><tr><Th>Workload</Th><Th>Images</Th><Th>Exposure</Th><Th>Security context</Th><Th className="text-right">Open findings</Th></tr></thead>
          <tbody>
            {list.data.items.map((w) => (
              <Fragment key={w.id}>
                <tr>
                  <Td>
                    <button type="button" className="flex items-center gap-1 text-left font-medium" onClick={() => setOpen(open === w.id ? null : w.id)} aria-expanded={open === w.id}>
                      {open === w.id ? <ChevronDown className="size-3.5 shrink-0" /> : <ChevronRight className="size-3.5 shrink-0" />}{w.name}
                    </button>
                    <div className="text-[11px] text-muted-foreground">
                      {w.cluster} / {w.namespace} · {w.kind}{w.replicas != null ? ` · ${w.ready_replicas ?? 0}/${w.replicas} ready` : ""}
                      {w.application_name && <> · <span className="text-foreground">{w.application_name}</span></>}
                    </div>
                  </Td>
                  <Td className="max-w-sm text-[11.5px]">
                    {w.images.filter((i) => !i.init).slice(0, 3).map((i) => (
                      <div key={`${i.container}-${i.digest}-${i.image}`} className="truncate font-mono" title={`${i.image}${i.digest ? ` @ ${i.digest}` : ""}`}>
                        {i.image}{i.links.length > 0 && <Badge tone="primary" className="ml-1">linked</Badge>}
                      </div>
                    ))}
                    {w.images.length > 3 && <div className="text-muted-foreground">+{w.images.length - 3} more</div>}
                  </Td>
                  <Td>
                    {w.internet_exposed ? <Badge tone="danger">Internet-exposed</Badge> : w.exposure.length ? <Badge tone="warning">Internal / node port</Badge> : <span className="text-[12px] text-muted-foreground">Cluster only</span>}
                    {w.exposure.find((x) => x.internet && x.host) && <div className="text-[11px] text-muted-foreground">{w.exposure.find((x) => x.internet && x.host)!.host}</div>}
                  </Td>
                  <Td className="text-[11.5px]">
                    <div className="flex flex-wrap gap-1">
                      {w.privileged && <Badge tone="danger">privileged</Badge>}
                      {w.host_network && <Badge tone="danger">hostNetwork</Badge>}
                      {w.host_pid && <Badge tone="danger">hostPID</Badge>}
                      {w.run_as_root === "yes" && <Badge tone="warning">root</Badge>}
                      {w.runtime_alerts > 0 && <Badge tone="danger">{w.runtime_alerts} alert{w.runtime_alerts > 1 ? "s" : ""}</Badge>}
                      {!w.privileged && !w.host_network && !w.host_pid && w.run_as_root !== "yes" && !w.runtime_alerts && <span className="text-muted-foreground">{w.run_as_root === "no" ? "non-root" : "—"}</span>}
                    </div>
                  </Td>
                  <Td className="tabular whitespace-nowrap text-right text-[12px]">
                    {w.findings.total}
                    {w.findings.critical + w.findings.high > 0 && <span className="text-muted-foreground"> ({w.findings.critical} critical, {w.findings.high} high)</span>}
                  </Td>
                </tr>
                {open === w.id && <tr><td colSpan={5} className="bg-surface-muted/40"><WorkloadDetail w={w} /></td></tr>}
              </Fragment>
            ))}
          </tbody>
        </Table>
      )}
      {list.data?.truncated && <p className="px-4 py-2 text-[11.5px] text-muted-foreground">Showing the first 1,000 workloads; narrow the filters.</p>}
    </Card>
  );
}

// --- application mappings -----------------------------------------------------------

function MappingsTab() {
  const qc = useQueryClient();
  const list = useMappings();
  const clusters = useClusters();
  const apps = useApplications();
  const manage = !!clusters.data?.can_manage;
  const [f, setF] = useState({ cluster_id: "", namespace: "", label_key: "", label_value: "", application_id: "" });
  const add = useMutation({
    mutationFn: () => api("/api/v1/runtime/mappings", { method: "POST", body: { ...f, cluster_id: f.cluster_id || null } }),
    onSuccess: () => {
      setF({ cluster_id: "", namespace: "", label_key: "", label_value: "", application_id: "" });
      void qc.invalidateQueries({ queryKey: ["runtime"] });
    },
  });
  const remove = useMutation({ mutationFn: (id: string) => api(`/api/v1/runtime/mappings/${id}`, { method: "DELETE" }), onSuccess: () => void qc.invalidateQueries({ queryKey: ["runtime"] }) });
  return (
    <Card>
      <h2 className="border-b border-border px-4 py-2.5 text-[13px] font-semibold">Workload → application mappings</h2>
      <p className="px-4 pt-2 text-[12px] text-muted-foreground">
        Assign workloads to applications by namespace, by a pod template label (for example <code className="font-mono">app.kubernetes.io/part-of</code>), or both.
        The most specific mapping wins (cluster, then label, then namespace).
      </p>
      {(add.error ?? remove.error) && <div className="p-3"><Alert>{(add.error ?? remove.error)!.message}</Alert></div>}
      {manage && (
        <div className="grid gap-2 p-4 md:grid-cols-6">
          <Select aria-label="Cluster" value={f.cluster_id} onChange={(e) => setF({ ...f, cluster_id: e.target.value })}>
            <option value="">Every cluster</option>{clusters.data?.items.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </Select>
          <Input aria-label="Namespace" placeholder="Namespace" value={f.namespace} onChange={(e) => setF({ ...f, namespace: e.target.value })} />
          <Input aria-label="Label key" placeholder="Label key" value={f.label_key} onChange={(e) => setF({ ...f, label_key: e.target.value })} />
          <Input aria-label="Label value" placeholder="Label value" value={f.label_value} onChange={(e) => setF({ ...f, label_value: e.target.value })} />
          <Select aria-label="Application" value={f.application_id} onChange={(e) => setF({ ...f, application_id: e.target.value })}>
            <option value="">Application…</option>{apps.data?.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </Select>
          <Button disabled={!f.application_id || (!f.namespace.trim() && !f.label_key.trim()) || add.isPending} onClick={() => add.mutate()}><Plus /> Add mapping</Button>
        </div>
      )}
      {list.isError ? <div className="p-3"><Alert>{list.error.message}</Alert></div> : list.isPending ? <Skeleton className="m-3 h-12" /> : !list.data.length ? (
        <p className="px-4 pb-4 text-[12px] text-muted-foreground">No mapping yet. Unmapped workloads still link to findings through their images.</p>
      ) : (
        <Table>
          <thead><tr><Th>Condition</Th><Th>Application</Th><Th className="text-right">Workloads of the application</Th>{manage && <Th />}</tr></thead>
          <tbody>
            {list.data.map((m) => (
              <tr key={m.id}>
                <Td className="text-[12px]">
                  {[m.cluster_name && `cluster ${m.cluster_name}`, m.namespace && `namespace ${m.namespace}`, m.label_key && `label ${m.label_key}${m.label_value ? `=${m.label_value}` : ""}`].filter(Boolean).join(" and ")}
                </Td>
                <Td>{m.application_name}</Td>
                <Td className="tabular text-right">{m.application_workloads}</Td>
                {manage && <Td className="text-right"><Button size="icon" variant="ghost" aria-label="Delete mapping" onClick={() => remove.mutate(m.id)}><Trash2 /></Button></Td>}
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

// --- page -----------------------------------------------------------------------------

const tabs = [
  { key: "workloads", label: "Workloads" },
  { key: "clusters", label: "Clusters" },
  { key: "registries", label: "Registries" },
  { key: "mappings", label: "Application mappings" },
] as const;

export function RuntimePage() {
  const summary = useRuntimeSummary();
  const clusters = useClusters();
  const [tab, setTab] = useState<(typeof tabs)[number]["key"]>("workloads");
  const s = summary.data;
  const none = clusters.data && !clusters.data.items.length;
  return (
    <>
      <PageHeader title="Runtime" description="What runs in your Kubernetes clusters, which images and digests, how it is exposed, and which findings it carries. Read-only; synchronised by the jobs service." />
      {summary.isError && <div className="mb-3"><Alert>{summary.error.message}</Alert></div>}
      {s && s.clusters > 0 && (
        <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
          {[
            ["Workloads", s.workloads], ["Internet-exposed workloads", s.internet_exposed_workloads], ["Privileged workloads", s.privileged_workloads],
            ["Running images linked to scans", `${s.linked_images} of ${s.running_images}`], ["Open findings deployed", s.deployed_findings], ["… of them internet-exposed", s.exposed_findings],
          ].map(([label, v]) => (
            <Card key={label as string} className="p-3">
              <div className="text-[11.5px] text-muted-foreground">{label}</div>
              <div className="tabular text-lg font-semibold">{v}</div>
            </Card>
          ))}
        </div>
      )}
      <div className="mb-3 flex flex-wrap gap-1" role="tablist">
        {tabs.map((t) => (
          <button key={t.key} type="button" role="tab" aria-selected={tab === t.key} onClick={() => setTab(t.key)}
            className={cn("rounded-md px-3 py-1.5 text-[12.5px]", tab === t.key ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-surface-muted")}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === "workloads" && (none ? <ClustersTab /> : <WorkloadsTab />)}
      {tab === "clusters" && <ClustersTab />}
      {tab === "registries" && <RegistriesTab />}
      {tab === "mappings" && <MappingsTab />}
    </>
  );
}

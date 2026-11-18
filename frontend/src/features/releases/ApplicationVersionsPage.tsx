import { useState, type FormEvent } from "react";
import { Link, useParams } from "@tanstack/react-router";
import { Download, Milestone, Plus, Trash2, Upload } from "lucide-react";
import { api } from "@/api/client";
import type { Severity } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { SeverityBadge } from "@/components/data/Severity";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { readVexFile, useReleasesMutation, useVersion, useVersions, type AppVersion, type ImportResult } from "./api";

/** Route wrapper: /applications/$id/versions. */
export function ApplicationVersionsRoute() {
  const { id } = useParams({ strict: false }) as { id: string };
  return <ApplicationVersionsPage appId={id} />;
}

export function ApplicationVersionsPage({ appId }: { appId: string }) {
  const versions = useVersions(appId);
  const [creating, setCreating] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const data = versions.data;
  return (
    <>
      <PageHeader
        title={data ? `${data.application.name}: versions` : "Application versions"}
        description="Releases freeze the commit, SBOM and findings of each repository at the time they are created, so you can tell which shipped versions contain a vulnerable component and export VEX for them."
        actions={data?.can_manage && <Button onClick={() => setCreating(true)}><Plus /> New version</Button>}
      />
      <div className="mb-3 text-[12.5px]"><Link to="/applications" className="text-primary hover:underline">← Applications</Link></div>
      {versions.isError && <Alert>{versions.error.message}</Alert>}
      <Card>
        {versions.isPending ? <Skeleton className="h-32" /> : !data?.items.length ? (
          <EmptyState icon={<Milestone />} title="No versions yet">
            Create a version when you release: PATHOS records the latest successful scan of each repository of the application.
          </EmptyState>
        ) : (
          <Table>
            <thead><tr><Th>Version</Th><Th>Released</Th><Th>Repositories</Th><Th>Components</Th><Th>Open findings</Th><Th>Created</Th></tr></thead>
            <tbody>
              {data.items.map((v) => (
                <tr key={v.id} className="cursor-pointer hover:bg-muted/40" onClick={() => setOpen(v.id)}>
                  <Td><button type="button" className="font-mono font-medium text-primary hover:underline">{v.version}</button>{v.description && <div className="max-w-sm truncate text-[12px] text-muted-foreground">{v.description}</div>}</Td>
                  <Td className="tabular">{v.released_at ? formatDateTime(v.released_at) : "—"}</Td>
                  <Td className="tabular">{v.repository_count}</Td>
                  <Td className="tabular">{v.component_count}</Td>
                  <Td className="tabular">{v.open_findings}</Td>
                  <Td className="text-[12px] text-muted-foreground">{formatDateTime(v.created_at)}{v.created_by && ` · ${v.created_by}`}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <CreateVersionDialog appId={appId} open={creating} onClose={() => setCreating(false)} onCreated={(id) => setOpen(id)} />
      <VersionDrawer appId={appId} versionId={open} onClose={() => setOpen(null)} />
    </>
  );
}

function CreateVersionDialog({ appId, open, onClose, onCreated }: { appId: string; open: boolean; onClose: () => void; onCreated: (id: string) => void }) {
  const [version, setVersion] = useState("");
  const [description, setDescription] = useState("");
  const [released, setReleased] = useState("");
  const [warnings, setWarnings] = useState<string[]>([]);
  const create = useReleasesMutation((body: unknown) =>
    api<{ version: AppVersion; warnings: string[] }>(`/api/v1/applications/${appId}/versions`, { method: "POST", body }));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate(
      { version, description, released_at: released ? new Date(released).toISOString() : null },
      {
        onSuccess: (r) => {
          setWarnings(r.warnings);
          setVersion(""); setDescription(""); setReleased("");
          if (!r.warnings.length) onClose();
          onCreated(r.version.id);
        },
      },
    );
  };
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) { setWarnings([]); create.reset(); onClose(); } }} title="New application version"
      description="Freezes each repository's latest successful scan: commit, component inventory and findings.">
      <form onSubmit={submit} className="space-y-3">
        <div><Label htmlFor="ver">Version</Label><Input id="ver" required maxLength={100} placeholder="2.3.1" value={version} onChange={(e) => setVersion(e.target.value)} /></div>
        <div><Label htmlFor="ver-desc">Description</Label><Input id="ver-desc" maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} /></div>
        <div><Label htmlFor="ver-date" hint="Optional">Release date</Label><Input id="ver-date" type="date" value={released} onChange={(e) => setReleased(e.target.value)} /></div>
        {create.isError && <Alert>{create.error.message}</Alert>}
        {warnings.length > 0 && <Alert tone="warning">Created with warnings:<ul className="ml-4 list-disc">{warnings.map((w) => <li key={w}>{w}</li>)}</ul></Alert>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>Close</Button>
          <Button type="submit" disabled={!version.trim() || create.isPending}>{create.isPending ? "Creating…" : "Create version"}</Button>
        </div>
      </form>
    </Dialog>
  );
}

function VersionDrawer({ appId, versionId, onClose }: { appId: string; versionId: string | null; onClose: () => void }) {
  const { can } = useSession();
  const d = useVersion(appId, versionId);
  const [confirm, setConfirm] = useState(false);
  const [imported, setImported] = useState<ImportResult | null>(null);
  const [fileErr, setFileErr] = useState<string | null>(null);
  const del = useReleasesMutation(() => api(`/api/v1/applications/${appId}/versions/${versionId}`, { method: "DELETE" }));
  const importVex = useReleasesMutation(({ doc, name }: { doc: unknown; name: string }) =>
    api<ImportResult>(`/api/v1/applications/${appId}/versions/${versionId}/vex?filename=${encodeURIComponent(name)}`, { method: "POST", body: doc }));
  const v = d.data?.version;
  const base = `/api/v1/applications/${appId}/versions/${versionId}`;
  const onFile = async (f: File | undefined) => {
    setFileErr(null); setImported(null);
    if (!f) return;
    try {
      const doc = await readVexFile(f);
      importVex.mutate({ doc, name: f.name }, { onSuccess: setImported });
    } catch (e) {
      setFileErr((e as Error).message);
    }
  };
  return (
    <Dialog side size="xl" open={!!versionId} onOpenChange={(o) => { if (!o) { setImported(null); onClose(); } }}
      title={v ? `Version ${v.version}` : "Version"} description={d.data?.application.name}>
      {d.isError ? <Alert>{d.error.message}</Alert> : !d.data || !v ? <Skeleton className="h-40" /> : (
        <div className="space-y-5 text-[13px]">
          <div className="flex flex-wrap items-center gap-2">
            {can("findings.export") && (
              <>
                <a className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-[12.5px] hover:bg-muted" href={`${base}/vex?format=openvex`} download><Download className="size-3.5" /> OpenVEX</a>
                <a className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-[12.5px] hover:bg-muted" href={`${base}/vex?format=cyclonedx`} download><Download className="size-3.5" /> CycloneDX VEX</a>
              </>
            )}
            {can("findings.triage") && (
              <label className="inline-flex cursor-pointer items-center gap-1 rounded-md border border-border px-2.5 py-1 text-[12.5px] hover:bg-muted">
                <Upload className="size-3.5" /> Import VEX
                <input type="file" accept=".json,application/json" className="sr-only" aria-label="Import VEX document" onChange={(e) => { void onFile(e.target.files?.[0]); e.target.value = ""; }} />
              </label>
            )}
            {d.data.can_manage && <Button size="sm" variant="secondary" onClick={() => setConfirm(true)}><Trash2 /> Delete version</Button>}
          </div>
          {(fileErr || importVex.isError) && <Alert>{fileErr ?? importVex.error?.message}</Alert>}
          {imported && <ImportSummary r={imported} />}
          {v.description && <p className="text-muted-foreground">{v.description}</p>}
          <section>
            <h3 className="mb-1 text-[13px] font-semibold">Repositories ({d.data.repositories.length})</h3>
            <ul className="divide-y divide-border rounded-md border border-border">
              {d.data.repositories.map((r) => (
                <li key={r.repository_id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-[12.5px]">
                  <span className="font-medium">{r.full_name}</span>
                  <span className="font-mono text-[12px] text-muted-foreground">{r.scan_job_id ? `${r.ref} @ ${r.commit_sha ? r.commit_sha.slice(0, 12) : "unknown commit"}` : "no successful scan at release"}</span>
                </li>
              ))}
            </ul>
          </section>
          <section>
            <h3 className="mb-1 text-[13px] font-semibold">Findings at release ({d.data.findings.length})</h3>
            {d.data.findings.length === 0 ? <p className="text-muted-foreground">None recorded (or none you may see).</p> : (
              <Table>
                <thead><tr><Th>Severity</Th><Th>Finding</Th><Th>Package</Th><Th>At release</Th><Th>Now</Th></tr></thead>
                <tbody>
                  {d.data.findings.map((f, i) => (
                    <tr key={f.finding_id ?? i}>
                      <Td><SeverityBadge value={f.severity as Severity} /></Td>
                      <Td>{f.cve ? <Link to="/vulnerabilities/$id" params={{ id: f.cve }} className="font-mono text-[12px] text-primary hover:underline">{f.cve}</Link> : null} <span>{f.title}</span></Td>
                      <Td className="font-mono text-[12px]">{f.package_name ? `${f.package_name}@${f.package_version}` : "—"}</Td>
                      <Td className="text-[12px]">{f.status_at_release.replace("_", " ")}</Td>
                      <Td className="text-[12px]">{f.status.replace("_", " ")}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </section>
          <section>
            <h3 className="mb-1 text-[13px] font-semibold">Components ({d.data.components.length})</h3>
            {d.data.components.length === 0 ? <p className="text-muted-foreground">No component inventory recorded (or none you may see).</p> : (
              <div className="max-h-96 overflow-auto rounded-md border border-border">
                <Table>
                  <thead><tr><Th>Component</Th><Th>Version</Th><Th>Licences</Th></tr></thead>
                  <tbody>
                    {d.data.components.map((c, i) => (
                      <tr key={`${c.repository_id}-${c.purl || c.name}-${i}`}>
                        <Td><div className="font-medium">{c.name}</div><div className="font-mono text-[11px] text-muted-foreground">{c.purl}</div></Td>
                        <Td className="font-mono text-[12px]">{c.version || "—"}</Td>
                        <Td className="text-[12px]">{c.licenses.join(", ") || "unknown"}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            )}
          </section>
        </div>
      )}
      <ConfirmDialog open={confirm} onOpenChange={setConfirm} title={`Delete version ${v?.version ?? ""}?`} confirmLabel="Delete"
        pending={del.isPending} error={del.error?.message ?? null}
        onConfirm={() => del.mutate(undefined, { onSuccess: () => { setConfirm(false); onClose(); } })}>
        The frozen SBOM and findings snapshot of this version are removed. Findings themselves are not changed.
      </ConfirmDialog>
    </Dialog>
  );
}

export function ImportSummary({ r }: { r: ImportResult }) {
  return (
    <Alert tone="success">
      Imported {r.statements} statement{r.statements === 1 ? "" : "s"} ({r.format}): {r.matched} matched a finding,{" "}
      <strong>{r.suggestions} suggestion{r.suggestions === 1 ? "" : "s"}</strong> await review, {r.informational} informational, {r.unmatched} unmatched.{" "}
      Nothing changes until another reviewer approves on the <Link to="/vex" className="underline">VEX review</Link> page.
      {r.suggestions === 0 && <Badge className="ml-2">nothing to review</Badge>}
    </Alert>
  );
}

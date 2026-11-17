import { useEffect, useState } from "react";
import { Lock, Plus, Star } from "lucide-react";
import { api } from "@/api/client";
import type { ProfileSettings, ScanProfile, Severity } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, Input, Label, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { useCatalog, useProfile, useProfiles, useScanMutation } from "./api";

export function ProfilesPage() {
  const { canOrgWide } = useSession();
  const profiles = useProfiles();
  const catalog = useCatalog();
  const [editing, setEditing] = useState<string | "new" | null>(null);
  const manage = canOrgWide("profiles.manage");
  const name = (k: string) => catalog.data?.find((s) => s.key === k)?.name ?? k;

  return (
    <>
      <PageHeader title="Scan profiles" description="Which scanners run and how. Every change creates a new immutable version; each scan records the version it ran with."
        actions={manage && <Button onClick={() => setEditing("new")}><Plus /> New profile</Button>} />
      {profiles.isPending ? <Skeleton className="h-32" /> : (
        <div className="grid gap-3 lg:grid-cols-2">
          {(profiles.data ?? []).map((p) => (
            <Card key={p.id} className="cursor-pointer p-4 hover:border-primary/40" onClick={() => setEditing(p.id)}>
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2 font-semibold">{p.name}{p.is_default && <Badge tone="primary"><Star className="size-3" /> default</Badge>}</div>
                  {p.description && <p className="text-[12px] text-muted-foreground">{p.description}</p>}
                </div>
                <span className="tabular text-[12px] text-muted-foreground">v{p.current.version}</span>
              </div>
              <div className="mt-3 flex flex-wrap gap-1">
                {p.current.scanners.map((s) => <Badge key={s.key}>{name(s.key)}</Badge>)}
              </div>
              <div className="mt-3 text-[12px] text-muted-foreground">
                Threshold {p.current.severity_threshold} · timeout {Math.round(p.current.timeout_seconds / 60)} min · retention {p.current.retention_days} d
                {p.current.fail_on_critical && " · fails on new critical"} · {p.is_default ? "applies to repositories without a profile" : `${p.repository_count} repositories`}
              </div>
            </Card>
          ))}
        </div>
      )}
      <ProfileEditor id={editing} onClose={() => setEditing(null)} readOnly={!manage} />
    </>
  );
}

const blank: ProfileSettings = { severity_threshold: "info", exclusions: [], timeout_seconds: 1800, sbom: true, fail_on_critical: false, retention_days: 90, scanners: [] };

function ProfileEditor({ id, onClose, readOnly }: { id: string | "new" | null; onClose: () => void; readOnly: boolean }) {
  const isNew = id === "new";
  const profile = useProfile(id && !isNew ? id : undefined);
  const catalog = useCatalog();
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [note, setNote] = useState("");
  const [st, setSt] = useState<ProfileSettings>(blank);
  const [excl, setExcl] = useState("");
  useEffect(() => {
    const p: ScanProfile | undefined = profile.data;
    const base = p ? p.current : { ...blank, scanners: (catalog.data ?? []).filter((s) => s.default_enabled).map((s) => ({ key: s.key })) };
    setName(p?.name ?? "");
    setDesc(p?.description ?? "");
    setNote("");
    setSt({ ...base, scanners: base.scanners.map((s) => ({ key: s.key })) });
    setExcl(base.exclusions.join("\n"));
  }, [profile.data, id, catalog.data]);

  const save = useScanMutation((body: unknown) =>
    isNew ? api("/api/v1/scan-profiles", { method: "POST", body }) : api(`/api/v1/scan-profiles/${id}`, { method: "PUT", body }));
  const makeDefault = useScanMutation(() => api(`/api/v1/scan-profiles/${id}/default`, { method: "POST" }));
  const archive = useScanMutation(() => api(`/api/v1/scan-profiles/${id}`, { method: "DELETE" }));
  const enabled = new Set(st.scanners.map((s) => s.key));
  const toggle = (key: string) =>
    setSt({ ...st, scanners: enabled.has(key) ? st.scanners.filter((s) => s.key !== key) : [...st.scanners, { key }] });
  const runnable = (catalog.data ?? []).filter((s) => s.adapter_available && !s.target_only && s.key !== "syft");
  const error = save.error ?? makeDefault.error ?? archive.error;

  const submit = () =>
    save.mutate(
      { ...(isNew || name !== profile.data?.name ? { name } : {}), description: desc, change_note: note, ...st,
        exclusions: excl.split("\n").map((s) => s.trim()).filter(Boolean),
        scanners: st.scanners.filter((s) => s.key !== "syft") },
      { onSuccess: onClose },
    );

  return (
    <Dialog side open={!!id} onOpenChange={(o) => !o && onClose()} title={isNew ? "New scan profile" : profile.data?.name ?? "Scan profile"}
      description={profile.data ? `Version ${profile.data.current.version}` : undefined}
      footer={readOnly ? undefined : (
        <>
          {!isNew && profile.data && !profile.data.is_default && (
            <>
              <Button variant="danger-outline" className="mr-auto" onClick={() => archive.mutate(undefined, { onSuccess: onClose })}>Archive</Button>
              <Button variant="secondary" onClick={() => makeDefault.mutate(undefined)}>Make default</Button>
            </>
          )}
          <Button onClick={submit} disabled={save.isPending || !name.trim()}>{isNew ? "Create" : "Save as new version"}</Button>
        </>
      )}>
      {!isNew && !profile.data ? <Skeleton className="h-60" /> : (
        <fieldset disabled={readOnly} className="space-y-4 text-[13px]">
          {error && <Alert>{error.message}</Alert>}
          <div className="grid grid-cols-2 gap-3">
            <div><Label htmlFor="pf-name">Name</Label><Input id="pf-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={200} /></div>
            <div><Label htmlFor="pf-desc" hint="(optional)">Description</Label><Input id="pf-desc" value={desc} onChange={(e) => setDesc(e.target.value)} /></div>
          </div>
          <div>
            <div className="mb-1.5 text-[12px] font-medium">Scanners</div>
            <div className="grid gap-1.5 sm:grid-cols-2">
              {runnable.map((s) => (
                <label key={s.key} className={`flex items-start gap-2 rounded-md border p-2 ${enabled.has(s.key) ? "border-primary/40 bg-primary/5" : "border-border"}`}>
                  <input type="checkbox" className="mt-0.5 accent-[var(--primary)]" checked={s.mandatory || enabled.has(s.key)} disabled={s.mandatory} onChange={() => toggle(s.key)} />
                  <span>
                    <span className="flex items-center gap-1 font-medium">{s.name}{s.mandatory && <Lock className="size-3 text-muted-foreground" aria-label="Always on" />}</span>
                    <span className="block text-[11.5px] text-muted-foreground">{s.category.toUpperCase()} · {s.license_spdx}{s.notes && ` · ${s.notes}`}</span>
                  </span>
                </label>
              ))}
            </div>
          </div>
          <label className="flex items-center gap-2"><input type="checkbox" className="accent-[var(--primary)]" checked={st.sbom} onChange={(e) => setSt({ ...st, sbom: e.target.checked })} /> Generate an SBOM (Syft, CycloneDX). Required by Grype.</label>
          <label className="flex items-center gap-2"><input type="checkbox" className="accent-[var(--primary)]" checked={st.fail_on_critical} onChange={(e) => setSt({ ...st, fail_on_critical: e.target.checked })} /> Mark the scan's security gate as failed when new critical findings appear</label>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <Label htmlFor="pf-th">Record severities from</Label>
              <Select id="pf-th" className="w-full capitalize" value={st.severity_threshold} onChange={(e) => setSt({ ...st, severity_threshold: e.target.value as Severity })}>
                {["info", "low", "medium", "high", "critical"].map((v) => <option key={v} value={v}>{v}</option>)}
              </Select>
            </div>
            <div><Label htmlFor="pf-to">Timeout (min)</Label><Input id="pf-to" type="number" min={1} max={240} value={Math.round(st.timeout_seconds / 60)} onChange={(e) => setSt({ ...st, timeout_seconds: Number(e.target.value) * 60 })} /></div>
            <div><Label htmlFor="pf-ret">Raw report retention (days)</Label><Input id="pf-ret" type="number" min={7} max={3650} value={st.retention_days} onChange={(e) => setSt({ ...st, retention_days: Number(e.target.value) })} /></div>
          </div>
          <div>
            <Label htmlFor="pf-ex" hint="(one glob per line, e.g. vendor/** or **/*_test.go)">Exclusions</Label>
            <textarea id="pf-ex" rows={4} value={excl} onChange={(e) => setExcl(e.target.value)} className="w-full rounded-md border border-border bg-surface p-2 font-mono text-[12px] focus-visible:outline-2 focus-visible:outline-ring" />
          </div>
          {!isNew && !readOnly && <div><Label htmlFor="pf-note" hint="(recorded in the version history)">Change note</Label><Input id="pf-note" value={note} onChange={(e) => setNote(e.target.value)} /></div>}
          {profile.data?.history && profile.data.history.length > 0 && (
            <div>
              <div className="mb-1.5 text-[12px] font-medium">Version history</div>
              <ul className="divide-y divide-border rounded-md border border-border text-[12px]">
                {profile.data.history.map((v) => (
                  <li key={v.id} className="flex justify-between gap-3 px-3 py-1.5">
                    <span><span className="font-medium">v{v.version}</span> {v.change_note && `· ${v.change_note}`} <span className="text-muted-foreground">· {v.scanners.length} scanners</span></span>
                    <span className="tabular text-muted-foreground">{v.created_by ?? "system"} · {formatDateTime(v.created_at)}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </fieldset>
      )}
    </Dialog>
  );
}

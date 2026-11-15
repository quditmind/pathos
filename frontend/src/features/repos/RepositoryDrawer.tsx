import { useEffect, useState } from "react";
import { ExternalLink } from "lucide-react";
import { api } from "@/api/client";
import type { Repository } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Input, Label, Select, Skeleton } from "@/components/ui/primitives";
import { CriticalityBadge, TagChip } from "@/components/data/TagChip";
import { useSession } from "@/features/auth/session";
import { useBusinessUnits, useRegions } from "@/features/users/api";
import { formatDateTime } from "@/lib/utils";
import { useApplications, useBranches, useRepoMutation, useRepository, useTagCategories } from "./api";
import { Link } from "@tanstack/react-router";
import { Radar } from "lucide-react";
import { JobStatusPill } from "@/components/data/Severity";
import { scanRepo, useProfiles, useScanMutation, useScans } from "@/features/scans/api";

interface Draft {
  application_id: string;
  business_unit_id: string;
  country_id: string;
  environment: string;
  criticality: string;
  scan_branch: string;
  scan_enabled: boolean;
  technologies: string;
  tag_ids: Set<string>;
}

function toDraft(r: Repository): Draft {
  return {
    application_id: r.application?.id ?? "",
    business_unit_id: r.business_unit?.id ?? "",
    country_id: r.country?.id ?? "",
    environment: r.environment,
    criticality: r.criticality,
    scan_branch: r.scan_branch,
    scan_enabled: r.scan_enabled,
    technologies: r.technologies.join(", "),
    tag_ids: new Set(r.tags.map((t) => t.id)),
  };
}

export function RepositoryDrawer({ id, onClose }: { id?: string; onClose: () => void }) {
  const { can } = useSession();
  const repo = useRepository(id);
  const r = repo.data;
  const [draft, setDraft] = useState<Draft | null>(null);
  const [editing, setEditing] = useState(false);
  const branches = useBranches(id, editing);
  const apps = useApplications();
  const bus = useBusinessUnits();
  const regions = useRegions();
  const cats = useTagCategories();
  useEffect(() => {
    if (r) setDraft(toDraft(r));
  }, [r]);
  useEffect(() => setEditing(false), [id]);

  const save = useRepoMutation((body: unknown) => api<Repository>(`/api/v1/repositories/${id}`, { method: "PATCH", body }));
  const action = useRepoMutation((path: string) => api(`/api/v1/repositories/${id}/${path}`, { method: "POST" }));
  const del = useRepoMutation(() => api(`/api/v1/repositories/${id}`, { method: "DELETE" }));
  const canManage = can("repos.manage");
  const scan = useScanMutation(() => scanRepo(id!));
  const scans = useScans({ repository_id: id }, !!id);
  const profiles = useProfiles();
  const setProfile = useRepoMutation((profile_id: string | null) => api(`/api/v1/repositories/${id}/scan-profile`, { method: "PUT", body: { profile_id } }));
  const recent = scans.data?.pages[0]?.items.slice(0, 5) ?? [];
  const error = save.error ?? action.error ?? del.error;

  const submit = () => {
    if (!r || !draft) return;
    const orig = toDraft(r);
    const body: Record<string, unknown> = {};
    const nul = (v: string) => (v === "" ? null : v);
    if (draft.application_id !== orig.application_id) body.application_id = nul(draft.application_id);
    if (draft.business_unit_id !== orig.business_unit_id) body.business_unit_id = nul(draft.business_unit_id);
    if (draft.country_id !== orig.country_id) body.country_id = nul(draft.country_id);
    if (draft.environment !== orig.environment) body.environment = draft.environment;
    if (draft.criticality !== orig.criticality) body.criticality = draft.criticality;
    if (draft.scan_branch !== orig.scan_branch) body.scan_branch = draft.scan_branch;
    if (draft.scan_enabled !== orig.scan_enabled) body.scan_enabled = draft.scan_enabled;
    if (draft.technologies !== orig.technologies)
      body.technologies = draft.technologies
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
    if ([...draft.tag_ids].sort().join() !== [...orig.tag_ids].sort().join()) body.tag_ids = [...draft.tag_ids];
    if (!Object.keys(body).length) return setEditing(false);
    save.mutate(body, { onSuccess: () => setEditing(false) });
  };

  const toggleTag = (catId: string, tagId: string, multiple: boolean) => {
    if (!draft) return;
    const next = new Set(draft.tag_ids);
    if (next.has(tagId)) next.delete(tagId);
    else {
      if (!multiple) for (const t of cats.data?.find((c) => c.id === catId)?.tags ?? []) next.delete(t.id);
      next.add(tagId);
    }
    setDraft({ ...draft, tag_ids: next });
  };

  return (
    <Dialog
      side
      open={!!id}
      onOpenChange={(o) => {
        if (!o) {
          save.reset();
          action.reset();
          onClose();
        }
      }}
      title={r?.full_name ?? "Repository"}
      description={r ? `${r.scm_connection_name} · ${r.visibility}` : undefined}
      footer={
        r && canManage ? (
          editing ? (
            <>
              <Button variant="secondary" onClick={() => { setEditing(false); setDraft(toDraft(r)); save.reset(); }}>
                Cancel
              </Button>
              <Button onClick={submit} disabled={save.isPending}>
                Save changes
              </Button>
            </>
          ) : (
            <>
              {r.archived_at ? (
                <>
                  <Button variant="danger-outline" disabled={del.isPending} onClick={() => del.mutate(undefined, { onSuccess: onClose })}>
                    Delete permanently
                  </Button>
                  <Button variant="secondary" onClick={() => action.mutate("unarchive")}>
                    Unarchive
                  </Button>
                </>
              ) : (
                <>
                  <Button variant="danger-outline" onClick={() => action.mutate("archive")}>
                    Archive
                  </Button>
                  <Button onClick={() => setEditing(true)}>Edit</Button>
                </>
              )}
            </>
          )
        ) : undefined
      }
    >
      {!r || !draft ? (
        repo.isError ? <Alert>{repo.error.message}</Alert> : <Skeleton className="h-40" />
      ) : (
        <div className="space-y-5 text-[13px]">
          {error && <Alert>{error.message}</Alert>}
          {r.remote_archived && <Alert tone="warning">This repository is archived in the SCM.</Alert>}
          <div className="flex flex-wrap items-center gap-3">
            <a href={r.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
              Open in SCM <ExternalLink className="size-3.5" />
            </a>
            {can("scans.run") && !r.archived_at && (
              <Button size="sm" variant="secondary" disabled={scan.isPending} onClick={() => scan.mutate(undefined)}>
                <Radar /> {scan.isSuccess ? (scan.data.coalesced ? "Already queued" : "Scan queued") : "Scan now"}
              </Button>
            )}
            {can("findings.read") && (
              <Link to="/findings" search={{ repository_id: r.id } as never} className="text-primary hover:underline">Findings →</Link>
            )}
            {can("findings.read") && (
              <a href={`/api/v1/repositories/${r.id}/sbom`} className="text-primary hover:underline" download>SBOM (CycloneDX)</a>
            )}
          </div>
          {scan.isError && <Alert>{scan.error.message}</Alert>}
          {r.description && <p className="text-muted-foreground">{r.description}</p>}

          {!editing ? (
            <>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
                <Field label="Criticality"><CriticalityBadge value={r.criticality} /></Field>
                <Field label="Environment"><span className="capitalize">{r.environment}</span></Field>
                <Field label="Application">{r.application?.name ?? "—"}</Field>
                <Field label="Business unit">{r.business_unit?.name ?? "—"}</Field>
                <Field label="Country">{r.country ? `${r.country.name} (${r.region?.name})` : "—"}</Field>
                <Field label="Scan branch">{r.scan_branch || `${r.default_branch} (default)`}</Field>
                <Field label="Scanning">{r.scan_enabled ? "Enabled" : "Disabled"}</Field>
                <Field label="Technologies">{r.technologies.join(", ") || "—"}</Field>
                <Field label="Imported">{formatDateTime(r.created_at)}</Field>
                <Field label="Last push">{formatDateTime(r.last_pushed_at)}</Field>
              </dl>
              <div>
                <Label htmlFor="repo-profile">Scan profile</Label>
                <Select id="repo-profile" className="w-full" disabled={!canManage || setProfile.isPending}
                  value={r.scan_profile_id ?? ""}
                  onChange={(e) => setProfile.mutate(e.target.value || null)}>
                  <option value="">Organization default</option>
                  {(profiles.data ?? []).filter((p) => !p.is_default).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </Select>
              </div>
              {recent.length > 0 && (
                <div>
                  <div className="mb-1.5 text-[12px] text-muted-foreground">Recent scans</div>
                  <ul className="divide-y divide-border rounded-md border border-border">
                    {recent.map((j) => (
                      <li key={j.id} className="flex items-center justify-between gap-2 px-3 py-1.5 text-[12px]">
                        <JobStatusPill status={j.status} />
                        <span className="tabular text-muted-foreground">+{j.findings_new} / −{j.findings_fixed}</span>
                        <Link to="/scans" search={{ job: j.id } as never} className="tabular text-primary hover:underline">{formatDateTime(j.queued_at)}</Link>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <div>
                <div className="mb-1.5 text-[12px] text-muted-foreground">Tags</div>
                <div className="flex flex-wrap gap-1">
                  {r.tags.length ? r.tags.map((t) => <TagChip key={t.id} name={t.name} category={t.category_name} color={t.color} />) : "—"}
                </div>
              </div>
            </>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <SelectField label="Criticality" value={draft.criticality} onChange={(v) => setDraft({ ...draft, criticality: v })}
                  options={["critical", "high", "medium", "low"].map((v) => [v, v])} />
                <SelectField label="Environment" value={draft.environment} onChange={(v) => setDraft({ ...draft, environment: v })}
                  options={["production", "staging", "development", "test", "other"].map((v) => [v, v])} />
                <SelectField label="Application" value={draft.application_id} onChange={(v) => setDraft({ ...draft, application_id: v })}
                  options={[["", "None"], ...(apps.data ?? []).map((a) => [a.id, a.name] as [string, string])]} />
                <SelectField label="Business unit" value={draft.business_unit_id} onChange={(v) => setDraft({ ...draft, business_unit_id: v })}
                  options={[["", "None"], ...(bus.data ?? []).map((b) => [b.id, b.name] as [string, string])]} />
                <SelectField label="Country" value={draft.country_id} onChange={(v) => setDraft({ ...draft, country_id: v })}
                  options={[["", "None"], ...(regions.data ?? []).flatMap((rg) => rg.countries.map((c) => [c.id, `${c.name} · ${rg.code}`] as [string, string])).sort((a, b) => a[1].localeCompare(b[1]))]} />
                <div>
                  <Label htmlFor="scan-branch" hint={branches.isFetching ? "(loading…)" : undefined}>Scan branch</Label>
                  <Select id="scan-branch" className="w-full" value={draft.scan_branch} onChange={(e) => setDraft({ ...draft, scan_branch: e.target.value })}>
                    <option value="">Default ({r.default_branch || "unknown"})</option>
                    {(branches.data?.items ?? (draft.scan_branch ? [draft.scan_branch] : [])).map((b) => (
                      <option key={b} value={b}>{b}</option>
                    ))}
                  </Select>
                  {branches.isError && <p className="mt-1 text-[11px] text-danger">Could not load branches: {branches.error.message}</p>}
                </div>
              </div>
              <div>
                <Label htmlFor="techs" hint="(comma-separated)">Technologies</Label>
                <Input id="techs" value={draft.technologies} onChange={(e) => setDraft({ ...draft, technologies: e.target.value })} />
              </div>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={draft.scan_enabled} onChange={(e) => setDraft({ ...draft, scan_enabled: e.target.checked })} className="accent-[var(--primary)]" />
                Include in scheduled scans
              </label>
              <div className="space-y-3">
                {(cats.data ?? []).map((c) => (
                  <div key={c.id}>
                    <div className="mb-1 text-[12px] font-medium">
                      {c.name} {c.is_mandatory && <span className="text-danger">*</span>}
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {c.tags.map((t) => (
                        <button key={t.id} type="button" onClick={() => toggleTag(c.id, t.id, c.allow_multiple)}
                          className={draft.tag_ids.has(t.id) ? "rounded ring-2 ring-primary" : "rounded opacity-60 hover:opacity-100"}>
                          <TagChip name={t.name} color={t.color} />
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Dialog>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-[12px] text-muted-foreground">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  );
}

function SelectField({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: [string, string][] }) {
  const id = `f-${label.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <div>
      <Label htmlFor={id}>{label}</Label>
      <Select id={id} className="w-full capitalize" value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map(([v, l]) => (
          <option key={v} value={v}>{l}</option>
        ))}
      </Select>
    </div>
  );
}

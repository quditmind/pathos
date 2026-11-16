import { useEffect, useMemo, useState } from "react";
import { ExternalLink, Pencil } from "lucide-react";
import { api, ApiError } from "@/api/client";
import type { AssetField, FieldErrors, Repository } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Input, Label, Select, Skeleton } from "@/components/ui/primitives";
import { ColorDot, CriticalityBadge } from "@/components/data/TagChip";
import { catalogEntry, useAssetSettings } from "@/features/assets/api";
import { useSession } from "@/features/auth/session";
import { cn, formatDateTime } from "@/lib/utils";
import { useBranches, useInvalidateRepos, useRepoMutation, useRepository, useTagCategories } from "./api";
import { MetadataSection } from "./metadata/MetadataSections";
import { MetadataSummary } from "./metadata/MetadataSummary";
import { clientErrors, diffMetadata, draftFromRepository, sectionForKey, sections, type MetadataDraft } from "./metadata/model";
import { SecurityPanel } from "./SecurityPanel";
import { SourcePanel } from "./SourcePanel";

type Tab = "details" | "source" | "security";

interface ScanDraft {
  scan_branch: string;
  scan_enabled: boolean;
  technologies: string;
  full_history: boolean;
}

const scanDraft = (r: Repository): ScanDraft => ({
  scan_branch: r.scan_branch,
  scan_enabled: r.scan_enabled,
  technologies: r.technologies.join(", "),
  full_history: r.full_history,
});

export function RepositoryDrawer({ id, onClose }: { id?: string; onClose: () => void }) {
  const repo = useRepository(id);
  const r = repo.data;
  const [tab, setTab] = useState<Tab>("details");
  useEffect(() => setTab("details"), [id]);
  const crit = useAssetSettings();
  const c = r ? catalogEntry(crit.data, "criticality", r.criticality) : undefined;

  return (
    <Dialog
      side
      size="lg"
      open={!!id}
      onOpenChange={(o) => !o && onClose()}
      title={r ? r.display_name || r.full_name : "Repository"}
      description={r ? `${r.full_name} · ${r.source_type === "upload" ? "Uploaded" : r.scm_connection_name} · ${r.visibility}` : undefined}
    >
      {!r ? (
        repo.isError ? (
          <Alert>
            {repo.error.message}{" "}
            <button className="underline" onClick={() => void repo.refetch()}>
              Try again
            </button>
          </Alert>
        ) : (
          <Skeleton className="h-40" />
        )
      ) : (
        <div className="space-y-4 text-[13px]">
          <div className="flex flex-wrap items-center gap-2">
            <ColorDot color={r.color} label={r.color ? "Asset colour" : undefined} />
            <CriticalityBadge value={r.criticality} label={c?.label} color={c?.color} />
            {r.archived_at && <span className="rounded bg-surface-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">archived</span>}
            {r.url && (
              <a href={r.url} target="_blank" rel="noopener noreferrer" className="ml-auto inline-flex items-center gap-1 text-primary hover:underline">
                Open in provider <ExternalLink className="size-3.5" />
              </a>
            )}
          </div>
          {r.remote_archived && <Alert tone="warning">This repository is archived at the provider.</Alert>}
          <div className="flex gap-1 border-b border-border" role="tablist" aria-label="Repository sections">
            {(
              [
                ["details", "Details"],
                ["source", "Source"],
                ["security", "Security"],
              ] as const
            ).map(([k, l]) => (
              <button
                key={k}
                role="tab"
                id={`repo-tab-${k}`}
                aria-selected={tab === k}
                aria-controls={`repo-panel-${k}`}
                onClick={() => setTab(k)}
                className={cn("-mb-px border-b-2 px-3 py-1.5 text-[13px]", tab === k ? "border-primary font-medium text-primary" : "border-transparent text-muted-foreground hover:text-foreground")}
              >
                {l}
              </button>
            ))}
          </div>
          <div role="tabpanel" id={`repo-panel-${tab}`} aria-labelledby={`repo-tab-${tab}`}>
            {tab === "details" && <DetailsPanel key={r.id} r={r} onDeleted={onClose} />}
            {tab === "source" && <SourcePanel r={r} />}
            {tab === "security" && <SecurityPanel r={r} />}
          </div>
        </div>
      )}
    </Dialog>
  );
}

function DetailsPanel({ r, onDeleted }: { r: Repository; onDeleted: () => void }) {
  const { can } = useSession();
  const settings = useAssetSettings();
  const cats = useTagCategories();
  const [editing, setEditing] = useState(false);
  const orig = useMemo(() => draftFromRepository(r), [r]);
  const [draft, setDraft] = useState<MetadataDraft>(orig);
  const [scan, setScan] = useState<ScanDraft>(scanDraft(r));
  const [errors, setErrors] = useState<FieldErrors>({});
  const [saved, setSaved] = useState(false);
  const [confirm, setConfirm] = useState<"archive" | "delete" | null>(null);
  const branches = useBranches(r.id, editing && r.source_type !== "upload");
  const invalidate = useInvalidateRepos();
  const required = useMemo(
    () => new Set<AssetField>([...(settings.data?.required_fields ?? []), ...(settings.data?.always_required ?? [])]),
    [settings.data],
  );
  useEffect(() => {
    if (!editing) {
      setDraft(orig);
      setScan(scanDraft(r));
    }
  }, [orig, r, editing]);

  const save = useRepoMutation((body: unknown) => api<Repository>(`/api/v1/repositories/${r.id}`, { method: "PATCH", body }));
  const action = useRepoMutation((path: string) => api(`/api/v1/repositories/${r.id}/${path}`, { method: "POST" }));
  const del = useRepoMutation(() => api(`/api/v1/repositories/${r.id}`, { method: "DELETE" }));
  const canManage = r.can_manage ?? can("repos.manage");
  const canEdit = r.can_edit ?? canManage;

  const submit = () => {
    setSaved(false);
    const errs = clientErrors(draft, required, { categories: cats.data, names: true });
    if (Object.keys(errs).length) {
      setErrors(errs);
      return;
    }
    const body: Record<string, unknown> = { ...diffMetadata(orig, draft) };
    const o = scanDraft(r);
    if (scan.scan_branch !== o.scan_branch) body.scan_branch = scan.scan_branch;
    if (scan.scan_enabled !== o.scan_enabled) body.scan_enabled = scan.scan_enabled;
    if (scan.full_history !== o.full_history) body.full_history = scan.full_history;
    if (scan.technologies !== o.technologies)
      body.technologies = scan.technologies
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
    if (!Object.keys(body).length) return setEditing(false);
    save.mutate(body, {
      onSuccess: () => {
        setEditing(false);
        setErrors({});
        setSaved(true);
      },
      onError: (e) => {
        if (e instanceof ApiError && e.fields) setErrors(e.fields);
      },
    });
  };

  const set = (p: Partial<MetadataDraft>) => setDraft((d) => ({ ...d, ...p }));
  const errorSections = new Set(Object.keys(errors).map(sectionForKey));

  if (!editing) {
    return (
      <div className="space-y-5">
        {saved && <Alert tone="success">Changes saved.</Alert>}
        {(action.error || del.error) && <Alert>{(action.error ?? del.error)!.message}</Alert>}
        <div className="flex flex-wrap gap-2">
          {canEdit && !r.archived_at && (
            <Button size="sm" onClick={() => setEditing(true)}>
              <Pencil /> Edit metadata
            </Button>
          )}
          {canManage &&
            (r.archived_at ? (
              <>
                <Button size="sm" variant="secondary" disabled={action.isPending} onClick={() => action.mutate("unarchive")}>
                  Unarchive
                </Button>
                <Button size="sm" variant="danger-outline" onClick={() => setConfirm("delete")}>
                  Delete permanently
                </Button>
              </>
            ) : (
              <Button size="sm" variant="danger-outline" onClick={() => setConfirm("archive")}>
                Archive
              </Button>
            ))}
          {!canEdit && <span className="self-center text-[12px] text-muted-foreground">Read-only: you are not an owner of this repository.</span>}
        </div>
        <MetadataSummary draft={orig} settings={settings.data} showNames />
        <section aria-label="Scanning">
          <h3 className="mb-1.5 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">Scanning</h3>
          <dl className="grid gap-x-4 gap-y-2.5 sm:grid-cols-2">
            <div>
              <dt className="text-[12px] text-muted-foreground">Scan branch</dt>
              <dd>{r.source_type === "upload" ? "Current snapshot" : r.scan_branch || `${r.default_branch || "default"} (default)`}</dd>
            </div>
            <div>
              <dt className="text-[12px] text-muted-foreground">Scheduled scans</dt>
              <dd>{r.scan_enabled ? "Included" : "Excluded"}</dd>
            </div>
            <div>
              <dt className="text-[12px] text-muted-foreground">History</dt>
              <dd>{r.full_history ? "Full history" : "Shallow clone"}</dd>
            </div>
            <div>
              <dt className="text-[12px] text-muted-foreground">Technologies</dt>
              <dd>{r.technologies.join(", ") || "—"}</dd>
            </div>
            <div>
              <dt className="text-[12px] text-muted-foreground">Registered</dt>
              <dd>{formatDateTime(r.created_at)}</dd>
            </div>
          </dl>
        </section>
        <ConfirmDialog
          open={confirm === "archive"}
          onOpenChange={(o) => !o && setConfirm(null)}
          title="Archive this repository?"
          confirmLabel="Archive"
          pending={action.isPending}
          onConfirm={() => action.mutate("archive", { onSuccess: () => setConfirm(null) })}
        >
          <p>Archived repositories are no longer scanned and are hidden from the default list. Findings and history are kept; you can unarchive later.</p>
        </ConfirmDialog>
        <ConfirmDialog
          open={confirm === "delete"}
          onOpenChange={(o) => !o && setConfirm(null)}
          title="Delete this repository permanently?"
          confirmLabel="Delete permanently"
          pending={del.isPending}
          error={del.error?.message}
          onConfirm={() =>
            del.mutate(undefined, {
              onSuccess: () => {
                setConfirm(null);
                invalidate();
                onDeleted();
              },
            })
          }
        >
          <p>
            <strong>{r.display_name || r.full_name}</strong>, its scan history, findings and source snapshots are deleted. This cannot be undone.
          </p>
        </ConfirmDialog>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {save.isError && !(save.error instanceof ApiError && save.error.fields) && <Alert>{save.error.message}</Alert>}
      {Object.keys(errors).length > 0 && <Alert>Please correct the highlighted fields ({[...errorSections].filter(Boolean).length || 1} section(s)).</Alert>}
      {!canManage && <Alert tone="warning">As an owner you can edit descriptive metadata; business unit, department and country need repository management permission.</Alert>}
      {sections.map((s) => (
        <section key={s.key} aria-labelledby={`edit-${s.key}`} className="space-y-3">
          <h3 id={`edit-${s.key}`} className={cn("border-b border-border pb-1 text-[13px] font-semibold", errorSections.has(s.key) && "text-danger")}>
            {s.title}
          </h3>
          <MetadataSection section={s.key} draft={draft} set={set} errors={errors} required={required} settings={settings.data} names={s.key === "general"} placementLocked={!canManage} />
        </section>
      ))}
      <section aria-labelledby="edit-scanning" className="space-y-3">
        <h3 id="edit-scanning" className="border-b border-border pb-1 text-[13px] font-semibold">
          Scanning
        </h3>
        <div className="grid gap-3 sm:grid-cols-2">
          {r.source_type !== "upload" && (
            <div>
              <Label htmlFor="scan-branch" hint={branches.isFetching ? "(loading…)" : undefined}>
                Scan branch
              </Label>
              <Select id="scan-branch" className="w-full" value={scan.scan_branch} onChange={(e) => setScan({ ...scan, scan_branch: e.target.value })}>
                <option value="">Default ({r.default_branch || "unknown"})</option>
                {(branches.data?.items ?? (scan.scan_branch ? [scan.scan_branch] : [])).map((b) => (
                  <option key={b} value={b}>
                    {b}
                  </option>
                ))}
              </Select>
              {branches.isError && <p className="mt-1 text-[11px] text-danger">Could not load branches: {branches.error.message}</p>}
            </div>
          )}
          <div>
            <Label htmlFor="techs" hint="(comma-separated)">
              Technologies
            </Label>
            <Input id="techs" value={scan.technologies} onChange={(e) => setScan({ ...scan, technologies: e.target.value })} />
          </div>
        </div>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={scan.scan_enabled} onChange={(e) => setScan({ ...scan, scan_enabled: e.target.checked })} className="accent-[var(--primary)]" />
          Include in scheduled scans
        </label>
        {r.source_type !== "upload" && (
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={scan.full_history} onChange={(e) => setScan({ ...scan, full_history: e.target.checked })} className="accent-[var(--primary)]" />
            Clone full history (secret scanning covers past commits; slower)
          </label>
        )}
      </section>
      <div className="sticky bottom-0 flex justify-end gap-2 border-t border-border bg-surface py-3">
        <Button
          variant="secondary"
          onClick={() => {
            setEditing(false);
            setErrors({});
            save.reset();
          }}
        >
          Cancel
        </Button>
        <Button onClick={submit} disabled={save.isPending}>
          {save.isPending ? "Saving…" : "Save changes"}
        </Button>
      </div>
    </div>
  );
}

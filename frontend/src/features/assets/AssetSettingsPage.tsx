import { useEffect, useState } from "react";
import { Archive, ArchiveRestore, Lock, Pencil, Plus } from "lucide-react";
import { ApiError } from "@/api/client";
import type { AssetField, Classification, ClassificationKind } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ColorPicker } from "@/components/ui/color-picker";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, Input, PageHeader, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { ColorDot } from "@/components/data/TagChip";
import { useSession } from "@/features/auth/session";
import { FormField, Textarea } from "@/features/repos/metadata/fields";
import { fieldLabels, sections, slugify } from "@/features/repos/metadata/model";
import { cn } from "@/lib/utils";
import { catalog, useAssetSettings, useCreateClassification, useUpdateAssetSettings, useUpdateClassification, type ClassificationInput } from "./api";

export const kindLabels: Record<ClassificationKind, { title: string; help: string }> = {
  criticality: { title: "Criticality", help: "Fixed four levels. Labels, descriptions and colours are editable; colours also feed the suggested asset colours." },
  data_classification: { title: "Data classification", help: "Sensitivity of the data the code processes." },
  environment: { title: "Environment", help: "Deployment environments." },
  application_type: { title: "Application type", help: "Kinds of application (web app, API, batch, library…)." },
  internet_exposure: { title: "Internet exposure", help: "How reachable the workload is from the internet." },
  compliance: { title: "Compliance scope", help: "Regimes that apply to the asset. Applicability, not certification." },
  hosting_region: { title: "Hosting region", help: "Where workloads run (cloud regions, data centres). Independent of business regions." },
  lifecycle_status: { title: "Lifecycle status", help: "Life-cycle states; colours feed the suggested asset colours." },
};

const kinds = Object.keys(kindLabels) as ClassificationKind[];

export const colorSwatches = [
  "#b42318", "#d9480f", "#b7791f", "#1e7b45", "#0f766e", "#1f5fd6", "#6d28d9", "#be185d", "#52667a",
].map((c) => ({ value: c, label: c }));

/** Mirrors the server rule for Repository ID prefixes. */
export function repositoryKeyPrefixProblem(v: string): string | null {
  if (!v) return "Enter a prefix, e.g. QD-REPO";
  if (v.length > 20) return "At most 20 characters";
  if (!/^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$/.test(v)) return "Start with a letter; use upper-case letters, digits and single hyphens (no trailing hyphen)";
  return null;
}

export function AssetSettingsPage() {
  const { canOrgWide } = useSession();
  const manage = canOrgWide("assets.configure");
  const settings = useAssetSettings();
  const update = useUpdateAssetSettings();
  const [req, setReq] = useState<Set<AssetField>>(new Set());
  const [scanOnImport, setScanOnImport] = useState(false);
  const [prefix, setPrefix] = useState("");
  const [saved, setSaved] = useState(false);
  const [kind, setKind] = useState<ClassificationKind>("criticality");

  useEffect(() => {
    if (settings.data) {
      setReq(new Set(settings.data.required_fields));
      setScanOnImport(settings.data.scan_on_import);
      setPrefix(settings.data.repository_key_prefix ?? "");
    }
  }, [settings.data]);

  if (settings.isPending) return <Skeleton className="h-96" />;
  if (settings.isError)
    return (
      <Alert>
        Could not load asset settings: {settings.error.message}{" "}
        <button className="underline" onClick={() => void settings.refetch()}>
          Try again
        </button>
      </Alert>
    );
  const s = settings.data;
  // The public exposure question is mandatory regardless of policy.
  const always = new Set<AssetField>([...s.always_required, "public_exposure"]);
  const prefixChanged = prefix !== (s.repository_key_prefix ?? "");
  const prefixError = prefixChanged ? repositoryKeyPrefixProblem(prefix) : null;
  const dirty = scanOnImport !== s.scan_on_import || prefixChanged || [...req].sort().join() !== [...s.required_fields].sort().join();

  return (
    <>
      <PageHeader title="Asset settings" description="Required registration fields, onboarding behaviour and the classification catalogs used by every import method." />
      {!manage && (
        <div className="mb-4">
          <Alert tone="warning">You can view these settings; changing them requires the asset configuration permission.</Alert>
        </div>
      )}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <Card className="p-4">
          <h2 className="text-[14px] font-semibold">Required fields</h2>
          <p className="mb-3 text-[12px] text-muted-foreground">Fields every import and edit must fill in. Locked fields are always required.</p>
          <div className="space-y-4">
            {sections.map((sec) => (
              <fieldset key={sec.key} disabled={!manage}>
                <legend className="mb-1 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">{sec.title}</legend>
                <div className="grid gap-1 sm:grid-cols-2">
                  {sec.fields.map((f) => (
                    <label key={f} className={cn("flex items-center gap-2 text-[13px]", always.has(f) && "text-muted-foreground")}>
                      <input
                        type="checkbox"
                        className="accent-[var(--primary)]"
                        checked={always.has(f) || req.has(f)}
                        disabled={always.has(f)}
                        onChange={(e) => {
                          const next = new Set(req);
                          if (e.target.checked) next.add(f);
                          else next.delete(f);
                          setReq(next);
                          setSaved(false);
                        }}
                      />
                      {fieldLabels[f]}
                      {always.has(f) && <Lock className="size-3" aria-label="always required" />}
                    </label>
                  ))}
                </div>
              </fieldset>
            ))}
          </div>
          <div className="mt-5 border-t border-border pt-4">
            <label className="flex items-start gap-2 text-[13px]">
              <input
                type="checkbox"
                className="mt-0.5 accent-[var(--primary)]"
                disabled={!manage}
                checked={scanOnImport}
                onChange={(e) => {
                  setScanOnImport(e.target.checked);
                  setSaved(false);
                }}
              />
              <span>
                Scan on import
                <span className="block text-[12px] text-muted-foreground">Offer “Start onboarding scan” in the wizard and queue a scan when a repository is registered.</span>
              </span>
            </label>
          </div>
          <div className="mt-5 border-t border-border pt-4">
            <FormField
              label="Repository ID prefix"
              error={prefixError ?? undefined}
              hint={
                <>
                  Applies to repositories registered from now on; existing IDs never change. Starts with a letter; upper-case letters, digits and single hyphens (max 20).
                  {!prefixError && prefix && (
                    <>
                      {" "}
                      Next IDs look like <span className="font-mono">{prefix}-000123</span>.
                    </>
                  )}
                </>
              }
            >
              <Input
                className="max-w-56 font-mono"
                disabled={!manage}
                value={prefix}
                maxLength={20}
                spellCheck={false}
                autoCapitalize="characters"
                onChange={(e) => {
                  setPrefix(e.target.value.toUpperCase());
                  setSaved(false);
                }}
              />
            </FormField>
          </div>
          {update.isError && (
            <div className="mt-3">
              <Alert>{update.error.message}</Alert>
            </div>
          )}
          {saved && !dirty && (
            <div className="mt-3">
              <Alert tone="success">Settings saved.</Alert>
            </div>
          )}
          {manage && (
            <div className="mt-4 flex justify-end gap-2">
              <Button
                variant="secondary"
                disabled={!dirty || update.isPending}
                onClick={() => {
                  setReq(new Set(s.required_fields));
                  setScanOnImport(s.scan_on_import);
                  setPrefix(s.repository_key_prefix ?? "");
                }}
              >
                Reset
              </Button>
              <Button
                disabled={!dirty || !!prefixError || update.isPending}
                onClick={() =>
                  update.mutate(
                    { required_fields: [...req].filter((f) => !always.has(f)), scan_on_import: scanOnImport, ...(prefixChanged ? { repository_key_prefix: prefix } : {}) },
                    { onSuccess: () => setSaved(true) },
                  )
                }
              >
                {update.isPending ? "Saving…" : "Save"}
              </Button>
            </div>
          )}
        </Card>

        <Card>
          <div className="flex flex-wrap gap-1 border-b border-border p-2" role="tablist" aria-label="Classification catalogs">
            {kinds.map((k) => (
              <button
                key={k}
                role="tab"
                aria-selected={kind === k}
                onClick={() => setKind(k)}
                className={cn("rounded px-2.5 py-1 text-[12px]", kind === k ? "bg-primary/10 font-medium text-primary" : "text-muted-foreground hover:bg-surface-muted")}
              >
                {kindLabels[k].title}
              </button>
            ))}
          </div>
          <CatalogEditor key={kind} kind={kind} entries={catalog(s, kind, true)} manage={manage} />
          {s.suggested_colors.length > 0 && (
            <div className="border-t border-border p-4">
              <div className="mb-1.5 text-[12px] font-medium">Colour scheme suggested for assets</div>
              <div className="flex flex-wrap gap-3 text-[12px]">
                {s.suggested_colors.map((c) => (
                  <span key={c.key} className="flex items-center gap-1.5">
                    <ColorDot color={c.color} /> {c.label}
                  </span>
                ))}
              </div>
              <p className="mt-1 text-[11.5px] text-muted-foreground">Derived from the criticality and lifecycle colours above.</p>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}

function CatalogEditor({ kind, entries, manage }: { kind: ClassificationKind; entries: Classification[]; manage: boolean }) {
  const [editing, setEditing] = useState<Classification | "new" | null>(null);
  const [archiving, setArchiving] = useState<Classification | null>(null);
  const update = useUpdateClassification();
  const fixed = kind === "criticality";
  return (
    <div className="p-4">
      <div className="mb-3 flex items-start justify-between gap-3">
        <p className="text-[12px] text-muted-foreground">{kindLabels[kind].help}</p>
        {manage && !fixed && (
          <Button size="sm" onClick={() => setEditing("new")}>
            <Plus /> Add
          </Button>
        )}
      </div>
      {update.isError && (
        <div className="mb-2">
          <Alert>{update.error.message}</Alert>
        </div>
      )}
      {!entries.length ? (
        <p className="py-6 text-center text-[13px] text-muted-foreground">No entries yet.</p>
      ) : (
        <Table>
          <thead>
            <tr>
              <Th className="w-8">
                <span className="sr-only">Colour</span>
              </Th>
              <Th>Label</Th>
              <Th>Key</Th>
              <Th className="w-14">Order</Th>
              <Th className="w-24">
                <span className="sr-only">Actions</span>
              </Th>
            </tr>
          </thead>
          <tbody>
            {entries.map((c) => (
              <tr key={c.id} className={c.archived ? "opacity-60" : undefined}>
                <Td>
                  <ColorDot color={c.color} label={c.color || "no colour"} />
                </Td>
                <Td>
                  <div className="flex items-center gap-1.5 font-medium">
                    {c.label}
                    {c.is_system && <Badge>system</Badge>}
                    {c.archived && <Badge tone="warning">archived</Badge>}
                  </div>
                  {c.description && <div className="text-[12px] text-muted-foreground">{c.description}</div>}
                </Td>
                <Td className="font-mono text-[12px]">{c.key}</Td>
                <Td className="tabular">{c.sort_order}</Td>
                <Td>
                  {manage && (
                    <div className="flex justify-end gap-0.5">
                      <Button size="icon" variant="ghost" aria-label={`Edit ${c.label}`} onClick={() => setEditing(c)}>
                        <Pencil />
                      </Button>
                      {!fixed && !c.is_system && (
                        c.archived ? (
                          <Button size="icon" variant="ghost" aria-label={`Restore ${c.label}`} disabled={update.isPending} onClick={() => update.mutate({ id: c.id, body: { archived: false } })}>
                            <ArchiveRestore />
                          </Button>
                        ) : (
                          <Button size="icon" variant="ghost" aria-label={`Archive ${c.label}`} onClick={() => setArchiving(c)}>
                            <Archive />
                          </Button>
                        )
                      )}
                    </div>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {editing && <ClassificationDialog kind={kind} entry={editing === "new" ? null : editing} nextOrder={(entries.at(-1)?.sort_order ?? 0) + 10} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={!!archiving}
        onOpenChange={(o) => !o && setArchiving(null)}
        title={`Archive “${archiving?.label}”?`}
        confirmLabel="Archive"
        pending={update.isPending}
        error={update.error?.message}
        onConfirm={() => archiving && update.mutate({ id: archiving.id, body: { archived: true } }, { onSuccess: () => setArchiving(null) })}
      >
        <p>It can no longer be chosen for new or edited assets. Assets that already use it keep the value, and you can restore it later.</p>
      </ConfirmDialog>
    </div>
  );
}

function ClassificationDialog({ kind, entry, nextOrder, onClose }: { kind: ClassificationKind; entry: Classification | null; nextOrder: number; onClose: () => void }) {
  const [f, setF] = useState({
    key: entry?.key ?? "",
    label: entry?.label ?? "",
    description: entry?.description ?? "",
    color: entry?.color ?? "",
    sort_order: String(entry?.sort_order ?? nextOrder),
  });
  const [keyTouched, setKeyTouched] = useState(false);
  const create = useCreateClassification();
  const update = useUpdateClassification();
  const m = entry ? update : create;
  const fields = m.error instanceof ApiError ? m.error.fields : undefined;
  const fixed = kind === "criticality";
  const submit = () => {
    const body: ClassificationInput = { label: f.label.trim(), description: f.description.trim(), color: f.color };
    if (!fixed) body.sort_order = Number(f.sort_order) || 0;
    if (entry) update.mutate({ id: entry.id, body }, { onSuccess: onClose });
    else create.mutate({ ...body, kind, key: f.key.trim() }, { onSuccess: onClose });
  };
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={entry ? `Edit ${kindLabels[kind].title.toLowerCase()}` : `New ${kindLabels[kind].title.toLowerCase()}`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!f.label.trim() || (!entry && !f.key.trim()) || m.isPending}>
            {m.isPending ? "Saving…" : "Save"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {m.isError && !fields && <Alert>{m.error.message}</Alert>}
        <FormField label="Label" required error={fields?.label}>
          <Input
            autoFocus
            maxLength={100}
            value={f.label}
            onChange={(e) => setF({ ...f, label: e.target.value, key: entry || keyTouched ? f.key : slugify(e.target.value).replace(/-/g, "_") })}
          />
        </FormField>
        <FormField label="Key" required={!entry} error={fields?.key} hint={entry ? "Keys cannot be changed." : "Stored on assets; lower-case letters, digits and underscores."}>
          <Input
            className="font-mono"
            disabled={!!entry}
            maxLength={64}
            value={f.key}
            onChange={(e) => {
              setKeyTouched(true);
              setF({ ...f, key: e.target.value });
            }}
          />
        </FormField>
        <FormField label="Description" error={fields?.description}>
          <Textarea rows={2} maxLength={500} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} />
        </FormField>
        <div>
          <div className="mb-1 text-[12px] font-medium">Colour</div>
          <ColorPicker label="Colour" value={f.color} onChange={(color) => setF({ ...f, color })} swatches={colorSwatches} allowNone />
          {fields?.color && <p className="mt-1 text-[12px] text-danger">{fields.color}</p>}
        </div>
        {!fixed && (
          <FormField label="Sort order" error={fields?.sort_order}>
            <Input type="number" className="w-28" value={f.sort_order} onChange={(e) => setF({ ...f, sort_order: e.target.value })} />
          </FormField>
        )}
      </div>
    </Dialog>
  );
}

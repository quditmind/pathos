import { useEffect, useMemo, useState } from "react";
import { History, Play, Plus, Tags, Trash2, Wand2 } from "lucide-react";
import { api } from "@/api/client";
import type { TagColor } from "@/api/types";
import { TagChip } from "@/components/data/TagChip";
import { Button } from "@/components/ui/button";
import { ColorPicker } from "@/components/ui/color-picker";
import { ConfirmDialog } from "@/components/ui/confirm";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Alert, Badge, Card, EmptyState, Input, Label, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { catalog, useAssetSettings } from "@/features/assets/api";
import { colorSwatches } from "@/features/assets/AssetSettingsPage";
import { useSession } from "@/features/auth/session";
import { useApplications, useRepositories } from "@/features/repos/api";
import { formatDateTime } from "@/lib/utils";
import { fieldLabels, useInventoryMutation, useTagFramework, useTagHistory, type FrameworkCategory, type TagRule } from "./api";

const conditionLabels: Record<TagRule["condition"], string> = {
  classification: "Classification",
  repository_topic: "Repository topic",
  path_pattern: "Repository path pattern",
};

/**
 * Tag framework (Inventory › Tags, flag "onboarding"): category colours,
 * categories mandatory per application type, automatic tagging rules,
 * bulk tagging and tag history.
 */
export function TagFrameworkPanel() {
  const fw = useTagFramework();
  const { canOrgWide } = useSession();
  const manage = canOrgWide("tags.manage");
  if (fw.isPending) return <Skeleton className="mt-6 h-40" />;
  if (fw.isError) return <div className="mt-6"><ErrorPanel error={fw.error} onVerify={() => fw.refetch()} /></div>;
  const allTags = fw.data.categories.flatMap((c) => c.tags.map((t) => ({ ...t, category: c.name })));
  return (
    <div className="mt-8 space-y-6">
      <section aria-labelledby="tf-cats">
        <h2 id="tf-cats" className="mb-1 text-[15px] font-semibold">Category settings</h2>
        <p className="mb-3 text-[12.5px] text-muted-foreground">
          A colour per category, and the application types whose applications must carry a tag of the category (checked when an application is saved to the inventory).
        </p>
        <div className="grid gap-3 lg:grid-cols-2">
          {fw.data.categories.map((c) => (
            <CategorySettings key={c.id} c={c} manage={manage} />
          ))}
        </div>
      </section>
      <RulesSection rules={fw.data.rules} fields={fw.data.rule_fields} tags={allTags} manage={manage} />
      {manage && <BulkSection tags={allTags} />}
      {(manage || canOrgWide("audit.read")) && <HistorySection />}
    </div>
  );
}

function CategorySettings({ c, manage }: { c: FrameworkCategory; manage: boolean }) {
  const settings = useAssetSettings();
  const types = catalog(settings.data, "application_type");
  const [color, setColor] = useState(c.color);
  const [mand, setMand] = useState<string[]>(c.mandatory_asset_types);
  useEffect(() => {
    setColor(c.color);
    setMand(c.mandatory_asset_types);
  }, [c]);
  const save = useInventoryMutation(() => api(`/api/v1/tag-categories/${c.id}/framework`, { method: "PATCH", body: { color, mandatory_asset_types: mand } }));
  const dirty = color !== c.color || [...mand].sort().join() !== [...c.mandatory_asset_types].sort().join();
  const toggle = (k: string, on: boolean) => setMand((m) => (on ? [...m, k] : m.filter((x) => x !== k)));
  return (
    <Card className="space-y-2 p-4" style={c.color ? { borderLeft: `4px solid ${c.color}` } : undefined}>
      <div className="flex items-center gap-2 font-semibold">
        {c.name}
        {c.is_mandatory && <Badge tone="primary">mandatory for repositories</Badge>}
        {c.mandatory_asset_types.length > 0 && <Badge tone="warning">mandatory for applications</Badge>}
      </div>
      {c.noncompliant_applications > 0 && (
        <p className="text-[12px] text-warning">{c.noncompliant_applications} active applications of a mandatory type have no tag in this category.</p>
      )}
      <ColorPicker label={`Colour of ${c.name}`} value={color} onChange={setColor} swatches={colorSwatches} allowNone disabled={!manage} />
      <fieldset disabled={!manage}>
        <legend className="mb-1 text-[12px] font-medium">Mandatory for applications of type</legend>
        <div className="flex flex-wrap gap-x-3 gap-y-1 text-[12.5px]">
          <label className="flex items-center gap-1.5">
            <input type="checkbox" className="accent-[var(--primary)]" checked={mand.includes("all")} onChange={(e) => toggle("all", e.target.checked)} />
            All applications
          </label>
          {types.map((t) => (
            <label key={t.key} className="flex items-center gap-1.5">
              <input type="checkbox" className="accent-[var(--primary)]" checked={mand.includes(t.key)} disabled={mand.includes("all")} onChange={(e) => toggle(t.key, e.target.checked)} />
              {t.label}
            </label>
          ))}
        </div>
      </fieldset>
      {save.isError && <ErrorPanel error={save.error} />}
      {manage && (
        <div className="flex justify-end">
          <Button size="sm" disabled={!dirty || save.isPending} onClick={() => save.mutate(undefined)}>
            Save
          </Button>
        </div>
      )}
    </Card>
  );
}

type TagOption = { id: string; name: string; color: TagColor; category: string };

function RulesSection({ rules, fields, tags, manage }: { rules: TagRule[]; fields: string[]; tags: TagOption[]; manage: boolean }) {
  const settings = useAssetSettings();
  const empty = { name: "", tag_id: "", target_type: "application" as TagRule["target_type"], condition: "classification" as TagRule["condition"], field: "data_classification", value: "", apply: true };
  const [f, setF] = useState(empty);
  const [notice, setNotice] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<TagRule | null>(null);
  const create = useInventoryMutation(() =>
    api<{ rule: TagRule; applied: number }>("/api/v1/tag-rules", { method: "POST", body: { ...f, field: f.condition === "classification" ? f.field : "" } }),
  );
  const toggle = useInventoryMutation((r: TagRule) => api(`/api/v1/tag-rules/${r.id}`, { method: "PATCH", body: { enabled: !r.enabled } }));
  const apply = useInventoryMutation((r: TagRule) => api<{ tagged: number }>(`/api/v1/tag-rules/${r.id}/apply`, { method: "POST" }));
  const del = useInventoryMutation((r: TagRule) => api(`/api/v1/tag-rules/${r.id}`, { method: "DELETE" }));
  const kindFor: Record<string, string> = {
    application_type: "application_type", data_classification: "data_classification", internet_exposure: "internet_exposure",
    compliance_scopes: "compliance", authentication_model: "authentication_model", hosting_region: "hosting_region",
  };
  const valueOptions = f.condition === "classification" && kindFor[f.field] ? catalog(settings.data, kindFor[f.field] as never) : null;
  return (
    <section aria-labelledby="tf-rules">
      <h2 id="tf-rules" className="mb-1 flex items-center gap-1.5 text-[15px] font-semibold"><Wand2 className="size-4" aria-hidden /> Automatic tagging rules</h2>
      <p className="mb-3 text-[12.5px] text-muted-foreground">
        Rules add a tag when an application's classification matches, or when a repository's topic (technology label) or path matches a pattern (<code>*</code> within a
        segment, <code>**</code> across segments). Rules only add tags; they never remove a person's choice. They run when an application is classified, and on demand.
      </p>
      <Card>
        {!rules.length ? (
          <EmptyState icon={<Tags />} title="No rules yet" />
        ) : (
          <Table>
            <thead>
              <tr><Th>Rule</Th><Th>When</Th><Th>Adds</Th><Th>Applies to</Th><Th>Enabled</Th>{manage && <Th />}</tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <Td className="font-medium">{r.name}</Td>
                  <Td className="text-[12.5px]">
                    {conditionLabels[r.condition]}
                    {r.field && `: ${fieldLabels[r.field] ?? r.field}`} = <code>{r.value}</code>
                  </Td>
                  <Td><TagChip name={r.tag_name} category={r.category_name} color={r.tag_color} /></Td>
                  <Td className="text-[12.5px] capitalize">{r.target_type}s</Td>
                  <Td>
                    <input type="checkbox" className="accent-[var(--primary)]" aria-label={`Enable ${r.name}`} checked={r.enabled} disabled={!manage || toggle.isPending} onChange={() => toggle.mutate(r)} />
                  </Td>
                  {manage && (
                    <Td className="whitespace-nowrap text-right">
                      <Button size="sm" variant="ghost" disabled={!r.enabled || apply.isPending}
                        onClick={() => apply.mutate(r, { onSuccess: (x) => setNotice(`${r.name}: ${x.tagged} assets tagged.`) })}>
                        <Play /> Run now
                      </Button>
                      <Button size="icon" variant="ghost" className="text-danger" aria-label={`Delete rule ${r.name}`} onClick={() => setDeleting(r)}>
                        <Trash2 />
                      </Button>
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      {notice && <div className="mt-2"><Alert tone="success">{notice}</Alert></div>}
      {(toggle.error ?? apply.error) && <div className="mt-2"><ErrorPanel error={toggle.error ?? apply.error} /></div>}
      {manage && (
        <Card className="mt-3 p-4">
          <h3 className="mb-2 text-[13px] font-semibold">New rule</h3>
          <form
            className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate(undefined, {
                onSuccess: (x) => {
                  setNotice(`Rule “${x.rule.name}” created${f.apply ? `; ${x.applied} assets tagged` : ""}.`);
                  setF(empty);
                },
              });
            }}
          >
            <div>
              <Label htmlFor="rule-name">Name</Label>
              <Input id="rule-name" value={f.name} maxLength={100} required onChange={(e) => setF({ ...f, name: e.target.value })} />
            </div>
            <div>
              <Label htmlFor="rule-tag">Tag to add</Label>
              <Select id="rule-tag" className="w-full" value={f.tag_id} required onChange={(e) => setF({ ...f, tag_id: e.target.value })}>
                <option value="">Choose a tag</option>
                {tags.map((t) => <option key={t.id} value={t.id}>{t.category}: {t.name}</option>)}
              </Select>
            </div>
            <div>
              <Label htmlFor="rule-target">Applies to</Label>
              <Select id="rule-target" className="w-full" value={f.target_type}
                onChange={(e) => {
                  const target = e.target.value as TagRule["target_type"];
                  setF({ ...f, target_type: target, condition: target === "repository" && f.condition === "classification" ? "path_pattern" : f.condition });
                }}>
                <option value="application">Applications</option>
                <option value="repository">Repositories</option>
              </Select>
            </div>
            <div>
              <Label htmlFor="rule-cond">Condition</Label>
              <Select id="rule-cond" className="w-full" value={f.condition} onChange={(e) => setF({ ...f, condition: e.target.value as TagRule["condition"], value: "" })}>
                {f.target_type === "application" && <option value="classification">Classification</option>}
                <option value="repository_topic">Repository topic</option>
                <option value="path_pattern">Repository path pattern</option>
              </Select>
            </div>
            {f.condition === "classification" && (
              <div>
                <Label htmlFor="rule-field">Field</Label>
                <Select id="rule-field" className="w-full" value={f.field} onChange={(e) => setF({ ...f, field: e.target.value, value: "" })}>
                  {fields.map((x) => <option key={x} value={x}>{fieldLabels[x] ?? x}</option>)}
                </Select>
              </div>
            )}
            <div>
              <Label htmlFor="rule-value">{f.condition === "path_pattern" ? "Pattern" : "Value"}</Label>
              {valueOptions ? (
                <Select id="rule-value" className="w-full" value={f.value} required onChange={(e) => setF({ ...f, value: e.target.value })}>
                  <option value="">Choose</option>
                  {valueOptions.map((o) => <option key={o.key} value={o.key}>{o.label}</option>)}
                </Select>
              ) : (
                <Input id="rule-value" value={f.value} maxLength={200} required placeholder={f.condition === "path_pattern" ? "acme/payments-*" : f.condition === "repository_topic" ? "pci" : "production"}
                  onChange={(e) => setF({ ...f, value: e.target.value })} />
              )}
            </div>
            <label className="flex items-center gap-2 text-[12.5px] sm:col-span-2">
              <input type="checkbox" className="accent-[var(--primary)]" checked={f.apply} onChange={(e) => setF({ ...f, apply: e.target.checked })} />
              Also run it on existing assets now
            </label>
            <div className="flex items-end justify-end">
              <Button type="submit" disabled={create.isPending || !f.name.trim() || !f.tag_id || !f.value.trim()}>
                <Plus /> Create rule
              </Button>
            </div>
          </form>
          {create.isError && <div className="mt-2"><ErrorPanel error={create.error} /></div>}
        </Card>
      )}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete rule “${deleting?.name}”?`}
        confirmLabel="Delete rule"
        pending={del.isPending}
        error={del.error?.message}
        onConfirm={() => deleting && del.mutate(deleting, { onSuccess: () => setDeleting(null) })}
      >
        <p>Tags the rule already added stay on their assets.</p>
      </ConfirmDialog>
    </section>
  );
}

function BulkSection({ tags }: { tags: TagOption[] }) {
  const [target, setTarget] = useState<"application" | "repository">("application");
  const [q, setQ] = useState("");
  const [ids, setIds] = useState<Set<string>>(new Set());
  const [add, setAdd] = useState("");
  const [remove, setRemove] = useState("");
  const [confirm, setConfirm] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const apps = useApplications();
  const repos = useRepositories({ q: q || undefined } as never);
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (target === "application") return (apps.data ?? []).filter((a) => !needle || a.name.toLowerCase().includes(needle)).map((a) => ({ id: a.id, name: a.name, sub: a.application_key }));
    return (repos.data?.pages.flatMap((p) => p.items) ?? []).map((r) => ({ id: r.id, name: r.display_name || r.full_name, sub: r.full_name }));
  }, [target, q, apps.data, repos.data]);
  const bulk = useInventoryMutation(() =>
    api<{ items: { id: string; status: string; error?: string }[]; updated: number }>("/api/v1/tag-assignments/bulk", {
      method: "POST",
      body: { target_type: target, ids: [...ids], add_tag_ids: add ? [add] : [], remove_tag_ids: remove ? [remove] : [] },
    }),
  );
  return (
    <section aria-labelledby="tf-bulk">
      <h2 id="tf-bulk" className="mb-1 text-[15px] font-semibold">Bulk tagging</h2>
      <p className="mb-3 text-[12.5px] text-muted-foreground">Add or remove a tag on many applications or repositories at once. Every change is recorded in the tag history.</p>
      <Card className="space-y-3 p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <Label htmlFor="bulk-target">Assets</Label>
            <Select id="bulk-target" value={target} onChange={(e) => { setTarget(e.target.value as never); setIds(new Set()); }}>
              <option value="application">Applications</option>
              <option value="repository">Repositories</option>
            </Select>
          </div>
          <div className="min-w-48 flex-1">
            <Label htmlFor="bulk-q">Filter</Label>
            <Input id="bulk-q" value={q} placeholder="Name contains…" onChange={(e) => setQ(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="bulk-add">Add tag</Label>
            <Select id="bulk-add" value={add} onChange={(e) => setAdd(e.target.value)}>
              <option value="">None</option>
              {tags.map((t) => <option key={t.id} value={t.id}>{t.category}: {t.name}</option>)}
            </Select>
          </div>
          <div>
            <Label htmlFor="bulk-remove">Remove tag</Label>
            <Select id="bulk-remove" value={remove} onChange={(e) => setRemove(e.target.value)}>
              <option value="">None</option>
              {tags.map((t) => <option key={t.id} value={t.id}>{t.category}: {t.name}</option>)}
            </Select>
          </div>
          <Button disabled={!ids.size || (!add && !remove)} onClick={() => setConfirm(true)}>Apply to {ids.size} selected</Button>
        </div>
        <div className="max-h-64 overflow-y-auto rounded-md border border-border">
          <Table>
            <thead className="sticky top-0 bg-surface">
              <tr>
                <Th>
                  <input type="checkbox" className="accent-[var(--primary)]" aria-label="Select all shown"
                    checked={rows.length > 0 && rows.every((r) => ids.has(r.id))}
                    onChange={(e) => setIds(e.target.checked ? new Set(rows.slice(0, 500).map((r) => r.id)) : new Set())} />
                </Th>
                <Th>Name</Th>
                <Th>{target === "application" ? "Application ID" : "Full name"}</Th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, 500).map((r) => (
                <tr key={r.id}>
                  <Td>
                    <input type="checkbox" className="accent-[var(--primary)]" aria-label={`Select ${r.name}`} checked={ids.has(r.id)}
                      onChange={(e) => { const n = new Set(ids); if (e.target.checked) n.add(r.id); else n.delete(r.id); setIds(n); }} />
                  </Td>
                  <Td>{r.name}</Td>
                  <Td className="font-mono text-[12px] text-muted-foreground">{r.sub}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
        {result && <Alert tone="success">{result}</Alert>}
      </Card>
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title={`Change tags of ${ids.size} ${target === "application" ? "applications" : "repositories"}?`}
        confirmLabel="Apply"
        destructive={false}
        pending={bulk.isPending}
        error={bulk.error?.message}
        onConfirm={() =>
          bulk.mutate(undefined, {
            onSuccess: (x) => {
              const failed = x.items.filter((i) => i.status === "error");
              setResult(`${x.updated} updated${failed.length ? `; ${failed.length} not changed (${failed[0]!.error})` : ""}.`);
              setConfirm(false);
              setIds(new Set());
            },
          })
        }
      >
        <p>
          {add && `Adds ${tags.find((t) => t.id === add)?.name}. `}
          {remove && `Removes ${tags.find((t) => t.id === remove)?.name}. `}
          In single-value categories the added tag replaces the current one.
        </p>
      </ConfirmDialog>
    </section>
  );
}

function HistorySection() {
  const h = useTagHistory();
  return (
    <section aria-labelledby="tf-hist">
      <h2 id="tf-hist" className="mb-1 flex items-center gap-1.5 text-[15px] font-semibold"><History className="size-4" aria-hidden /> Tag history</h2>
      <p className="mb-3 text-[12.5px] text-muted-foreground">The latest tag changes on applications and repositories: who, when, and the tags before and after.</p>
      <Card>
        {h.isPending ? <Skeleton className="m-4 h-24" /> : h.isError ? <div className="p-4"><ErrorPanel error={h.error} /></div> : !h.data.length ? (
          <EmptyState icon={<History />} title="No tag changes recorded yet" />
        ) : (
          <Table>
            <thead><tr><Th>When</Th><Th>Who</Th><Th>Asset</Th><Th>Category</Th><Th>Before</Th><Th>After</Th><Th>How</Th></tr></thead>
            <tbody>
              {h.data.map((e) => (
                <tr key={e.id}>
                  <Td className="whitespace-nowrap text-[12px] text-muted-foreground">{formatDateTime(e.created_at)}</Td>
                  <Td className="text-[12px]">{e.actor_email || "System"}</Td>
                  <Td className="text-[12.5px]">{e.target_name} <span className="text-muted-foreground">({e.target_type})</span></Td>
                  <Td className="text-[12.5px]">{e.category_name}</Td>
                  <Td className="text-[12px]">{e.old_tags.join(", ") || "—"}</Td>
                  <Td className="text-[12px]">{e.new_tags.join(", ") || "—"}</Td>
                  <Td><Badge>{e.source}</Badge></Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </section>
  );
}

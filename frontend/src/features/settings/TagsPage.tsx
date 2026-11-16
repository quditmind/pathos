import { useState } from "react";
import { Pencil, Plus, Tags, Trash2 } from "lucide-react";
import { api, ApiError } from "@/api/client";
import type { Tag, TagCategory, TagColor } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ColorPicker } from "@/components/ui/color-picker";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Skeleton } from "@/components/ui/primitives";
import { TagChip } from "@/components/data/TagChip";
import { useCreateTag, useDeleteTag, useUpdateTag } from "@/features/assets/api";
import { useSession } from "@/features/auth/session";
import { useRepoMutation, useTagCategories } from "@/features/repos/api";
import { FormField } from "@/features/repos/metadata/fields";
import { tagSwatches } from "@/features/repos/metadata/TagPicker";

export function TagsPage() {
  const { canOrgWide } = useSession();
  const cats = useTagCategories();
  // Categories: repository managers; tags themselves: tags.manage.
  // Categories and tags both require tags.manage (enforced by the API).
  const manage = canOrgWide("tags.manage");
  const manageTags = canOrgWide("tags.manage");
  const [creating, setCreating] = useState(false);
  const [tagDialog, setTagDialog] = useState<{ category: TagCategory; tag: Tag | null } | null>(null);
  const [deleting, setDeleting] = useState<Tag | null>(null);
  const [deletingCat, setDeletingCat] = useState<TagCategory | null>(null);
  const update = useRepoMutation(({ id, body }: { id: string; body: unknown }) => api(`/api/v1/tag-categories/${id}`, { method: "PATCH", body }));
  const delCat = useRepoMutation((id: string) => api(`/api/v1/tag-categories/${id}`, { method: "DELETE" }));
  const delTag = useDeleteTag();
  const error = update.error ?? delCat.error;

  return (
    <>
      <PageHeader
        title="Tags"
        description="Tag categories classify repositories. Mandatory categories must be set on every import and edit."
        actions={manage && <Button onClick={() => setCreating(true)}><Plus /> New category</Button>}
      />
      {error && <div className="mb-3"><Alert>{error.message}</Alert></div>}
      {cats.isPending ? (
        <Skeleton className="h-32" />
      ) : !cats.data?.length ? (
        <Card><EmptyState icon={<Tags />} title="No tag categories">Create categories such as Team, Data classification or Compliance scope.</EmptyState></Card>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {cats.data.map((c) => (
            <Card key={c.id} className="p-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2 font-semibold">
                    {c.name}
                    {c.is_mandatory && <Badge tone="primary">mandatory</Badge>}
                    {!c.allow_multiple && <Badge>single value</Badge>}
                  </div>
                  {c.description && <p className="text-[12px] text-muted-foreground">{c.description}</p>}
                  {c.noncompliant_repositories > 0 && (
                    <p className="mt-1 text-[12px] text-warning">{c.noncompliant_repositories} active repositories have no tag in this category.</p>
                  )}
                </div>
                {manage && (
                  <Button variant="ghost" size="icon" aria-label={`Delete category ${c.name}`}
                    onClick={() => setDeletingCat(c)}>
                    <Trash2 />
                  </Button>
                )}
              </div>
              <ul className="mt-3 space-y-1">
                {c.tags.map((t) => (
                  <li key={t.id} className="group flex items-center gap-2 text-[12px]">
                    <TagChip name={t.name} color={t.color} />
                    <span className="tabular text-muted-foreground">{t.repository_count} repos</span>
                    {t.description && <span className="min-w-0 flex-1 truncate text-muted-foreground" title={t.description}>{t.description}</span>}
                    {manageTags && (
                      <span className="ml-auto flex gap-0.5">
                        <Button size="icon" variant="ghost" className="size-6" aria-label={`Edit tag ${t.name}`} onClick={() => setTagDialog({ category: c, tag: t })}>
                          <Pencil />
                        </Button>
                        <Button size="icon" variant="ghost" className="size-6 text-danger" aria-label={`Delete tag ${t.name}`} onClick={() => setDeleting(t)}>
                          <Trash2 />
                        </Button>
                      </span>
                    )}
                  </li>
                ))}
                {!c.tags.length && <li className="text-[12px] text-muted-foreground">No tags yet</li>}
              </ul>
              {manageTags && (
                <Button size="sm" variant="secondary" className="mt-3" onClick={() => setTagDialog({ category: c, tag: null })}>
                  <Plus /> Add tag
                </Button>
              )}
              {manage && (
                <>
                  <div className="mt-3 flex gap-4 text-[12px]">
                    <label className="flex items-center gap-1.5">
                      <input type="checkbox" className="accent-[var(--primary)]" checked={c.is_mandatory}
                        onChange={(e) => update.mutate({ id: c.id, body: { is_mandatory: e.target.checked } })} />
                      Mandatory
                    </label>
                    <label className="flex items-center gap-1.5">
                      <input type="checkbox" className="accent-[var(--primary)]" checked={c.allow_multiple}
                        onChange={(e) => update.mutate({ id: c.id, body: { allow_multiple: e.target.checked } })} />
                      Allow multiple tags
                    </label>
                  </div>
                </>
              )}
            </Card>
          ))}
        </div>
      )}
      <CreateCategory open={creating} onOpenChange={setCreating} />
      {tagDialog && <TagDialog category={tagDialog.category} tag={tagDialog.tag} onClose={() => setTagDialog(null)} />}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete tag “${deleting?.name}”?`}
        confirmLabel="Delete tag"
        pending={delTag.isPending}
        error={delTag.error?.message}
        onConfirm={() => deleting && delTag.mutate(deleting.id, { onSuccess: () => setDeleting(null) })}
      >
        <p>It is removed from {deleting?.repository_count ?? 0} repositories. This cannot be undone.</p>
      </ConfirmDialog>
      <ConfirmDialog
        open={!!deletingCat}
        onOpenChange={(o) => !o && setDeletingCat(null)}
        title={`Delete category “${deletingCat?.name}”?`}
        confirmLabel="Delete category"
        pending={delCat.isPending}
        error={delCat.error?.message}
        onConfirm={() => deletingCat && delCat.mutate(deletingCat.id, { onSuccess: () => setDeletingCat(null) })}
      >
        <p>All {deletingCat?.tags.length ?? 0} tags in it are deleted and removed from every repository.</p>
      </ConfirmDialog>
    </>
  );
}

function TagDialog({ category, tag, onClose }: { category: TagCategory; tag: Tag | null; onClose: () => void }) {
  const [f, setF] = useState({ name: tag?.name ?? "", color: (tag?.color ?? "blue") as string, description: tag?.description ?? "" });
  const create = useCreateTag();
  const update = useUpdateTag();
  const m = tag ? update : create;
  const fields = m.error instanceof ApiError ? m.error.fields : undefined;
  const submit = () => {
    const body = { name: f.name.trim(), color: f.color as TagColor, description: f.description.trim() };
    if (tag) update.mutate({ id: tag.id, body }, { onSuccess: onClose });
    else create.mutate({ categoryId: category.id, body }, { onSuccess: onClose });
  };
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={tag ? `Edit tag “${tag.name}”` : `New tag in ${category.name}`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={submit} disabled={!f.name.trim() || m.isPending}>{m.isPending ? "Saving…" : "Save"}</Button>
        </>
      }
    >
      <div className="space-y-3">
        {m.isError && !fields && <Alert>{m.error.message}</Alert>}
        <FormField label="Name" required error={fields?.name}>
          <Input autoFocus maxLength={100} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
        </FormField>
        <FormField label="Description" error={fields?.description}>
          <Input maxLength={500} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} />
        </FormField>
        <div>
          <div className="mb-1 text-[12px] font-medium">Colour</div>
          <ColorPicker label="Tag colour" value={f.color} onChange={(color) => setF({ ...f, color })} swatches={tagSwatches} />
          {fields?.color && <p className="mt-1 text-[12px] text-danger">{fields.color}</p>}
        </div>
        <div className="text-[12px] text-muted-foreground">
          Preview: <TagChip name={f.name || "Tag"} category={category.name} color={(f.color || "slate") as TagColor} />
        </div>
      </div>
    </Dialog>
  );
}

function CreateCategory({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [f, setF] = useState({ name: "", description: "", is_mandatory: false, allow_multiple: true });
  const create = useRepoMutation((body: unknown) => api("/api/v1/tag-categories", { method: "POST", body }));
  const close = () => { setF({ name: "", description: "", is_mandatory: false, allow_multiple: true }); create.reset(); onOpenChange(false); };
  return (
    <Dialog open={open} onOpenChange={(o) => (o ? onOpenChange(true) : close())} title="New tag category"
      footer={<><Button variant="secondary" onClick={close}>Cancel</Button><Button type="submit" form="cat-form" disabled={!f.name.trim() || create.isPending}>Create</Button></>}>
      <form id="cat-form" className="space-y-3" onSubmit={(e) => { e.preventDefault(); create.mutate({ ...f, name: f.name.trim() }, { onSuccess: close }); }}>
        {create.isError && <Alert>{create.error.message}</Alert>}
        <div><Label htmlFor="cat-name">Name</Label><Input id="cat-name" autoFocus maxLength={100} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Team" /></div>
        <div><Label htmlFor="cat-desc" hint="(optional)">Description</Label><Input id="cat-desc" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></div>
        <label className="flex items-center gap-2 text-[13px]"><input type="checkbox" className="accent-[var(--primary)]" checked={f.is_mandatory} onChange={(e) => setF({ ...f, is_mandatory: e.target.checked })} /> Mandatory on every repository</label>
        <label className="flex items-center gap-2 text-[13px]"><input type="checkbox" className="accent-[var(--primary)]" checked={f.allow_multiple} onChange={(e) => setF({ ...f, allow_multiple: e.target.checked })} /> Allow more than one tag per repository</label>
      </form>
    </Dialog>
  );
}

import { useState, type FormEvent } from "react";
import { Plus, Tags, Trash2, X } from "lucide-react";
import { api } from "@/api/client";
import type { TagCategory, TagColor } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { TagChip, tagColorNames } from "@/components/data/TagChip";
import { useSession } from "@/features/auth/session";
import { useRepoMutation, useTagCategories } from "@/features/repos/api";

export function TagsPage() {
  const { canOrgWide } = useSession();
  const cats = useTagCategories();
  const manage = canOrgWide("repos.manage");
  const [creating, setCreating] = useState(false);
  const update = useRepoMutation(({ id, body }: { id: string; body: unknown }) => api(`/api/v1/tag-categories/${id}`, { method: "PATCH", body }));
  const delCat = useRepoMutation((id: string) => api(`/api/v1/tag-categories/${id}`, { method: "DELETE" }));
  const delTag = useRepoMutation((id: string) => api(`/api/v1/tags/${id}`, { method: "DELETE" }));
  const error = update.error ?? delCat.error ?? delTag.error;

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
                    onClick={() => confirm(`Delete "${c.name}" and remove its tags from all repositories?`) && delCat.mutate(c.id)}>
                    <Trash2 />
                  </Button>
                )}
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {c.tags.map((t) => (
                  <span key={t.id} className="inline-flex items-center gap-0.5">
                    <TagChip name={`${t.name} · ${t.repository_count}`} color={t.color} />
                    {manage && (
                      <button aria-label={`Delete tag ${t.name}`} className="rounded p-0.5 text-muted-foreground hover:text-danger"
                        onClick={() => confirm(`Delete tag "${t.name}"? It is removed from ${t.repository_count} repositories.`) && delTag.mutate(t.id)}>
                        <X className="size-3" />
                      </button>
                    )}
                  </span>
                ))}
                {!c.tags.length && <span className="text-[12px] text-muted-foreground">No tags yet</span>}
              </div>
              {manage && (
                <>
                  <AddTag category={c} />
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
    </>
  );
}

function AddTag({ category }: { category: TagCategory }) {
  const [name, setName] = useState("");
  const [color, setColor] = useState<TagColor>("blue");
  const add = useRepoMutation((body: unknown) => api(`/api/v1/tag-categories/${category.id}/tags`, { method: "POST", body }));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    add.mutate({ name: name.trim(), color }, { onSuccess: () => setName("") });
  };
  return (
    <form onSubmit={submit} className="mt-3 flex items-center gap-2">
      <Input aria-label={`New tag in ${category.name}`} placeholder="New tag" value={name} onChange={(e) => setName(e.target.value)} className="max-w-48" maxLength={100} />
      <Select aria-label="Tag colour" value={color} onChange={(e) => setColor(e.target.value as TagColor)} className="capitalize">
        {tagColorNames.map((c) => <option key={c} value={c}>{c}</option>)}
      </Select>
      <Button size="sm" type="submit" variant="secondary" disabled={!name.trim() || add.isPending}>Add</Button>
      {add.isError && <span className="text-[12px] text-danger">{add.error.message}</span>}
    </form>
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

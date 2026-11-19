import { useId, useState } from "react";
import { Plus, Search } from "lucide-react";
import { ApiError } from "@/api/client";
import type { TagCategory, TagColor } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ColorPicker } from "@/components/ui/color-picker";
import { Badge, Input, Select, Skeleton } from "@/components/ui/primitives";
import { paletteSwatch, TagChip, tagColorNames } from "@/components/data/TagChip";
import { useCreateTag } from "@/features/assets/api";
import { useSession } from "@/features/auth/session";
import { cn } from "@/lib/utils";
import { useTagCategories } from "../api";
import { FormField } from "./fields";
import { ErrorPanel } from "@/components/ui/error-panel";

/** Selects tag ids; keeps single-choice categories to one tag. */
export function toggleTag(categories: TagCategory[], value: string[], tagId: string): string[] {
  if (value.includes(tagId)) return value.filter((t) => t !== tagId);
  const cat = categories.find((c) => c.tags.some((t) => t.id === tagId));
  const drop = cat && !cat.allow_multiple ? new Set(cat.tags.map((t) => t.id)) : new Set<string>();
  return [...value.filter((t) => !drop.has(t)), tagId];
}

export const tagSwatches = tagColorNames.map((n) => ({ value: n, label: n[0]!.toUpperCase() + n.slice(1), paint: paletteSwatch[n] }));

export function TagPicker({
  value,
  onChange,
  disabled,
  required,
  error,
}: {
  value: string[];
  onChange: (ids: string[]) => void;
  disabled?: boolean;
  required?: boolean;
  error?: string;
}) {
  const id = useId();
  const cats = useTagCategories();
  const { canOrgWide } = useSession();
  const [q, setQ] = useState("");
  const [creating, setCreating] = useState(false);
  const all = cats.data ?? [];
  const needle = q.trim().toLowerCase();
  const selected = new Set(value);
  const shown = all
    .map((c) => ({
      ...c,
      tags: needle ? c.tags.filter((t) => `${c.name} ${t.name} ${t.description ?? ""}`.toLowerCase().includes(needle)) : c.tags,
    }))
    .filter((c) => c.tags.length || !needle);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-[12px] font-medium" id={`${id}-label`}>
          Tags
          {required && <span className="ml-0.5 text-danger" aria-hidden>*</span>}
          <span className="ml-1.5 font-normal text-muted-foreground">{value.length} selected</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input aria-label="Search tags" placeholder="Search tags" className="h-7 w-48 pl-7" value={q} onChange={(e) => setQ(e.target.value)} disabled={disabled} />
          </div>
          {canOrgWide("tags.manage") && !disabled && (
            <Button size="sm" variant="secondary" type="button" onClick={() => setCreating((c) => !c)} aria-expanded={creating}>
              <Plus /> New tag
            </Button>
          )}
        </div>
      </div>
      {error && <p role="alert" className="text-[12px] text-danger">{error}</p>}
      {creating && (
        <CreateTagInline
          categories={all}
          onCancel={() => setCreating(false)}
          onCreated={(tagId) => {
            setCreating(false);
            // Categories refetch after creation; toggle against the current list.
            onChange(toggleTag(all, value, tagId));
          }}
        />
      )}
      {cats.isPending ? (
        <Skeleton className="h-20" />
      ) : cats.isError ? (
        <ErrorPanel error={cats.error} title="Could not load tags" />
      ) : !all.length ? (
        <p className="text-[12px] text-muted-foreground">No tag categories exist yet.</p>
      ) : (
        <div className="max-h-80 space-y-3 overflow-y-auto rounded-md border border-border p-3" role="group" aria-labelledby={`${id}-label`}>
          {shown.map((c) => {
            const missing = c.is_mandatory && !all.find((x) => x.id === c.id)?.tags.some((t) => selected.has(t.id));
            return (
              <div key={c.id}>
                <div className="mb-1 flex items-center gap-1.5 text-[12px] font-medium">
                  {c.name}
                  {c.is_mandatory && <Badge tone={missing ? "danger" : "primary"}>required</Badge>}
                  {!c.allow_multiple && <Badge>choose one</Badge>}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {c.tags.map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      disabled={disabled}
                      aria-pressed={selected.has(t.id)}
                      title={t.description || undefined}
                      onClick={() => onChange(toggleTag(all, value, t.id))}
                      className={cn("rounded focus-visible:outline-2 focus-visible:outline-ring", selected.has(t.id) ? "ring-2 ring-primary" : "opacity-60 hover:opacity-100")}
                    >
                      <TagChip name={t.name} color={t.color} />
                    </button>
                  ))}
                  {!c.tags.length && <span className="text-[12px] text-muted-foreground">No tags</span>}
                </div>
              </div>
            );
          })}
          {!shown.length && <p className="text-[12px] text-muted-foreground">No tags match “{q}”.</p>}
        </div>
      )}
    </div>
  );
}

function CreateTagInline({ categories, onCancel, onCreated }: { categories: TagCategory[]; onCancel: () => void; onCreated: (id: string) => void }) {
  const [f, setF] = useState({ category: categories[0]?.id ?? "", name: "", color: "blue" as string, description: "" });
  const create = useCreateTag();
  const fieldErr = create.error instanceof ApiError ? create.error.fields : undefined;
  return (
    <div className="space-y-3 rounded-md border border-primary/30 bg-primary/5 p-3">
      {create.isError && !fieldErr && <ErrorPanel error={create.error} />}
      <div className="grid gap-3 sm:grid-cols-2">
        <FormField label="Category" required>
          <Select className="w-full" value={f.category} onChange={(e) => setF({ ...f, category: e.target.value })}>
            {categories.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </Select>
        </FormField>
        <FormField label="Tag name" required error={fieldErr?.name}>
          <Input value={f.name} maxLength={100} onChange={(e) => setF({ ...f, name: e.target.value })} />
        </FormField>
      </div>
      <FormField label="Description" error={fieldErr?.description}>
        <Input value={f.description} maxLength={500} onChange={(e) => setF({ ...f, description: e.target.value })} />
      </FormField>
      <div>
        <div className="mb-1 text-[12px] font-medium">Colour</div>
        <ColorPicker label="Tag colour" value={f.color} onChange={(color) => setF({ ...f, color })} swatches={tagSwatches} />
      </div>
      <div className="flex items-center gap-2">
        <Button
          type="button"
          size="sm"
          disabled={!f.name.trim() || !f.category || create.isPending}
          onClick={() =>
            create.mutate(
              { categoryId: f.category, body: { name: f.name.trim(), color: f.color as TagColor, description: f.description.trim() } },
              { onSuccess: (t) => onCreated(t.id) },
            )
          }
        >
          {create.isPending ? "Creating…" : "Create and select"}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

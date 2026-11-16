import { useState } from "react";
import { Archive, Radar } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Alert } from "@/components/ui/primitives";
import { TagChip } from "@/components/data/TagChip";
import { Dialog } from "@/components/ui/dialog";
import { useSession } from "@/features/auth/session";
import { useRepoMutation, useTagCategories } from "./api";

export function BulkScan({ ids }: { ids: string[] }) {
  const { can } = useSession();
  const [msg, setMsg] = useState<string | null>(null);
  const m = useRepoMutation((body: unknown) => api<{ items: { error?: string }[] }>("/api/v1/scans", { method: "POST", body }));
  if (!can("scans.run")) return null;
  return (
    <>
      <Button size="sm" variant="secondary" disabled={m.isPending}
        onClick={() => m.mutate({ repository_ids: ids }, { onSuccess: (r) => setMsg(`${r.items.filter((i) => !i.error).length} scans queued`) })}>
        <Radar /> Scan
      </Button>
      {msg && <span className="text-[12px] text-success">{msg}</span>}
    </>
  );
}

export function BulkArchive({ ids, onDone }: { ids: string[]; onDone: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const m = useRepoMutation(async () => {
    for (const id of ids) await api(`/api/v1/repositories/${id}/archive`, { method: "POST" }).catch(() => undefined);
  });
  return (
    <>
      <Button size="sm" variant="secondary" disabled={m.isPending} onClick={() => m.mutate(undefined, { onSuccess: onDone, onError: (e) => setError(e.message) })}>
        <Archive /> Archive
      </Button>
      {error && <span className="text-danger">{error}</span>}
    </>
  );
}

export function BulkTagDialog({ open, onOpenChange, ids }: { open: boolean; onOpenChange: (o: boolean) => void; ids: string[] }) {
  const cats = useTagCategories();
  const [add, setAdd] = useState<Set<string>>(new Set());
  const [remove, setRemove] = useState<Set<string>>(new Set());
  const m = useRepoMutation((body: unknown) => api("/api/v1/repositories/bulk-tags", { method: "POST", body }));
  const close = () => {
    setAdd(new Set());
    setRemove(new Set());
    m.reset();
    onOpenChange(false);
  };
  const cycle = (id: string) => {
    const a = new Set(add);
    const r = new Set(remove);
    if (a.has(id)) {
      a.delete(id);
      r.add(id);
    } else if (r.has(id)) r.delete(id);
    else a.add(id);
    setAdd(a);
    setRemove(r);
  };
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => (o ? onOpenChange(true) : close())}
      title={`Edit tags on ${ids.length} repositories`}
      description="Click a tag once to add it, twice to remove it, three times to leave it unchanged."
      footer={
        <>
          <Button variant="secondary" onClick={close}>
            Cancel
          </Button>
          <Button
            disabled={m.isPending || add.size + remove.size === 0}
            onClick={() => m.mutate({ repository_ids: ids, add: [...add], remove: [...remove] }, { onSuccess: close })}
          >
            Apply
          </Button>
        </>
      }
    >
      {m.isError && (
        <div className="mb-3">
          <Alert>{m.error.message}</Alert>
        </div>
      )}
      <div className="space-y-4">
        {(cats.data ?? []).map((c) => (
          <div key={c.id}>
            <div className="mb-1.5 text-[12px] font-medium">
              {c.name}
              {c.is_mandatory && <span className="ml-1 text-danger">*</span>}
              {!c.allow_multiple && <span className="ml-1 font-normal text-muted-foreground">(one per repository)</span>}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {c.tags.map((t) => (
                <button
                  key={t.id}
                  onClick={() => cycle(t.id)}
                  className={`rounded ${add.has(t.id) ? "ring-2 ring-success" : remove.has(t.id) ? "opacity-50 ring-2 ring-danger line-through" : ""}`}
                >
                  <TagChip name={(add.has(t.id) ? "+ " : remove.has(t.id) ? "− " : "") + t.name} color={t.color} />
                </button>
              ))}
              {!c.tags.length && <span className="text-[12px] text-muted-foreground">No tags in this category</span>}
            </div>
          </div>
        ))}
        {!cats.data?.length && <p className="text-[13px] text-muted-foreground">No tag categories yet. Create them under Administration → Tags.</p>}
      </div>
    </Dialog>
  );
}

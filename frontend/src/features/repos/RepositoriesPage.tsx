import { useDeferredValue, useEffect, useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Archive, GitBranch, Plus, Radar, Search, Tags } from "lucide-react";
import type { Repository } from "@/api/types";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Alert, Card, EmptyState, Input, PageHeader } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { FilterBar, type FilterDef } from "@/components/data/FilterBar";
import { CriticalityBadge, TagChip } from "@/components/data/TagChip";
import { Dialog } from "@/components/ui/dialog";
import { useSession } from "@/features/auth/session";
import { useBusinessUnits } from "@/features/users/api";
import { formatDateTime } from "@/lib/utils";
import { useApplications, useConnections, useRepoMutation, useRepositories, useTagCategories, type RepoFilters } from "./api";
import { RepositoryDrawer } from "./RepositoryDrawer";

export type RepoSearch = RepoFilters & { repo?: string };

export function validateRepoSearch(s: Record<string, unknown>): RepoSearch {
  const out: RepoSearch = {};
  for (const k of ["q", "scm_connection_id", "application_id", "business_unit_id", "country_id", "criticality", "environment", "tag_id", "status", "owner", "repo"] as const) {
    if (typeof s[k] === "string" && (s[k] as string).length <= 200) out[k] = s[k] as string;
  }
  return out;
}

const columns: Column<Repository>[] = [
  {
    id: "name",
    header: "Repository",
    required: true,
    cell: (r) => (
      <div className="min-w-0">
        <div className="flex items-center gap-1.5 font-medium">
          <GitBranch className="size-3.5 shrink-0 text-muted-foreground" />
          <span className="truncate">{r.full_name}</span>
          {r.archived_at && <span className="rounded bg-surface-muted px-1 text-[10px] text-muted-foreground">archived</span>}
        </div>
        <div className="truncate text-[12px] text-muted-foreground">
          {r.scm_connection_name} · {r.scan_branch || r.default_branch || "default branch"}
        </div>
      </div>
    ),
    csv: (r) => r.full_name,
  },
  { id: "criticality", header: "Criticality", cell: (r) => <CriticalityBadge value={r.criticality} />, csv: (r) => r.criticality },
  { id: "application", header: "Application", cell: (r) => r.application?.name ?? <span className="text-muted-foreground">—</span>, csv: (r) => r.application?.name },
  {
    id: "placement",
    header: "Business unit / country",
    cell: (r) => (
      <span className="text-[12px]">
        {r.business_unit?.name ?? "—"}
        <span className="text-muted-foreground"> · {r.country ? `${r.country.name}` : "—"}</span>
      </span>
    ),
    csv: (r) => `${r.business_unit?.name ?? ""} / ${r.country?.code ?? ""}`,
  },
  { id: "environment", header: "Environment", cell: (r) => <span className="text-[12px] capitalize">{r.environment}</span>, csv: (r) => r.environment },
  {
    id: "tags",
    header: "Tags",
    cell: (r) => (
      <div className="flex max-w-72 flex-wrap gap-1">
        {r.tags.map((t) => (
          <TagChip key={t.id} name={t.name} category={t.category_name} color={t.color} />
        ))}
      </div>
    ),
    csv: (r) => r.tags.map((t) => `${t.category_name}:${t.name}`).join(";"),
  },
  { id: "tech", header: "Technologies", defaultHidden: true, className: "text-[12px]", cell: (r) => r.technologies.join(", ") || "—", csv: (r) => r.technologies.join(";") },
  { id: "visibility", header: "Visibility", defaultHidden: true, cell: (r) => <span className="text-[12px] capitalize">{r.visibility}</span>, csv: (r) => r.visibility },
  { id: "pushed", header: "Last push", defaultHidden: true, className: "tabular text-[12px] text-muted-foreground", cell: (r) => formatDateTime(r.last_pushed_at), csv: (r) => r.last_pushed_at },
];

export function RepositoriesPage() {
  const { can } = useSession();
  const search = useSearch({ strict: false }) as RepoSearch;
  const navigate = useNavigate();
  const [q, setQ] = useState(search.q ?? "");
  const dq = useDeferredValue(q.trim());
  const { repo, ...filters } = search;
  const repos = useRepositories({ ...filters, q: dq || undefined });
  const conns = useConnections();
  const apps = useApplications();
  const bus = useBusinessUnits();
  const cats = useTagCategories();
  const [selection, setSelection] = useState<Set<string>>(new Set());
  const [bulkOpen, setBulkOpen] = useState(false);
  useEffect(() => setSelection(new Set()), [JSON.stringify(filters)]);

  const set = (next: Partial<RepoSearch>) => void navigate({ to: "/repositories", search: { ...search, ...next } as never, replace: true });
  const rows = repos.data?.pages.flatMap((p) => p.items) ?? [];
  const canManage = can("repos.manage");

  const filterDefs: FilterDef[] = [
    { key: "scm_connection_id", label: "Connection", allLabel: "All connections", options: (conns.data ?? []).map((c) => ({ value: c.id, label: c.name })) },
    { key: "application_id", label: "Application", allLabel: "All applications", options: (apps.data ?? []).map((a) => ({ value: a.id, label: a.name })) },
    { key: "business_unit_id", label: "Business unit", allLabel: "All business units", options: (bus.data ?? []).map((b) => ({ value: b.id, label: b.name })) },
    {
      key: "criticality",
      label: "Criticality",
      allLabel: "All criticalities",
      options: ["critical", "high", "medium", "low"].map((v) => ({ value: v, label: v[0]!.toUpperCase() + v.slice(1) })),
    },
    {
      key: "environment",
      label: "Environment",
      allLabel: "All environments",
      options: ["production", "staging", "development", "test", "other"].map((v) => ({ value: v, label: v[0]!.toUpperCase() + v.slice(1) })),
    },
    {
      key: "tag_id",
      label: "Tag",
      allLabel: "All tags",
      options: (cats.data ?? []).flatMap((c) => c.tags.map((t) => ({ value: t.id, label: `${c.name}: ${t.name}` }))),
    },
    { key: "owner", label: "Ownership", allLabel: "Any ownership", options: [{ value: "none", label: "No application" }] },
    { key: "status", label: "Status", allLabel: "Active", options: [{ value: "archived", label: "Archived" }, { value: "all", label: "All" }] },
  ];

  return (
    <>
      <PageHeader
        title="Repositories"
        description="Source code repositories under PATHOS management."
        actions={
          canManage && (
            <Button asChild>
              <Link to="/repositories/import">
                <Plus /> Import repositories
              </Link>
            </Button>
          )
        }
      />
      <Card className="mb-3 p-3">
        <FilterBar
          filters={filterDefs}
          values={filters as Record<string, string | undefined>}
          onChange={(k, v) => set({ [k]: v })}
          onReset={() => {
            setQ("");
            void navigate({ to: "/repositories", search: {} as never, replace: true });
          }}
        />
      </Card>
      {selection.size > 0 && canManage && (
        <div className="mb-3 flex items-center gap-2 rounded-lg border border-primary/30 bg-primary/5 px-3 py-2 text-[13px]">
          <span className="font-medium">{selection.size} selected</span>
          <Button size="sm" variant="secondary" onClick={() => setBulkOpen(true)}>
            <Tags /> Edit tags
          </Button>
          <BulkScan ids={[...selection]} />
          <BulkArchive ids={[...selection]} onDone={() => setSelection(new Set())} />
          <Button size="sm" variant="ghost" onClick={() => setSelection(new Set())}>
            Clear
          </Button>
        </div>
      )}
      <Card>
        <DataTable
          tableId="repositories"
          exportName="pathos-repositories"
          columns={columns}
          rows={rows}
          rowKey={(r) => r.id}
          isPending={repos.isPending}
          error={repos.error}
          hasMore={repos.hasNextPage}
          loadingMore={repos.isFetchingNextPage}
          onLoadMore={() => void repos.fetchNextPage()}
          onRowClick={(r) => set({ repo: r.id })}
          selection={canManage ? selection : undefined}
          onSelectionChange={canManage ? setSelection : undefined}
          empty={
            <EmptyState icon={<GitBranch />} title={Object.keys(filters).length || dq ? "No repositories match these filters" : "No repositories yet"}>
              {canManage && !Object.keys(filters).length && !dq && (
                <>
                  Connect GitHub or Azure DevOps under <Link to="/admin/scm" className="text-primary underline">SCM connections</Link>, then import repositories.
                </>
              )}
            </EmptyState>
          }
          toolbar={
            <div className="relative w-full max-w-xs">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                aria-label="Search repositories"
                placeholder="Search repositories"
                className="pl-8"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                onBlur={() => set({ q: q.trim() || undefined })}
              />
            </div>
          }
        />
      </Card>
      <BulkTagDialog open={bulkOpen} onOpenChange={setBulkOpen} ids={[...selection]} />
      <RepositoryDrawer id={repo} onClose={() => set({ repo: undefined })} />
    </>
  );
}

function BulkScan({ ids }: { ids: string[] }) {
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

function BulkArchive({ ids, onDone }: { ids: string[]; onDone: () => void }) {
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

function BulkTagDialog({ open, onOpenChange, ids }: { open: boolean; onOpenChange: (o: boolean) => void; ids: string[] }) {
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

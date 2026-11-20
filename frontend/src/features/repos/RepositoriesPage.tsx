import { lazy, Suspense, useDeferredValue, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { ChartColumn, GitBranch, History, List, Plus, Search, SlidersHorizontal, Tags } from "lucide-react";
import type { AssetSettings, Repository } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Card, EmptyState, Input, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { FilterBar, type FilterDef } from "@/components/data/FilterBar";
import { ColorDot, CriticalityBadge, TagChip } from "@/components/data/TagChip";
import { catalog, catalogEntry, catalogLabel, useAssetSettings } from "@/features/assets/api";
import { useSession } from "@/features/auth/session";
import { useProviders } from "@/features/settings/scmApi";
import { useBusinessUnits, useRegions } from "@/features/users/api";
import { formatDateTime } from "@/lib/utils";
import { repoFilterKeys, repoSorts, useApplications, useConnections, useRepositories, useRepositoryInsights, useTagCategories, type RepoFilters } from "./api";
import { JobStatusPill } from "@/components/data/Severity";
import { ExternalUrl, ProviderIcon, PublicExposureBadge, publicExposureOptions, RepositoryKey, SyncStatusBadge, syncStatusOptions } from "./badges";
import { BulkArchive, BulkScan, BulkTagDialog } from "./BulkActions";
import { PersonPicker } from "./metadata/MetadataSections";
import { buTree } from "./metadata/fields";
import { RepoKpis } from "./RepoKpis";
import { RepositoryDrawer } from "./RepositoryDrawer";

const InsightsCharts = lazy(() => import("./InsightsCharts"));

export type RepoSearch = RepoFilters & { repo?: string; view?: "list" | "insights" };

export function validateRepoSearch(s: Record<string, unknown>): RepoSearch {
  const out: RepoSearch = {};
  for (const k of [...repoFilterKeys, "repo"] as const) {
    const v = s[k];
    // The router JSON-parses search values: "?missing_production_url=true" arrives as a boolean.
    if (typeof v === "boolean" || typeof v === "number") out[k] = String(v);
    else if (typeof v === "string" && v.length <= 200) out[k] = v;
  }
  if (s.view === "insights") out.view = "insights";
  return out;
}

const dash = <span className="text-muted-foreground">—</span>;

function buildColumns(settings: AssetSettings | undefined): Column<Repository>[] {
  return [
    {
      id: "repository_key",
      header: "Repository ID",
      exportAlways: true,
      cell: (r) => <RepositoryKey value={r.repository_key} copy />,
      csv: (r) => r.repository_key,
    },
    {
      id: "name",
      header: "Repository",
      required: true,
      cell: (r) => (
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 font-medium">
            <ColorDot color={r.color} label={r.color ? `Asset colour ${r.color}` : undefined} />
            <span className="truncate">{r.display_name || r.full_name}</span>
            {r.archived_at && <span className="rounded bg-surface-muted px-1 text-[10px] text-muted-foreground">archived</span>}
            {r.source_type === "git" && (
              <span className="rounded bg-warning-soft px-1 text-[10px] text-warning" title="Imported by URL without a token: public, read-only">
                anonymous
              </span>
            )}
          </div>
          <div className="truncate text-[12px] text-muted-foreground">
            {r.full_name}
            {r.source_type !== "upload" && ` · ${r.scan_branch || r.default_branch || "default branch"}`}
          </div>
        </div>
      ),
      csv: (r) => r.display_name || r.full_name,
    },
    {
      id: "production_url",
      header: "Production URL",
      exportAlways: true,
      cell: (r) => (r.production_url ? <ExternalUrl href={r.production_url} className="max-w-56" /> : dash),
      csv: (r) => r.production_url,
    },
    {
      id: "staging_url",
      header: "Staging URL",
      defaultHidden: true,
      exportAlways: true,
      cell: (r) => (r.staging_url ? <ExternalUrl href={r.staging_url} className="max-w-56" /> : dash),
      csv: (r) => r.staging_url,
    },
    { id: "public_exposure", header: "Public exposure", exportAlways: true, cell: (r) => <PublicExposureBadge value={r.public_exposure} />, csv: (r) => r.public_exposure },
    {
      id: "public_endpoints",
      header: "Public endpoints",
      defaultHidden: true,
      exportAlways: true,
      className: "text-[12px]",
      cell: (r) => {
        const all = [...(r.public_urls ?? []), ...(r.public_domains ?? []), ...(r.public_ips ?? [])];
        return all.length ? <span className="block max-w-64 truncate font-mono" title={all.join("\n")}>{all.join(", ")}</span> : dash;
      },
      csv: (r) => [...(r.public_urls ?? []), ...(r.public_domains ?? []), ...(r.public_ips ?? [])].join(";"),
    },
    {
      id: "last_scan",
      header: "Last scan",
      cell: (r) =>
        r.last_scan_status ? (
          <span className="flex flex-col">
            <JobStatusPill status={r.last_scan_status} />
            {r.last_scan_at && <span className="tabular text-[11px] text-muted-foreground">{formatDateTime(r.last_scan_at)}</span>}
          </span>
        ) : (
          <span className="text-[12px] text-muted-foreground">Never</span>
        ),
      csv: (r) => (r.last_scan_status ? `${r.last_scan_status}${r.last_scan_at ? ` ${r.last_scan_at}` : ""}` : ""),
    },
    { id: "source", header: "Source", cell: (r) => <ProviderIcon provider={r.provider} withLabel />, csv: (r) => r.provider },
    {
      id: "criticality",
      header: "Criticality",
      cell: (r) => {
        const c = catalogEntry(settings, "criticality", r.criticality);
        return <CriticalityBadge value={r.criticality} label={c?.label} color={c?.color} />;
      },
      csv: (r) => r.criticality,
    },
    { id: "business_owner", header: "Business owner", cell: (r) => r.business_owner?.name ?? dash, csv: (r) => r.business_owner?.email },
    { id: "technical_owner", header: "Technical owner", defaultHidden: true, cell: (r) => r.technical_owner?.name ?? dash, csv: (r) => r.technical_owner?.email },
    { id: "business_region", header: "Business region", cell: (r) => r.business_region?.name ?? dash, csv: (r) => r.business_region?.name },
    {
      id: "data_classification",
      header: "Data classification",
      cell: (r) => catalogLabel(settings, "data_classification", r.data_classification) || dash,
      csv: (r) => r.data_classification,
    },
    { id: "lifecycle", header: "Lifecycle", defaultHidden: true, cell: (r) => catalogLabel(settings, "lifecycle_status", r.lifecycle_status) || dash, csv: (r) => r.lifecycle_status },
    { id: "sync", header: "Sync", cell: (r) => <SyncStatusBadge status={r.sync_status} />, csv: (r) => r.sync_status },
    { id: "application", header: "Application", defaultHidden: true, cell: (r) => r.application?.name ?? dash, csv: (r) => r.application?.name },
    {
      id: "placement",
      header: "Business unit / country",
      defaultHidden: true,
      cell: (r) => (
        <span className="text-[12px]">
          {r.business_unit?.name ?? "—"}
          <span className="text-muted-foreground"> · {r.country ? r.country.name : "—"}</span>
        </span>
      ),
      csv: (r) => `${r.business_unit?.name ?? ""} / ${r.country?.code ?? ""}`,
    },
    { id: "environment", header: "Environment", defaultHidden: true, cell: (r) => catalogLabel(settings, "environment", r.environment) || dash, csv: (r) => r.environment },
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
    { id: "last_sync", header: "Last sync", defaultHidden: true, className: "tabular text-[12px] text-muted-foreground", cell: (r) => formatDateTime(r.last_sync_at), csv: (r) => r.last_sync_at },
    { id: "tech", header: "Technologies", defaultHidden: true, className: "text-[12px]", cell: (r) => r.technologies.join(", ") || "—", csv: (r) => r.technologies.join(";") },
    { id: "visibility", header: "Visibility", defaultHidden: true, cell: (r) => <span className="text-[12px] capitalize">{r.visibility}</span>, csv: (r) => r.visibility },
    { id: "pushed", header: "Last push", defaultHidden: true, className: "tabular text-[12px] text-muted-foreground", cell: (r) => formatDateTime(r.last_pushed_at), csv: (r) => r.last_pushed_at },
  ];
}

const primaryFilters = new Set(["provider", "business_unit_id", "business_region_id", "criticality", "public_exposure", "data_classification", "lifecycle_status", "sync_status", "status"]);

/** Free-text filter committed to the URL on Enter or blur. */
function TextFilter({ id, label, placeholder, value, onCommit, mono }: { id: string; label: string; placeholder: string; value?: string; onCommit: (v: string | undefined) => void; mono?: boolean }) {
  const [v, setV] = useState(value ?? "");
  useEffect(() => setV(value ?? ""), [value]);
  const commit = () => {
    const t = v.trim();
    if (t !== (value ?? "")) onCommit(t || undefined);
  };
  return (
    <div className="w-56">
      <Input
        id={id}
        value={v}
        placeholder={placeholder}
        maxLength={200}
        className={mono ? "font-mono" : undefined}
        onChange={(e) => setV(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => e.key === "Enter" && commit()}
      />
      <label htmlFor={id} className="text-[11px] text-muted-foreground">
        {label}
      </label>
    </div>
  );
}

export function RepositoriesPage() {
  const { can } = useSession();
  const search = validateRepoSearch(useSearch({ strict: false }) as Record<string, unknown>);
  const navigate = useNavigate();
  const [q, setQ] = useState(search.q ?? "");
  const dq = useDeferredValue(q.trim());
  const { repo, view, ...filters } = search;
  const listFilters = { ...filters, q: dq || undefined };
  const repos = useRepositories(listFilters);
  const insights = useRepositoryInsights(listFilters);
  const settings = useAssetSettings();
  const providers = useProviders();
  const conns = useConnections();
  const apps = useApplications();
  const bus = useBusinessUnits();
  const regions = useRegions();
  const cats = useTagCategories();
  const [selection, setSelection] = useState<Set<string>>(new Set());
  const [bulkOpen, setBulkOpen] = useState(false);
  const [more, setMore] = useState(false);
  const [owners, setOwners] = useState<Record<string, { id: string; name: string }>>({});
  useEffect(() => setSelection(new Set()), [JSON.stringify(filters)]);
  const columns = useMemo(() => buildColumns(settings.data), [settings.data]);

  const set = (next: Partial<RepoSearch>) => void navigate({ to: "/repositories", search: { ...search, ...next } as never, replace: true });
  const rows = repos.data?.pages.flatMap((p) => p.items) ?? [];
  const canManage = can("repos.manage");
  const cat = (kind: Parameters<typeof catalog>[1]) => catalog(settings.data, kind).map((c) => ({ value: c.key, label: c.label }));

  const filterDefs: FilterDef[] = [
    {
      key: "provider",
      label: "Source",
      allLabel: "All sources",
      options: [...(providers.data ?? []).map((p) => ({ value: p.key, label: p.label })), { value: "upload", label: "Local upload" }],
    },
    { key: "business_unit_id", label: "Business unit", allLabel: "All business units", options: buTree(bus.data ?? []).map(({ unit, depth }) => ({ value: unit.id, label: `${"  ".repeat(depth)}${unit.name}` })) },
    { key: "business_region_id", label: "Business region", allLabel: "All business regions", options: (regions.data ?? []).map((r) => ({ value: r.id, label: r.name })) },
    { key: "criticality", label: "Criticality", allLabel: "All criticalities", options: cat("criticality").length ? cat("criticality") : ["critical", "high", "medium", "low"].map((v) => ({ value: v, label: v[0]!.toUpperCase() + v.slice(1) })) },
    { key: "public_exposure", label: "Public exposure", allLabel: "Any public exposure", options: publicExposureOptions },
    { key: "data_classification", label: "Data classification", allLabel: "All data classifications", options: cat("data_classification") },
    { key: "lifecycle_status", label: "Lifecycle", allLabel: "All lifecycle states", options: cat("lifecycle_status") },
    { key: "sync_status", label: "Sync status", allLabel: "Any sync status", options: syncStatusOptions },
    { key: "status", label: "Status", allLabel: "Active", options: [{ value: "archived", label: "Archived" }, { value: "all", label: "Active and archived" }] },
    // More filters
    { key: "scm_connection_id", label: "Connection", allLabel: "All connections", options: (conns.data ?? []).map((c) => ({ value: c.id, label: c.name })) },
    { key: "application_id", label: "Application", allLabel: "All applications", options: (apps.data ?? []).map((a) => ({ value: a.id, label: a.name })) },
    {
      key: "country_id",
      label: "Country",
      allLabel: "All countries",
      options: (regions.data ?? []).flatMap((r) => r.countries.map((c) => ({ value: c.id, label: `${c.name} · ${r.code}` }))).sort((a, b) => a.label.localeCompare(b.label)),
    },
    { key: "environment", label: "Environment", allLabel: "All environments", options: cat("environment") },
    { key: "internet_exposure", label: "Network reachability", allLabel: "Any network reachability", options: cat("internet_exposure") },
    { key: "compliance", label: "Compliance scope", allLabel: "Any compliance scope", options: cat("compliance") },
    { key: "tag_id", label: "Tag", allLabel: "All tags", options: (cats.data ?? []).flatMap((c) => c.tags.map((t) => ({ value: t.id, label: `${c.name}: ${t.name}` }))) },
    {
      key: "missing_owner",
      label: "Missing owner",
      allLabel: "Any ownership",
      options: [
        { value: "business", label: "No business owner" },
        { value: "technical", label: "No technical owner" },
        { value: "any", label: "Missing any owner" },
      ],
    },
    { key: "owner", label: "Application ownership", allLabel: "Any application", options: [{ value: "none", label: "No application" }] },
  ];
  const shownFilters = filterDefs.filter((f) => more || primaryFilters.has(f.key));
  const extraKeys = ["business_owner_id", "technical_owner_id", "repository_key", "production_url", "staging_url"] as const;
  const hiddenActive = filterDefs.filter((f) => !primaryFilters.has(f.key) && filters[f.key as keyof RepoFilters]).length + extraKeys.filter((k) => filters[k]).length;

  const ownerValue = (key: "business_owner_id" | "technical_owner_id") => {
    const id = filters[key];
    if (!id) return null;
    const known = owners[id] ?? insights.data?.by_business_owner.find((b) => b.key === id);
    return { id, name: known ? ("name" in known ? known.name : known.label) : "Selected person" };
  };

  const resetAll = () => {
    setQ("");
    void navigate({ to: "/repositories", search: (view ? { view } : {}) as never, replace: true });
  };

  return (
    <>
      <PageHeader
        title="Repositories"
        description="Source code repositories under PATHOS management."
        actions={
          <>
            <Button variant="ghost" asChild>
              <Link to="/repositories/imports">
                <History /> Import history
              </Link>
            </Button>
            {canManage && (
              <Button asChild>
                <Link to="/repositories/import">
                  <Plus /> Import repositories
                </Link>
              </Button>
            )}
          </>
        }
      />
      <RepoKpis insights={insights} />

      <Card className="mb-3 space-y-2 p-3">
        <FilterBar
          filters={shownFilters}
          values={filters as Record<string, string | undefined>}
          onChange={(k, v) => set({ [k]: v })}
          onReset={resetAll}
          trailing={
            <>
              <label className="flex items-center gap-1.5 text-[12px] text-muted-foreground">
                <input
                  type="checkbox"
                  className="accent-[var(--primary)]"
                  checked={filters.missing_production_url === "true"}
                  onChange={(e) => set({ missing_production_url: e.target.checked ? "true" : undefined })}
                />
                Missing production URL
              </label>
              <Button variant="ghost" size="sm" onClick={() => setMore((m) => !m)} aria-expanded={more}>
                <SlidersHorizontal /> {more ? "Fewer filters" : `More filters${hiddenActive ? ` (${hiddenActive})` : ""}`}
              </Button>
            </>
          }
        />
        {more && (
          <div className="flex flex-wrap gap-2">
            <TextFilter id="filter-repository-key" label="Repository ID (exact)" placeholder="QD-REPO-000042" mono value={filters.repository_key} onCommit={(v) => set({ repository_key: v })} />
            <TextFilter id="filter-production-url" label="Production URL contains" placeholder="example.com" value={filters.production_url} onCommit={(v) => set({ production_url: v })} />
            <TextFilter id="filter-staging-url" label="Staging URL contains" placeholder="staging.example.com" value={filters.staging_url} onCommit={(v) => set({ staging_url: v })} />
            <div className="w-56">
              <PersonPicker
                id="filter-business-owner"
                value={ownerValue("business_owner_id")}
                onChange={(v) => {
                  if (v) setOwners((o) => ({ ...o, [v.id]: v }));
                  set({ business_owner_id: v?.id });
                }}
              />
              <label htmlFor="filter-business-owner" className="text-[11px] text-muted-foreground">
                Business owner
              </label>
            </div>
            <div className="w-56">
              <PersonPicker
                id="filter-technical-owner"
                value={ownerValue("technical_owner_id")}
                onChange={(v) => {
                  if (v) setOwners((o) => ({ ...o, [v.id]: v }));
                  set({ technical_owner_id: v?.id });
                }}
              />
              <label htmlFor="filter-technical-owner" className="text-[11px] text-muted-foreground">
                Technical owner
              </label>
            </div>
          </div>
        )}
      </Card>

      <div className="mb-3 flex items-center gap-2">
        <div className="flex rounded-md border border-border bg-surface p-0.5" role="tablist" aria-label="View">
          {(
            [
              ["list", "List", <List key="l" className="size-4" />],
              ["insights", "Insights", <ChartColumn key="i" className="size-4" />],
            ] as const
          ).map(([v, l, icon]) => (
            <button
              key={v}
              role="tab"
              aria-selected={(view ?? "list") === v}
              onClick={() => set({ view: v === "list" ? undefined : v })}
              className={`flex items-center gap-1.5 rounded px-3 py-1 text-[13px] ${(view ?? "list") === v ? "bg-primary/10 font-medium text-primary" : "text-muted-foreground"}`}
            >
              {icon}
              {l}
            </button>
          ))}
        </div>
      </div>

      {view === "insights" ? (
        insights.isError ? (
          <Alert>
            Could not load insights: {insights.error.message}{" "}
            <button className="underline" onClick={() => void insights.refetch()}>
              Try again
            </button>
          </Alert>
        ) : !insights.data ? (
          <Skeleton className="h-80" />
        ) : (
          <Suspense fallback={<Skeleton className="h-80" />}>
            <InsightsCharts
              insights={insights.data}
              onDrill={(filter, key) => {
                if (key === "" && filter === "business_owner_id") set({ missing_owner: "business", view: undefined });
                else if (key) set({ [filter]: key, view: undefined });
              }}
            />
          </Suspense>
        )
      ) : (
        <>
          {selection.size > 0 && canManage && (
            <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-primary/30 bg-primary/5 px-3 py-2 text-[13px]">
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
              tableId="repositories-v3"
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
                      <Link to="/repositories/import" className="text-primary underline">
                        Import repositories
                      </Link>{" "}
                      from a local archive, a Git provider or Azure DevOps.
                    </>
                  )}
                </EmptyState>
              }
              toolbar={
                <>
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
                  <Select aria-label="Sort" value={filters.sort ?? ""} onChange={(e) => set({ sort: e.target.value || undefined })}>
                    <option value="">Default order</option>
                    {repoSorts.map(([v, l]) => (
                      <option key={v} value={v}>
                        {l}
                      </option>
                    ))}
                  </Select>
                </>
              }
            />
          </Card>
        </>
      )}
      <BulkTagDialog open={bulkOpen} onOpenChange={setBulkOpen} ids={[...selection]} />
      <RepositoryDrawer id={repo} onClose={() => set({ repo: undefined })} />
    </>
  );
}

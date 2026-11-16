import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, getCsrfToken } from "@/api/client";
import type {
  Application,
  DiscoveredRepo,
  ImportResponse,
  Page,
  Repository,
  RepositoryInsights,
  RepositorySecurity,
  ScmConnection,
  SourceSnapshot,
  SyncRun,
  TagCategory,
} from "@/api/types";

export const repoFilterKeys = [
  "q", "scm_connection_id", "application_id", "business_unit_id", "country_id", "criticality", "environment", "tag_id", "status", "owner",
  "provider", "source_type", "business_owner_id", "technical_owner_id", "business_region_id", "data_classification", "lifecycle_status",
  "sync_status", "internet_exposure", "compliance", "missing_owner", "sort",
] as const;

export type RepoFilters = Partial<Record<(typeof repoFilterKeys)[number], string>>;

export const repoSorts = [
  ["name", "Name (A–Z)"],
  ["-name", "Name (Z–A)"],
  ["-created_at", "Newest first"],
  ["created_at", "Oldest first"],
  ["-criticality", "Most critical first"],
  ["criticality", "Least critical first"],
  ["-last_sync_at", "Recently synced"],
  ["last_sync_at", "Least recently synced"],
] as const;

function filterParams(f: RepoFilters, omit: string[] = []) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) if (v && !omit.includes(k)) p.set(k, v);
  return p;
}

export function useRepositories(f: RepoFilters) {
  return useInfiniteQuery({
    queryKey: ["repositories", f],
    initialPageParam: "",
    queryFn: ({ pageParam, signal }) => {
      const p = filterParams(f);
      p.set("limit", "100");
      if (pageParam) p.set("cursor", pageParam);
      return api<Page<Repository>>(`/api/v1/repositories?${p}`, { signal });
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
}

export function useRepository(id: string | undefined) {
  return useQuery({ queryKey: ["repository", id], queryFn: () => api<Repository>(`/api/v1/repositories/${id}`), enabled: !!id });
}

/** KPIs and breakdowns for the same filters as the list (sort is ignored). */
export function useRepositoryInsights(f: RepoFilters, enabled = true) {
  return useQuery({
    queryKey: ["repository-insights", f],
    queryFn: ({ signal }) => api<RepositoryInsights>(`/api/v1/repositories/insights?${filterParams(f, ["sort"])}`, { signal }),
    enabled,
    staleTime: 30_000,
  });
}

export function useSyncRuns(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["repository-sync-runs", id],
    queryFn: () => api<{ items: SyncRun[] }>(`/api/v1/repositories/${id}/sync-runs`).then((r) => r.items),
    enabled: !!id && enabled,
  });
}

export function useSnapshots(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["repository-snapshots", id],
    queryFn: () => api<{ items: SourceSnapshot[] }>(`/api/v1/repositories/${id}/snapshots`).then((r) => r.items),
    enabled: !!id && enabled,
  });
}

export function useRepositorySecurity(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["repository-security", id],
    queryFn: () => api<RepositorySecurity>(`/api/v1/repositories/${id}/security`),
    enabled: !!id && enabled,
  });
}

export function useSyncRepository(id: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api<{ run: SyncRun; repository: Repository }>(`/api/v1/repositories/${id}/sync`, { method: "POST" }),
    onSuccess: (r) => {
      qc.setQueryData(["repository", id], r.repository);
      for (const k of ["repository-sync-runs", "repositories", "repository-insights"]) void qc.invalidateQueries({ queryKey: [k] });
    },
  });
}

export function useBranches(id: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ["branches", id],
    queryFn: () => api<{ items: string[]; default_branch: string }>(`/api/v1/repositories/${id}/branches`),
    enabled: !!id && enabled,
    staleTime: 60_000,
    retry: false,
  });
}

export function useApplications(status = "") {
  return useQuery({
    queryKey: ["applications", status],
    queryFn: () => api<Page<Application>>(`/api/v1/applications${status ? `?status=${status}` : ""}`).then((r) => r.items),
  });
}

export function useTagCategories() {
  return useQuery({ queryKey: ["tag-categories"], queryFn: () => api<Page<TagCategory>>("/api/v1/tag-categories").then((r) => r.items) });
}

export function useConnections() {
  return useQuery({ queryKey: ["scm-connections"], queryFn: () => api<Page<ScmConnection>>("/api/v1/scm-connections").then((r) => r.items) });
}

export function useDiscover(connectionId: string | undefined) {
  return useQuery({
    queryKey: ["discover", connectionId],
    queryFn: () => api<{ items: DiscoveredRepo[]; truncated: boolean }>(`/api/v1/scm-connections/${connectionId}/discover`),
    enabled: !!connectionId,
    retry: false,
    staleTime: 60_000,
  });
}

/** Invalidates everything derived from repositories. */
export function useInvalidateRepos() {
  const qc = useQueryClient();
  return () => {
    for (const k of ["repositories", "repository", "repository-insights", "applications", "tag-categories", "discover", "dashboard", "scm-connections", "remote-repositories"]) {
      void qc.invalidateQueries({ queryKey: [k] });
    }
  };
}

export function useRepoMutation<T, V>(fn: (v: V) => Promise<T>) {
  const invalidate = useInvalidateRepos();
  return useMutation({ mutationFn: fn, onSuccess: () => invalidate() });
}

export const importRepos = (body: unknown) => api<ImportResponse>("/api/v1/repositories/import", { method: "POST", body });

export async function importCsv(connectionId: string, csv: string, dryRun: boolean): Promise<ImportResponse> {
  const res = await fetch(`/api/v1/repositories/import-csv?scm_connection_id=${connectionId}&dry_run=${dryRun}`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "text/csv", "X-CSRF-Token": getCsrfToken() },
    body: csv,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error?.message ?? res.statusText);
  return data as ImportResponse;
}

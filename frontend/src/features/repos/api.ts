import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, getCsrfToken } from "@/api/client";
import type { Application, DiscoveredRepo, ImportResponse, Page, Repository, ScmConnection, TagCategory } from "@/api/types";

export interface RepoFilters {
  q?: string;
  scm_connection_id?: string;
  application_id?: string;
  business_unit_id?: string;
  country_id?: string;
  criticality?: string;
  environment?: string;
  tag_id?: string;
  status?: string;
  owner?: string;
}

export function useRepositories(f: RepoFilters) {
  return useInfiniteQuery({
    queryKey: ["repositories", f],
    initialPageParam: "",
    queryFn: ({ pageParam, signal }) => {
      const p = new URLSearchParams({ limit: "100" });
      for (const [k, v] of Object.entries(f)) if (v) p.set(k, v);
      if (pageParam) p.set("cursor", pageParam);
      return api<Page<Repository>>(`/api/v1/repositories?${p}`, { signal });
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
}

export function useRepository(id: string | undefined) {
  return useQuery({ queryKey: ["repository", id], queryFn: () => api<Repository>(`/api/v1/repositories/${id}`), enabled: !!id });
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
    for (const k of ["repositories", "repository", "applications", "tag-categories", "discover", "dashboard", "scm-connections"]) {
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

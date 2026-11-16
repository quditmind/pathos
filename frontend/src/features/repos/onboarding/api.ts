import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type {
  CreateImportRequest,
  ImportJob,
  ImportStatus,
  ImportValidation,
  Page,
  RemoteRepoDetails,
  RemoteRepoPage,
  ScmOrganization,
  ScmProject,
} from "@/api/types";

export function useScmOrganizations(connectionId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["scm-organizations", connectionId],
    queryFn: ({ signal }) => api<{ items: ScmOrganization[] }>(`/api/v1/scm-connections/${connectionId}/organizations`, { signal }).then((r) => r.items),
    enabled: !!connectionId && enabled,
    retry: false,
    staleTime: 60_000,
  });
}

export function useScmProjects(connectionId: string | undefined, organization: string, enabled = true) {
  return useQuery({
    queryKey: ["scm-projects", connectionId, organization],
    queryFn: ({ signal }) =>
      api<{ items: ScmProject[] }>(`/api/v1/scm-connections/${connectionId}/projects?${new URLSearchParams({ organization })}`, { signal }).then((r) => r.items),
    enabled: !!connectionId && enabled,
    retry: false,
    staleTime: 60_000,
  });
}

export function useRemoteRepositories(connectionId: string | undefined, f: { organization: string; project: string; q: string }, enabled = true) {
  return useInfiniteQuery({
    queryKey: ["remote-repositories", connectionId, f],
    initialPageParam: "",
    queryFn: ({ pageParam, signal }) => {
      const p = new URLSearchParams();
      if (f.organization) p.set("organization", f.organization);
      if (f.project) p.set("project", f.project);
      if (f.q) p.set("q", f.q);
      if (pageParam) p.set("page_token", pageParam);
      return api<RemoteRepoPage>(`/api/v1/scm-connections/${connectionId}/remote-repositories?${p}`, { signal });
    },
    getNextPageParam: (last) => last.next_page_token || undefined,
    enabled: !!connectionId && enabled,
    retry: false,
    staleTime: 30_000,
  });
}

export function useRemoteRepoDetails(
  connectionId: string | undefined,
  ref: { external_id: string; full_name: string; organization: string; project: string } | null,
) {
  return useQuery({
    queryKey: ["remote-repository-details", connectionId, ref?.external_id],
    queryFn: ({ signal }) => {
      const p = new URLSearchParams({
        external_id: ref!.external_id,
        full_name: ref!.full_name,
        organization: ref!.organization,
        project: ref!.project,
      });
      return api<RemoteRepoDetails>(`/api/v1/scm-connections/${connectionId}/remote-repositories/details?${p}`, { signal });
    },
    enabled: !!connectionId && !!ref,
    retry: false,
    staleTime: 60_000,
  });
}

export const validateImport = (body: CreateImportRequest) =>
  api<ImportValidation>("/api/v1/repository-imports/validate", { method: "POST", body });

export const createImport = (body: CreateImportRequest) => api<ImportJob>("/api/v1/repository-imports", { method: "POST", body });

export const activeStatuses: ImportStatus[] = ["pending", "queued", "validating", "importing", "registering"];
export const isActive = (s: ImportStatus) => activeStatuses.includes(s);

/** Poll every 2 s while the job or any item is still being processed; stop when everything is terminal. */
export function importPollInterval(job: ImportJob | undefined): number | false {
  if (!job) return false;
  return isActive(job.status) || (job.items ?? []).some((i) => isActive(i.status)) ? 2000 : false;
}

export function useImportJob(id: string) {
  return useQuery({
    queryKey: ["repository-import", id],
    queryFn: ({ signal }) => api<ImportJob>(`/api/v1/repository-imports/${id}`, { signal }),
    refetchInterval: (q) => importPollInterval(q.state.data),
  });
}

export function useImportJobs(f: { status: string; mine: boolean }) {
  return useInfiniteQuery({
    queryKey: ["repository-imports", f],
    initialPageParam: "",
    queryFn: ({ pageParam, signal }) => {
      const p = new URLSearchParams({ status: f.status || "all" });
      if (f.mine) p.set("mine", "true");
      if (pageParam) p.set("cursor", pageParam);
      return api<Page<ImportJob>>(`/api/v1/repository-imports?${p}`, { signal });
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    refetchInterval: (q) => (q.state.data?.pages.some((pg) => pg.items.some((j) => isActive(j.status))) ? 5000 : false),
  });
}

export function useImportAction(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (a: { action: "cancel" } | { action: "retry"; item_ids?: string[]; allow_duplicate?: boolean }) => {
      if (a.action === "cancel") return api<ImportJob>(`/api/v1/repository-imports/${id}/cancel`, { method: "POST" });
      const body: { item_ids?: string[]; allow_duplicate?: boolean } = {};
      if (a.item_ids) body.item_ids = a.item_ids;
      if (a.allow_duplicate) body.allow_duplicate = true;
      return api<ImportJob>(`/api/v1/repository-imports/${id}/retry`, { method: "POST", body });
    },
    onSuccess: (job) => {
      qc.setQueryData(["repository-import", id], (old: ImportJob | undefined) => ({ ...job, items: job.items ?? old?.items }));
      void qc.invalidateQueries({ queryKey: ["repository-import", id] });
      void qc.invalidateQueries({ queryKey: ["repository-imports"] });
    },
  });
}

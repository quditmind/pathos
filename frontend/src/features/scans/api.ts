import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { CatalogScanner, Finding, Page, ScanJob, ScanProfile, Worker } from "@/api/types";

export function useScans(f: { status?: string; repository_id?: string; schedule_id?: string }, live = true) {
  return useInfiniteQuery({
    queryKey: ["scans", f],
    initialPageParam: "",
    queryFn: ({ pageParam, signal }) => {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(f)) if (v) p.set(k, v);
      if (pageParam) p.set("cursor", pageParam);
      return api<Page<ScanJob>>(`/api/v1/scans?${p}`, { signal });
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    // Poll while jobs are active.
    refetchInterval: (q) =>
      live && q.state.data?.pages.some((pg) => pg.items.some((j) => j.status === "queued" || j.status === "running")) ? 4000 : false,
  });
}

export function useScan(id: string | undefined) {
  return useQuery({
    queryKey: ["scan", id],
    queryFn: () => api<ScanJob>(`/api/v1/scans/${id}`),
    enabled: !!id,
    refetchInterval: (q) => (q.state.data && (q.state.data.status === "queued" || q.state.data.status === "running") ? 3000 : false),
  });
}

export function useFindings(f: Record<string, string | undefined>) {
  return useInfiniteQuery({
    queryKey: ["findings", f],
    initialPageParam: "",
    queryFn: ({ pageParam, signal }) => {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(f)) if (v) p.set(k, v);
      if (pageParam) p.set("cursor", pageParam);
      return api<Page<Finding>>(`/api/v1/findings?${p}`, { signal });
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
}

export function useFindingSummary(f: Record<string, string | undefined>) {
  return useQuery({
    queryKey: ["findings-summary", f],
    queryFn: () => {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(f)) if (v) p.set(k, v);
      return api<Record<string, number>>(`/api/v1/findings/summary?${p}`);
    },
  });
}

export function useFinding(id: string | undefined) {
  return useQuery({ queryKey: ["finding", id], queryFn: () => api<Finding>(`/api/v1/findings/${id}`), enabled: !!id });
}

export function useProfiles() {
  return useQuery({ queryKey: ["scan-profiles"], queryFn: () => api<Page<ScanProfile>>("/api/v1/scan-profiles").then((r) => r.items) });
}

export function useProfile(id: string | undefined) {
  return useQuery({ queryKey: ["scan-profile", id], queryFn: () => api<ScanProfile>(`/api/v1/scan-profiles/${id}`), enabled: !!id });
}

export function useCatalog() {
  return useQuery({ queryKey: ["scanners"], queryFn: () => api<Page<CatalogScanner>>("/api/v1/scanners").then((r) => r.items), staleTime: 600_000 });
}

export function useWorkers() {
  return useQuery({ queryKey: ["workers"], queryFn: () => api<Page<Worker>>("/api/v1/workers").then((r) => r.items), refetchInterval: 15_000 });
}

export function useScanMutation<T, V>(fn: (v: V) => Promise<T>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      for (const k of ["scans", "scan", "scan-profiles", "scan-profile", "workers", "findings", "dashboard", "repository"]) void qc.invalidateQueries({ queryKey: [k] });
    },
  });
}

export const scanRepo = (id: string) => api<{ job_id: string; coalesced: boolean }>(`/api/v1/repositories/${id}/scan`, { method: "POST" });

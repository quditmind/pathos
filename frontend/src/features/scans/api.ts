import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import { toolCheckLabel } from "@/lib/checkKinds";
import type {
  CatalogScanner,
  Finding,
  Page,
  ScanComparison,
  ScanEvent,
  ScanFinding,
  ScanJob,
  ScanLogLine,
  ScanOverview,
  ScanProfile,
  ScanKindProgress,
  ProfileKind,
  ScanStage,
  StartScanItem,
  ScanTypesResponse,
  StartScanRequest,
  Worker,
} from "@/api/types";

/** Query parameters of GET /api/v1/scans (see types.ts). */
export type ScanListFilters = Partial<
  Record<"q" | "scan_key" | "repository_key" | "repository_id" | "profile_id" | "schedule_id" | "trigger" | "scanner" | "kind" | "status" | "asset_type" | "from" | "to", string>
>;

export const isActive = (j: Pick<ScanJob, "status">) => j.status === "queued" || j.status === "running";

export function useScans(f: ScanListFilters, live = true, interval = 5000) {
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
      live && q.state.data?.pages.some((pg) => pg.items.some(isActive)) ? interval : false,
  });
}

export function useScan(id: string | undefined) {
  return useQuery({
    queryKey: ["scan", id],
    queryFn: () => api<ScanJob>(`/api/v1/scans/${id}`),
    enabled: !!id,
    refetchInterval: (q) => (q.state.data && isActive(q.state.data) ? 3000 : false),
  });
}

export function useScanStages(id: string, live: boolean) {
  return useQuery({
    queryKey: ["scan", id, "stages"],
    queryFn: () => api<{ stages: ScanStage[]; events: ScanEvent[]; kinds?: ScanKindProgress[] }>(`/api/v1/scans/${id}/stages`),
    refetchInterval: live ? 3000 : false,
  });
}

export function useScanFindings(id: string, f: { severity?: string; scanner?: string; kind?: string }, enabled = true) {
  return useQuery({
    queryKey: ["scan", id, "findings", f],
    queryFn: () => {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(f)) if (v) p.set(k, v);
      return api<{ items: ScanFinding[] }>(`/api/v1/scans/${id}/findings?${p}`).then((r) => r.items);
    },
    enabled,
  });
}

export function useScanHistory(id: string) {
  return useQuery({ queryKey: ["scan", id, "history"], queryFn: () => api<{ items: ScanJob[] }>(`/api/v1/scans/${id}/history`).then((r) => r.items) });
}

export type LogPage = { items: ScanLogLine[]; sources: string[]; next_after_id: number | null };

export const fetchScanLogs = (id: string, f: { source?: string; level?: string; after_id?: number }, signal?: AbortSignal) => {
  const p = new URLSearchParams();
  if (f.source) p.set("source", f.source);
  if (f.level) p.set("level", f.level);
  if (f.after_id) p.set("after_id", String(f.after_id));
  return api<LogPage>(`/api/v1/scans/${id}/logs?${p}`, { signal });
};

export function useScanOverview(days: number) {
  return useQuery({
    queryKey: ["scans-overview", days],
    queryFn: () => api<ScanOverview>(`/api/v1/scans/overview?days=${days}`),
    refetchInterval: (q) => (q.state.data && (q.state.data.scans.running > 0 || q.state.data.scans.queued > 0 || q.state.data.recent.some(isActive)) ? 10_000 : false),
  });
}

export function useScanComparison(ids: string[]) {
  return useQuery({
    queryKey: ["scans-compare", ids],
    queryFn: () => api<ScanComparison>(`/api/v1/scans/compare?ids=${ids.map(encodeURIComponent).join(",")}`),
    enabled: ids.length >= 2 && ids.length <= 10,
  });
}

export const startScans = (body: StartScanRequest) => api<{ items: StartScanItem[] }>("/api/v1/scans", { method: "POST", body });
export const cancelScan = (id: string) => api<ScanJob>(`/api/v1/scans/${id}/cancel`, { method: "POST" });
export const retryScan = (id: string) => api<ScanJob>(`/api/v1/scans/${id}/retry`, { method: "POST" });

/** Human label of an execution stage ("scanning:checkov" → "Scanning (Infrastructure as code)"): kinds of check, never engines (rule 3). */
export function stageLabel(stage: string): string {
  if (!stage) return "—";
  const [head, rest] = stage.split(":", 2) as [string, string | undefined];
  const base: Record<string, string> = {
    queued: "Queued",
    starting: "Starting",
    fetching_source: "Fetching source",
    scanning: "Scanning",
    finalizing: "Finalizing",
    finished: "Finished",
  };
  const label = base[head] ?? head.replace(/_/g, " ");
  return rest ? `${label} (${head === "scanning" ? toolCheckLabel(rest) : rest})` : label;
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

export function useProfileKinds(id: string | undefined) {
  return useQuery({
    queryKey: ["scan-profile", id, "kinds"],
    queryFn: () => api<{ profile_id: string; kinds: ProfileKind[]; workers_online: number }>(`/api/v1/scan-profiles/${id}/kinds`),
    enabled: !!id,
  });
}

export function useCatalog() {
  return useQuery({ queryKey: ["scanners"], queryFn: () => api<Page<CatalogScanner>>("/api/v1/scanners").then((r) => r.items), staleTime: 600_000 });
}

/** The 25 scan types with the tools, import formats and live workers of this deployment. */
export function useScanTypes() {
  return useQuery({ queryKey: ["scan-types"], queryFn: () => api<ScanTypesResponse>("/api/v1/scan-types"), refetchInterval: 30_000 });
}

export function useWorkers() {
  return useQuery({ queryKey: ["workers"], queryFn: () => api<Page<Worker>>("/api/v1/workers").then((r) => r.items), refetchInterval: 15_000 });
}

export function useScanMutation<T, V>(fn: (v: V) => Promise<T>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      for (const k of ["scans", "scan", "scans-overview", "scan-profiles", "scan-profile", "workers", "findings", "dashboard", "repository"]) void qc.invalidateQueries({ queryKey: [k] });
    },
  });
}

export const scanRepo = (id: string) => api<{ job_id: string; coalesced: boolean }>(`/api/v1/repositories/${id}/scan`, { method: "POST" });

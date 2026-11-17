import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, getCsrfToken } from "@/api/client";
import type {
  Catalog,
  Comment,
  DataFlow,
  Evidence,
  HistoryEntry,
  Overview,
  Recommendation,
  Report,
  ReviewDetail,
  ReviewFilters,
  ReviewItem,
  ReviewPage,
  Reviewer,
  Settings,
  SourceCommits,
  SourceView,
  Workload,
} from "./types";

export const qs = (f: Record<string, string | undefined>) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) if (v) p.set(k, v);
  return p.toString();
};

export function useCatalog() {
  return useQuery({ queryKey: ["hr-catalog"], queryFn: () => api<Catalog>("/api/v1/human-review/catalog"), staleTime: Infinity });
}

export function useReviews(f: ReviewFilters, enabled = true) {
  return useQuery({
    queryKey: ["hr-reviews", f],
    queryFn: ({ signal }) => api<ReviewPage>(`/api/v1/human-reviews?${qs(f)}`, { signal }),
    placeholderData: (prev) => prev,
    enabled,
  });
}

export function useReview(id: string) {
  return useQuery({ queryKey: ["hr-review", id], queryFn: () => api<ReviewDetail>(`/api/v1/human-reviews/${id}`) });
}

export function useOverview(f: ReviewFilters) {
  return useQuery({ queryKey: ["hr-overview", f], queryFn: ({ signal }) => api<Overview>(`/api/v1/human-review/overview?${qs(f)}`, { signal }) });
}

export function useReport(f: ReviewFilters) {
  return useQuery({ queryKey: ["hr-report", f], queryFn: ({ signal }) => api<Report>(`/api/v1/human-review/reports?${qs(f)}`, { signal }) });
}

export function useWorkload(f: ReviewFilters) {
  return useQuery({
    queryKey: ["hr-workload", f],
    queryFn: ({ signal }) => api<{ items: Workload[] }>(`/api/v1/human-review/workload?${qs(f)}`, { signal }).then((r) => r.items),
  });
}

export function useReviewers(repositoryId?: string, enabled = true) {
  return useQuery({
    queryKey: ["hr-reviewers", repositoryId ?? ""],
    queryFn: () => api<{ items: Reviewer[] }>(`/api/v1/human-review/reviewers${repositoryId ? `?repository_id=${repositoryId}` : ""}`).then((r) => r.items),
    staleTime: 60_000,
    enabled,
  });
}

export function useSettings() {
  return useQuery({ queryKey: ["hr-settings"], queryFn: () => api<Settings>("/api/v1/human-review/settings") });
}

export function useSource(id: string, path: string, commit: string, enabled = true) {
  return useQuery({
    queryKey: ["hr-source", id, path, commit],
    queryFn: () => api<SourceView>(`/api/v1/human-reviews/${id}/source?${qs({ path, commit })}`),
    staleTime: 5 * 60_000,
    enabled,
  });
}

export function useSourceCommits(id: string, path: string, enabled: boolean) {
  return useQuery({
    queryKey: ["hr-commits", id, path],
    queryFn: () => api<SourceCommits>(`/api/v1/human-reviews/${id}/source/commits?${qs({ path })}`),
    staleTime: 5 * 60_000,
    enabled,
  });
}

export function useDataFlow(id: string) {
  return useQuery({ queryKey: ["hr-dataflow", id], queryFn: () => api<DataFlow>(`/api/v1/human-reviews/${id}/dataflow`) });
}

export function useEvidence(id: string) {
  return useQuery({
    queryKey: ["hr-evidence", id],
    queryFn: () => api<{ items: Evidence[]; uploads_enabled: boolean; allowed_extensions: string[] }>(`/api/v1/human-reviews/${id}/evidence`),
  });
}

export function useComments(id: string) {
  return useQuery({
    queryKey: ["hr-comments", id],
    queryFn: () => api<{ items: Comment[] }>(`/api/v1/human-reviews/${id}/comments`).then((r) => r.items),
  });
}

export function useHistory(id: string) {
  return useQuery({
    queryKey: ["hr-history", id],
    queryFn: () => api<{ items: HistoryEntry[] }>(`/api/v1/human-reviews/${id}/history`).then((r) => r.items),
  });
}

export function useRecommendations(id: string) {
  return useQuery({
    queryKey: ["hr-ai", id],
    queryFn: () => api<{ items: Recommendation[] }>(`/api/v1/human-reviews/${id}/ai`).then((r) => r.items),
  });
}

/** Mutation that refreshes everything Human Eye shows afterwards. */
export function useReviewMutation<T, V>(fn: (v: V) => Promise<T>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      for (const k of ["hr-review", "hr-reviews", "hr-overview", "hr-history", "hr-comments", "hr-evidence", "hr-workload", "hr-dataflow", "hr-ai", "hr-report"]) {
        void qc.invalidateQueries({ queryKey: [k] });
      }
    },
  });
}

const post = <T>(path: string, body?: unknown) => api<T>(path, { method: "POST", body });
const put = <T>(path: string, body?: unknown) => api<T>(path, { method: "PUT", body });

export const reviewApi = {
  create: (body: { finding_ids: string[]; reason: string; priority?: string; due_at?: string; reviewer_id?: string }) =>
    post<{ created: string[]; existing: string[] }>("/api/v1/human-reviews", body),
  bulk: (body: { review_ids: string[]; action: "assign" | "priority" | "due_date"; reviewer_id?: string; priority?: string; due_at?: string; note?: string }) =>
    post<{ updated: number }>("/api/v1/human-reviews/bulk", body),
  sync: () => post<{ created: number }>("/api/v1/human-review/sync"),
  assign: (id: string, body: { reviewer_id?: string; independent_reviewer_id?: string; due_at?: string; priority?: string; note?: string }) =>
    post<ReviewItem>(`/api/v1/human-reviews/${id}/assign`, body),
  patch: (id: string, body: { priority?: string; due_at?: string }) => api<ReviewItem>(`/api/v1/human-reviews/${id}`, { method: "PATCH", body }),
  start: (id: string) => post<ReviewItem>(`/api/v1/human-reviews/${id}/start`),
  status: (id: string, body: { status: string; note: string }) => post<ReviewItem>(`/api/v1/human-reviews/${id}/status`, body),
  assessment: (id: string, body: Record<string, unknown>) => put(`/api/v1/human-reviews/${id}/assessment`, body),
  severity: (id: string, body: { severity: string; cvss_vector: string; cvss_score: number | null; justification: string }) =>
    put<ReviewItem>(`/api/v1/human-reviews/${id}/severity`, body),
  decision: (id: string, body: Record<string, unknown>) => post<ReviewItem>(`/api/v1/human-reviews/${id}/decision`, body),
  independent: (id: string, body: { outcome: string; comments: string }) => post<ReviewItem>(`/api/v1/human-reviews/${id}/independent-review`, body),
  reopen: (id: string, reason: string) => post<ReviewItem>(`/api/v1/human-reviews/${id}/reopen`, { reason }),
  remediation: (id: string, body: Record<string, unknown>) => put<ReviewItem>(`/api/v1/human-reviews/${id}/remediation`, body),
  comment: (id: string, body: string) => post(`/api/v1/human-reviews/${id}/comments`, { body }),
  ai: (id: string, kind: string) => post<Recommendation>(`/api/v1/human-reviews/${id}/ai`, { kind }),
  deleteEvidence: (id: string, eid: string, reason: string) =>
    api(`/api/v1/human-reviews/${id}/evidence/${eid}?reason=${encodeURIComponent(reason)}`, { method: "DELETE" }),
  saveSettings: (s: Settings) => put<Settings>("/api/v1/human-review/settings", s),
};

/** Multipart evidence upload (the JSON client does not send forms). */
export async function uploadEvidence(id: string, form: FormData): Promise<Evidence> {
  const res = await fetch(`/api/v1/human-reviews/${id}/evidence`, {
    method: "POST",
    body: form,
    credentials: "same-origin",
    headers: { Accept: "application/json", "X-CSRF-Token": getCsrfToken() },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = data?.error ?? {};
    throw new ApiError(res.status, err.code ?? "error", err.message ?? res.statusText, data?.request_id, err.fields, err);
  }
  return data as Evidence;
}

export const exportUrl = (f: ReviewFilters) => `/api/v1/human-review/reports/export?${qs(f)}`;
export const evidenceUrl = (id: string, eid: string, inline = false) => `/api/v1/human-reviews/${id}/evidence/${eid}/content${inline ? "?inline=1" : ""}`;

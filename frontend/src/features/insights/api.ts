import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";

/** Material change categories (backend package material). */
export const materialCategories: readonly (readonly [string, string])[] = [
  ["auth", "Authentication / authorization"],
  ["api_endpoint", "New API endpoint"],
  ["dependency", "New dependency"],
  ["crypto", "Cryptography"],
  ["iac_exposure", "Infrastructure exposure"],
  ["secrets_handling", "Secrets handling"],
  ["cicd", "CI/CD pipeline"],
  ["sensitive_data", "Sensitive data model"],
];

export interface MaterialRun {
  scan_job_id: string;
  repository_id: string;
  status: "computed" | "baseline" | "unchanged" | "unavailable";
  reason: string;
  base_sha: string;
  head_sha: string;
  files_changed: number;
  truncated: boolean;
  change_count: number;
  dependency_status: "computed" | "baseline" | "none";
  commits_complete: boolean;
  created_at: string;
}

export interface MaterialChange {
  id: string;
  scan_job_id: string;
  category: string;
  category_label: string;
  rule_id: string;
  rule_title: string;
  level: "high" | "medium" | "low";
  file_path: string;
  change_type: string;
  side: "added" | "removed" | "file";
  start_line: number | null;
  end_line: number | null;
  match_count: number;
  snippet: string;
  explanation: string;
  detail: string;
  author_name?: string;
  created_at: string;
  commit_sha?: string;
  base_sha?: string;
}

export interface MaterialRule {
  id: string;
  category: string;
  category_label: string;
  title: string;
  explanation: string;
  level: string;
  applies: string;
}

export function useScanMaterialChanges(jobId: string) {
  return useQuery({
    queryKey: ["material", "scan", jobId],
    queryFn: () => api<{ run: MaterialRun | null; items: MaterialChange[] }>(`/api/v1/scans/${jobId}/material-changes`),
  });
}

export function useRepoMaterialChanges(repoId: string, f: { category?: string; days?: number }) {
  const q = new URLSearchParams();
  if (f.category) q.set("category", f.category);
  if (f.days) q.set("days", String(f.days));
  return useQuery({
    queryKey: ["material", "repo", repoId, f],
    queryFn: () => api<{ items: MaterialChange[]; truncated: boolean; runs: MaterialRun[] }>(`/api/v1/repositories/${repoId}/material-changes?${q}`),
  });
}

export function useMaterialRules(enabled = true) {
  return useQuery({
    queryKey: ["material", "rules"],
    queryFn: () => api<{ items: MaterialRule[] }>("/api/v1/material-changes/rules").then((r) => r.items),
    enabled,
    staleTime: 60 * 60 * 1000,
  });
}

export interface InsightSettings {
  attribution_enabled: boolean;
  updated_at: string | null;
  can_manage: boolean;
  can_view_people: boolean;
  can_link_identities: boolean;
}

export function useInsightSettings(enabled = true) {
  return useQuery({ queryKey: ["insights", "settings"], queryFn: () => api<InsightSettings>("/api/v1/insights/settings"), enabled });
}

export function useSetAttribution() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (on: boolean) => api<InsightSettings>("/api/v1/insights/settings", { method: "PUT", body: { attribution_enabled: on } }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["insights"] }),
  });
}

export interface Developer {
  author_name: string;
  user: { id: string; name: string } | null;
  introduced: number;
  introduced_critical_high: number;
  fixed: number;
  still_open: number;
  mean_time_to_fix_hours: number | null;
  repositories: number;
}

export interface TeamStats {
  id: string | null;
  name: string;
  developers: number;
  introduced: number;
  introduced_critical_high: number;
  fixed: number;
  still_open: number;
  mean_time_to_fix_hours: number | null;
}

export interface TrendPoint {
  week: string;
  introduced: number;
  fixed: number;
}

export function useDevelopers(days: number, enabled = true) {
  return useQuery({
    queryKey: ["insights", "developers", days],
    queryFn: () => api<{ items: Developer[] }>(`/api/v1/insights/developers?days=${days}`).then((r) => r.items),
    enabled,
  });
}

export function useTeams(days: number, enabled = true) {
  return useQuery({
    queryKey: ["insights", "teams", days],
    queryFn: () => api<{ items: TeamStats[] }>(`/api/v1/insights/teams?days=${days}`).then((r) => r.items),
    enabled,
  });
}

export function useTrend(days: number, author: string, enabled = true) {
  return useQuery({
    queryKey: ["insights", "trend", days, author],
    queryFn: () => api<{ items: TrendPoint[] }>(`/api/v1/insights/trend?days=${days}&author=${encodeURIComponent(author)}`).then((r) => r.items),
    enabled,
  });
}

export interface IdentityLink {
  id: string;
  author_name: string;
  user_id: string;
  user_name: string;
  created_at: string;
}

export function useIdentities(enabled = true) {
  return useQuery({
    queryKey: ["insights", "identities"],
    queryFn: () => api<{ items: IdentityLink[]; unlinked_authors: string[] }>("/api/v1/insights/identities"),
    enabled,
  });
}

export function useIdentityMutations() {
  const qc = useQueryClient();
  const done = () => void qc.invalidateQueries({ queryKey: ["insights"] });
  return {
    link: useMutation({
      mutationFn: (b: { author_name: string; user_id: string }) => api<{ id: string }>("/api/v1/insights/identities", { method: "POST", body: b }),
      onSuccess: done,
    }),
    unlink: useMutation({
      mutationFn: (id: string) => api<void>(`/api/v1/insights/identities/${id}`, { method: "DELETE" }),
      onSuccess: done,
    }),
  };
}

/** Hours as "3.5 h" or "2.1 d". */
export function formatHours(h: number | null | undefined): string {
  if (h == null) return "—";
  return h < 48 ? `${h.toFixed(1)} h` : `${(h / 24).toFixed(1)} d`;
}

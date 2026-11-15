import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { ComponentGroup, HistoryEntry, Page, RiskAcceptance } from "@/api/types";

export const useHistory = (id: string | undefined) =>
  useQuery({ queryKey: ["finding-history", id], queryFn: () => api<Page<HistoryEntry>>(`/api/v1/findings/${id}/history`).then((r) => r.items), enabled: !!id });
export const useAcceptances = (f: { status?: string; finding_id?: string }) =>
  useQuery({
    queryKey: ["risk-acceptances", f],
    queryFn: () => {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(f)) if (v) p.set(k, v);
      return api<Page<RiskAcceptance>>(`/api/v1/risk-acceptances?${p}`).then((r) => r.items);
    },
  });
export const useSLA = () => useQuery({ queryKey: ["sla"], queryFn: () => api<Record<string, number | null>>("/api/v1/sla-policies") });
export const useLicensePolicy = () =>
  useQuery({ queryKey: ["license-policy"], queryFn: () => api<Page<{ spdx_id: string; decision: "deny" | "review" }>>("/api/v1/license-policies").then((r) => r.items) });
export const useComponents = (f: { q?: string; repository_id?: string; license?: string }) =>
  useQuery({
    queryKey: ["components", f],
    queryFn: () => {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(f)) if (v) p.set(k, v);
      return api<Page<ComponentGroup>>(`/api/v1/sbom/components?${p}`).then((r) => r.items);
    },
  });

export function useVulnMutation<T, V>(fn: (v: V) => Promise<T>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      for (const k of ["findings", "finding", "finding-history", "findings-summary", "risk-acceptances", "sla", "license-policy", "components", "dashboard"])
        void qc.invalidateQueries({ queryKey: [k] });
    },
  });
}

export const statusLabel: Record<string, string> = {
  open: "Open", in_progress: "In progress", needs_review: "Needs review", fixed: "Fixed", false_positive: "False positive", accepted_risk: "Accepted risk",
};
export const transitions: Record<string, string[]> = {
  open: ["in_progress", "needs_review", "false_positive", "fixed"],
  in_progress: ["open", "needs_review", "false_positive", "fixed"],
  needs_review: ["open", "in_progress", "false_positive", "fixed"],
  false_positive: ["open"],
  fixed: ["open"],
  accepted_risk: [],
};
export const needsReason = (s: string) => s === "false_positive" || s === "fixed";

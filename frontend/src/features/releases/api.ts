import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";

export type AppVersion = {
  id: string;
  application_id: string;
  version: string;
  description: string;
  released_at: string | null;
  created_by: string;
  created_at: string;
  repository_count: number;
  component_count: number;
  open_findings: number;
};

export type VersionList = { items: AppVersion[]; application: { id: string; name: string }; can_manage: boolean };

export type VersionDetail = {
  version: AppVersion;
  application: { id: string; name: string };
  repositories: { repository_id: string; full_name: string; ref: string; commit_sha: string; scan_job_id: string | null }[];
  components: { repository_id: string; name: string; version: string; purl: string; type: string; licenses: string[] }[];
  findings: {
    finding_id: string | null; repository_id: string; category: string; title: string; severity: string; cve: string;
    package_name: string; package_version: string; fixed_version: string; status_at_release: string; status: string;
  }[];
  can_manage: boolean;
};

export type ImportResult = { import_id: string; format: string; statements: number; matched: number; suggestions: number; informational: number; unmatched: number };

export type VexSuggestion = {
  id: string; import_id: string; finding_id: string; finding_title: string; finding_status: string; severity: string;
  package_name: string; package_version: string; repository_id: string; repository: string; vulnerability: string;
  vex_status: "not_affected" | "fixed"; justification: string; impact_statement: string;
  status: "pending" | "approved" | "rejected" | "superseded"; requested_by_id: string; requested_by: string; decided_by: string;
  decided_at: string | null; decision_note: string; created_at: string; can_decide: boolean; cannot_decide_reason?: string;
};

export type VexImport = {
  id: string; repository_id: string | null; repository: string; application_version_id: string | null; application: string; version: string;
  format: string; filename: string; document_sha256: string; author: string; statements: number; matched: number; pending: number;
  imported_by: string; created_at: string;
};

export type PolicyParams = { max_days?: number; versions_behind?: "any" | "major"; licenses?: string[]; include_unknown?: boolean; min_severity?: string };

export type ComponentPolicy = {
  id: string; name: string; description: string; enabled: boolean;
  condition_kind: "component_age" | "outdated" | "license" | "vulnerability_severity";
  params: PolicyParams; violation_state: "fail" | "warn" | "info";
  created_at: string; updated_at: string; evaluated_at: string | null; open_violations: number;
};

export type PolicyViolation = {
  id: string; policy_id: string; policy_name: string; violation_state: string; repository_id: string; repository: string;
  component: string; component_version: string; purl: string; detail: string; first_seen_at: string; last_seen_at: string; resolved_at: string | null;
};

export type Portfolio = {
  versions: { application_id: string; application_name: string; version_id: string; version: string; repository: string; component: string; component_version: string; purl: string; matched_by: string }[];
  repositories: { repository_id: string; repository: string; component: string; component_version: string; purl: string; matched_by: string }[];
};

export const useVersions = (appId: string) =>
  useQuery({ queryKey: ["app-versions", appId], queryFn: () => api<VersionList>(`/api/v1/applications/${appId}/versions`) });

export const useVersion = (appId: string, vid: string | null) =>
  useQuery({ queryKey: ["app-version", appId, vid], enabled: !!vid, queryFn: () => api<VersionDetail>(`/api/v1/applications/${appId}/versions/${vid}`) });

export function useSuggestions(status: string) {
  return useQuery({
    queryKey: ["vex-suggestions", status],
    queryFn: () => api<{ items: VexSuggestion[] }>(`/api/v1/vex-suggestions${status ? `?status=${status}` : ""}`).then((r) => r.items),
  });
}

export const useVexImports = () => useQuery({ queryKey: ["vex-imports"], queryFn: () => api<{ items: VexImport[] }>("/api/v1/vex-imports").then((r) => r.items) });

export const usePolicies = () =>
  useQuery({ queryKey: ["component-policies"], queryFn: () => api<{ items: ComponentPolicy[]; can_manage: boolean }>("/api/v1/component-policies") });

export function useViolations(policyId: string, state: "open" | "resolved") {
  const q = new URLSearchParams();
  if (policyId) q.set("policy_id", policyId);
  if (state === "resolved") q.set("state", "resolved");
  return useQuery({
    queryKey: ["component-policy-violations", policyId, state],
    queryFn: () => api<{ items: PolicyViolation[] }>(`/api/v1/component-policy-violations?${q}`).then((r) => r.items),
  });
}

/** Invalidates everything the releases pages show after a change. */
export function useReleasesMutation<A, R>(fn: (a: A) => Promise<R>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      for (const k of ["app-versions", "app-version", "vex-suggestions", "vex-imports", "component-policies", "component-policy-violations"]) {
        void qc.invalidateQueries({ queryKey: [k] });
      }
    },
  });
}

/** Reads a VEX file chosen by the user and returns its parsed JSON. */
export async function readVexFile(file: File): Promise<unknown> {
  if (file.size > 10 * 1024 * 1024) throw new Error("The VEX document is larger than 10 MB.");
  const text = await file.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("The file is not valid JSON (OpenVEX or CycloneDX VEX).");
  }
}

export const vexStatusLabel: Record<string, string> = {
  not_affected: "Not affected",
  fixed: "Fixed",
  affected: "Affected",
  under_investigation: "Under investigation",
};

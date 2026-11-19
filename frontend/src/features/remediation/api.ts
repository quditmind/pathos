import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/api/client";
import type { Severity } from "@/api/types";

/**
 * Typed client for the remediation workspace and security gates
 * (/api/v1/remediation/*, /api/v1/gates/*, /api/v1/gate-exceptions/*;
 * PATHOS 3.0 M8, behind the `remediation_workspace` flag).
 */

export const itemStatuses = ["open", "planned", "in_progress", "fix_submitted", "verifying", "closed", "wont_fix"] as const;
export type ItemStatus = (typeof itemStatuses)[number];
export const statusLabel: Record<ItemStatus, string> = {
  open: "Open",
  planned: "Planned",
  in_progress: "In progress",
  fix_submitted: "Fix submitted",
  verifying: "Verifying",
  closed: "Closed (verified)",
  wont_fix: "Won't fix",
};
/** Statuses a person may set by hand: "closed" is set only by a verification that proves the fix. */
export const manualStatuses: ItemStatus[] = ["open", "planned", "in_progress", "fix_submitted", "wont_fix"];

export const priorities = ["critical", "high", "medium", "low"] as const;
export type Priority = (typeof priorities)[number];

export type ItemKind = "code_fix" | "dependency_upgrade" | "configuration" | "threat_mitigation" | "design_change";
export const kindLabel: Record<ItemKind, string> = {
  code_fix: "Code fix",
  dependency_upgrade: "Dependency upgrade",
  configuration: "Configuration",
  threat_mitigation: "Threat mitigation",
  design_change: "Design change",
};

export interface FixPRRef {
  id: string;
  status: string;
  pr_url: string;
  kind: string;
  created_at?: string;
}

export interface VerificationRef {
  id: string;
  status: VerificationStatus;
  result: VerificationResult | null;
  created_at: string;
}

export interface RemediationItem {
  id: string;
  title: string;
  kind: ItemKind;
  status: ItemStatus;
  priority: Priority;
  repository_id: string | null;
  repository_name: string;
  application_id: string | null;
  application_name: string;
  owner_id: string | null;
  owner_email: string;
  due_at: string | null;
  due_source: "sla" | "manual" | "none";
  overdue: boolean;
  root_cause: string;
  finding_count: number;
  open_finding_count: number;
  top_severity: Severity | "";
  affected_files: string[];
  fix_pull_request: FixPRRef | null;
  last_verification: VerificationRef | null;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}

export interface ItemFinding {
  id: string;
  title: string;
  severity: Severity;
  status: string;
  category: string;
  rule_id: string;
  file_path: string;
  start_line: number | null;
  scanner_keys: string[];
}

export type GuidanceEvidence = "verified" | "ai_inferred" | "scanner" | "human";
export interface Guidance {
  source: "dependency_upgrade" | "verified_ai_fix" | "ai_review" | "human_review" | "finding";
  evidence: GuidanceEvidence;
  title: string;
  text: string;
  link?: string;
}

export type VerificationStatus = "queued" | "running" | "completed" | "failed";
export type VerificationResult = "fixed" | "still_present" | "regressed" | "inconclusive";

export interface Verification {
  id: string;
  item_id: string;
  status: VerificationStatus;
  result: VerificationResult | null;
  trigger: "manual" | "fix_pr_merged" | "existing_scan";
  scanner_key: string;
  scanner_version: string;
  files: string[];
  before: { scan_job_id: string | null; commit: string; result_count: number };
  after: { scan_job_id: string | null; commit: string; result_count: number };
  findings: { finding_id: string; status_before: string; status_after: string; reproduced: boolean; removed: boolean }[];
  regressions: { rule_id: string; file: string; line: number; title: string }[];
  failure_reason: string;
  requested_by_email: string;
  created_at: string;
  finished_at: string | null;
}

export interface ItemDetail extends RemediationItem {
  findings: ItemFinding[];
  guidance: Guidance[];
  fix_prs: FixPRRef[];
  verifications: Verification[];
  can_verify: boolean;
  verify_unavailable_reason: string;
}

export interface SavedView {
  id: string;
  name: string;
  filters: Record<string, string>;
  shared: boolean;
  owner_email: string;
  created_at: string;
}

/** Workspace filters (also the URL search and the saved-view payload). */
export interface ItemFilters {
  status?: string;
  owner_id?: string;
  unassigned?: string;
  priority?: string;
  repository_id?: string;
  overdue?: string;
  q?: string;
  sort?: string;
}
export const filterKeys: (keyof ItemFilters)[] = ["status", "owner_id", "unassigned", "priority", "repository_id", "overdue", "q", "sort"];

// --- gates --------------------------------------------------------------------

export const stages = ["ide", "pre_commit", "pull_request", "ci", "release", "deploy"] as const;
export type Stage = (typeof stages)[number];
export const stageLabel: Record<Stage, string> = {
  ide: "IDE",
  pre_commit: "Pre-commit",
  pull_request: "Pull request",
  ci: "CI",
  release: "Release",
  deploy: "Deploy",
};
export const modes = ["block", "warn", "require_approval"] as const;
export type GateMode = (typeof modes)[number];
export const modeLabel: Record<GateMode, string> = { block: "Block", warn: "Warn", require_approval: "Require approval" };

export const outcomes = ["pass", "warn", "block", "approval_required", "exception_applied"] as const;
export type Outcome = (typeof outcomes)[number];
export const outcomeLabel: Record<Outcome, string> = {
  pass: "Pass",
  warn: "Warn",
  block: "Block",
  approval_required: "Approval required",
  exception_applied: "Exception applied",
};
export const outcomeTone: Record<Outcome, "success" | "warning" | "danger" | "neutral"> = {
  pass: "success",
  warn: "warning",
  block: "danger",
  approval_required: "warning",
  exception_applied: "neutral",
};

export interface PolicyRef {
  id: string;
  name: string;
  version: number;
  enabled?: boolean;
}

export interface Gate {
  id: string;
  name: string;
  stage: Stage;
  mode: GateMode;
  allow_exceptions: boolean;
  application_id: string | null;
  repository_id: string | null;
  repository_name?: string;
  enabled: boolean;
  managed: boolean;
  policy: PolicyRef;
  created_at: string;
  updated_at: string;
}

export interface GateInput {
  name: string;
  stage: Stage;
  policy_id: string;
  mode: GateMode;
  allow_exceptions: boolean;
  application_id?: string | null;
  repository_id?: string | null;
  enabled?: boolean;
}

export interface DecisionReason {
  code: string;
  message: string;
  gate_id?: string;
  policy_id?: string;
  count?: number;
}

export interface Decision {
  id: string;
  stage: Stage;
  outcome: Outcome;
  repository_id: string | null;
  repository_name: string;
  application_id: string | null;
  scan_job_id: string | null;
  commit_sha: string;
  pull_request: number | null;
  gates: {
    id: string;
    name: string;
    mode: GateMode;
    matched: boolean;
    count: number;
    effect: Outcome | "skipped";
    policy: PolicyRef;
  }[];
  policy_ids: string[];
  reasons: DecisionReason[];
  evidence: { scope: "new" | "open"; by_severity: Record<string, number>; finding_ids: string[]; scan_job_id: string | null };
  exceptions: { id: string; status: ExceptionStatus; expires_at: string }[];
  requested_by_email: string;
  created_at: string;
  docs_url: string;
}

export type ExceptionStatus = "requested" | "approved" | "rejected" | "expired" | "revoked";
export const exceptionStatuses: ExceptionStatus[] = ["requested", "approved", "rejected", "expired", "revoked"];

export interface GateException {
  id: string;
  gate_id: string;
  gate_name: string;
  decision_id: string | null;
  kind: "exception" | "approval";
  scope: { repository_id?: string; application_id?: string; commit_sha?: string; pull_request?: number };
  reason: string;
  status: ExceptionStatus;
  requested_by_email: string;
  decided_by_email: string;
  decision_note: string;
  expires_at: string;
  created_at: string;
  decided_at: string | null;
  can_decide: boolean;
}

// --- helpers --------------------------------------------------------------------

/** True when the API answered that the module is switched off (PTH-PLAT-1007). */
export function isFeatureDisabled(err: unknown): boolean {
  return err instanceof ApiError && (err.code === "feature_disabled" || err.errorCode === "PTH-PLAT-1007");
}

function itemsOf<T>(r: unknown): T[] {
  if (Array.isArray(r)) return r as T[];
  if (r && typeof r === "object" && Array.isArray((r as { items?: unknown }).items)) return (r as { items: T[] }).items;
  return [];
}

function qs(params: Record<string, string | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) p.set(k, v);
  const s = p.toString();
  return s ? `?${s}` : "";
}

export const remKeys = {
  all: ["remediation"] as const,
  items: (f: ItemFilters, cursor?: string) => ["remediation", "items", f, cursor ?? ""] as const,
  item: (id: string) => ["remediation", "item", id] as const,
  views: ["remediation", "views"] as const,
  gates: ["remediation", "gates"] as const,
  decisions: (stage?: string, outcome?: string, repo?: string) => ["remediation", "decisions", stage ?? "", outcome ?? "", repo ?? ""] as const,
  exceptions: (status?: string) => ["remediation", "exceptions", status ?? ""] as const,
};

// --- remediation hooks ----------------------------------------------------------

export function useItems(f: ItemFilters, cursor?: string) {
  return useQuery({
    queryKey: remKeys.items(f, cursor),
    queryFn: () =>
      api<{ items: RemediationItem[]; next_cursor: string | null }>(`/api/v1/remediation/items${qs({ ...f, limit: "50", cursor })}`).then((r) => ({
        items: r.items ?? [],
        next_cursor: r.next_cursor ?? null,
      })),
    retry: false,
  });
}

export function useItem(id: string) {
  return useQuery({
    queryKey: remKeys.item(id),
    queryFn: () => api<ItemDetail>(`/api/v1/remediation/items/${encodeURIComponent(id)}`),
    retry: false,
    // Poll while a verification is queued or running.
    refetchInterval: (q) => (q.state.data?.verifications?.some((v) => v.status === "queued" || v.status === "running") ? 10_000 : false),
  });
}

export interface ItemPatch {
  title?: string;
  status?: ItemStatus;
  owner_id?: string;
  clear_owner?: boolean;
  due_at?: string;
  clear_due?: boolean;
  priority?: Priority;
  root_cause?: string;
  fix_pull_request_id?: string;
}

export function useUpdateItem(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ItemPatch) => api<RemediationItem>(`/api/v1/remediation/items/${encodeURIComponent(id)}`, { method: "PATCH", body }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: remKeys.all }),
  });
}

export interface BulkUpdate {
  ids: string[];
  owner_id?: string;
  clear_owner?: boolean;
  due_at?: string;
  status?: ItemStatus;
  priority?: Priority;
}

export function useBulkUpdate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: BulkUpdate) => api<{ updated: number }>("/api/v1/remediation/items/bulk", { method: "POST", body }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: remKeys.all }),
  });
}

export function useCreateItems() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { finding_ids: string[]; mode: "per_finding" | "group"; title?: string }) =>
      api<{ items: RemediationItem[] }>("/api/v1/remediation/items", { method: "POST", body }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: remKeys.all }),
  });
}

export function useVerify(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { scan_job_id?: string }) => api<Verification>(`/api/v1/remediation/items/${encodeURIComponent(id)}/verify`, { method: "POST", body }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: remKeys.all }),
  });
}

export function useViews() {
  return useQuery({ queryKey: remKeys.views, queryFn: () => api<unknown>("/api/v1/remediation/views").then((r) => itemsOf<SavedView>(r)), retry: false });
}

export function useSaveView() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { name: string; filters: ItemFilters; shared: boolean }) => api<SavedView>("/api/v1/remediation/views", { method: "POST", body }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: remKeys.views }),
  });
}

export function useDeleteView() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(`/api/v1/remediation/views/${encodeURIComponent(id)}`, { method: "DELETE" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: remKeys.views }),
  });
}

// --- gate hooks -----------------------------------------------------------------

export function useGates() {
  return useQuery({ queryKey: remKeys.gates, queryFn: () => api<unknown>("/api/v1/gates").then((r) => itemsOf<Gate>(r)), retry: false });
}

export function useSaveGate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id?: string; body: GateInput }) =>
      id ? api<Gate>(`/api/v1/gates/${encodeURIComponent(id)}`, { method: "PUT", body }) : api<Gate>("/api/v1/gates", { method: "POST", body }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: remKeys.gates }),
  });
}

export function useDeleteGate() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(`/api/v1/gates/${encodeURIComponent(id)}`, { method: "DELETE" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: remKeys.gates }),
  });
}

export function useDecisions(stage?: string, outcome?: string, repo?: string) {
  return useQuery({
    queryKey: remKeys.decisions(stage, outcome, repo),
    queryFn: () =>
      api<{ items: Decision[]; next_cursor: string | null }>(`/api/v1/gates/decisions${qs({ stage, outcome, repository_id: repo, limit: "100" })}`).then((r) => r.items ?? []),
    retry: false,
  });
}

export function useRequestException() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ decisionId, body }: { decisionId: string; body: { reason: string; expires_at: string; gate_id?: string } }) =>
      api<GateException>(`/api/v1/gates/decisions/${encodeURIComponent(decisionId)}/exceptions`, { method: "POST", body }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: remKeys.all }),
  });
}

export function useExceptions(status?: string) {
  return useQuery({
    queryKey: remKeys.exceptions(status),
    queryFn: () => api<unknown>(`/api/v1/gate-exceptions${qs({ status })}`).then((r) => itemsOf<GateException>(r)),
    retry: false,
  });
}

export function useDecideException() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, action, note }: { id: string; action: "approve" | "reject" | "revoke"; note: string }) =>
      api<GateException>(`/api/v1/gate-exceptions/${encodeURIComponent(id)}/${action}`, { method: "POST", body: { note } }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: remKeys.all }),
  });
}

/** Security policies for the gate form's policy picker (existing endpoint). */
export function usePolicies(enabled = true) {
  return useQuery({
    queryKey: ["security-policies", "picker"],
    // Policies generated from a repository's pull request settings belong
    // to that repository's managed gate (the API refuses them, PTH-GATE-1105).
    queryFn: () =>
      api<unknown>("/api/v1/security-policies").then((r) =>
        itemsOf<{ id: string; name: string; enabled: boolean; version: number; managed_by?: string }>(r).filter((p) => !p.managed_by),
      ),
    enabled,
    retry: false,
  });
}

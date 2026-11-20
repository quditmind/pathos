import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import { redactToolNames } from "@/lib/checkKinds";

/**
 * AI security intelligence (PATHOS 3.0 M7, flag ai_intelligence): AI
 * evidence records, replay, model per task, retention, cross-phase
 * correlation and AI threat suggestions.
 */

export type ReviewDecision = "pending" | "accepted" | "rejected" | "not_required";
export type ProviderLocation = "local" | "cloud" | "user";
export type EvidenceStatus = "succeeded" | "invalid_output" | "failed" | "disabled";

export interface EvidenceRecord {
  id: string;
  task: string;
  task_label: string;
  operation: string;
  subject_kind: string;
  subject_id: string | null;
  finding_id: string | null;
  related: Record<string, unknown> | null;
  parent_id: string | null;
  config_version_id: string | null;
  provider: string;
  provider_location: ProviderLocation;
  model: string;
  model_reported: string;
  model_digest: string;
  prompt_template: string;
  parameters: Record<string, unknown> | null;
  deterministic: boolean;
  determinism_note: string;
  sent_code: boolean;
  input_sha256: string;
  response_sha256: string;
  steps: string[];
  conclusion: string;
  verdict: string;
  confidence: number | null;
  status: EvidenceStatus;
  error_code: string;
  error: string;
  input_tokens: number;
  output_tokens: number;
  review_decision: ReviewDecision;
  reviewer_id: string | null;
  reviewer_name: string | null;
  reviewed_at: string | null;
  review_note: string;
  replay_of: string | null;
  comparison: ReplayComparison | null;
  payload_expires_at: string | null;
  payload_purged_at: string | null;
  payload_available: boolean;
  requested_by: string | null;
  requested_by_name: string | null;
  created_at: string;
  label: "ai_inferred";
  confirmed: boolean;
  proposes_suppression: boolean;
  replayable: boolean;
  replay_unavailable?: string;
  can_review: boolean;
}

export interface ReplayComparison {
  same_conclusion: boolean;
  same_verdict: boolean;
  identical_response: boolean;
  original_verdict: string;
  replay_verdict: string;
  original_conclusion: string;
  replay_conclusion: string;
  steps_added: string[];
  steps_removed: string[];
  original_model: string;
  replay_model: string;
  model_changed: boolean;
  deterministic: boolean;
  determinism_note: string;
  original_confidence: number | null;
  replay_confidence: number | null;
}

export interface EvidenceDetail {
  record: EvidenceRecord;
  related_records: EvidenceRecord[];
  prompt?: { system: string; user: string; schema?: unknown; request?: unknown };
  response?: string;
  payload_unavailable?: string;
}

export interface ReplayResult {
  record: EvidenceRecord;
  original: EvidenceRecord;
  comparison: ReplayComparison | null;
  error?: { code: string; message: string };
}

export interface EvidenceFilters {
  task?: string;
  status?: string;
  review_decision?: string;
  subject_kind?: string;
  provider_location?: string;
  finding_id?: string;
  threat_id?: string;
  subject_id?: string;
  limit?: number;
}

// Rule 3 (build prompt §1, decision C5): scanner tool names stay on the
// configuration pages. AI prompts carry the finding's engine and models may
// echo it, so every free text of a record, prompt, response, correlation and
// suggestion is shown with tool names replaced by "engine".
const rd = (t: string | null | undefined) => redactToolNames(t);
const rdList = (l: string[] | null | undefined) => (l ?? []).map(rd);

export function displayComparison(c: ReplayComparison | null): ReplayComparison | null {
  if (!c) return c;
  return {
    ...c,
    original_conclusion: rd(c.original_conclusion),
    replay_conclusion: rd(c.replay_conclusion),
    steps_added: rdList(c.steps_added),
    steps_removed: rdList(c.steps_removed),
    determinism_note: rd(c.determinism_note),
  };
}

export function displayRecord(r: EvidenceRecord): EvidenceRecord {
  return {
    ...r,
    conclusion: rd(r.conclusion),
    steps: rdList(r.steps),
    error: rd(r.error),
    review_note: rd(r.review_note),
    determinism_note: rd(r.determinism_note),
    comparison: displayComparison(r.comparison),
    ...(r.replay_unavailable ? { replay_unavailable: rd(r.replay_unavailable) } : {}),
  };
}

export function displayDetail(d: EvidenceDetail): EvidenceDetail {
  return {
    ...d,
    record: displayRecord(d.record),
    related_records: (d.related_records ?? []).map(displayRecord),
    ...(d.prompt ? { prompt: { ...d.prompt, system: rd(d.prompt.system), user: rd(d.prompt.user) } } : {}),
    ...(d.response !== undefined ? { response: rd(d.response) } : {}),
    ...(d.payload_unavailable ? { payload_unavailable: rd(d.payload_unavailable) } : {}),
  };
}

export function displayCorrelation(c: Correlation): Correlation {
  return {
    ...c,
    finding: { ...c.finding, title: rd(c.finding.title) },
    codegraph: c.codegraph
      ? {
          ...c.codegraph,
          nodes: c.codegraph.nodes.map((n) => ({ ...n, label: rd(n.label) })),
          ...(c.codegraph.note ? { note: rd(c.codegraph.note) } : {}),
        }
      : c.codegraph,
    threats: (c.threats ?? []).map((t) => ({ ...t, title: rd(t.title) })),
    ...(c.threats_note ? { threats_note: rd(c.threats_note) } : {}),
    related_findings: (c.related_findings ?? []).map((f) => ({ ...f, title: rd(f.title) })),
  };
}

export const evidenceKeys = {
  all: ["ai-evidence"] as const,
  list: (f: EvidenceFilters) => ["ai-evidence", "list", f] as const,
  detail: (id: string, payload: boolean) => ["ai-evidence", "detail", id, payload] as const,
};

function qs(f: Record<string, string | number | undefined>) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) if (v !== undefined && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
}

export const fetchEvidence = (f: EvidenceFilters & { cursor?: string }) =>
  api<{ items: EvidenceRecord[]; next_cursor: string }>(`/api/v1/ai/evidence${qs({ ...f })}`).then((r) => ({ ...r, items: (r.items ?? []).map(displayRecord) }));

export function useEvidenceList(f: EvidenceFilters, enabled = true) {
  return useQuery({ queryKey: evidenceKeys.list(f), queryFn: () => fetchEvidence(f), enabled });
}

export function useEvidenceDetail(id: string | undefined, payload = false) {
  return useQuery({
    queryKey: evidenceKeys.detail(id ?? "", payload),
    queryFn: () => api<EvidenceDetail>(`/api/v1/ai/evidence/${encodeURIComponent(id!)}${payload ? "?include=prompt,response" : ""}`).then(displayDetail),
    enabled: !!id,
  });
}

function useInvalidateAI() {
  const qc = useQueryClient();
  return () => {
    for (const k of ["ai-evidence", "threat-models", "findings", "finding", "finding-reviews", "ai-reviews"]) void qc.invalidateQueries({ queryKey: [k] });
  };
}

export function useReviewEvidence() {
  const inv = useInvalidateAI();
  return useMutation({
    mutationFn: ({ id, decision, note }: { id: string; decision: "accepted" | "rejected"; note?: string }) =>
      api<EvidenceRecord>(`/api/v1/ai/evidence/${encodeURIComponent(id)}/review`, { method: "POST", body: { decision, note: note ?? "" } }).then(displayRecord),
    onSuccess: inv,
  });
}

export function useReplayEvidence() {
  const inv = useInvalidateAI();
  return useMutation({
    mutationFn: (id: string) =>
      api<ReplayResult>(`/api/v1/ai/evidence/${encodeURIComponent(id)}/replay`, { method: "POST" }).then((r) => ({
        ...r,
        record: r.record ? displayRecord(r.record) : r.record,
        original: r.original ? displayRecord(r.original) : r.original,
        comparison: displayComparison(r.comparison),
        ...(r.error ? { error: { ...r.error, message: rd(r.error.message) } } : {}),
      })),
    onSuccess: inv,
  });
}

// --- model per task and retention ---------------------------------------------

export interface EffectiveConfig {
  configuration_id: string;
  configuration_name: string;
  provider_kind: string;
  location: ProviderLocation;
  model: string;
  send_code_context: boolean;
  source: string;
}

export interface TaskAssignment {
  task: string;
  label: string;
  code_bearing: boolean;
  description: string;
  configuration_id: string | null;
  effective: EffectiveConfig | null;
  warning?: string;
}

export interface EvidenceSettings {
  retention_days: number;
  store_payloads: boolean;
  updated_at: string | null;
}

export interface TaskAssignments {
  items: TaskAssignment[];
  evidence: EvidenceSettings;
}

export function useTaskAssignments(enabled = true) {
  return useQuery({ queryKey: ["ai-task-assignments"], queryFn: () => api<TaskAssignments>("/api/v1/ai/task-assignments"), enabled });
}

export function useSaveTaskAssignments() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (assignments: Record<string, string | null>) => api<TaskAssignments>("/api/v1/ai/task-assignments", { method: "PUT", body: { assignments } }),
    onSuccess: (d) => qc.setQueryData(["ai-task-assignments"], d),
  });
}

export function useSaveEvidenceSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (s: { retention_days: number; store_payloads: boolean }) => api<EvidenceSettings>("/api/v1/ai/evidence-settings", { method: "PUT", body: s }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["ai-task-assignments"] }),
  });
}

// --- correlation ------------------------------------------------------------------

export type EvidenceLabelValue = "verified" | "observed" | "ai_inferred" | string;

export interface Correlation {
  finding: { id: string; title: string; severity: string; status: string; file_path: string; start_line: number | null; package_name: string };
  deterministic: boolean;
  codegraph: {
    snapshot_id: string | null;
    snapshot_status: string;
    nodes: { key: string; type: string; label: string; file_path: string; start_line: number | null; end_line: number | null; match: string; evidence: EvidenceLabelValue }[];
    edges: { key: string; type: string; source: string; target: string; evidence: EvidenceLabelValue }[];
    note?: string;
  } | null;
  threats: { id: string; threat_model_id: string; model_status: string; model_version: number; title: string; category: string; severity: string; status: string; link: string; evidence: EvidenceLabelValue }[];
  threats_note?: string;
  components: { name: string; version: string; purl: string; type: string; licenses: string[]; evidence: EvidenceLabelValue }[];
  runtime: { status: string; exposed: boolean; privileged: boolean; alert: boolean; context: unknown; evidence: EvidenceLabelValue } | null;
  related_findings: { id: string; relation: string; title: string; severity: string; status: string; evidence: EvidenceLabelValue }[];
}

export interface CorrelationExplanation {
  correlation: Correlation;
  explanation: { priority: string; exploitability: string; confidence: number; explanation: string; reasoning: string[] };
  evidence_record_id: string;
  label: "ai_inferred";
  review_decision: ReviewDecision;
  provider_location: ProviderLocation;
  model: string;
  proposes_suppression: boolean;
  note: string;
}

export function useCorrelation(findingId: string, enabled = true) {
  return useQuery({
    queryKey: ["finding-correlation", findingId],
    queryFn: () => api<Correlation>(`/api/v1/findings/${encodeURIComponent(findingId)}/correlation`).then(displayCorrelation),
    enabled,
  });
}

export function useExplainCorrelation(findingId: string) {
  const inv = useInvalidateAI();
  return useMutation({
    mutationFn: () =>
      api<CorrelationExplanation>(`/api/v1/findings/${encodeURIComponent(findingId)}/correlation/explain`, { method: "POST" }).then((r) => ({
        ...r,
        correlation: r.correlation ? displayCorrelation(r.correlation) : r.correlation,
        explanation: r.explanation
          ? { ...r.explanation, exploitability: rd(r.explanation.exploitability), explanation: rd(r.explanation.explanation), reasoning: rdList(r.explanation.reasoning) }
          : r.explanation,
        note: rd(r.note),
      })),
    onSuccess: inv,
  });
}

// --- threat suggestions -------------------------------------------------------------

export interface SuggestResult {
  items: { id: string; title: string }[];
  evidence_record_id: string;
  dropped: number;
  model: string;
  label: string;
  note: string;
}

export function useSuggestThreats(modelId: string) {
  const inv = useInvalidateAI();
  return useMutation({
    mutationFn: (maxThreats?: number) =>
      api<SuggestResult>(`/api/v1/threat-models/${encodeURIComponent(modelId)}/suggest`, { method: "POST", body: maxThreats ? { max_threats: maxThreats } : {} }).then((r) => ({
        ...r,
        items: (r.items ?? []).map((i) => ({ ...i, title: rd(i.title) })),
        note: rd(r.note),
      })),
    onSuccess: inv,
  });
}

export const locationLabel: Record<ProviderLocation, string> = { local: "Local model", cloud: "Cloud model", user: "Person's own assistant" };
export const decisionLabel: Record<ReviewDecision, string> = { pending: "Awaiting a decision", accepted: "Accepted", rejected: "Rejected", not_required: "No decision needed" };

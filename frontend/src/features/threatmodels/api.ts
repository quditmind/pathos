import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { EvidenceRef, GraphData, GraphSeverity, NodeDetail } from "@/components/graph";
import { normaliseGraph, redactRef } from "@/features/codegraph/api";
import { redactToolNames } from "@/lib/checkKinds";

/**
 * Typed client for the threat-model API (docs/api-reference/threat-models.md,
 * PATHOS 3.0 M5; every route behind the `threat_models` flag).
 */

export const modelStatuses = ["draft", "in_review", "approved", "superseded", "archived"] as const;
export type ModelStatus = (typeof modelStatuses)[number];

export const strideCategories = ["spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege"] as const;
export const linddunCategories = ["linking", "identifying", "non_repudiation", "detecting", "data_disclosure", "unawareness", "non_compliance"] as const;
export const threatCategories = [...strideCategories, ...linddunCategories] as const;
export type ThreatCategory = (typeof threatCategories)[number];

export const threatStatuses = ["open", "mitigated", "accepted", "not_applicable"] as const;
export type ThreatStatus = (typeof threatStatuses)[number];

export const threatSeverities = ["critical", "high", "medium", "low", "info"] as const;
export type ThreatSeverity = (typeof threatSeverities)[number];

export const changeStates = ["new", "changed", "unchanged", "resolved"] as const;
export type ChangeState = (typeof changeStates)[number] | "";

export const threatMethods = ["rule", "attack_path", "manual", "imported", "ai"] as const;
export type ThreatMethod = (typeof threatMethods)[number];

export type EvidenceType = "verified" | "observed" | "unverified" | "ai_inferred";

export const exportFormats = ["pathos", "threat_dragon", "pytm", "markdown"] as const;
export type ExportFormat = (typeof exportFormats)[number];
export const importFormats = ["threat_dragon", "pathos"] as const;
export type ImportFormat = (typeof importFormats)[number];

export const categoryLabel: Record<ThreatCategory, string> = {
  spoofing: "Spoofing",
  tampering: "Tampering",
  repudiation: "Repudiation",
  information_disclosure: "Information disclosure",
  denial_of_service: "Denial of service",
  elevation_of_privilege: "Elevation of privilege",
  linking: "Linking (LINDDUN)",
  identifying: "Identifying (LINDDUN)",
  non_repudiation: "Non-repudiation (LINDDUN)",
  detecting: "Detecting (LINDDUN)",
  data_disclosure: "Data disclosure (LINDDUN)",
  unawareness: "Unawareness (LINDDUN)",
  non_compliance: "Non-compliance (LINDDUN)",
};
export const statusLabel: Record<ModelStatus, string> = {
  draft: "Draft",
  in_review: "In review",
  approved: "Approved",
  superseded: "Superseded",
  archived: "Archived",
};
export const threatStatusLabel: Record<ThreatStatus, string> = { open: "Open", mitigated: "Mitigated", accepted: "Accepted", not_applicable: "Not applicable" };
export const methodLabel: Record<ThreatMethod, string> = { rule: "Rule", attack_path: "Attack path", manual: "Manual", imported: "Imported", ai: "AI-suggested" };
export const exportLabel: Record<ExportFormat, string> = {
  pathos: "PATHOS JSON",
  threat_dragon: "OWASP Threat Dragon (JSON v2)",
  pytm: "pytm description (Python)",
  markdown: "Markdown report",
};
export const exportExt: Record<ExportFormat, string> = { pathos: "json", threat_dragon: "json", pytm: "py", markdown: "md" };
export const importLabel: Record<ImportFormat, string> = { threat_dragon: "OWASP Threat Dragon (JSON v2)", pathos: "PATHOS JSON" };

export interface UserRef {
  id: string;
  name: string;
}

export interface GenerationInfo {
  engines?: string[];
  rules?: { id: string; version: string; threats: number }[];
  snapshots?: { id: string; repository_id: string; repository_name?: string; commit_sha?: string; status?: string }[];
  counts?: Partial<Record<"new" | "changed" | "unchanged" | "resolved", number>>;
  notes?: string[];
}

export interface ModelCounts {
  total: number;
  open: number;
  mitigated: number;
  accepted: number;
  not_applicable: number;
  by_severity?: Partial<Record<ThreatSeverity, number>>;
  by_category?: Partial<Record<ThreatCategory, number>>;
  unverified: number;
  without_mitigation: number;
  /** AI-suggested threats no person has decided yet (M7); they block submission. */
  ai_pending?: number;
}

export interface ThreatModel {
  id: string;
  lineage_id: string;
  version: number;
  status: ModelStatus;
  application_id: string;
  application_name?: string;
  repository_id: string | null;
  repository_name?: string;
  title: string;
  summary: string;
  method: "stride" | "manual" | "imported";
  imported_format?: string;
  codegraph_snapshot_ids?: string[];
  generated_at?: string | null;
  generation?: GenerationInfo;
  created_by?: UserRef | null;
  created_at: string;
  updated_at: string;
  submitted_by?: UserRef | null;
  submitted_at?: string | null;
  approved_by?: UserRef | null;
  approved_at?: string | null;
  previous_version_id?: string | null;
  counts?: ModelCounts;
  can_edit?: boolean;
  can_approve?: boolean;
}

export interface ModelElement {
  id: string;
  kind: "process" | "data_store" | "external_entity" | "data_flow" | "trust_boundary";
  name: string;
  codegraph_key?: string;
  node_type?: string;
  repository_id?: string | null;
}

export interface EvidenceNode {
  id: string;
  key: string;
  type: string;
  label: string;
  file?: string;
  line?: number;
}
export interface EvidenceEdge {
  id: string;
  key?: string;
  source: string;
  target: string;
  type: string;
  evidence: "verified" | "observed" | "ai_inferred";
  refs?: EvidenceRef[];
}
export interface AttackPathEvidence {
  entry?: string;
  steps?: { type: string; label: string; sub?: string; link?: string }[];
  reasons?: string[];
  risk?: number;
  kev?: boolean;
  exploit_available?: boolean;
  finding_id?: string;
}
export interface ThreatEvidence {
  snapshot_id?: string;
  repository_id?: string;
  application_id?: string;
  rule?: { id: string; version: string; logic?: string };
  nodes?: EvidenceNode[];
  edges?: EvidenceEdge[];
  absent?: string[];
  exposure?: { level: string; reasons?: string[] };
  runtime?: string[];
  attack_path?: AttackPathEvidence;
  links?: { label: string; href: string }[];
}

export interface ThreatMapping {
  framework: "attack" | "capec" | "cwe" | "d3fend" | "linddun";
  id: string;
  name?: string;
  url?: string;
  source: "rule" | "finding" | "user" | "imported" | "ai";
}

export interface ThreatFinding {
  id: string;
  title: string;
  severity: GraphSeverity;
  status?: string;
  cwe?: string;
  href?: string;
}

export interface Threat {
  id: string;
  threat_model_id: string;
  fingerprint?: string;
  title: string;
  description: string;
  category: ThreatCategory;
  method: ThreatMethod;
  rule_id?: string;
  rule_version?: string;
  evidence_type: EvidenceType;
  label?: string;
  severity: ThreatSeverity;
  severity_reason?: string;
  severity_overridden?: boolean;
  confidence: number;
  confidence_reason?: string;
  status: ThreatStatus;
  status_reason?: string;
  mitigation: string;
  mitigation_edited?: boolean;
  change_state?: ChangeState;
  owner?: UserRef | null;
  evidence?: ThreatEvidence;
  elements?: ModelElement[];
  findings?: ThreatFinding[];
  mappings?: ThreatMapping[];
  created_at?: string;
  updated_at?: string;
  /** M7: the AI evidence record of an AI-suggested threat and its review decision. */
  ai_evidence_id?: string | null;
  ai_review?: "pending" | "accepted" | "rejected" | "not_required" | "";
}

export interface ThreatEvent {
  id: string;
  action: string;
  from?: string;
  to?: string;
  reason?: string;
  actor?: UserRef | null;
  at: string;
}

export interface Approval {
  id: string;
  threat_model_id: string;
  version: number;
  decision: "submitted" | "approved" | "rejected" | "changes_requested";
  actor?: UserRef | null;
  note?: string;
  decided_at: string;
}

/** Rule 5 label of a threat: the server's `label`, else derived from evidence type and method. */
export function evidenceLabel(t: Pick<Threat, "evidence_type" | "method" | "label">): string {
  if (t.label) return t.label;
  switch (t.evidence_type) {
    case "verified":
      return "verified";
    case "observed":
      return "observed";
    case "ai_inferred":
      return "AI-inferred";
    default:
      return t.method === "imported" ? "imported, unverified" : t.method === "manual" ? "manual, unverified" : "unverified";
  }
}

/**
 * Rule 3: threat-model pages never name scanner tools. Threat evidence copies
 * CodeGraph evidence (discovery engines in references and details), attack
 * paths carry finding steps, imports carry free text, and generation notes
 * name snapshots; their texts are redacted here ("engine"), as on CodeGraph.
 * The mitigation is left as written: it is edited in place.
 */
const redactList = (xs: string[] | undefined) => xs?.map(redactToolNames);
export function displayThreat(t: Threat): Threat {
  const ev = t.evidence;
  return {
    ...t,
    title: redactToolNames(t.title),
    description: redactToolNames(t.description),
    ...(t.severity_reason ? { severity_reason: redactToolNames(t.severity_reason) } : {}),
    ...(t.confidence_reason ? { confidence_reason: redactToolNames(t.confidence_reason) } : {}),
    ...(t.status_reason ? { status_reason: redactToolNames(t.status_reason) } : {}),
    elements: t.elements?.map((e) => ({ ...e, name: redactToolNames(e.name) })),
    findings: t.findings?.map((f) => ({ ...f, title: redactToolNames(f.title) })),
    mappings: t.mappings?.map((m) => (m.name ? { ...m, name: redactToolNames(m.name) } : m)),
    evidence: ev && {
      ...ev,
      rule: ev.rule && { ...ev.rule, logic: ev.rule.logic && redactToolNames(ev.rule.logic) },
      nodes: ev.nodes?.map((n) => ({ ...n, label: redactToolNames(n.label) })),
      edges: ev.edges?.map((e) => ({ ...e, refs: e.refs?.map(redactRef) })),
      absent: redactList(ev.absent),
      exposure: ev.exposure && { ...ev.exposure, reasons: redactList(ev.exposure.reasons) },
      runtime: redactList(ev.runtime),
      attack_path: ev.attack_path && {
        ...ev.attack_path,
        steps: ev.attack_path.steps?.map((s) => ({ ...s, label: redactToolNames(s.label), ...(s.sub ? { sub: redactToolNames(s.sub) } : {}) })),
        reasons: redactList(ev.attack_path.reasons),
      },
      links: ev.links?.map((l) => ({ ...l, label: redactToolNames(l.label) })),
    },
  };
}
export function displayModel(m: ThreatModel): ThreatModel {
  return {
    ...m,
    title: redactToolNames(m.title),
    summary: redactToolNames(m.summary),
    generation: m.generation && { ...m.generation, engines: undefined, notes: redactList(m.generation.notes) },
  };
}
const displayEvent = (e: ThreatEvent): ThreatEvent => ({
  ...e,
  ...(e.reason ? { reason: redactToolNames(e.reason) } : {}),
  ...(e.from ? { from: redactToolNames(e.from) } : {}),
  ...(e.to ? { to: redactToolNames(e.to) } : {}),
});
const displayElement = (e: ModelElement): ModelElement => ({ ...e, name: redactToolNames(e.name) });
const displayApproval = (a: Approval): Approval => (a.note ? { ...a, note: redactToolNames(a.note) } : a);

const enc = encodeURIComponent;
const list = <T,>(r: T[] | { items?: T[] } | null | undefined): T[] => (Array.isArray(r) ? r : (r?.items ?? []));

export const tmKeys = {
  all: ["threat-models"] as const,
  list: (f: { application_id?: string; status?: string }) => ["threat-models", "list", f.application_id ?? "", f.status ?? ""] as const,
  model: (id: string) => ["threat-models", "model", id] as const,
  threats: (id: string) => ["threat-models", "threats", id] as const,
  threat: (id: string) => ["threat-models", "threat", id] as const,
  versions: (id: string) => ["threat-models", "versions", id] as const,
  diagram: (id: string) => ["threat-models", "diagram", id] as const,
};

export function useThreatModels(f: { application_id?: string; status?: string }, enabled = true) {
  const p = new URLSearchParams();
  if (f.application_id) p.set("application_id", f.application_id);
  if (f.status) p.set("status", f.status);
  const qs = p.toString();
  return useQuery({
    queryKey: tmKeys.list(f),
    queryFn: () => api<{ items: ThreatModel[] } | ThreatModel[]>(`/api/v1/threat-models${qs ? `?${qs}` : ""}`).then((r) => list(r).map(displayModel)),
    enabled,
  });
}

export interface ModelDetail {
  model: ThreatModel;
  elements: ModelElement[];
  versions: ThreatModel[];
}

export function useThreatModel(id: string, enabled = true) {
  return useQuery({
    queryKey: tmKeys.model(id),
    queryFn: () =>
      api<Partial<ModelDetail> & Partial<ThreatModel>>(`/api/v1/threat-models/${enc(id)}`).then(
        (r): ModelDetail => ({
          model: displayModel((r.model ?? r) as ThreatModel),
          elements: (r.elements ?? []).map(displayElement),
          versions: Array.isArray(r.versions) ? r.versions.map(displayModel) : [],
        }),
      ),
    enabled: enabled && !!id,
  });
}

export function useThreats(id: string, enabled = true) {
  return useQuery({
    queryKey: tmKeys.threats(id),
    queryFn: () => api<{ items: Threat[] } | Threat[]>(`/api/v1/threat-models/${enc(id)}/threats`).then((r) => list(r).map(displayThreat)),
    enabled: enabled && !!id,
  });
}

export function useThreat(id: string | undefined) {
  return useQuery({
    queryKey: tmKeys.threat(id ?? ""),
    queryFn: () =>
      api<{ threat?: Threat; events?: ThreatEvent[] } & Partial<Threat>>(`/api/v1/threats/${enc(id!)}`).then((r) => ({
        threat: displayThreat((r.threat ?? r) as Threat),
        events: (r.events ?? []).map(displayEvent),
      })),
    enabled: !!id,
  });
}

export function useVersions(id: string, enabled = true) {
  return useQuery({
    queryKey: tmKeys.versions(id),
    queryFn: () =>
      api<{ items?: ThreatModel[]; approvals?: Approval[] }>(`/api/v1/threat-models/${enc(id)}/versions`).then((r) => ({
        items: (r.items ?? []).map(displayModel),
        approvals: (r.approvals ?? []).map(displayApproval),
      })),
    enabled: enabled && !!id,
  });
}

export function useDiagram(id: string, enabled = true) {
  return useQuery({
    queryKey: tmKeys.diagram(id),
    queryFn: () => api<Parameters<typeof normaliseGraph>[0]>(`/api/v1/threat-models/${enc(id)}/diagram`).then(normaliseGraph),
    enabled: enabled && !!id,
    staleTime: 30_000,
  });
}

/** Inspector payload for a diagram element: its threats take the place of findings. */
export function diagramDetail(g: GraphData, threats: Threat[], modelId: string, nodeId: string): NodeDetail {
  const node = g.nodes.find((n) => n.id === nodeId)!;
  const elementId = typeof node?.attrs?.element_id === "string" ? node.attrs.element_id : nodeId;
  const key = node?.attrs?.codegraph_key;
  const mine = threats.filter((t) =>
    (t.elements ?? []).some((e) => e.id === elementId || e.id === nodeId || (key && e.codegraph_key === key)),
  );
  return {
    node,
    findings: mine.map((t) => ({
      id: t.id,
      title: `${t.title} (${threatStatusLabel[t.status] ?? t.status})`,
      severity: t.severity,
      rule: t.rule_id,
      href: `/threat-models/${modelId}?tab=threats&threat=${t.id}`,
    })),
    edges: g.edges.filter((e) => e.source === nodeId || e.target === nodeId),
  };
}

export function exportUrl(id: string, format: ExportFormat) {
  return `/api/v1/threat-models/${enc(id)}/export?format=${format}`;
}

function useInvalidate() {
  const qc = useQueryClient();
  return () => void qc.invalidateQueries({ queryKey: tmKeys.all });
}

export interface CreateModelInput {
  application_id: string;
  repository_id?: string;
  title: string;
  summary?: string;
  generate?: boolean;
}

export function useCreateModel() {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (b: CreateModelInput) => api<ThreatModel | { model: ThreatModel }>("/api/v1/threat-models", { method: "POST", body: b }).then((r) => ("model" in r ? r.model : r)),
    onSuccess: inv,
  });
}

export interface ImportInput {
  application_id: string;
  repository_id?: string;
  format: ImportFormat;
  title?: string;
  document: unknown;
}

export function useImportModel() {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (b: ImportInput) => api<ThreatModel | { model: ThreatModel }>("/api/v1/threat-models/import", { method: "POST", body: b }).then((r) => ("model" in r ? r.model : r)),
    onSuccess: inv,
  });
}

export interface GenerateResult {
  model: ThreatModel;
  result?: { new?: number; changed?: number; unchanged?: number; resolved?: number; created_version?: boolean };
}

/** Model-level actions: generate, new version, submit, approve, reject, patch. */
export function useModelAction(id: string) {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: ({ action, body }: { action: "generate" | "versions" | "submit" | "approve" | "reject" | "patch"; body?: unknown }) =>
      action === "patch"
        ? api<ThreatModel>(`/api/v1/threat-models/${enc(id)}`, { method: "PATCH", body: body ?? {} }).then((m): GenerateResult => ({ model: m }))
        : api<GenerateResult | ThreatModel>(`/api/v1/threat-models/${enc(id)}/${action}`, { method: "POST", body: body ?? {} }).then((r): GenerateResult =>
            "model" in r && r.model ? (r as GenerateResult) : { model: r as ThreatModel },
          ),
    onSuccess: inv,
  });
}

export interface ManualThreatInput {
  title: string;
  description?: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  mitigation?: string;
  element_keys?: { repository_id: string; key: string }[];
  finding_ids?: string[];
  mappings?: { framework: string; id: string }[];
}

export function useAddThreat(modelId: string) {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (b: ManualThreatInput) => api<Threat>(`/api/v1/threat-models/${enc(modelId)}/threats`, { method: "POST", body: b }),
    onSuccess: inv,
  });
}

export interface ThreatPatch {
  severity?: ThreatSeverity;
  status?: ThreatStatus;
  reason?: string;
  mitigation?: string;
  owner_id?: string | null;
  title?: string;
  description?: string;
  link?: { element_keys?: { repository_id: string; key: string }[]; finding_ids?: string[] };
  unlink_findings?: string[];
  mappings_add?: { framework: string; id: string }[];
  mappings_remove?: { framework: string; id: string }[];
}

export function useUpdateThreat(threatId: string) {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (b: ThreatPatch) => api<Threat>(`/api/v1/threats/${enc(threatId)}`, { method: "PATCH", body: b }),
    onSuccess: inv,
  });
}

export function useDeleteThreat() {
  const inv = useInvalidate();
  return useMutation({
    mutationFn: (threatId: string) => api<void>(`/api/v1/threats/${enc(threatId)}`, { method: "DELETE" }),
    onSuccess: inv,
  });
}

/** Validates a severity or status change: a reason is mandatory (PTH-TM-1007 server-side). */
export function patchProblem(p: ThreatPatch, current: Pick<Threat, "severity" | "status">): string | undefined {
  const changes = (p.severity && p.severity !== current.severity) || (p.status && p.status !== current.status);
  if (changes && !p.reason?.trim()) return "Give a reason for changing the severity or status.";
  return undefined;
}

/** Why the current user cannot approve (UI hint; the API enforces it with PTH-TM-1005). */
export function approveBlockedReason(m: ThreatModel, userId: string, canApprovePerm: boolean): string | undefined {
  if (m.status !== "in_review") return "Only a version in review can be approved.";
  if (!canApprovePerm) return "Approving needs the threats.approve permission.";
  if (m.created_by?.id === userId || m.submitted_by?.id === userId) return "You wrote or submitted this version, so someone else must approve it.";
  if (m.can_approve === false) return "You cannot approve this version.";
  return undefined;
}

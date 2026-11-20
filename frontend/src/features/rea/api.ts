import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { EvidenceRef, GraphData, NodeDetail } from "@/components/graph";
import { normaliseDetail, normaliseGraph } from "@/features/codegraph/api";

/**
 * Typed client for the reverse-engineering API (static tier, PATHOS 3.0 M10;
 * docs/api-reference/reverse-engineering.md; every route behind the
 * `reverse_engineering` flag). Base: /api/v1/rea.
 */

export const REA = "/api/v1/rea";
const enc = encodeURIComponent;

/** The analysis tools the configuration knows (keys of the API). */
export const reaToolKeys = ["radare2", "binwalk", "ghidra", "jadx", "ilspy"] as const;
export type ReaToolKey = (typeof reaToolKeys)[number];

/**
 * Rule 3 (ADR-011): outside the configuration pages the UI names the kind of
 * analysis, never the tool. Only "Reverse engineering tools" shows tool names.
 */
export const analysisKind: Record<string, string> = {
  radare2: "Binary triage",
  ghidra: "Decompiler",
  binwalk: "Firmware extraction",
  jadx: "Android decompiler",
  ilspy: ".NET decompiler",
  "pathos-rea": "Binary analysis",
};

export function kindOf(tool: string | undefined): string {
  if (!tool) return "Binary analysis";
  return analysisKind[tool.toLowerCase()] ?? "Binary analysis";
}

const toolWord = new RegExp(`\\b(${Object.keys(analysisKind).map((k) => k.replace(/[.-]/g, "\\$&")).join("|")})\\b`, "gi");

/** Replaces tool names in server text (evidence details, tool errors) with the kind of analysis. */
export function hideToolNames(text: string | undefined): string {
  if (!text) return "";
  return text.replace(toolWord, (m) => kindOf(m));
}

export type TrustStatus = "trusted" | "authorized" | "untrusted";
export type TrustBasis = "signature" | "provenance" | "authorization" | "";

export interface Authorization {
  id: string;
  reason: string;
  authorized_by?: string;
  authorized_by_email?: string;
  created_at: string;
}

export interface ArtifactTrust {
  status: TrustStatus;
  basis: TrustBasis;
  reason?: string;
  signature?: { status: string; mode?: string; verified_at?: string | null } | null;
  provenance?: { status: string; commit?: string; builder?: string; verified_at?: string | null } | null;
  authorization?: Authorization | null;
}

export type AnalysisStatus = "queued" | "running" | "ready" | "partial" | "failed";

export interface ToolRun {
  version?: string;
  status: "succeeded" | "failed" | "skipped" | "timed_out" | string;
  detail?: string;
  duration_ms?: number;
}

export interface Analysis {
  id: string;
  target_id: string;
  artifact_name: string;
  artifact_sha256: string;
  repository_id?: string;
  repository_name?: string;
  application_id?: string | null;
  scan_job_id?: string | null;
  status: AnalysisStatus;
  trust_basis?: TrustBasis;
  commit_sha?: string;
  commit_source?: "provenance" | "binary" | "user" | "";
  source_snapshot_id?: string | null;
  snapshot_id?: string | null;
  format?: string;
  arch?: string;
  language?: string;
  tools?: Record<string, ToolRun>;
  stats?: Record<string, unknown>;
  error_code?: string;
  error?: string;
  requested_by?: string | null;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
}

export interface Artifact {
  target_id: string;
  name: string;
  file_name: string;
  sha256: string;
  size: number;
  kind: string;
  repository_id: string;
  repository_name?: string;
  application_id?: string | null;
  created_at: string;
  trust: ArtifactTrust;
  last_analysis?: Analysis | null;
}

export type InputPolicy = "own_builds_or_authorized" | "own_builds_only";
export type DecompiledCodeAI = "none" | "local" | "cloud";

export interface ReaSettings {
  enabled_tools: string[];
  memory_mb: number;
  timeout_minutes: number;
  input_policy: InputPolicy;
  decompiled_code_ai: DecompiledCodeAI;
  /** Read-only: the default AI configuration allows sending code (AI settings). */
  ai_send_code_allowed?: boolean;
  updated_at?: string | null;
}

export interface ReaTool {
  key: string;
  name: string;
  license: string;
  purpose: string;
  installed: boolean;
  version?: string;
  enabled: boolean;
  optional: boolean;
}

export type MatchState = "matched" | "binary_only" | "library" | "unmatched";

export interface FunctionItem {
  node_id: string;
  key: string;
  name: string;
  addr?: string;
  offset?: number;
  size?: number;
  section?: string;
  tool?: string;
  library?: boolean;
  match: MatchState;
  sensitive?: boolean;
  source?: { file: string; line?: number; node_key?: string } | null;
  has_code?: boolean;
}

export interface StringItem {
  node_id: string;
  value: string;
  offset?: number;
  vaddr?: string | number;
  section?: string;
  kind?: string;
  redacted?: boolean;
  tool?: string;
}

export interface ImportItem {
  node_id: string;
  name: string;
  library?: string;
  kind?: string;
  tool?: string;
  sensitive?: boolean;
}

export interface Ref {
  evidence: "verified" | "observed" | "ai_inferred";
  kind: "binary" | "file_line" | string;
  ref: string;
  detail?: string;
}

export interface FunctionDetail {
  function: FunctionItem;
  code?: { tool: string; kind: "pseudo_c" | "disassembly" | string; text: string } | null;
  code_withheld?: string;
  callers: FunctionItem[];
  callees: FunctionItem[];
  strings: StringItem[];
  evidence: Ref[];
}

export type DiffSide = "binary_only" | "source_only" | "matched";
export type DiffStatus = "ready" | "no_commit" | "no_source_snapshot" | "pending";

export interface DiffItem {
  id: string;
  side: DiffSide;
  kind: "function" | "package" | "route" | "string" | string;
  name: string;
  sensitive?: boolean;
  sensitive_reason?: string;
  binary?: { node_id: string; key: string; offset?: number; tool?: string } | null;
  source?: { node_id: string; key: string; file?: string; line?: number } | null;
  evidence: Ref[];
}

export interface DiffResult {
  status: DiffStatus;
  commit_sha?: string;
  commit_source?: string;
  source_snapshot_id?: string | null;
  counts: { binary_only: number; source_only: number; matched: number };
  items: DiffItem[];
  total: number;
}

export interface Draft {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "proposed" | "dismissed" | "created";
  label?: string;
  evidence: Ref[];
  diff_item_id?: string | null;
  finding_id?: string | null;
  application_id?: string | null;
  created_at: string;
}

export interface Page<T> {
  items: T[];
  total: number;
}

export const reaKeys = {
  settings: ["rea", "settings"] as const,
  tools: ["rea", "tools"] as const,
  artifacts: (repo: string, q: string) => ["rea", "artifacts", repo, q] as const,
  analyses: (target: string) => ["rea", "analyses", target] as const,
  analysis: (id: string) => ["rea", "analysis", id] as const,
  functions: (id: string, p: object) => ["rea", "analysis", id, "functions", p] as const,
  fn: (id: string, nid: string) => ["rea", "analysis", id, "function", nid] as const,
  strings: (id: string, p: object) => ["rea", "analysis", id, "strings", p] as const,
  imports: (id: string, p: object) => ["rea", "analysis", id, "imports", p] as const,
  graph: (id: string, view: string, focus: string) => ["rea", "analysis", id, "graph", view, focus] as const,
  diff: (id: string, p: object) => ["rea", "analysis", id, "diff", p] as const,
  drafts: (id: string) => ["rea", "analysis", id, "drafts"] as const,
};

function qs(p: Record<string, string | number | undefined>): string {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(p)) if (v !== undefined && v !== "") u.set(k, String(v));
  const s = u.toString();
  return s ? `?${s}` : "";
}

const page = <T,>(r: Partial<Page<T>> | T[] | null | undefined): Page<T> =>
  Array.isArray(r) ? { items: r, total: r.length } : { items: r?.items ?? [], total: r?.total ?? r?.items?.length ?? 0 };

export function useReaSettings(enabled = true) {
  return useQuery({ queryKey: reaKeys.settings, queryFn: () => api<ReaSettings>(`${REA}/settings`), enabled });
}

export function useSaveReaSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (s: Omit<ReaSettings, "ai_send_code_allowed" | "updated_at">) => api<ReaSettings>(`${REA}/settings`, { method: "PUT", body: s }),
    onSuccess: (s) => qc.setQueryData(reaKeys.settings, s),
  });
}

export function useReaTools(enabled = true) {
  return useQuery({
    queryKey: reaKeys.tools,
    queryFn: () => api<{ tools?: ReaTool[]; worker_online?: boolean }>(`${REA}/tools`).then((r) => ({ tools: r.tools ?? [], worker_online: !!r.worker_online })),
    enabled,
  });
}

export function useArtifacts(f: { repository_id?: string; q?: string }, enabled = true) {
  return useQuery({
    queryKey: reaKeys.artifacts(f.repository_id ?? "", f.q ?? ""),
    queryFn: () => api<{ artifacts?: Artifact[] }>(`${REA}/artifacts${qs({ repository_id: f.repository_id, q: f.q, limit: 200 })}`).then((r) => r.artifacts ?? []),
    enabled,
    refetchInterval: (q) => (q.state.data?.some((a) => a.last_analysis && (a.last_analysis.status === "queued" || a.last_analysis.status === "running")) ? 5000 : false),
  });
}

export function useAuthorize(targetId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (reason: string) => api<Authorization>(`${REA}/artifacts/${enc(targetId)}/authorizations`, { method: "POST", body: { reason } }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["rea", "artifacts"] }),
  });
}

export function useRevokeAuthorization(targetId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (aid: string) => api<void>(`${REA}/artifacts/${enc(targetId)}/authorizations/${enc(aid)}`, { method: "DELETE" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["rea", "artifacts"] }),
  });
}

export function useStartAnalysis() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: { target_id: string; commit_sha?: string }) =>
      api<{ analysis?: Analysis } & Partial<Analysis>>(`${REA}/analyses`, { method: "POST", body: b }).then((r) => (r.analysis ?? r) as Analysis),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["rea"] }),
  });
}

export function useAnalyses(targetId: string | undefined) {
  return useQuery({
    queryKey: reaKeys.analyses(targetId ?? ""),
    queryFn: () => api<{ analyses?: Analysis[] }>(`${REA}/analyses${qs({ target_id: targetId, limit: 100 })}`).then((r) => r.analyses ?? []),
    enabled: !!targetId,
  });
}

export interface AnalysisDetail {
  analysis: Analysis;
  counts: { functions?: number; imports?: number; strings?: number; sections?: number; calls?: number };
}

export function useAnalysis(id: string) {
  return useQuery({
    queryKey: reaKeys.analysis(id),
    queryFn: () => api<Partial<AnalysisDetail>>(`${REA}/analyses/${enc(id)}`).then((r) => ({ analysis: r.analysis!, counts: r.counts ?? {} })),
    enabled: !!id,
    refetchInterval: (q) => {
      const s = q.state.data?.analysis?.status;
      return s === "queued" || s === "running" ? 5000 : false;
    },
  });
}

export const analysisReady = (a?: Analysis) => !!a && (a.status === "ready" || a.status === "partial");

export interface ListParams {
  q?: string;
  match?: string;
  kind?: string;
  limit: number;
  offset: number;
}

export function useFunctions(id: string, p: ListParams, enabled = true) {
  return useQuery({
    queryKey: reaKeys.functions(id, p),
    queryFn: () => api<Partial<Page<FunctionItem>>>(`${REA}/analyses/${enc(id)}/functions${qs({ q: p.q, match: p.match, limit: p.limit, offset: p.offset })}`).then(page),
    enabled,
    placeholderData: (prev) => prev,
  });
}

export function useFunctionDetail(id: string, nid: string | undefined) {
  return useQuery({
    queryKey: reaKeys.fn(id, nid ?? ""),
    queryFn: () =>
      api<Partial<FunctionDetail>>(`${REA}/analyses/${enc(id)}/functions/${enc(nid!)}`).then(
        (r): FunctionDetail => ({
          function: r.function!,
          code: r.code ?? null,
          code_withheld: r.code_withheld,
          callers: r.callers ?? [],
          callees: r.callees ?? [],
          strings: r.strings ?? [],
          evidence: r.evidence ?? [],
        }),
      ),
    enabled: !!nid,
  });
}

export function useStrings(id: string, p: ListParams, enabled = true) {
  return useQuery({
    queryKey: reaKeys.strings(id, p),
    queryFn: () => api<Partial<Page<StringItem>>>(`${REA}/analyses/${enc(id)}/strings${qs({ q: p.q, kind: p.kind, limit: p.limit, offset: p.offset })}`).then(page),
    enabled,
    placeholderData: (prev) => prev,
  });
}

export function useImports(id: string, p: ListParams, enabled = true) {
  return useQuery({
    queryKey: reaKeys.imports(id, p),
    queryFn: () => api<Partial<Page<ImportItem>>>(`${REA}/analyses/${enc(id)}/imports${qs({ q: p.q, limit: p.limit, offset: p.offset })}`).then(page),
    enabled,
    placeholderData: (prev) => prev,
  });
}

export const binaryViews = ["binary_call_graph", "binary_imports", "binary_layout"] as const;
export type BinaryView = (typeof binaryViews)[number];
export const binaryViewInfo: Record<BinaryView, { label: string; description: string }> = {
  binary_call_graph: { label: "Call graph", description: "Functions of the binary and the calls between them, including calls to imported functions." },
  binary_imports: { label: "Imports", description: "Libraries, packages and functions the binary imports." },
  binary_layout: { label: "Layout", description: "Sections of the binary and the functions they contain." },
};

/** Binary evidence: the detail names the tool ("radare2: call at …"); rule 3 shows the kind of analysis. */
export function sanitiseGraph(g: GraphData): GraphData {
  const fix = (r: EvidenceRef): EvidenceRef => ({ ...r, detail: hideToolNames(r.detail) });
  return {
    ...g,
    nodes: g.nodes.map((n) => (n.attrs?.tool ? { ...n, attrs: { ...n.attrs, tool: kindOf(String(n.attrs.tool)) } } : n)),
    edges: g.edges.map((e) => ({ ...e, evidence_refs: e.evidence_refs.map(fix) })),
  };
}

export function useBinaryGraph(id: string, view: BinaryView, focus: string | undefined, enabled = true) {
  return useQuery({
    queryKey: reaKeys.graph(id, view, focus ?? ""),
    queryFn: () =>
      api<Parameters<typeof normaliseGraph>[0]>(`${REA}/analyses/${enc(id)}/graph${qs({ view, focus, limit: 500 })}`)
        .then(normaliseGraph)
        .then(sanitiseGraph),
    enabled,
    staleTime: 60_000,
  });
}

export function fetchBinaryNode(id: string, nid: string): Promise<NodeDetail> {
  return api<Parameters<typeof normaliseDetail>[0]>(`${REA}/analyses/${enc(id)}/graph/nodes/${enc(nid)}`)
    .then(normaliseDetail)
    .then((d) => {
      const g = sanitiseGraph({ nodes: [d.node], edges: d.edges ?? [] });
      return { ...d, node: g.nodes[0]!, edges: g.edges };
    });
}

export function useDiff(id: string, p: { side?: string; kind?: string; limit: number; offset: number }, enabled = true) {
  return useQuery({
    queryKey: reaKeys.diff(id, p),
    queryFn: () =>
      api<Partial<DiffResult>>(`${REA}/analyses/${enc(id)}/diff${qs(p)}`).then(
        (r): DiffResult => ({
          status: r.status ?? "pending",
          commit_sha: r.commit_sha,
          commit_source: r.commit_source,
          source_snapshot_id: r.source_snapshot_id,
          counts: { binary_only: r.counts?.binary_only ?? 0, source_only: r.counts?.source_only ?? 0, matched: r.counts?.matched ?? 0 },
          items: r.items ?? [],
          total: r.total ?? r.items?.length ?? 0,
        }),
      ),
    enabled,
    placeholderData: (prev) => prev,
  });
}

export function useRecomputeDiff(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (snapshotId: string) => api<unknown>(`${REA}/analyses/${enc(id)}/diff`, { method: "POST", body: { source_snapshot_id: snapshotId } }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["rea", "analysis", id] }),
  });
}

export function useDrafts(id: string, enabled = true) {
  return useQuery({
    queryKey: reaKeys.drafts(id),
    queryFn: () => api<{ drafts?: Draft[] }>(`${REA}/analyses/${enc(id)}/drafts`).then((r) => r.drafts ?? []),
    enabled,
  });
}

export function useCreateFinding(analysisId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (draftId: string) => api<{ finding_id: string }>(`${REA}/drafts/${enc(draftId)}/create-finding`, { method: "POST", body: {} }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: reaKeys.drafts(analysisId) }),
  });
}

export function useDismissDraft(analysisId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: { id: string; reason: string }) => api<unknown>(`${REA}/drafts/${enc(b.id)}/dismiss`, { method: "POST", body: { reason: b.reason } }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: reaKeys.drafts(analysisId) }),
  });
}

/** Text of an evidence reference for people: binary offsets with the kind of analysis, source lines as file:line. */
export function refText(r: Ref): string {
  if (r.kind === "binary") return `offset ${r.ref}${r.detail ? ` (${hideToolNames(r.detail)})` : ""}`;
  if (r.kind === "file_line") return `${r.ref}${r.detail ? ` (${hideToolNames(r.detail)})` : ""}`;
  return `${r.ref}${r.detail ? ` (${hideToolNames(r.detail)})` : ""}`;
}

export const hex = (n: number | undefined) => (n == null ? "" : `0x${n.toString(16)}`);

/** STRIDE category proposed for a draft when it goes to a threat model. */
export function threatCategoryFor(d: Pick<Draft, "title" | "description">): "information_disclosure" | "elevation_of_privilege" | "tampering" {
  const t = `${d.title} ${d.description}`.toLowerCase();
  if (/exec|command|setuid|privilege|shell|system\(/.test(t)) return "elevation_of_privilege";
  if (/write|tamper|modify/.test(t)) return "tampering";
  return "information_disclosure";
}

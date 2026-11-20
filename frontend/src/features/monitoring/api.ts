import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/api/client";
import type { Severity } from "@/api/types";
import { redactToolNames } from "@/lib/checkKinds";

/**
 * Typed client for continuous monitoring (/api/v1/monitoring/*, PATHOS 3.0
 * M9, behind the `continuous_monitoring` flag): the feed of the seven
 * feedback loops, architecture drift between CodeGraph snapshots, and the
 * drift-alert settings.
 */

export const FLAG = "continuous_monitoring";

export type EvidenceLabel = "verified" | "observed" | "ai_inferred";
export const severities: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface EventType {
  type: string;
  label: string;
  loop: number | null;
  description: string;
}

export interface MonitoringEvent {
  id: string;
  type: string;
  type_label: string;
  loop: number | null;
  severity: Severity;
  title: string;
  summary: string;
  evidence_label: EvidenceLabel;
  evidence: {
    from_snapshot_id?: string;
    to_snapshot_id?: string;
    commit?: string;
    scan_job_id?: string;
    gate_decision_id?: string;
    verification_id?: string;
    threat_model_id?: string;
    feed?: string;
    [k: string]: unknown;
  } | null;
  application_id: string | null;
  application_name: string;
  repository_id: string | null;
  repository_name: string;
  subject_type: string | null;
  subject_id: string | null;
  link: string;
  details: Record<string, unknown> | null;
  created_at: string;
}

export interface Summary {
  days: number;
  total: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  latest_at: string | null;
  drift: { total: number; with_changes: number; latest_at: string | null };
}

export const driftCountKeys = [
  "added_routes",
  "removed_routes",
  "added_external_services",
  "removed_external_services",
  "added_datastores",
  "removed_datastores",
  "added_internet_exposure",
  "removed_internet_exposure",
  "added_boundary_crossings",
  "removed_boundary_crossings",
  "added_components",
  "removed_components",
  "changed_components",
] as const;
export type DriftCountKey = (typeof driftCountKeys)[number];

/** Count categories shown on the timeline: label, added key, removed key (and changed for components). */
export const driftCategories: { label: string; added: DriftCountKey; removed: DriftCountKey; changed?: DriftCountKey }[] = [
  { label: "Routes", added: "added_routes", removed: "removed_routes" },
  { label: "External services", added: "added_external_services", removed: "removed_external_services" },
  { label: "Data stores", added: "added_datastores", removed: "removed_datastores" },
  { label: "Internet exposure", added: "added_internet_exposure", removed: "removed_internet_exposure" },
  { label: "Trust boundary crossings", added: "added_boundary_crossings", removed: "removed_boundary_crossings" },
  { label: "Components", added: "added_components", removed: "removed_components", changed: "changed_components" },
];

export interface Drift {
  id: string;
  application_id: string;
  application_name: string;
  repository_id: string;
  repository_name: string;
  from_snapshot_id: string | null;
  to_snapshot_id: string;
  from_commit: string;
  to_commit: string;
  severity: Severity;
  has_changes: boolean;
  counts: Partial<Record<DriftCountKey, number>>;
  created_at: string;
}

export type DriftCategory = "route" | "api_operation" | "external_service" | "datastore" | "queue" | "internet_exposure" | "boundary_crossing" | "component";
export const driftCategoryLabel: Record<DriftCategory, string> = {
  route: "Routes",
  api_operation: "API operations",
  external_service: "External services",
  datastore: "Data stores",
  queue: "Queues",
  internet_exposure: "Internet exposure",
  boundary_crossing: "Trust boundary crossings",
  component: "Components",
};

export interface DriftEvidence {
  kind: string;
  ref: string;
  detail: string;
  file: string;
  line: number;
}

export interface DriftItem {
  change: "added" | "removed" | "changed";
  category: DriftCategory;
  key: string;
  label: string;
  detail: string;
  file: string;
  evidence_label: EvidenceLabel;
  evidence: DriftEvidence[];
}

export interface DriftDetail extends Drift {
  items: DriftItem[];
  truncated: boolean;
}

export interface MonitoringSettings {
  drift_alerts: boolean;
  drift_alert_min_severity: Severity;
  updated_at: string | null;
  updated_by: string | null;
}

/** Feed filters (also the URL search of /monitoring). */
export interface FeedFilters {
  application_id?: string;
  repository_id?: string;
  type?: string;
  severity?: string;
  loop?: string;
  since?: string;
  until?: string;
}
export const feedFilterKeys: (keyof FeedFilters)[] = ["application_id", "repository_id", "type", "severity", "loop", "since", "until"];

/** True when the API answered that the module is switched off (PTH-PLAT-1007). */
export function isFeatureDisabled(err: unknown): boolean {
  return err instanceof ApiError && (err.code === "feature_disabled" || err.errorCode === "PTH-PLAT-1007");
}

export function qs(params: Record<string, string | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) p.set(k, v);
  const s = p.toString();
  return s ? `?${s}` : "";
}

/** Rule 3: events and drift items may quote engine output; their texts are redacted. */
export function displayEvent(e: MonitoringEvent): MonitoringEvent {
  return { ...e, title: redactToolNames(e.title ?? ""), summary: redactToolNames(e.summary ?? ""), type_label: redactToolNames(e.type_label ?? "") };
}
function displayDriftItem(i: DriftItem): DriftItem {
  return {
    ...i,
    label: redactToolNames(i.label ?? ""),
    detail: redactToolNames(i.detail ?? ""),
    evidence: (i.evidence ?? []).map((e) => ({ ...e, ref: redactToolNames(e.ref ?? ""), detail: redactToolNames(e.detail ?? "") })),
  };
}

/** URL of the version-stamped CSV export of the feed with the current filters (needs findings.export). */
export function feedCsvUrl(f: FeedFilters): string {
  return `/api/v1/monitoring/events${qs({ ...f, format: "csv" })}`;
}

export const monKeys = {
  all: ["monitoring"] as const,
  types: ["monitoring", "types"] as const,
  events: (f: FeedFilters, cursor: string, limit: number) => ["monitoring", "events", f, cursor, limit] as const,
  summary: (app: string, days: number) => ["monitoring", "summary", app, days] as const,
  drift: (app: string, changedOnly: boolean, cursor: string, limit: number) => ["monitoring", "drift", app, changedOnly, cursor, limit] as const,
  driftDetail: (id: string) => ["monitoring", "drift-detail", id] as const,
  settings: ["monitoring", "settings"] as const,
};

export function useEventTypes(enabled = true) {
  return useQuery({
    enabled,
    queryKey: monKeys.types,
    queryFn: () => api<{ items: EventType[] }>("/api/v1/monitoring/types").then((r) => r.items ?? []),
    staleTime: 10 * 60_000,
    retry: false,
  });
}

export function useEvents(f: FeedFilters, cursor?: string, limit = 50, enabled = true) {
  return useQuery({
    enabled,
    queryKey: monKeys.events(f, cursor ?? "", limit),
    queryFn: () =>
      api<{ items: MonitoringEvent[]; next_cursor: string | null }>(`/api/v1/monitoring/events${qs({ ...f, cursor, limit: String(limit) })}`).then((r) => ({
        items: (r.items ?? []).map(displayEvent),
        next_cursor: r.next_cursor ?? null,
      })),
    retry: false,
  });
}

export function useSummary(applicationId: string | undefined, days = 30, enabled = true) {
  return useQuery({
    enabled,
    queryKey: monKeys.summary(applicationId ?? "", days),
    queryFn: () => api<Summary>(`/api/v1/monitoring/summary${qs({ application_id: applicationId, days: String(days) })}`),
    retry: false,
  });
}

export function useDrifts(applicationId: string | undefined, changedOnly: boolean, cursor?: string, limit = 50, enabled = true) {
  return useQuery({
    enabled,
    queryKey: monKeys.drift(applicationId ?? "", changedOnly, cursor ?? "", limit),
    queryFn: () =>
      api<{ items: Drift[]; next_cursor: string | null }>(
        `/api/v1/monitoring/drift${qs({ application_id: applicationId, changed_only: String(changedOnly), cursor, limit: String(limit) })}`,
      ).then((r) => ({ items: r.items ?? [], next_cursor: r.next_cursor ?? null })),
    retry: false,
  });
}

export function useDrift(id: string | undefined) {
  return useQuery({
    enabled: !!id,
    queryKey: monKeys.driftDetail(id ?? ""),
    queryFn: () =>
      api<DriftDetail>(`/api/v1/monitoring/drift/${encodeURIComponent(id!)}`).then((d) => ({ ...d, items: (d.items ?? []).map(displayDriftItem), truncated: !!d.truncated })),
    retry: false,
  });
}

export function useMonitoringSettings(enabled = true) {
  return useQuery({ enabled, queryKey: monKeys.settings, queryFn: () => api<MonitoringSettings>("/api/v1/monitoring/settings"), retry: false });
}

export function useSaveMonitoringSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Pick<MonitoringSettings, "drift_alerts" | "drift_alert_min_severity">) => api<MonitoringSettings>("/api/v1/monitoring/settings", { method: "PUT", body }),
    onSuccess: (s) => qc.setQueryData(monKeys.settings, s),
  });
}

// --- time ranges ---------------------------------------------------------------

export const rangePresets = [
  { key: "24h", label: "Last 24 hours", hours: 24 },
  { key: "7d", label: "Last 7 days", hours: 24 * 7 },
  { key: "30d", label: "Last 30 days", hours: 24 * 30 },
] as const;

/** `since` (RFC 3339) for a preset key, computed from `now`. */
export function sinceFor(key: string, now = Date.now()): string | undefined {
  const p = rangePresets.find((x) => x.key === key);
  return p ? new Date(now - p.hours * 3600_000).toISOString() : undefined;
}

export const shortSha = (s: string | null | undefined) => (s ? s.slice(0, 12) : "");

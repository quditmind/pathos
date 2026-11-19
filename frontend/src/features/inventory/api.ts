import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/api/client";
import type { Criticality, Ref, TagColor, UserRef } from "@/api/types";

/** Where an automatically filled value came from. */
export interface Detection {
  source: "repository" | "sbom" | "scm";
  detail: string;
}

export interface AppTag {
  id: string;
  name: string;
  color: TagColor;
  category_id: string;
  category_name: string;
  category_color: string;
  source: "manual" | "rule" | "bulk" | "onboarding";
}

export interface Progress {
  filled: number;
  required: number;
  missing: string[];
  missing_tag_categories: Ref[];
  /** "Onboarding: 6 of 9 fields" or "Registered". */
  label: string;
}

/** GET /api/v1/applications/{id}: the application profile. */
export interface ApplicationProfile {
  id: string;
  application_key: string;
  name: string;
  description: string;
  external_ref: string;
  business_unit: Ref | null;
  owner: UserRef | null;
  security_owner: UserRef | null;
  technical_owner: UserRef | null;
  criticality: Criticality;
  lifecycle: string;
  environment: string;
  application_type: string;
  languages: string[];
  frameworks: string[];
  runtimes: string[];
  data_classification: string;
  internet_exposure: string;
  compliance_scopes: string[];
  authentication_model: string;
  hosting_region: string;
  data_residency_region: Ref | null;
  onboarding_status: "draft" | "complete";
  detected: Record<string, Detection>;
  progress: Progress;
  tags: AppTag[];
  repository_count: number;
  can_manage: boolean;
  archived_at: string | null;
  created_at: string;
  updated_at: string;
}

/** PATCH /api/v1/applications/{id}/classification (absent = unchanged). */
export interface ClassificationPatch {
  description?: string;
  business_unit_id?: string | null;
  owner_user_id?: string | null;
  security_owner_user_id?: string | null;
  technical_owner_user_id?: string | null;
  criticality?: string;
  environment?: string;
  lifecycle?: string;
  external_ref?: string;
  application_type?: string;
  languages?: string[];
  frameworks?: string[];
  runtimes?: string[];
  data_classification?: string;
  internet_exposure?: string;
  compliance_scopes?: string[];
  authentication_model?: string;
  hosting_region?: string;
  data_residency_region_id?: string | null;
  tag_ids?: string[];
}

export interface SourceRef {
  repository_id?: string;
  scm_connection_id?: string;
  external_id: string;
  full_name: string;
  url: string;
  organization: string;
  project: string;
  language: string;
}

export interface RepoRef {
  id: string;
  name: string;
  full_name: string;
  url: string;
  application: Ref | null;
}

export interface MatchSource extends SourceRef {
  source_key: string;
  existing_repository: RepoRef | null;
  /** Registered in a scope the caller cannot see. */
  registered_elsewhere: boolean;
  onboarding: { id: string; application_id: string; application_name: string; status: string } | null;
}

export interface Candidate {
  id: string;
  application_key: string;
  name: string;
  onboarding_status: "draft" | "complete";
  repository_count: number;
  score: number;
  reasons: string[];
}

export interface MatchResult {
  sources: MatchSource[];
  candidates: Candidate[];
  suggested_name: string;
}

export interface OnboardingSource {
  id: string;
  full_name: string;
  url: string;
  scm_connection_id: string | null;
  external_id: string;
  organization: string;
  project: string;
  decision: "linked_existing" | "registered_new";
  status: "draft" | "saved" | "discovery_started";
  repository_id: string | null;
  repository_name: string | null;
  import_job_id: string | null;
  import_status: string | null;
  language: string;
  created_at: string;
}

export interface Onboarding {
  application: ApplicationProfile;
  sources: OnboardingSource[];
}

export interface DraftItem {
  id: string;
  application_key: string;
  name: string;
  progress: Progress;
  repository_count: number;
  updated_at: string;
}

export interface ApplicationSettings {
  required_fields: string[];
  fields: string[];
  labels: Record<string, string>;
}

export interface Phase {
  number: number;
  key: string;
  title: string;
  available: boolean;
  has_data: boolean;
  summary: string;
  metrics: Record<string, number>;
  restricted: boolean;
}

export interface AppLifecycle {
  id: string;
  application_key: string;
  name: string;
  onboarding_status: "draft" | "complete";
  criticality: Criticality;
  last_scan_at: string | null;
  phases: Phase[];
  phases_with_data: number;
}

export interface ActivityItem {
  at: string;
  kind: "audit" | "tags";
  action: string;
  actor: string;
  target: string;
  summary: string;
  metadata?: Record<string, unknown>;
}

export interface FrameworkTag {
  id: string;
  name: string;
  color: TagColor;
  repository_count: number;
  application_count: number;
}

export interface FrameworkCategory {
  id: string;
  name: string;
  color: string;
  is_mandatory: boolean;
  allow_multiple: boolean;
  mandatory_asset_types: string[];
  tags: FrameworkTag[];
  noncompliant_applications: number;
}

export interface TagRule {
  id: string;
  name: string;
  tag_id: string;
  tag_name: string;
  tag_color: TagColor;
  category_name: string;
  target_type: "application" | "repository";
  condition: "classification" | "repository_topic" | "path_pattern";
  field: string;
  value: string;
  enabled: boolean;
  created_at: string;
}

export interface TagFramework {
  categories: FrameworkCategory[];
  rules: TagRule[];
  rule_fields: string[];
}

export interface HistoryEntry {
  id: string;
  target_type: "application" | "repository";
  target_id: string;
  target_name: string;
  category_id: string | null;
  category_name: string;
  old_tags: string[];
  new_tags: string[];
  source: "manual" | "rule" | "bulk" | "onboarding";
  rule_id: string | null;
  actor_email: string;
  created_at: string;
}

/** Application field keys → labels (mirrors the server's FieldLabels). */
export const fieldLabels: Record<string, string> = {
  description: "Description", owner: "Business owner", security_owner: "Security owner", technical_owner: "Technical owner",
  business_unit: "Business unit", criticality: "Criticality", external_ref: "External ID", application_type: "Application type",
  languages: "Languages", frameworks: "Frameworks", runtimes: "Runtime", data_classification: "Data classification",
  internet_exposure: "Internet exposure", compliance_scopes: "Compliance scope", authentication_model: "Authentication model",
  hosting_region: "Hosting region", data_residency: "Data residency", environment: "Environment", lifecycle: "Lifecycle",
};

export const appKeys = {
  profile: (id: string) => ["application", id] as const,
  lifecycle: (id: string) => ["application-lifecycle", id] as const,
  activity: (id: string) => ["application-activity", id] as const,
  onboarding: (id: string) => ["application-onboarding", id] as const,
};

export function useApplicationProfile(id: string | undefined) {
  return useQuery({
    queryKey: appKeys.profile(id ?? ""),
    queryFn: () => api<ApplicationProfile>(`/api/v1/applications/${id}`),
    enabled: !!id,
    retry: false,
  });
}

export function useApplicationLifecycle(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: appKeys.lifecycle(id ?? ""),
    queryFn: () => api<AppLifecycle>(`/api/v1/applications/${id}/lifecycle`),
    enabled: !!id && enabled,
    retry: false,
  });
}

export function useApplicationActivity(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: appKeys.activity(id ?? ""),
    queryFn: () => api<{ items: ActivityItem[]; audit_visible: boolean }>(`/api/v1/applications/${id}/activity`),
    enabled: !!id && enabled,
    retry: false,
  });
}

export function useOnboarding(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: appKeys.onboarding(id ?? ""),
    queryFn: () => api<Onboarding>(`/api/v1/applications/${id}/onboarding`),
    enabled: !!id && enabled,
    retry: false,
  });
}

export function useOnboardingDrafts(enabled = true) {
  return useQuery({
    queryKey: ["onboarding-drafts"],
    queryFn: () => api<{ items: DraftItem[] }>("/api/v1/onboarding").then((r) => r.items),
    enabled,
    retry: false,
  });
}

export function useApplicationSettings(enabled = true) {
  return useQuery({
    queryKey: ["application-settings"],
    queryFn: () => api<ApplicationSettings>("/api/v1/application-settings"),
    enabled,
    staleTime: 60_000,
    retry: false,
  });
}

export function useLifecycleOverview(enabled = true) {
  return useQuery({
    queryKey: ["lifecycle-overview"],
    queryFn: () => api<{ items: AppLifecycle[]; phase_totals: number[]; truncated: boolean }>("/api/v1/lifecycle/overview"),
    enabled,
    retry: false,
  });
}

export function useTagFramework(enabled = true) {
  return useQuery({ queryKey: ["tag-framework"], queryFn: () => api<TagFramework>("/api/v1/tag-framework"), enabled, retry: false });
}

export function useTagHistory(target?: { type: "application" | "repository"; id: string }, enabled = true) {
  const q = target ? `?target_type=${target.type}&target_id=${target.id}` : "";
  return useQuery({
    queryKey: ["tag-history", target?.type ?? "", target?.id ?? ""],
    queryFn: () => api<{ items: HistoryEntry[] }>(`/api/v1/tag-history${q}`).then((r) => r.items),
    enabled,
    retry: false,
  });
}

/** Invalidates everything the inventory module derives. */
export function useInvalidateInventory() {
  const qc = useQueryClient();
  return () => {
    for (const k of ["application", "application-lifecycle", "application-activity", "application-onboarding", "onboarding-drafts",
      "lifecycle-overview", "tag-framework", "tag-history", "applications", "tag-categories", "repositories", "application-settings"]) {
      void qc.invalidateQueries({ queryKey: [k] });
    }
  };
}

export function useInventoryMutation<T, V>(fn: (v: V) => Promise<T>) {
  const invalidate = useInvalidateInventory();
  return useMutation({ mutationFn: fn, onSuccess: () => invalidate() });
}

export const matchSources = (body: { repositories: SourceRef[]; application_name?: string }) =>
  api<MatchResult>("/api/v1/onboarding/match", { method: "POST", body });

export const registerOnboarding = (body: {
  mode: "link" | "new";
  application_id?: string;
  application?: { name: string; description?: string; business_unit_id?: string | null };
  repositories: SourceRef[];
}) => api<Onboarding>("/api/v1/onboarding", { method: "POST", body });

export const saveClassification = (id: string, body: ClassificationPatch) =>
  api<ApplicationProfile>(`/api/v1/applications/${id}/classification`, { method: "PATCH", body });

export const completeOnboarding = (id: string) => api<Onboarding>(`/api/v1/applications/${id}/onboarding/complete`, { method: "POST" });

export const startDiscovery = (id: string, importJobId?: string) =>
  api<Onboarding>(`/api/v1/applications/${id}/onboarding/discovery`, { method: "POST", body: importJobId ? { import_job_id: importJobId } : {} });

/** The application ID named by an onboarding conflict (PTH-ONB-1008/1011), when the caller may see it. */
export function conflictApplication(e: unknown): string | undefined {
  if (!(e instanceof ApiError)) return undefined;
  const d = e.details?.details as { application_id?: string } | undefined;
  return d?.application_id;
}

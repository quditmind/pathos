export type UserStatus = "invited" | "active" | "deactivated";
export type ScopeType = "organization" | "region" | "business_unit" | "repository";

export interface User {
  id: string;
  organization_id: string;
  email: string;
  display_name: string;
  status: UserStatus;
  last_login_at: string | null;
  deactivated_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface RoleAssignment {
  id: string;
  user_id: string;
  role_id: string;
  role_key: string;
  role_name: string;
  scope_type: ScopeType;
  scope_id: string;
  scope_name: string;
  created_by: string | null;
  created_at: string;
}

export interface Me {
  user: User;
  permissions: string[];
  org_wide_permissions: string[] | null;
  role_assignments: RoleAssignment[];
  csrf_token: string;
}

export interface Role {
  id: string;
  key: string;
  name: string;
  description: string;
  is_system: boolean;
  permissions: string[];
}

export interface Region {
  id: string;
  code: string;
  name: string;
  countries: { id: string; code: string; name: string }[];
}

export interface BusinessUnit {
  id: string;
  parent_id: string | null;
  name: string;
  description: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
}

export interface Page<T> {
  items: T[];
  next_cursor?: string | null;
}

export interface AuditRecord {
  id: string;
  actor_id: string | null;
  actor_email: string;
  action: string;
  target_type: string;
  target_id: string;
  outcome: "success" | "denied" | "failure";
  ip: string | null;
  user_agent: string;
  request_id: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface CreateUserResponse {
  user: User;
  role_assignments: RoleAssignment[];
  provisioning: { status: "created" | "linked_existing" | "skipped" | "failed"; message?: string };
}

export type KpiStatus = "ok" | "not_yet_available" | "restricted";

export interface Point {
  date: string;
  value: number;
}

export interface Kpi {
  key: string;
  label: string;
  group: string;
  description: string;
  unit: "count" | "percent" | "days" | "score";
  polarity: "higher_is_better" | "lower_is_better" | "neutral";
  drill: string;
  status: KpiStatus;
  phase: number;
  value: number | null;
  previous: number | null;
  sparkline?: Point[];
  org_wide?: boolean;
}

export interface Chart {
  key: string;
  title: string;
  kind: "line" | "bar" | "stacked_bar" | "donut";
  status: KpiStatus;
  phase: number;
  drill: string;
  series?: { name: string; points: Point[] }[];
  categories?: { label: string; value: number }[];
}

export interface Dashboard {
  filters: { days: number; region_id?: string; country_id?: string; business_unit_id?: string };
  period_start: string;
  period_end: string;
  groups: string[];
  kpis: Kpi[];
  charts: Chart[];
}

export interface SearchResult {
  type: "repository" | "application" | "user" | "business_unit" | "region" | "country";
  id: string;
  title: string;
  subtitle: string;
  href: string;
}

export type Criticality = "low" | "medium" | "high" | "critical";
/** Key from the organization's environment catalog (asset_classifications, kind "environment"). */
export type Environment = string;
export type TagPaletteColor = "slate" | "blue" | "green" | "amber" | "red" | "purple" | "teal" | "pink";
/** A palette name or a lower-case hex colour such as "#1f6feb". */
export type TagColor = TagPaletteColor | `#${string}`;

export interface Ref {
  id: string;
  name: string;
  code?: string;
}

export interface TagRef {
  id: string;
  name: string;
  color: TagColor;
  category_id: string;
  category_name: string;
}

export type SourceType = "scm" | "upload";
export type SyncStatus = "never" | "ok" | "failed" | "missing" | "permission_denied" | "archived_upstream";

export interface Repository {
  id: string;
  /** null for uploaded repositories (source_type "upload"). */
  scm_connection_id: string | null;
  scm_connection_name: string;
  /** Connection provider, or "upload". */
  provider: string;
  source_type: SourceType;
  scm_organization: string;
  scm_project: string;
  external_id: string;
  full_name: string;
  name: string;
  url: string;
  default_branch: string;
  scan_branch: string;
  visibility: "public" | "private" | "internal";
  description: string;
  technologies: string[];
  application: Ref | null;
  business_unit: Ref | null;
  country: Ref | null;
  region: Ref | null;
  environment: Environment;
  criticality: Criticality;
  scan_enabled: boolean;
  scan_profile_id: string | null;
  remote_archived: boolean;
  last_pushed_at: string | null;
  archived_at: string | null;
  created_at: string;
  tags: TagRef[];

  // Enterprise asset metadata (AssetMetadata fields, resolved).
  display_name: string;
  asset_name: string;
  business_purpose: string;
  application_type: string;
  business_owner: UserRef | null;
  technical_owner: UserRef | null;
  application_owner: UserRef | null;
  responsible_team: Ref | null;
  supporting_team: Ref | null;
  department: Ref | null;
  cost_centre: string;
  business_region: Ref | null;
  data_residency_region: Ref | null;
  hosting_region: string;
  operational_location: string;
  data_classification: string;
  internet_exposure: string;
  compliance_scopes: string[];
  lifecycle_status: string;
  go_live_date: string | null;
  retirement_date: string | null;
  color: string;
  full_history: boolean;

  // Source state.
  latest_commit_sha: string;
  latest_commit_at: string | null;
  size_bytes: number | null;
  file_count: number | null;
  languages: Record<string, number>;
  last_sync_at: string | null;
  last_sync_ok_at: string | null;
  sync_status: SyncStatus;
  sync_error: string;
  current_snapshot: SnapshotSummary | null;
  /** True when the caller may edit this repository's metadata (repos.manage or ownership). */
  can_edit: boolean;
  /** True when the caller may change placement (business unit, country) — requires repos.manage. */
  can_manage: boolean;
}

export interface SnapshotSummary {
  id: string;
  created_at: string;
  archive_filename: string;
  archive_sha256: string;
  snapshot_sha256: string;
  file_count: number;
  uncompressed_bytes: number;
  /** "unavailable": a scanner is configured but was unreachable (and not required). */
  malware_scan: "clean" | "not_configured" | "unavailable";
}

export interface SourceSnapshot extends SnapshotSummary {
  archive_size: number;
  snapshot_size: number;
  languages: Record<string, number>;
  manifests: string[];
  skipped: Record<string, number>;
  malware_engine: string;
  created_by: UserRef | null;
}

export interface SyncRun {
  id: string;
  trigger: "manual" | "schedule" | "webhook" | "import" | "upload";
  status: Exclude<SyncStatus, "never">;
  branch: string;
  previous_commit_sha: string;
  commit_sha: string;
  changed: boolean;
  error: string;
  triggered_by: UserRef | null;
  started_at: string;
  finished_at: string;
}

export interface RepositorySecurity {
  latest_scan: {
    id: string;
    status: JobStatus;
    trigger: string;
    commit_sha: string;
    snapshot_id: string | null;
    profile_name: string;
    queued_at: string;
    finished_at: string | null;
    scanners: { key: string; version: string; status: string; findings: number }[];
  } | null;
  open_findings: { critical: number; high: number; medium: number; low: number; info: number };
  scan_on_import: boolean;
}

/**
 * The registration payload shared by every import method and by
 * PATCH /api/v1/repositories/{id}. Empty strings / null clear optional values.
 * Which fields are mandatory is AssetSettings.required_fields.
 */
export interface AssetMetadata {
  display_name?: string;
  asset_name?: string;
  description?: string;
  application_id?: string | null;
  /** Create an application on the fly (requires repos.manage at the business unit). */
  new_application?: { name: string; external_ref?: string } | null;
  application_type?: string;
  business_purpose?: string;
  business_owner_id?: string | null;
  technical_owner_id?: string | null;
  application_owner_id?: string | null;
  business_unit_id?: string | null;
  department_id?: string | null;
  responsible_team_id?: string | null;
  supporting_team_id?: string | null;
  cost_centre?: string;
  business_region_id?: string | null;
  country_id?: string | null;
  hosting_region?: string;
  data_residency_region_id?: string | null;
  operational_location?: string;
  criticality?: Criticality;
  data_classification?: string;
  environment?: string;
  internet_exposure?: string;
  compliance_scopes?: string[];
  tag_ids?: string[];
  color?: string;
  lifecycle_status?: string;
  go_live_date?: string | null;
  retirement_date?: string | null;
}

/** Field keys usable in AssetSettings.required_fields. */
export type AssetField =
  | "description" | "application" | "application_type" | "business_purpose"
  | "business_owner" | "technical_owner" | "application_owner" | "business_unit" | "department"
  | "responsible_team" | "supporting_team" | "cost_centre"
  | "business_region" | "country" | "hosting_region" | "data_residency_region" | "operational_location"
  | "criticality" | "data_classification" | "environment" | "internet_exposure" | "compliance_scopes"
  | "tags" | "lifecycle_status";

export type ClassificationKind =
  | "criticality" | "data_classification" | "environment" | "application_type"
  | "internet_exposure" | "compliance" | "hosting_region" | "lifecycle_status";

export interface Classification {
  id: string;
  kind: ClassificationKind;
  key: string;
  label: string;
  description: string;
  /** "" or "#rrggbb" */
  color: string;
  sort_order: number;
  is_system: boolean;
  archived: boolean;
}

export interface AssetSettings {
  required_fields: AssetField[];
  /** Fields that are always required regardless of policy. */
  always_required: AssetField[];
  scan_on_import: boolean;
  classifications: Record<ClassificationKind, Classification[]>;
  upload: { max_bytes: number; chunk_size: number; formats: ("zip" | "tar" | "tar.gz")[] };
  /** Colour suggestions keyed by criticality / lifecycle, for the colour picker. */
  suggested_colors: { key: string; label: string; color: string }[];
}

/** Validation error body: HTTP 422 { error: { code: "validation_failed", message, fields } }. */
export interface FieldErrors {
  [field: string]: string;
}

export interface DirectoryUser {
  id: string;
  name: string;
  email: string;
}

export interface DirectoryTeam {
  id: string;
  name: string;
  member_count: number;
}

export interface UserRef {
  id: string;
  name: string;
  email: string;
}

export interface Application {
  id: string;
  name: string;
  description: string;
  business_unit: Ref | null;
  owner: UserRef | null;
  security_owner: UserRef | null;
  criticality: Criticality;
  repository_count: number;
  archived_at: string | null;
  created_at: string;
}

export interface Tag {
  id: string;
  name: string;
  color: TagColor;
  description: string;
  repository_count: number;
}

/** GET /api/v1/tags?q= — flat tag search across categories. */
export interface TagSearchResult extends Tag {
  category_id: string;
  category_name: string;
}

export interface TagCategory {
  id: string;
  name: string;
  description: string;
  is_mandatory: boolean;
  allow_multiple: boolean;
  tags: Tag[];
  noncompliant_repositories: number;
}

export type Provider = "github" | "github_enterprise" | "gitlab" | "bitbucket" | "azure_devops" | "azure_devops_server";
export type AuthType = "pat" | "github_app" | "oauth" | "api_token" | "service_principal";

export interface ScmConnection {
  id: string;
  name: string;
  provider: Provider;
  base_url: string;
  auth_type: AuthType;
  owner: string;
  github_app_id: number | null;
  github_installation_id: number | null;
  oauth_app_id: string | null;
  /** Identity the credential authenticates as (login / e-mail / app). */
  account: string;
  organizations: string[];
  token_expires_at: string | null;
  status: "untested" | "ok" | "error" | "expired" | "revoked";
  status_message: string;
  last_checked_at: string | null;
  webhook_url: string;
  repository_count: number;
  created_at: string;
  capabilities: ProviderCapabilities;
}

export interface ProviderCapabilities {
  organizations: boolean;
  projects: boolean;
  server_search: boolean;
}

/** GET /api/v1/scm-providers */
export interface ProviderInfo {
  key: Provider;
  label: string;
  /** "git" providers appear under Import from Git, "devops" under Import from DevOps Project. */
  category: "git" | "devops";
  default_base_url: string;
  base_url_required: boolean;
  base_url_help: string;
  owner_label: string;
  capabilities: ProviderCapabilities;
  auth_methods: AuthMethod[];
}

export interface AuthMethod {
  key: AuthType;
  label: string;
  description: string;
  /** Uses a registered OAuth application and a browser redirect; no secret fields. */
  oauth: boolean;
  fields: AuthField[];
  docs_url: string;
}

export interface AuthField {
  /** Request field name in the create/update connection body. */
  name: string;
  label: string;
  type: "text" | "password" | "textarea" | "number" | "list";
  required: boolean;
  secret: boolean;
  help: string;
}

/** POST /api/v1/scm-connections body (fields depend on the auth method). */
export interface CreateConnectionRequest {
  name: string;
  provider: Provider;
  base_url?: string;
  auth_type: Exclude<AuthType, "oauth">;
  owner?: string;
  token?: string;
  private_key?: string;
  github_app_id?: number;
  github_installation_id?: number;
  username?: string;
  tenant_id?: string;
  client_id?: string;
  client_secret?: string;
  certificate_pem?: string;
  private_key_pem?: string;
  organizations?: string[];
}

/** GET/POST/PATCH /api/v1/scm-oauth-apps — the client secret is write-only. */
export interface OAuthApp {
  id: string;
  provider: Exclude<Provider, "azure_devops_server">;
  name: string;
  base_url: string;
  tenant_id: string;
  client_id: string;
  scopes: string;
  /** Register this exact URL at the provider. */
  redirect_uri: string;
  connection_count: number;
  created_at: string;
}

export interface OAuthAppRequest {
  provider?: OAuthApp["provider"];
  name?: string;
  base_url?: string;
  tenant_id?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string;
}

/**
 * POST /api/v1/scm-connections/oauth/start → { authorize_url }.
 * The browser navigates to authorize_url; the provider redirects to
 * /api/v1/scm-oauth/callback, which redirects to
 * /admin/scm?oauth=success&connection=<id> or /admin/scm?oauth=error&message=<text>.
 * Pass connection_id to reconnect an existing OAuth connection.
 */
export interface OAuthStartRequest {
  oauth_app_id: string;
  name?: string;
  owner?: string;
  connection_id?: string;
  /** Where to return after success (same-origin path, default /admin/scm). */
  return_to?: string;
}

export interface ScmOrganization {
  id: string;
  name: string;
  display_name: string;
  kind: "user" | "organization" | "group" | "workspace";
}

export interface ScmProject {
  id: string;
  name: string;
  description: string;
}

export interface DiscoveredRepo {
  external_id: string;
  full_name: string;
  name: string;
  organization: string;
  project: string;
  url: string;
  clone_url: string;
  default_branch: string;
  visibility: string;
  description: string;
  language: string;
  archived: boolean;
  pushed_at: string | null;
  size_bytes: number;
  imported_id: string | null;
}

/** GET /api/v1/scm-connections/{id}/remote-repositories?organization=&project=&q=&page_token= */
export interface RemoteRepoPage {
  items: DiscoveredRepo[];
  next_page_token: string;
}

/** GET /api/v1/scm-connections/{id}/remote-repositories/details?external_id=&full_name=&organization=&project= */
export interface RemoteRepoDetails {
  repository: DiscoveredRepo;
  branches: { name: string; commit_sha: string; is_default: boolean }[];
  latest_commit: { sha: string; message: string; author: string; committed_at: string | null } | null;
  languages: Record<string, number>;
  permission: "read" | "write" | "admin" | "unknown";
}

/** POST /api/v1/source-uploads body. */
export interface CreateUploadRequest {
  filename: string;
  size: number;
  /** Lower-case hex SHA-256 of the whole file. */
  sha256: string;
}

export interface SourceUpload {
  id: string;
  filename: string;
  format: "zip" | "tar" | "tar.gz";
  size: number;
  sha256: string;
  chunk_size: number;
  status: "uploading" | "complete" | "consumed" | "expired" | "cancelled";
  received_parts: number[];
  received_bytes: number;
  expires_at: string;
}
// PUT /api/v1/source-uploads/{id}/parts/{n}: body = raw bytes of part n
// (n = 0..ceil(size/chunk_size)-1), Content-Type application/octet-stream,
// header X-Content-SHA256 = hex SHA-256 of the part. Re-sending an
// identical part is idempotent. POST /api/v1/source-uploads/{id}/complete
// seals it; DELETE cancels.

export type ImportSource = "upload" | "git" | "devops";
export type ImportStatus =
  | "draft" | "pending" | "queued" | "validating" | "importing" | "registering"
  | "completed" | "failed" | "cancelled" | "needs_attention";

/** One repository to import. Exactly one of the ref shapes applies per source. */
export interface ImportItemRequest {
  /** git / devops */
  ref?: { external_id: string; full_name: string; organization?: string; project?: string };
  /** upload */
  upload_id?: string;
  /** upload: add a new snapshot to an existing uploaded repository instead of creating one */
  target_repository_id?: string;
  /** Branch to track and scan; "" = default branch. */
  branch?: string;
  full_history?: boolean;
  /** Per-item overrides of the shared metadata (names must be unique per asset). */
  display_name?: string;
  asset_name?: string;
  allow_duplicate?: boolean;
}

/** POST /api/v1/repository-imports (and /validate with the same body). */
export interface CreateImportRequest {
  source: ImportSource;
  scm_connection_id?: string;
  /** Random per wizard submission; resubmitting returns the same job. */
  idempotency_key: string;
  metadata: AssetMetadata;
  items: ImportItemRequest[];
  /** Queue an onboarding scan after registration (only honoured when AssetSettings.scan_on_import). */
  start_scan?: boolean;
}

/** POST /api/v1/repository-imports/validate → 200 always (unless the request itself is malformed). */
export interface ImportValidation {
  valid: boolean;
  /** Errors keyed by AssetMetadata field name. */
  fields: FieldErrors;
  /** Per-item problems (index into items): duplicates, already imported, invalid branch, name clash. */
  items: { index: number; code: string; message: string; repository_id?: string }[];
}

export interface ImportItem {
  id: string;
  position: number;
  display_name: string;
  status: ImportStatus;
  /** Last stage reached: where a failed / cancelled item stopped. */
  stage: "queued" | "validating" | "importing" | "registering" | "completed";
  result: "" | "imported" | "already_imported" | "snapshot_added";
  progress: number;
  progress_message: string;
  error_code: string;
  error_message: string;
  attempts: number;
  max_attempts: number;
  repository_id: string | null;
  snapshot_id: string | null;
  started_at: string | null;
  completed_at: string | null;
  can_retry: boolean;
}

export interface ImportJob {
  id: string;
  source_type: ImportSource;
  scm_connection_id: string | null;
  scm_connection_name: string;
  status: ImportStatus;
  requested_by: UserRef;
  total_items: number;
  completed_items: number;
  failed_items: number;
  attention_items: number;
  start_scan: boolean;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  /** Only in GET /repository-imports/{id}. */
  items?: ImportItem[];
  can_cancel: boolean;
  can_retry: boolean;
}

/** GET /api/v1/repositories/insights (respects the caller's scope and the same filters as the list). */
export interface RepositoryInsights {
  totals: {
    total: number;
    active: number;
    archived: number;
    critical: number;
    without_business_owner: number;
    without_technical_owner: number;
    production: number;
    confidential_or_restricted: number;
    pending_imports: number;
    failed_imports: number;
    sync_failures: number;
    last_successful_sync_at: string | null;
  };
  by_provider: InsightBucket[];
  by_business_region: InsightBucket[];
  by_business_unit: InsightBucket[];
  by_business_owner: InsightBucket[];
  by_criticality: InsightBucket[];
  by_data_classification: InsightBucket[];
  by_environment: InsightBucket[];
  by_compliance: InsightBucket[];
  by_lifecycle: InsightBucket[];
}

export interface InsightBucket {
  /** id or key; "" = not set */
  key: string;
  label: string;
  count: number;
  /** Optional "#rrggbb" from the classification catalog. */
  color?: string;
}

export interface ImportResult {
  line?: number;
  external_id: string;
  full_name: string;
  status: "imported" | "would_import" | "already_imported" | "error";
  error?: string;
  repository_id?: string;
}

export interface ImportResponse {
  results: ImportResult[];
  imported: number;
  dry_run: boolean;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type JobStatus = "queued" | "running" | "succeeded" | "partial" | "failed" | "cancelled";

export interface ScanResult {
  scanner_key: string;
  scanner_version: string;
  status: "succeeded" | "failed" | "skipped" | "timed_out";
  duration_ms: number;
  findings_count: number;
  error: string;
  has_artifact: boolean;
}

export interface ScanJob {
  id: string;
  repository_id: string;
  repository_name: string;
  profile_name: string;
  profile_version: number;
  trigger: string;
  priority: number;
  status: JobStatus;
  ref: string;
  commit_sha: string;
  attempts: number;
  worker_name: string | null;
  requested_by: string | null;
  error: string;
  findings_new: number;
  findings_fixed: number;
  gate_failed: boolean;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  results?: ScanResult[];
}

export interface Finding {
  id: string;
  repository_id: string;
  repository_name: string;
  category: string;
  scanner_keys: string[];
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string[];
  cve: string;
  cvss: number | null;
  package_name: string;
  package_version: string;
  fixed_version: string;
  file_path: string;
  start_line: number | null;
  status: string;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  assignee_id: string | null;
  assignee_name: string | null;
  sla_due_at: string | null;
  recurrence_count: number;
  accepted_until: string | null;
  ai_status: string;
  snippet?: string;
  snippet_start_line?: number | null;
  occurrences?: { scan_job_id: string; scanner_key: string; commit_sha: string; file_path: string; start_line: number | null; seen_at: string }[];
}

export interface CatalogScanner {
  key: string;
  name: string;
  category: string;
  license_spdx: string;
  decision: "use" | "optional" | "restricted";
  worker_family: string;
  requires_build: boolean;
  mandatory: boolean;
  adapter_available: boolean;
  default_enabled: boolean;
  output_format: string;
  homepage: string;
  notes: string;
}

export interface ProfileSettings {
  severity_threshold: Severity;
  exclusions: string[];
  timeout_seconds: number;
  sbom: boolean;
  fail_on_critical: boolean;
  retention_days: number;
  scanners: { key: string; config?: unknown }[];
}

export interface ProfileVersion extends ProfileSettings {
  id: string;
  version: number;
  change_note: string;
  created_by: string | null;
  created_at: string;
}

export interface ScanProfile {
  id: string;
  name: string;
  description: string;
  is_default: boolean;
  repository_count: number;
  current: ProfileVersion;
  history?: ProfileVersion[];
}

export interface Worker {
  id: string;
  name: string;
  family: string;
  version: string;
  scanners: Record<string, string>;
  last_seen_at: string | null;
  revoked_at: string | null;
  created_at: string;
  online: boolean;
  active_jobs: number;
}

export interface AIProvider {
  id: string;
  name: string;
  kind: "anthropic" | "openai" | "xai" | "self_hosted";
  base_url: string;
  status: "untested" | "ok" | "error";
  status_message: string;
  default_model: string;
  created_at: string;
}

export interface AIConfigVersion {
  id: string;
  version: number;
  provider_id: string;
  model: string;
  effort: "low" | "medium" | "high";
  instructions: string;
  auto_review: boolean;
  categories: string[];
  min_severity: Severity;
  approval_policy: "always" | "false_positives" | "never";
  allow_self_approval: boolean;
  daily_limit: number;
  send_code_context: boolean;
  redaction_patterns: string[];
  change_note: string;
  created_at: string;
}

export interface AIConfiguration {
  id: string;
  name: string;
  is_default: boolean;
  current: AIConfigVersion;
  used_today: number;
}

export interface AIReview {
  id: string;
  finding_id: string;
  finding_title: string;
  finding_severity: Severity;
  finding_status: string;
  repository_name: string;
  source: "automated" | "interactive_mcp";
  provider: string;
  model: string;
  verdict: "true_positive" | "false_positive" | "needs_review";
  confidence: number;
  suggested_severity: Severity;
  rationale: string;
  remediation: string;
  evidence_cited: string[];
  status: "pending_approval" | "applied" | "rejected" | "superseded";
  reviewed_by: string | null;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string;
  transmitted_sha256: string;
  created_at: string;
}

export interface ApiToken {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  expires_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface McpServer {
  id: string;
  name: string;
  description: string;
  transport: "stdio" | "streamable_http";
  endpoint: string;
  status: "pending" | "approved" | "rejected" | "disabled";
  data_access: "none" | "findings_redacted" | "findings_full";
  built_in: boolean;
  requested_by: string | null;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string;
  tools: { tool: string; access: "read" | "write"; allowed: boolean }[];
  created_at: string;
}

export interface HistoryEntry {
  from_status: string | null;
  to_status: string;
  actor: string | null;
  source: string;
  reason: string;
  created_at: string;
}

export interface RiskAcceptance {
  id: string;
  finding_id: string;
  finding_title: string;
  finding_severity: Severity;
  repository_name: string;
  requested_by: string;
  justification: string;
  expires_at: string;
  status: "pending" | "approved" | "rejected" | "expired" | "revoked" | "withdrawn";
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string;
  created_at: string;
}

export interface ComponentGroup {
  name: string;
  version: string;
  purl: string;
  type: string;
  licenses: string[];
  license_policy: "" | "deny" | "review";
  repositories: string[];
  open_vulnerabilities: number;
}

// Phase 7: scheduling and notifications

export type ScheduleTarget = "organization" | "region" | "business_unit" | "repository" | "profile";

export interface Schedule {
  id: string;
  name: string;
  enabled: boolean;
  cron: string;
  timezone: string;
  target_type: ScheduleTarget;
  target_id: string | null;
  target_name: string;
  priority: number;
  next_run_at: string | null;
  last_run_at: string | null;
  last_status: string;
  last_queued: number;
  missed_runs: number;
  created_at: string;
  can_manage: boolean;
}

export interface SchedulerStatus {
  leader: string;
  heartbeat_at: string | null;
  healthy: boolean;
  workers_online: number;
  workers_offline: number;
  queued: number;
  running: number;
  oldest_queued_at: string | null;
  schedules: number;
  missed_runs: number;
}

export interface NotificationEvent {
  key: string;
  label: string;
  description: string;
  severity: boolean;
  repository: boolean;
  dynamic: string[];
  default_subject: string;
  default_body: string;
}

export interface NotificationRule {
  id: string;
  name: string;
  enabled: boolean;
  event_key: string;
  min_severity: Severity | null;
  scope_type: "organization" | "region" | "business_unit" | "repository";
  scope_id: string | null;
  scope_name: string;
  recipients: { roles: string[]; users: string[]; emails: string[]; dynamic: string[] };
  email: boolean;
  in_app: boolean;
  system: boolean;
  updated_at: string;
}

export interface SmtpSettings {
  enabled: boolean;
  host: string;
  port: number;
  tls_mode: "starttls" | "tls" | "none";
  username: string;
  has_password: boolean;
  from_address: string;
  from_name: string;
  updated_at: string | null;
}

export interface NotificationTemplate {
  event_key: string;
  label: string;
  subject: string;
  body: string;
  default_subject: string;
  default_body: string;
  customized: boolean;
}

export interface Delivery {
  id: string;
  event_key: string;
  channel: "email" | "in_app";
  recipient: string;
  subject: string;
  body?: string;
  link: string;
  status: "pending" | "sent" | "failed" | "suppressed";
  attempts: number;
  last_error: string;
  rule_name: string | null;
  sent_at: string | null;
  read_at: string | null;
  created_at: string;
}

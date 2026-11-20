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

/** "git": imported anonymously by URL (public repository, no SCM connection). */
export type SourceType = "scm" | "upload" | "git";
export type SyncStatus = "never" | "ok" | "failed" | "missing" | "permission_denied" | "archived_upstream";

export interface Repository {
  id: string;
  /** null for uploaded repositories (source_type "upload"). */
  scm_connection_id: string | null;
  scm_connection_name: string;
  /** Connection provider, or "upload". */
  provider: string;
  source_type: SourceType;
  /** Imported anonymously by URL (public, read-only, no token). */
  anonymous?: boolean;
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

  /** Permanent, unique, human-readable Repository ID (e.g. "QD-REPO-000042"); never editable. */
  repository_key: string;
  staging_url: string;
  production_url: string;
  public_exposure: PublicExposure;
  public_urls: string[];
  public_domains: string[];
  public_ips: string[];
  exposure_notes: string;
  /** User who registered the repository. */
  registered_by: UserRef | null;
  updated_at: string;
  last_scan_status: JobStatus | null;
  last_scan_at: string | null;
}

/** "Is this application or asset publicly exposed to the internet?" (mandatory). */
export type PublicExposure = "yes" | "no" | "unknown";

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
  /** Absolute http(s) URLs, "" = not applicable. Normalized by the server. Never fetched. */
  staging_url?: string;
  production_url?: string;
  /** Mandatory. "yes" requires at least one public URL, domain or IP; "no" allows none. */
  public_exposure?: PublicExposure;
  public_urls?: string[];
  /** Domain names; "*.example.com" allowed. */
  public_domains?: string[];
  /** Public IPv4/IPv6 addresses (private, loopback and link-local are rejected). */
  public_ips?: string[];
  exposure_notes?: string;
}

/** Field keys usable in AssetSettings.required_fields. */
export type AssetField =
  | "description" | "application" | "application_type" | "business_purpose"
  | "business_owner" | "technical_owner" | "application_owner" | "business_unit" | "department"
  | "responsible_team" | "supporting_team" | "cost_centre"
  | "business_region" | "country" | "hosting_region" | "data_residency_region" | "operational_location"
  | "criticality" | "data_classification" | "environment" | "internet_exposure" | "compliance_scopes"
  | "tags" | "lifecycle_status" | "staging_url" | "production_url" | "public_exposure";

export type ClassificationKind =
  | "criticality" | "data_classification" | "environment" | "application_type"
  | "internet_exposure" | "compliance" | "hosting_region" | "lifecycle_status" | "authentication_model";

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
  /** Prefix for newly generated Repository IDs (PATCH-able with assets.configure); existing IDs never change. */
  repository_key_prefix: string;
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
  /** Permanent application ID, e.g. QD-APP-000042. */
  application_key: string;
  name: string;
  description: string;
  business_unit: Ref | null;
  owner: UserRef | null;
  security_owner: UserRef | null;
  technical_owner: UserRef | null;
  lifecycle: "planned" | "development" | "active" | "maintenance" | "deprecated" | "retired";
  environment: "production" | "staging" | "development" | "test" | "other";
  criticality: Criticality;
  /** Organization's application identifier (e.g. CMDB ID); "" when not set. */
  external_ref: string;
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
  /** Connectors feature: whether a private CA bundle is set (the PEM is never returned). */
  has_ca_bundle?: boolean;
  /** Connectors feature: the CA bundle's certificates. */
  ca_certificates?: CACertificate[];
}

/** One certificate of a connection's private CA bundle. */
export interface CACertificate {
  subject: string;
  issuer: string;
  not_after: string;
  sha256_fingerprint: string;
  is_ca: boolean;
  expired: boolean;
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
    publicly_exposed: number;
    not_public: number;
    exposure_unknown: number;
    missing_production_url: number;
    /** Active repositories without a business or a technical owner. */
    missing_ownership: number;
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
  by_public_exposure: InsightBucket[];
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
  /** Permanent Repository ID, e.g. QD-REPO-000042. */
  repository_key: string;
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

  /** Permanent Scan ID, e.g. QD-SCAN-000042 (unique, never reused). */
  scan_key: string;
  name: string;
  /** repository, or the kind of scan target the execution scanned. */
  asset_type: "repository" | "image" | "url" | "api" | "sbom" | "artifact" | "endpoints" | "mobile-app" | "llm-endpoint";
  target_id?: string | null;
  target_name?: string | null;
  target_reference?: string | null;
  profile_id: string;
  /** 0-100, derived from recorded stages (lease, source checkout, finished engine jobs, finalization). */
  progress: number;
  /** queued | starting | fetching_source | scanning | scanning:<scanner> | finalizing | finished */
  stage: string;
  /** The failed execution this one retries. */
  retry_of: string | null;
  retry_count: number;
  schedule_id: string | null;
  schedule_run_id: string | null;
  snapshot_id: string | null;
  duration_ms: number | null;
  /** Distinct findings observed by this execution. */
  findings_total: number;
  severity: Record<"critical" | "high" | "medium" | "low" | "info", number>;
  /** Immutable effective configuration (only on GET /scans/{id}). */
  config_snapshot?: ScanConfigSnapshot;
  /** Push and merge scans: new and fixed findings since the previous scanned commit. */
  change_summary?: ScanChangeSummary | null;
}

export interface ScanChangeSummary {
  base_commit: string;
  base_scan_id: string | null;
  head_commit: string;
  new: Partial<Record<Severity, number>>;
  fixed: Partial<Record<Severity, number>>;
  new_total: number;
  fixed_total: number;
}

/** Read-only snapshot of the profile version used by an execution. */
export interface ScanConfigSnapshot {
  profile_id: string;
  profile_name: string;
  profile_version_id: string;
  profile_version: number;
  change_note: string;
  severity_threshold: string;
  exclusions: string[];
  timeout_seconds: number;
  sbom: boolean;
  fail_on_critical: boolean;
  retention_days: number;
  scanners: { key: string; config?: unknown }[];
  captured_at: string;
}

/** POST /api/v1/scans → 202 { items: StartScanItem[] } */
export interface StartScanRequest {
  repository_ids: string[];
  /** An existing scan profile (managed in Configurations); omit for each repository's own profile. */
  profile_id?: string;
  name?: string;
  trigger?: "manual" | "emergency" | "onboarding";
}
export interface StartScanItem {
  repository_id: string;
  job_id?: string;
  coalesced?: boolean;
  error?: string;
}

/**
 * GET /api/v1/scans query: q (scan/repository name or key), scan_key, repository_key, repository_id,
 * profile_id, schedule_id, trigger, scanner, status (queued|running|succeeded|partial|failed|cancelled|active),
 * asset_type=repository, from, to (YYYY-MM-DD or RFC 3339), cursor. Page size 50.
 * POST /api/v1/scans/{id}/retry → 202 ScanJob (new execution, retry_of set); only failed/partial/cancelled.
 * POST /api/v1/scans/{id}/cancel → ScanJob (queued or running).
 */

/** GET /api/v1/scans/{id}/stages */
export interface ScanStage {
  key: string; // queued | source | scanner:<key> | finalize
  label: string;
  scanner: string;
  scanner_version: string;
  status: "pending" | "running" | "succeeded" | "failed" | "skipped" | "timed_out" | "cancelled";
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  findings: number | null;
  error: string;
  /** Kind of check of a scanner stage (the UI names kinds, not engines). */
  kind_of_check?: string;
  kind_of_check_name?: string;
}
/** Progress of one kind of check in a scan ("Infrastructure as code: 7 of 10 checks finished"). */
export interface ScanKindProgress {
  id: string;
  name: string;
  total: number;
  finished: number;
  failed: number;
  running: number;
}
export interface ScanEvent {
  stage: string;
  scanner: string;
  status: string;
  message: string;
  at: string;
}

/** GET /api/v1/scans/{id}/logs?source=&level=debug|info|warn|error&after_id= → { items, sources, next_after_id } */
export interface ScanLogLine {
  id: number;
  at: string;
  level: "debug" | "info" | "warn" | "error";
  /** "worker", "platform" or a scanner key. */
  source: string;
  message: string;
}

/** GET /api/v1/scans/{id}/findings?severity=&scanner= → { items } (findings.read on the repository). */
export interface ScanFinding extends Finding {
  scanner: string;
  /** file:line or package@version */
  evidence: string;
  occurrence_commit_sha: string;
  /** First seen in this execution. */
  is_new: boolean;
}

/** GET /api/v1/scans/{id}/history → { items: ScanJob[] } same repository, last 360 days. */

/** GET /api/v1/scans/overview?days=1..360 (default 30) */
export interface ScanOverview {
  days: number;
  scans: { total: number; running: number; queued: number; completed: number; failed: number; cancelled: number };
  open_findings: Record<"critical" | "high" | "medium" | "low" | "info", number>;
  open_findings_total: number;
  critical_high: number;
  recent: ScanJob[];
  trend: { day: string; completed: number; failed: number; cancelled: number; new_findings: number }[];
  upcoming: { schedule_id: string; name: string; next_run_at: string; kind: ScheduleKind }[];
}

/** GET /api/v1/scans/compare?ids=a,b[,c…] (2-10, scans.compare) — chronological; each compared with the previous. */
export interface ScanComparison {
  scans: (ScanJob & {
    scanners: ScanResult[];
    succeeded_scanners: string[];
    complete: boolean;
    new: number;
    fixed: number;
    recurring: number;
    unchanged: number;
    /** Absent now, but this execution failed or its covering scanner did not succeed: not counted as fixed. */
    not_covered: number;
    profile_changed: boolean;
    engine_changes: string[];
    duration_delta_ms: number | null;
  })[];
  findings: {
    id: string;
    title: string;
    severity: Severity;
    scanners: string[];
    /** scan id → present (first scan) | new | recurring | unchanged | fixed | not_covered | absent */
    states: Record<string, string>;
  }[];
}

export interface Finding {
  id: string;
  repository_id: string;
  repository_name: string;
  /** Permanent Repository ID, e.g. QD-REPO-000042. */
  repository_key: string;
  category: string;
  /** Engines that reported the finding: kept for audit; the UI shows kind_of_check and engines_count (rule 3). */
  scanner_keys: string[];
  /** Kind of check (one of the 20 kinds, or ai / manual / other). */
  kind_of_check?: string;
  kind_of_check_name?: string;
  /** Distinct engines that confirmed the finding after de-duplication. */
  engines_count?: number;
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
  /** Human Eye outcome (the scanner data above is unchanged by it). */
  human_review_id?: string | null;
  human_review_key?: string | null;
  human_review_status?: string | null;
  human_disposition?: string | null;
  human_severity?: Severity | null;
  /** Unified lifecycle status, derived from the stored status. */
  lifecycle_status?: LifecycleStatus;
  cvss_version?: string;
  cvss_vector?: string;
  confidence?: "high" | "medium" | "low" | "unknown";
  epss?: number | null;
  epss_percentile?: number | null;
  kev?: boolean;
  kev_due_date?: string | null;
  exploit_available?: boolean;
  /** A known malicious package (OSV MAL- advisory or malware report). */
  malicious?: boolean;
  /** Commit of the scan that first detected the finding. */
  introduced_commit?: string;
  /**
   * The commit that introduced the code (git blame of the scanned commit):
   * known, shallow_clone (unknown: the repository is cloned without
   * history), not_found (the line is not in the scanned commit) or "".
   */
  introduced_status?: "" | "known" | "shallow_clone" | "not_found";
  introduced_commit_sha?: string;
  /** Author name (e-mail addresses are not stored). */
  introduced_author?: string;
  introduced_at?: string | null;
  reachability?: "reachable" | "not_reachable" | "unknown";
  /** Why: e.g. "a dependency of express, which the code uses". */
  reachability_basis?: string;
  /**
   * How reachability was decided: import (package level), call_graph
   * (govulncheck) or symbol_calls (pathos-reach), "" when not analysed.
   */
  reachability_method?: ReachabilityMethod;
  /** Evidence of a function-level answer (finding detail only). */
  reachability_evidence?: ReachabilityEvidence | null;
  /** The approved suppression rule that decided the status. */
  suppression_rule_id?: string | null;
  /** Contextual risk score 0-100 (null until scored). */
  risk_score?: number | null;
  application_id?: string | null;
  application_name?: string | null;
  /** Scan target (container image, web application, API, SBOM); null for the repository's code. */
  scan_target_id?: string | null;
  scan_target_kind?: "image" | "url" | "api" | "sbom" | "artifact" | "endpoints" | "mobile-app" | "llm-endpoint" | null;
  scan_target_name?: string | null;
  /** Runtime context: "" (unknown), deployed or not_deployed. */
  runtime_status?: "" | "deployed" | "not_deployed";
  runtime_exposed?: boolean;
  snippet?: string;
  snippet_start_line?: number | null;
  occurrences?: { scan_job_id: string; scanner_key: string; commit_sha: string; file_path: string; start_line: number | null; seen_at: string }[];
  /** Live secret validation verdict (secret findings only). */
  secret_validation?: SecretValidation;
}

export type SecretValidationStatus = "active" | "inactive" | "error" | "not_checked";

/** Whether a detected secret is still active, checked by a worker against its provider. Never contains the secret. */
export interface SecretValidation {
  status: SecretValidationStatus;
  provider: string;
  provider_name: string;
  /** Non-secret identity of an active credential (account ID, user name). */
  identity: string;
  checked_at: string | null;
  evidence: {
    status?: SecretValidationStatus;
    endpoint?: string;
    http_status?: number;
    detail?: string;
    checked_at?: string;
    scan_job_id?: string;
    worker?: string;
    severity_raised_from?: Severity;
    severity_restored_to?: Severity;
    recheck_job_id?: string;
    recheck_requested_at?: string;
    last_attempt?: { status: SecretValidationStatus; detail?: string; endpoint?: string; http_status?: number; checked_at?: string };
  } | null;
}

export interface SecretProviderSetting {
  id: string;
  name: string;
  hosts: string[] | null;
  endpoint: string;
  checkable: boolean;
  note?: string;
  enabled: boolean;
}

export interface SecretValidationSettings {
  providers: SecretProviderSetting[];
  rate_per_second: number;
  max_checks_per_scan: number;
  updated_at: string | null;
  can_manage: boolean;
  offline: boolean;
}

export type ReachabilityMethod = "" | "import" | "call_graph" | "symbol_calls";

/** One step of a call path: a call at file:line inside function. */
export interface ReachFrame {
  file: string;
  line: number;
  function: string;
}

export interface ReachabilityEvidence {
  tool: "pathos-reach" | "govulncheck";
  scan_job_id?: string;
  analysed_at?: string;
  /** The vulnerable functions checked, as the advisory names them. */
  symbols: string[];
  /** Call chains, outermost caller first, ending at the vulnerable call. */
  paths: ReachFrame[][];
  /** Calls of a vulnerable method's name on values of unknown type. */
  unresolved?: ReachFrame[];
  /** Constructs the analysis cannot follow (module "" = any module). */
  dynamic?: { ecosystem: string; module: string; reason: string; file: string; line: number; test: boolean }[];
  /** What the method does not see. */
  limits: string;
}

export type LifecycleStatus = "new" | "open" | "in_progress" | "under_review" | "confirmed" | "false_positive" | "accepted_risk" | "resolved" | "reopened";

export interface RiskFactor {
  key: string;
  label: string;
  value: string;
  weight: number;
  /** Evidence of runtime factors (cluster, namespace, workload, ingress host, alert). */
  evidence?: string[];
}

export interface FindingRisk {
  risk_score: number | null;
  band: "critical" | "high" | "medium" | "low" | "none" | "";
  explanation: { score: number; base: number; factors: RiskFactor[]; reason?: string; model_version: number } | null;
  scored_at: string | null;
  pending: boolean;
  cve: string;
  epss: number | null;
  epss_percentile: number | null;
  kev: boolean;
  kev_due_date: string | null;
  confidence: string;
  reachability: string;
  reachability_method?: ReachabilityMethod;
  cvss_version: string;
  cvss_vector: string;
}

export interface RiskWeights {
  severity: Record<string, number>;
  use_cvss: boolean;
  kev: number;
  exploit_available: number;
  epss_weight: number;
  likelihood_unknown: number;
  criticality: Record<string, number>;
  exposure: Record<string, number>;
  reachability: Record<string, number>;
  /** Replaces reachability when the answer is function level. */
  function_reachability?: Record<string, number>;
  confidence: Record<string, number>;
  human_confirmed: number;
  compensating_controls: number;
  fix_available: number;
  /** Runtime context (Kubernetes inventory). */
  deployment: Record<string, number>;
  runtime_exposed: number;
  privileged_workload: number;
  runtime_alert: number;
}

export interface RiskModel {
  version: number;
  weights: RiskWeights;
  change_note: string;
  created_by: string | null;
  created_at: string;
  is_default: boolean;
}

export interface FeedRun {
  id: string;
  feed: string;
  mode: "online" | "file";
  status: "running" | "succeeded" | "failed";
  records: number;
  as_of: string;
  error: string;
  started_at: string;
  finished_at: string | null;
}

export interface IntelFeed {
  feed: "epss" | "kev" | "osv" | "depsdev";
  label: string;
  enabled: boolean;
  url: string;
  interval_hours: number;
  records: number;
  last_run: FeedRun | null;
  last_success: FeedRun | null;
  next_due: string | null;
  updated_at: string;
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
  /** Runs for scan targets (images, URLs, APIs), not in repository profiles. */
  target_only?: boolean;
  default_enabled: boolean;
  output_format: string;
  homepage: string;
  notes: string;
  /** What the tool contacts while it runs: none, target (the scan target) or registry. */
  network?: "none" | "target" | "registry";
  /** Sends attack traffic: needs the target's "intrusive testing authorized" flag. */
  intrusive?: boolean;
  /** Scan types the tool covers (GET /api/v1/scan-types). */
  scan_types?: string[];
  /** An online worker advertises the tool. */
  runnable?: boolean;
  /** What the tool scans: repository, image, url, api, mobile-app, binary, model. */
  targets?: string[];
}

/** A tool of a scan type (GET /api/v1/scan-types). */
export interface ScanTypeTool {
  key: string;
  name: string;
  category: string;
  license_spdx: string;
  /** catalog, plugin (operator plugin advertised by a worker) or server (evaluated by PATHOS). */
  source: "catalog" | "plugin" | "server";
  adapter_available: boolean;
  runnable: boolean;
  workers: number;
  network: string;
  intrusive: boolean;
  targets: string[];
  decision: string;
}

export interface ScanTypeFormat {
  id: string;
  label: string;
  tool: string;
}

/** One of the 25 scan types with what this deployment provides. */
export interface ScanTypeCoverage {
  id: string;
  name: string;
  /** The kind of check the scan type is grouped under. */
  kind_of_check?: string;
  description: string;
  categories: string[];
  note?: string;
  tools: ScanTypeTool[];
  import_formats: ScanTypeFormat[];
  runnable_tools: number;
  runnable: boolean;
  importable: boolean;
}

export interface ScanTypesResponse {
  items: ScanTypeCoverage[];
  generic_import_formats: ScanTypeFormat[];
  workers_online: number;
  kinds?: KindCoverage[];
}

/** One §7 tool of a kind of check (Configurations pages only: tool names, rule 3). */
export interface KindTool {
  name: string;
  key?: string;
  source: "catalog" | "feed" | "pathos" | "gap";
  mode?: string;
  after_v2?: boolean;
  runnable: boolean;
}

/** A kind of check of the build prompt's §7 table and what the deployment provides. */
export interface KindCoverage {
  id: string;
  name: string;
  phase: number;
  after_v2: boolean;
  outside_kinds: boolean;
  scan_types: string[];
  tools: KindTool[];
  extra_tools: string[];
  catalogued: number;
  runnable: number;
  gaps: number;
}

/** A kind of check as a scan profile covers it (GET /api/v1/scan-profiles/{id}/kinds). */
export interface ProfileKind {
  id: string;
  name: string;
  phase: number;
  after_v2: boolean;
  outside_kinds: boolean;
  tools_target: number;
  listed: number;
  selected: { key: string; name: string; listed: boolean; runnable: boolean }[];
  runnable: number;
  available: number;
  repository_scope: boolean;
  lacks_runnable: boolean;
}

export interface ProfileSettings {
  severity_threshold: Severity;
  exclusions: string[];
  /** Drop secret findings in vendored code, test fixtures, lockfiles and minified files (default on). */
  secret_default_exclusions?: boolean;
  /** Further globs whose secret findings are dropped. */
  secret_exclusions?: string[];
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
  /** Seeded tier (quick, standard, comprehensive); null for Default and custom profiles. */
  template?: "quick" | "standard" | "comprehensive" | null;
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

export type ScheduleKind = "cron" | "once" | "interval";

/** One execution-plan row: assets (organization / region / business unit / repository) × an existing profile. */
export interface SchedulePlanEntry {
  id?: string;
  target_type: "organization" | "region" | "business_unit" | "repository";
  target_id: string | null;
  target_name?: string;
  /** null = each repository's own (or the default) profile */
  profile_id: string | null;
  profile_name?: string;
}

/** POST /api/v1/schedules, PUT /api/v1/schedules/{id}; POST /api/v1/schedules/preview takes the same body. */
export interface ScheduleRequest {
  name: string;
  enabled?: boolean;
  kind: ScheduleKind;
  /** kind cron (daily/weekly/monthly presets are cron expressions); at most once per hour */
  cron?: string;
  /** kind once: when; kind interval: optional first run */
  run_at?: string | null;
  /** kind interval: 60..525600 */
  interval_minutes?: number | null;
  timezone: string;
  /** Approved scan window "HH:MM" in the schedule's time zone (both or neither); start > end spans midnight. */
  window_start?: string;
  window_end?: string;
  /** 0 = Sunday … 6 = Saturday; empty = every day */
  window_days?: number[];
  retry_max?: number; // 0..5
  retry_delay_minutes?: number; // 5..1440
  /** Maximum queued+running executions from this schedule; 0 = unlimited */
  max_concurrent?: number;
  notify_on?: ("completed" | "failed")[];
  priority?: number; // 0..90
  plan: SchedulePlanEntry[];
}

/** POST /api/v1/schedules/preview → next runs and the number of executions per activation. */
export interface SchedulePreview {
  next_runs: string[];
  repositories: number;
  executions: number;
  window: string;
}

/** GET /api/v1/schedules/{id}/runs → { items } */
export interface ScheduleRun {
  id: string;
  due_at: string;
  trigger: "schedule" | "manual" | "catch_up";
  status: "running" | "waiting" | "completed" | "partial" | "failed";
  queued: number;
  skipped: number;
  failed: number;
  pending: number;
  message: string;
  started_at: string;
  finished_at: string | null;
  /** execution status → count */
  jobs: Record<string, number>;
}

/** POST /api/v1/schedules/{id}/pause and /resume → Schedule; POST /run → RunResult. GET /schedules/{id} → Schedule. */
export interface Schedule {
  id: string;
  name: string;
  /** false = paused */
  enabled: boolean;
  kind: ScheduleKind;
  run_at: string | null;
  interval_minutes: number | null;
  window_start: string;
  window_end: string;
  window_days: number[];
  retry_max: number;
  retry_delay_minutes: number;
  max_concurrent: number;
  notify_on: ("completed" | "failed")[];
  plan: SchedulePlanEntry[];
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

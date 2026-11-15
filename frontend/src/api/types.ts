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
export type Environment = "production" | "staging" | "development" | "test" | "other";
export type TagColor = "slate" | "blue" | "green" | "amber" | "red" | "purple" | "teal" | "pink";

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

export interface Repository {
  id: string;
  scm_connection_id: string;
  scm_connection_name: string;
  provider: string;
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
  repository_count: number;
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

export type Provider = "github" | "github_enterprise" | "azure_devops" | "azure_devops_server";

export interface ScmConnection {
  id: string;
  name: string;
  provider: Provider;
  base_url: string;
  auth_type: "pat" | "github_app";
  owner: string;
  github_app_id: number | null;
  github_installation_id: number | null;
  status: "untested" | "ok" | "error";
  status_message: string;
  last_checked_at: string | null;
  webhook_url: string;
  repository_count: number;
  created_at: string;
}

export interface DiscoveredRepo {
  external_id: string;
  full_name: string;
  name: string;
  url: string;
  default_branch: string;
  visibility: string;
  description: string;
  language: string;
  archived: boolean;
  pushed_at: string | null;
  imported_id: string | null;
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
  kind: "anthropic" | "openai" | "xai";
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

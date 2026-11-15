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

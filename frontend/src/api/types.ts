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
  type: "user" | "business_unit" | "region" | "country";
  id: string;
  title: string;
  subtitle: string;
  href: string;
}

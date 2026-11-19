// Shapes of the PATHOS REST API objects used by the extension. Only the
// fields the extension reads are declared; the API returns more.
// See docs/api-reference/findings.md and docs/api-reference/repositories.md.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Repository {
  id: string;
  full_name: string;
  name?: string;
  display_name?: string | null;
  repository_key?: string;
  provider?: string;
  source_type?: string;
  /** Web URL of the repository at its provider, for example https://github.com/org/repo. */
  url?: string | null;
}

export interface Finding {
  id: string;
  repository_id: string;
  repository_name?: string;
  repository_key?: string;
  category?: string;
  scanner_keys?: string[] | null;
  rule_id?: string;
  title: string;
  description?: string;
  severity: Severity | string;
  cwe?: string[] | null;
  cve?: string;
  cvss?: number | null;
  package_name?: string;
  package_version?: string;
  fixed_version?: string;
  file_path?: string;
  start_line?: number | null;
  status: string;
  lifecycle_status?: string;
  first_seen_at?: string;
  last_seen_at?: string;
  assignee_name?: string | null;
  sla_due_at?: string | null;
  human_review_key?: string | null;
  human_review_status?: string | null;
  human_disposition?: string | null;
  risk_score?: number | null;
  confidence?: string;
  epss_percentile?: number | null;
  kev?: boolean;
  reachability?: string;
  scan_target_kind?: string | null;
  scan_target_name?: string | null;
  /** Only on GET /api/v1/findings/{id}. */
  snippet?: string;
  snippet_start_line?: number | null;
}

/** Stored statuses a finding can be changed to manually (docs: "Change the status"). */
export type FindingStatus = "open" | "in_progress" | "needs_review" | "false_positive" | "fixed";

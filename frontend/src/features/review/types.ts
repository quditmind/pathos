// Human Eye module contract (backend/internal/review).
import type { Severity } from "@/api/types";

export type ReviewStatus =
  | "pending"
  | "assigned"
  | "in_progress"
  | "awaiting_information"
  | "awaiting_independent_review"
  | "completed"
  | "reopened";

export type Disposition =
  | "confirmed"
  | "false_positive"
  | "duplicate"
  | "not_exploitable"
  | "accepted_risk"
  | "mitigated"
  | "needs_more_information"
  | "out_of_scope";

export type RemediationStatus = "not_required" | "open" | "in_progress" | "fixed" | "pending_verification" | "verified" | "reopened";
export type Priority = "p1" | "p2" | "p3" | "p4";
export type Answer = "yes" | "no" | "unknown" | "not_applicable";

export interface ReviewItem {
  id: string;
  review_key: string;
  finding_id: string;
  title: string;
  category: string;
  rule_id: string;
  /** Scanner severity (preserved). */
  severity: Severity;
  assessed_severity: Severity | null;
  scanner: string;
  repository_id: string;
  repository_name: string;
  repository_key: string;
  application_id: string | null;
  application_name: string | null;
  branch: string;
  commit_sha: string;
  file_path: string;
  start_line: number | null;
  detected_at: string;
  reviewer_id: string | null;
  reviewer_name: string | null;
  independent_reviewer_id: string | null;
  independent_reviewer_name: string | null;
  priority: Priority;
  status: ReviewStatus;
  disposition: Disposition | null;
  remediation_status: RemediationStatus | null;
  due_at: string | null;
  overdue: boolean;
  source: "automatic" | "manual";
  round: number;
  finding_status: string;
  created_at: string;
  completed_at: string | null;
  updated_at: string;
}

export interface ReviewPage {
  items: ReviewItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface Field {
  key: string;
  label: string;
  options?: string[];
}

export interface Catalog {
  statuses: ReviewStatus[];
  dispositions: Disposition[];
  remediation_statuses: RemediationStatus[];
  priorities: Priority[];
  answers: Answer[];
  questions: { key: string; label: string }[];
  assessment_fields: Field[];
  reproduction_fields: Field[];
  risk_fields: Field[];
  remediation_fields: Field[];
  evidence_types: string[];
  evidence_classifications: string[];
  ai_kinds: string[];
}

export interface Assessment {
  round: number;
  answers: Record<string, string>;
  fields: Record<string, string>;
  reproduction: Record<string, string>;
  risk: Record<string, string>;
  remediation: Record<string, string>;
  dataflow_notes: Record<string, string>;
  updated_by: string | null;
  updated_at: string | null;
}

export interface Approval {
  id: string;
  reviewer_id: string;
  reviewer_name: string;
  outcome: "approved" | "rejected" | "information_requested";
  comments: string;
  created_at: string;
  /** 1: independent reviewer, 2: final approver. */
  level?: number;
}

export interface Decision {
  id: string;
  round: number;
  disposition: Disposition;
  reason: string;
  duplicate_of: string | null;
  duplicate_of_title: string | null;
  risk_owner_id: string | null;
  risk_owner_name: string | null;
  risk_expires_at: string | null;
  assessed_severity: Severity | null;
  requires_independent: boolean;
  outcome: "final" | "pending_approval" | "open";
  decided_by: string;
  decided_by_name: string;
  created_at: string;
  approvals: Approval[];
}

export interface Capabilities {
  assess: boolean;
  start: boolean;
  assign: boolean;
  approve: boolean;
  /** The independent reviewer approved; a final approval by a third person is awaited. */
  final_approval?: boolean;
  comment: boolean;
  reopen: boolean;
  remediate: boolean;
  upload_files: boolean;
  ai: boolean;
  ai_unavailable_reason?: string;
  accept_risk: boolean;
  source_viewer: boolean;
}

export interface ReviewDetail extends ReviewItem {
  finding: {
    id: string;
    title: string;
    description: string;
    category: string;
    rule_id: string;
    scanner_keys: string[];
    severity: Severity;
    cvss: number | null;
    cwe: string[];
    cve: string;
    owasp: string[];
    package_name: string;
    package_version: string;
    fixed_version: string;
    file_path: string;
    start_line: number | null;
    end_line: number | null;
    snippet: string;
    snippet_start_line: number | null;
    status: string;
    ai_status: string;
    first_seen_at: string;
    last_seen_at: string;
    sla_due_at: string | null;
    assignee_name: string | null;
  };
  default_branch: string;
  source_type: "scm" | "upload";
  scan_job_id: string | null;
  scan_key: string | null;
  source_reason: string;
  created_by_name: string | null;
  original: {
    severity: Severity;
    cvss: number | null;
    cvss_vector: string;
    output: unknown;
    rule: unknown;
    captured_at: string | null;
    capture_error: string;
  };
  assessment: Assessment;
  assessed_cvss: number | null;
  assessed_cvss_vector: string;
  severity_justification: string;
  remediation_owner_id: string | null;
  remediation_owner_name: string | null;
  remediation_due_at: string | null;
  remediation_priority: Priority | null;
  remediation_link: string;
  risk_acceptance_id: string | null;
  started_at: string | null;
  submitted_at: string | null;
  ai_review: {
    id: string;
    verdict: string;
    confidence: number;
    suggested_severity: string;
    rationale: string;
    remediation: string;
    status: string;
    source: string;
    model: string;
    created_at: string;
  } | null;
  triage: { status: string; source: string | null; reason: string | null; changed_at: string | null };
  decisions: Decision[];
  evidence_count: number;
  requires_independent_review: boolean;
  required_fields: string[];
  evidence_required_for: boolean;
  evidence_required_dispositions: Disposition[];
  can: Capabilities;
}

export interface SourceView {
  available: boolean;
  unavailable_code?: string;
  unavailable_message?: string;
  origin: "scm" | "snapshot" | "";
  repository_id: string;
  repository: string;
  branch: string;
  commit_sha: string;
  snapshot_id?: string | null;
  scanned: boolean;
  path: string;
  language: string;
  lines: string[];
  focus_line: number | null;
  truncated: boolean;
  redacted: boolean;
  scanner_context?: string;
  scanner_context_start?: number | null;
}

export interface CommitRef {
  sha: string;
  label: string;
  message?: string;
  author?: string;
  committed_at?: string | null;
  scan_job_id?: string | null;
  scan_key?: string;
}

export interface SourceCommits {
  scanned: CommitRef;
  occurrences: CommitRef[];
  history: CommitRef[];
  head: CommitRef | null;
  history_unavailable: string;
}

export interface FlowStep {
  file_path: string;
  line?: number;
  column?: number;
  message?: string;
  snippet?: string;
  kinds?: string[];
  function?: string;
}

export interface FlowNode extends FlowStep {
  role: "source" | "intermediate" | "sink" | "related";
}

export interface DataFlow {
  status: "confirmed" | "incomplete" | "inferred" | "unavailable";
  reason: string;
  scanner: string;
  paths: { message?: string; status: "confirmed" | "incomplete"; nodes: FlowNode[] }[];
  related: FlowNode[];
  notes: Record<string, string>;
  sink: FlowStep | null;
}

export interface Evidence {
  id: string;
  evidence_key: string;
  finding_id: string;
  round: number;
  evidence_type: string;
  classification: string;
  description: string;
  comments: string;
  file_name: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  is_file: boolean;
  text?: string | null;
  uploaded_by: string;
  uploaded_by_name: string;
  created_at: string;
  deleted_at: string | null;
  deleted_by_name: string | null;
  delete_reason: string;
}

export interface Comment {
  id: string;
  author_id: string;
  author_name: string;
  kind: "comment" | "assignment" | "independent" | "information_request";
  body: string;
  created_at: string;
}

export interface HistoryEntry {
  id: string;
  round: number;
  actor_id: string | null;
  actor: string | null;
  action: string;
  field: string;
  old_value: unknown;
  new_value: unknown;
  note: string;
  review_id: string;
  finding_id: string;
  created_at: string;
}

export interface Recommendation {
  id: string;
  kind: string;
  provider: string;
  model: string;
  content: { summary: string; points: string[]; references: string[]; code: string };
  transmitted_sha256: string;
  requested_by: string;
  requested_by_name: string;
  created_at: string;
  label: string;
  /** Patch proposals: a person approves or rejects them; never applied automatically. */
  patch_status?: "proposed" | "approved" | "rejected";
  patch_decided_by?: string;
  patch_decided_at?: string;
  patch_note?: string;
}

export interface Reviewer {
  id: string;
  name: string;
  email: string;
  can_assess: boolean;
  can_approve: boolean;
  open_reviews: number;
}

export interface Count {
  key: string;
  label?: string;
  count: number;
}

export interface Workload {
  reviewer_id: string | null;
  reviewer_name: string;
  assigned: number;
  pending: number;
  in_progress: number;
  completed: number;
  overdue: number;
  avg_completion_hours: number | null;
}

export interface Overview {
  metrics: {
    total: number;
    pending: number;
    in_progress: number;
    completed: number;
    confirmed: number;
    false_positives: number;
    duplicates: number;
    not_exploitable: number;
    accepted_risks: number;
    overdue: number;
    avg_completion_hours: number | null;
    confirmed_awaiting_remediation: number;
    awaiting_independent_review: number;
  };
  by_severity: Count[];
  by_status: Count[];
  by_disposition: Count[];
  by_scanner: Count[];
  workload: Workload[];
  trend: { day: string; created: number; completed: number }[];
  awaiting_remediation: ReviewItem[];
}

export interface Report {
  from: string;
  to: string;
  total_reviewed: number;
  confirmed: number;
  false_positives: number;
  false_positive_pct: number;
  avg_review_hours: number | null;
  overdue: number;
  by_severity: Count[];
  by_scanner: Count[];
  by_repository: Count[];
  by_disposition: Count[];
  by_analyst: Workload[];
  severity_raised: number;
  severity_lowered: number;
  severity_adjustments: { review_id: string; review_key: string; title: string; repository: string; original: Severity; assessed: Severity; justification: string }[];
  independent_review_results: Count[];
  confirmed_awaiting_remediation: number;
  awaiting_remediation: ReviewItem[];
}

export interface Settings {
  auto_queue: boolean;
  auto_triggers: string[];
  auto_scanners: string[];
  auto_categories: string[];
  auto_min_severity: Severity;
  priority_by_severity: Partial<Record<Severity, Priority>>;
  sla_days: Partial<Record<Severity, number>>;
  assignment_strategy: "manual" | "round_robin" | "least_loaded";
  assignment_pool: string[];
  allow_self_assign: boolean;
  independent_review_severities: Severity[];
  independent_review_dispositions: Disposition[];
  final_approval_severities: Severity[];
  final_approval_dispositions: Disposition[];
  evidence_required_dispositions: Disposition[];
  evidence_required_severities: Severity[];
  required_fields: string[];
  notify_assignment: boolean;
  notify_independent_review: boolean;
  notify_overdue: boolean;
  ai_assist: boolean;
  ai_send_code: boolean;
  evidence_max_mb: number;
  unassigned_can_assess: boolean;
  updated_at?: string;
  updated_by?: string | null;
}

/** Filters shared by the queue, overview and reports (query parameters). */
export type ReviewFilters = Partial<
  Record<
    | "q"
    | "status"
    | "disposition"
    | "remediation_status"
    | "severity"
    | "priority"
    | "scanner"
    | "category"
    | "repository_id"
    | "application_id"
    | "reviewer"
    | "independent_reviewer"
    | "overdue"
    | "source"
    | "branch"
    | "from"
    | "to"
    | "sort"
    | "order"
    | "page"
    | "page_size",
    string
  >
>;

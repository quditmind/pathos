import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

export type Dimension = "application" | "business_unit" | "team" | "owner" | "region";

export const dimensionLabel: Record<Dimension, string> = {
  application: "Application",
  business_unit: "Business unit",
  team: "Team",
  owner: "Owner",
  region: "Region",
};

export interface PostureGroup {
  id: string | null;
  label: string;
  repositories: number;
  open: Record<"critical" | "high" | "medium" | "low" | "info", number>;
  open_total: number;
  kev_open: number;
  sla_breached: number;
  high_risk_open: number;
  max_risk: number | null;
  avg_risk: number | null;
  risk_score: number;
  risk_band: "critical" | "high" | "medium" | "low" | "none";
  risk_basis: { max_finding_risk: number; other_high_risk_findings: number; uplift: number };
  fixed: number;
  mttr_days: number | null;
  sla_compliance: number | null;
  last_scan_at: string | null;
  coverage: number | null;
}

export interface AppPosture extends PostureGroup {
  application_key: string;
  criticality: string;
  lifecycle: string;
  environment: string;
  business_unit: string | null;
  owner: string | null;
  scan_targets: number;
}

export interface Benchmark extends PostureGroup {
  open_per_repository: number;
  critical_high_per_repository: number;
  rank: number;
}

export interface BenchmarkMetric {
  key: keyof Benchmark;
  label: string;
  lower_is_better: boolean;
}

export type CoverageStatus = "covered" | "stale" | "never" | "not_configured";

export interface CoverageRow {
  repository_id: string;
  repository_name: string;
  repository_key: string;
  application_id: string | null;
  application_name: string | null;
  scan_enabled: boolean;
  cells: Record<string, { status: CoverageStatus; last_at: string | null; scanners: string[] }>;
}

export interface CoverageResponse {
  days: number;
  categories: string[];
  summary: { category: string; covered: number; percent: number }[];
  items: CoverageRow[];
  truncated: boolean;
}

export const coverageLabel: Record<string, string> = {
  sast: "Code (SAST)",
  secrets: "Secrets",
  sca: "Dependencies",
  iac: "Infrastructure as code",
  cicd: "CI/CD workflows",
  container: "Container images",
  dast: "Web and API (DAST)",
};

export interface UnmanagedResponse {
  stale_days: number;
  active_days: number;
  issue_labels: Record<string, string>;
  counts: Record<string, number>;
  repositories: {
    id: string;
    name: string;
    repository_key: string;
    issues: string[];
    last_scan_at: string | null;
    last_pushed_at: string | null;
    open_findings: number;
    criticality: string;
  }[];
  shadow_visible: boolean;
  shadow?: {
    scm_connection_id: string;
    scm_connection_name: string;
    provider: string;
    external_id: string;
    full_name: string;
    url: string;
    visibility: string;
    pushed_at: string | null;
    first_seen_at: string;
  }[];
  shadow_truncated?: boolean;
  inventory?: {
    scm_connection_id: string;
    scm_connection_name: string;
    status: "running" | "succeeded" | "failed" | null;
    finished_at: string | null;
    repositories: number | null;
    truncated: boolean | null;
    error: string | null;
  }[];
}

export interface DepComponent {
  ref: string;
  name: string;
  version: string;
  purl: string;
  type: string;
  licenses: string[];
  depth: number | null;
  open_vulnerabilities: number;
  max_severity: string | null;
  /** Package health from deps.dev, when the feed has run. */
  latest_version?: string;
  outdated: boolean;
  deprecated: boolean;
  scorecard?: number;
  /** SLSA provenance of this version (direct dependencies are checked). */
  provenance?: "verified" | "unverified" | "none";
  provenance_source?: string;
  /** End of life (endoflife.date) when the package is a tracked framework. */
  eol_status?: "eol" | "approaching" | "supported";
  eol_cycle?: string;
  eol_date?: string | null;
}

export interface DependencyGraph {
  components: DepComponent[];
  edges: { parent: string; child: string }[];
  stats: Partial<Record<"components" | "edges" | "roots" | "direct" | "transitive" | "unknown" | "vulnerable" | "vulnerable_transitive" | "outdated" | "deprecated", number>>;
  truncated: boolean;
}

export interface PathNode {
  ref: string;
  name: string;
  version: string;
}

export interface Affected {
  repository_id: string;
  repository_name: string;
  repository_key: string;
  application_id: string | null;
  application_name: string | null;
  business_unit: string | null;
  owner: string | null;
  team: string | null;
  criticality: string;
  public_exposure: string;
  packages: string[];
  relation: "root" | "direct" | "transitive" | "unknown" | "none";
  open_findings: number;
  max_risk: number | null;
  kev: boolean;
  targets: string[];
}

export interface BlastRadius {
  query: { cve: string; package: string; version: string };
  summary: { repositories: number; applications: number; business_units: number; internet_exposed: number };
  items: Affected[];
}

export interface GraphNode {
  id: string;
  type: "application" | "repository" | "owner" | "team" | "business_unit" | "target" | "component" | "finding";
  label: string;
  sub?: string;
  risk?: number | null;
  severity?: string;
  link?: string;
}

export interface ContextGraph {
  root: string;
  nodes: GraphNode[];
  edges: { from: string; to: string; kind: string }[];
}

export const relationLabel: Record<string, string> = {
  root: "Project",
  direct: "Direct",
  transitive: "Transitive",
  unknown: "Unknown",
  none: "Not in SBOM",
};

export function useAppPosture(days: number) {
  return useQuery({
    queryKey: ["posture", "applications", days],
    queryFn: () => api<{ items: AppPosture[] }>(`/api/v1/posture/applications?days=${days}`).then((r) => r.items),
  });
}

export function useAggregate(by: Dimension, days: number, enabled = true) {
  return useQuery({
    queryKey: ["posture", "aggregate", by, days],
    queryFn: () => api<{ items: PostureGroup[] }>(`/api/v1/posture/aggregate?by=${by}&days=${days}`).then((r) => r.items),
    enabled,
  });
}

export function useBenchmark(by: Dimension, days: number) {
  return useQuery({
    queryKey: ["posture", "benchmark", by, days],
    queryFn: () => api<{ metrics: BenchmarkMetric[]; items: Benchmark[] }>(`/api/v1/posture/benchmark?by=${by}&days=${days}`),
  });
}

export function useDependencyGraph(repoId: string) {
  return useQuery({
    queryKey: ["dependency-graph", repoId],
    queryFn: () => api<DependencyGraph>(`/api/v1/repositories/${repoId}/dependencies`),
  });
}

/**
 * Rule 3 (build prompt §1, decision C5): scanner tool names appear only on
 * Configurations › Scan profiles, Configurations › Scanners & workers and
 * Import results. Everywhere else the UI names the kind of check and
 * "confirmed by N engines".
 *
 * This test renders the main pages with EXAMPLE FIXTURE DATA (labelled, not
 * real results) whose engine fields, errors, versions and log lines are full
 * of catalogued tool names, and asserts that no catalogued tool name
 * (CATALOG_TOOLS, generated from backend/internal/scanners) reaches the
 * page text, titles or accessible labels. A positive control renders the
 * Scan profiles page, where the names must appear.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import type { Finding, ScanFinding, ScanJob } from "@/api/types";
import { mockApi, renderApp } from "@/test/harness";
import { CATALOG_TOOLS, TOOL_NAME_TERMS, findingCheckLabel, redactToolNames } from "@/lib/checkKinds";
import { FindingsPage } from "@/features/findings/FindingsPage";
import { RelatedFindings } from "@/features/vuln/RelatedFindings";
import { ScansPage } from "@/features/scans/ScansPage";
import { OverviewTab } from "@/features/scans/details/OverviewTab";
import { StagesTab } from "@/features/scans/details/StagesTab";
import { ConfigurationTab } from "@/features/scans/details/ConfigurationTab";
import { FindingsTab } from "@/features/scans/details/FindingsTab";
import { LogsTab } from "@/features/scans/details/LogsTab";
import { QueuePage } from "@/features/review/QueuePage";
import { Workspace } from "@/features/review/workspace/WorkspacePage";
import { ReportsPage as ReviewReportsPage } from "@/features/review/ReportsPage";
import { ProfilesPage } from "@/features/scans/ProfilesPage";
import type { Catalog, ReviewDetail } from "@/features/review/types";

afterEach(() => vi.unstubAllGlobals());

// --- example fixture data (test only) -------------------------------------------

const third = CATALOG_TOOLS.filter((t) => !t.first_party);
/** Engine keys of the fixtures: every catalogued third-party tool. */
const ENGINE_KEYS = third.map((t) => t.key);
/** Free text that names tools, as raw errors and log lines do. */
const NOISY = `${third.slice(0, 12).map((t) => t.name).join(", ")} failed: exit status 2 (checkov, trivy, grype)`;

const finding = (over: Partial<Finding> = {}): Finding =>
  ({
    id: "f1", repository_id: "r1", repository_name: "example/payments", repository_key: "QD-REPO-000042", category: "iac",
    scanner_keys: ["checkov", "kics", "trivy-config", "import-iac-checkov"], rule_id: "CKV_AWS_20", title: "S3 bucket allows public read",
    description: "Example finding (test fixture).", severity: "high", cwe: [], cve: "", cvss: null, package_name: "", package_version: "", fixed_version: "",
    file_path: "infra/main.tf", start_line: 12, status: "open", first_seen_at: "2026-11-01T10:00:00Z", last_seen_at: "2026-11-02T10:00:00Z",
    resolved_at: null, assignee_id: null, assignee_name: null, sla_due_at: null, recurrence_count: 0, accepted_until: null, ai_status: "none",
    lifecycle_status: "open", occurrences: ENGINE_KEYS.slice(0, 6).map((k, i) => ({ scan_job_id: "j1", scanner_key: k, commit_sha: "abcdef1234567890", file_path: "infra/main.tf", start_line: 12, seen_at: `2026-11-0${i + 1}T10:00:00Z` })),
    ...over,
  }) as unknown as Finding;

const job = (over: Partial<ScanJob> = {}): ScanJob =>
  ({
    id: "j1", repository_id: "r1", repository_name: "example/payments", repository_key: "QD-REPO-000042", profile_name: "Default", profile_version: 3,
    trigger: "manual", priority: 70, status: "partial", ref: "main", commit_sha: "abcdef1234567890", attempts: 1, worker_name: "w1", requested_by: "ada@example.com",
    error: NOISY, findings_new: 2, findings_fixed: 1, gate_failed: false, queued_at: "2026-11-01T10:00:00Z", started_at: "2026-11-01T10:00:05Z",
    finished_at: "2026-11-01T10:02:05Z", scan_key: "QD-SCAN-000007", name: "Nightly", asset_type: "repository", profile_id: "p1", progress: 100, stage: "finished",
    retry_of: null, retry_count: 0, schedule_id: null, schedule_run_id: null, snapshot_id: null, duration_ms: 120000, findings_total: 5,
    severity: { critical: 1, high: 2, medium: 1, low: 1, info: 0 },
    results: ENGINE_KEYS.map((k, i) => ({ scanner_key: k, scanner_version: `${k} 1.${i}.0`, status: i % 7 === 0 ? "failed" : "succeeded", duration_ms: 1000 + i, findings_count: i, error: i % 7 === 0 ? `${k}: ${NOISY}` : "", has_artifact: true })),
    config_snapshot: {
      profile_id: "p1", profile_name: "Default", profile_version_id: "v3", profile_version: 3, change_note: "", severity_threshold: "info", exclusions: [],
      timeout_seconds: 1800, sbom: true, fail_on_critical: false, retention_days: 90, captured_at: "2026-11-01T10:00:00Z",
      scanners: ENGINE_KEYS.map((k) => ({ key: k, config: { engine: k } })),
    },
    ...over,
  }) as unknown as ScanJob;

const stages = {
  stages: [
    { key: "source", label: "Source checkout", scanner: "", scanner_version: "", status: "succeeded", started_at: null, finished_at: null, duration_ms: 10, findings: null, error: "" },
    ...ENGINE_KEYS.map((k, i) => ({ key: `scanner:${k}`, label: k, scanner: k, scanner_version: `${k} 2.0`, status: i % 5 === 0 ? "running" : "succeeded", started_at: null, finished_at: null, duration_ms: 10, findings: 1, error: i % 9 === 0 ? `${k} crashed (${NOISY})` : "" })),
  ],
  events: ENGINE_KEYS.slice(0, 20).map((k) => ({ stage: "scanner", scanner: k, status: "started", message: `${k} started; ${NOISY}`, at: "2026-11-01T10:00:00Z" })),
};

const reviewCatalog: Catalog = {
  statuses: [], dispositions: [], remediation_statuses: [], priorities: ["p1", "p2", "p3", "p4"], answers: ["yes", "no", "unknown", "not_applicable"],
  questions: [], assessment_fields: [], reproduction_fields: [], risk_fields: [], remediation_fields: [], evidence_types: [], evidence_classifications: [], ai_kinds: [],
};

const reviewDetail = (): ReviewDetail =>
  ({
    id: "rv1", review_key: "QD-HR-000001", finding_id: "f1", title: "SQL injection in OrderController.search", category: "sast", rule_id: "python.sqli",
    severity: "critical", assessed_severity: null, scanner: "semgrep-ce", repository_id: "r1", repository_name: "example/payments", repository_key: "QD-REPO-000042",
    application_id: null, application_name: null, branch: "main", commit_sha: "0123456789abcdef", file_path: "app/db.py", start_line: 4, detected_at: "2026-11-01T10:00:00Z",
    reviewer_id: null, reviewer_name: null, independent_reviewer_id: null, independent_reviewer_name: null, priority: "p1", status: "in_progress", disposition: null,
    remediation_status: null, due_at: null, overdue: false, source: "automatic", round: 1, finding_status: "needs_review", created_at: "2026-11-01T10:00:00Z",
    completed_at: null, updated_at: "2026-11-01T10:00:00Z",
    finding: {
      id: "f1", title: "SQL injection in OrderController.search", description: "Example (test fixture)", category: "sast", rule_id: "python.sqli",
      scanner_keys: ["opengrep", "semgrep-ce", "bandit", "codeql"], severity: "critical", cvss: null, cwe: ["CWE-89"], cve: "", owasp: [], package_name: "", package_version: "",
      fixed_version: "", file_path: "app/db.py", start_line: 4, end_line: 4, snippet: "", snippet_start_line: null, status: "needs_review", ai_status: "none",
      first_seen_at: "2026-11-01T10:00:00Z", last_seen_at: "2026-11-01T10:00:00Z", sla_due_at: null, assignee_name: null,
    },
    default_branch: "main", source_type: "scm", scan_job_id: "j1", scan_key: "QD-SCAN-000007", source_reason: "Needs review", created_by_name: null,
    original: { severity: "critical", cvss: null, cvss_vector: "", output: { ruleId: "python.sqli" }, rule: null, captured_at: "2026-11-01T10:01:00Z", capture_error: "" },
    assessment: { round: 1, answers: {}, fields: {}, reproduction: {}, risk: {}, remediation: {}, dataflow_notes: {}, updated_by: null, updated_at: null },
    assessed_cvss: null, assessed_cvss_vector: "", severity_justification: "", remediation_owner_id: null, remediation_owner_name: null, remediation_due_at: null,
    remediation_priority: null, remediation_link: "", risk_acceptance_id: null, started_at: null, submitted_at: null, ai_review: null,
    triage: { status: "needs_review", source: "ai", reason: "", changed_at: "2026-11-01T10:00:00Z" }, decisions: [], evidence_count: 0,
    requires_independent_review: false, required_fields: [], evidence_required_for: false, evidence_required_dispositions: [],
    can: { assess: false, start: false, assign: false, approve: false, comment: false, reopen: false, remediate: false, upload_files: false, ai: false, ai_unavailable_reason: "", accept_risk: false, source_viewer: false },
  }) as unknown as ReviewDetail;

const counts = (keys: string[]) => keys.map((k, i) => ({ key: k, count: i + 1 }));

const routes = {
  "GET /api/v1/findings": () => ({ items: [finding(), finding({ id: "f2", category: "sast", scanner_keys: ["bandit", "import-sast-gosec"] }), finding({ id: "f3", category: "sca", scanner_keys: ["trivy-fs", "grype", "osv-scanner", "sarif-trivy"] })], next_cursor: null }),
  "GET /api/v1/findings/summary": () => ({ total: 3, by_severity: { high: 3 } }),
  "GET /api/v1/findings/f1": () => finding(),
  "GET /api/v1/findings/f1/related": () => ({ cve: "", other_repositories: 0, items: [{ id: "f9", relation: "same_location", title: "Bucket encryption", severity: "medium", status: "open", scanner_keys: ["kics", "checkov", "trivy-config"], file_path: "infra/main.tf", start_line: 12, scan_target_name: null, risk_score: null }] }),
  "GET /api/v1/scanners": () => ({ items: CATALOG_TOOLS.map((t) => ({ ...t, adapter_available: true, category: "sast", license_spdx: "MIT", notes: "", mandatory: false, target_only: false, default_enabled: true })) }),
  "GET /api/v1/repositories": () => ({ items: [], next_cursor: null }),
  "GET /api/v1/scans": () => ({ items: [job({ status: "running", stage: "scanning:checkov", progress: 40, finished_at: null }), job({ id: "j2", scan_key: "QD-SCAN-000008", stage: "scanning:trivy-fs" })], next_cursor: null }),
  "GET /api/v1/scan-profiles": () => ({ items: [{ id: "p1", name: "Default", description: "", is_default: true, repository_count: 1, current: { id: "v3", version: 3, scanners: [], severity_threshold: "info", timeout_seconds: 1800, retention_days: 90 } }] }),
  "GET /api/v1/workers": () => ({ items: [] }),
  "GET /api/v1/schedules": () => ({ items: [] }),
  "GET /api/v1/scans/j1/stages": () => stages,
  "GET /api/v1/scans/j1/findings": () => ({ items: [{ ...finding(), scanner: "checkov", evidence: "infra/main.tf:12", occurrence_commit_sha: "abc", is_new: true } as ScanFinding] }),
  "GET /api/v1/scans/j1/logs": () => ({
    items: ENGINE_KEYS.slice(0, 15).map((k, i) => ({ id: i + 1, at: "2026-11-01T10:00:00Z", level: "info", source: k, message: `running ${k}: ${NOISY}` })),
    sources: [...ENGINE_KEYS.slice(0, 15), "worker"], next_after_id: null,
  }),
  "GET /api/v1/human-reviews": () => ({ items: [{ ...reviewDetail(), scanner: "semgrep-ce" }], total: 1, page: 1, page_size: 25 }),
  "GET /api/v1/human-reviews/rv1": () => reviewDetail(),
  "GET /api/v1/human-review/catalog": () => reviewCatalog,
  "GET /api/v1/human-reviews/rv1/ai": () => ({ items: [] }),
  "GET /api/v1/human-review/reviewers": () => ({ items: [] }),
  "GET /api/v1/applications": () => ({ items: [] }),
  "GET /api/v1/human-review/reports": () => ({
    from: "2026-10-01", to: "2026-11-01", total_reviewed: 5, confirmed: 1, false_positives: 1, false_positive_pct: 20, avg_review_hours: 2, overdue: 0,
    by_severity: [], by_disposition: [], by_repository: [], independent_review_results: [], by_analyst: [], severity_raised: 0, severity_lowered: 0,
    severity_adjustments: [], confirmed_awaiting_remediation: 0, awaiting_remediation: [],
    by_scanner: counts(["opengrep", "semgrep-ce", "gitleaks", "trivy-fs", "import-sast-snyk-code", "none"]),
  }),
};

// --- the check ---------------------------------------------------------------

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Catalogued tool names found in the rendered page's text, titles and accessible labels. */
function toolNamesIn(root: HTMLElement): string[] {
  // Text node by text node: adjacent elements have no separator in textContent.
  const texts: string[] = [];
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) texts.push(n.textContent ?? "");
  root.querySelectorAll("[title], [aria-label], [placeholder]").forEach((el) => {
    for (const a of ["title", "aria-label", "placeholder"]) {
      const v = el.getAttribute(a);
      if (v) texts.push(v);
    }
  });
  root.querySelectorAll("option").forEach((o) => texts.push(o.textContent ?? ""));
  const all = texts.join("\n");
  return TOOL_NAME_TERMS.filter((t) => new RegExp(`(?<![\\w-])${escapeRe(t)}(?![\\w-])`).test(all));
}

const expectNoToolNames = (root: HTMLElement = document.body) => expect(toolNamesIn(root)).toEqual([]);

describe("rule 3: tool names only on the configuration pages", () => {
  it("covers the whole catalogue", () => {
    expect(CATALOG_TOOLS.length).toBeGreaterThanOrEqual(98);
    for (const name of ["Opengrep", "gitleaks", "Trivy", "Checkov", "Grype", "trivy-fs", "Semgrep CE"]) expect(TOOL_NAME_TERMS).toContain(name);
    expect(redactToolNames("trivy-fs and Checkov failed")).toBe("engine and engine failed");
    expect(findingCheckLabel(finding())).toBe("Infrastructure as code · confirmed by 3 engines");
  });

  it("Findings list and finding details", async () => {
    mockApi(routes);
    renderApp(<FindingsPage />, { permissions: ["findings.read"], path: "/findings?finding=f1" });
    expect(await screen.findAllByText("S3 bucket allows public read")).not.toHaveLength(0);
    await screen.findByText("Bucket encryption");
    await waitFor(() => expect(screen.getAllByText(/confirmed by 3 engines/).length).toBeGreaterThan(0));
    expectNoToolNames();
  });

  it("related findings", async () => {
    mockApi(routes);
    renderApp(<RelatedFindings findingId="f1" />);
    expect(await screen.findByText(/Infrastructure as code · confirmed by 3 engines/)).toBeInTheDocument();
    expectNoToolNames();
  });

  it("scans list (progress by kind of check)", async () => {
    mockApi(routes);
    renderApp(<ScansPage />, { permissions: ["scans.read", "scans.run"] });
    expect(await screen.findByText("Scanning (Infrastructure as code)")).toBeInTheDocument();
    expectNoToolNames();
  });

  it("scan details: overview, stages, configuration, findings and logs", async () => {
    mockApi(routes);
    renderApp(
      <>
        <OverviewTab job={job()} />
        <StagesTab job={job()} />
        <ConfigurationTab job={job()} />
        <FindingsTab job={job()} />
        <LogsTab job={job()} />
      </>,
      { permissions: ["scans.read", "findings.read"] },
    );
    await screen.findAllByTestId("kind-progress");
    expect(screen.getAllByText(/Infrastructure as code:/).length).toBeGreaterThan(0);
    await screen.findAllByTestId("log-line");
    expect((await screen.findAllByText("infra/main.tf:12")).length).toBeGreaterThan(0);
    expectNoToolNames();
  });

  it("Human Eye queue, workspace and reports", async () => {
    mockApi(routes);
    renderApp(
      <>
        <QueuePage />
        <Workspace id="rv1" />
        <ReviewReportsPage />
      </>,
      { permissions: ["reviews.read", "reviews.report"], path: "/human-review/queue" },
    );
    expect(await screen.findByRole("heading", { name: "SQL injection in OrderController.search" })).toBeInTheDocument();
    await screen.findByText("Findings by kind of check");
    await waitFor(() => expect(screen.getAllByText(/SAST: deep engines/).length).toBeGreaterThan(0));
    expectNoToolNames();
  });

  it("positive control: Scan profiles names the tools", async () => {
    mockApi({
      ...routes,
      "GET /api/v1/scan-profiles": () => ({ items: [{ id: "p1", name: "Default", description: "", is_default: true, template: null, repository_count: 1, current: { id: "v3", version: 3, scanners: [{ key: "checkov" }, { key: "gitleaks" }], severity_threshold: "info", timeout_seconds: 1800, retention_days: 90 } }] }),
      "GET /api/v1/scan-profiles/p1/kinds": () => ({ profile_id: "p1", workers_online: 0, kinds: [] }),
    });
    renderApp(<ProfilesPage />, { permissions: ["scans.read"] });
    await screen.findByText("Gitleaks");
    expect(toolNamesIn(document.body)).toEqual(expect.arrayContaining(["Checkov", "Gitleaks"]));
  });
});

describe("scan profile kinds", () => {
  it("shows N of 10 tools per kind and the kinds without a runnable tool", async () => {
    const { ProfileKindsPanel } = await import("@/features/scans/ProfilesPage");
    mockApi({
      "GET /api/v1/scan-profiles/p1/kinds": () => ({
        profile_id: "p1", workers_online: 1,
        kinds: [
          { id: "iac", name: "Infrastructure as code", phase: 6, after_v2: false, outside_kinds: false, tools_target: 10, listed: 7, runnable: 7, available: 12, repository_scope: true, lacks_runnable: false,
            selected: [{ key: "checkov", name: "Checkov", listed: true, runnable: true }] },
          { id: "secrets", name: "Secrets", phase: 6, after_v2: false, outside_kinds: false, tools_target: 10, listed: 2, runnable: 0, available: 5, repository_scope: true, lacks_runnable: true,
            selected: [{ key: "trufflehog", name: "TruffleHog", listed: true, runnable: false }] },
          { id: "web-api", name: "Web app & API testing", phase: 6, after_v2: false, outside_kinds: false, tools_target: 10, listed: 0, runnable: 0, available: 0, repository_scope: false, lacks_runnable: false, selected: [] },
        ],
      }),
    });
    renderApp(<ProfileKindsPanel id="p1" />);
    expect(await screen.findByText("7 of 10 tools")).toBeInTheDocument();
    expect(screen.getByText(/No online worker runs a selected tool for: Secrets/)).toBeInTheDocument();
    expect(screen.getByText("no runnable tool")).toBeInTheDocument();
    expect(screen.getByText("not in repository scans")).toBeInTheDocument();
  });
});

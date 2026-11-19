import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import { AppShell, groups } from "@/components/layout/AppShell";
import { QueuePage } from "./QueuePage";
import { Workspace } from "./workspace/WorkspacePage";
import type { Capabilities, Catalog, ReviewDetail, ReviewItem } from "./types";

afterEach(() => vi.unstubAllGlobals());

const item = (over: Partial<ReviewItem> = {}): ReviewItem => ({
  id: "rv1", review_key: "QD-HR-000001", finding_id: "f1", title: "SQL injection in OrderController.search", category: "sast", rule_id: "python.sqli",
  severity: "critical", assessed_severity: null, scanner: "opengrep", repository_id: "r1", repository_name: "acme/payments", repository_key: "QD-REPO-000042",
  application_id: null, application_name: "Payments", branch: "main", commit_sha: "0123456789abcdef0123456789abcdef01234567", file_path: "app/db.py", start_line: 4,
  detected_at: "2026-11-01T10:00:00Z", reviewer_id: "u1", reviewer_name: "Ada", independent_reviewer_id: null, independent_reviewer_name: null, priority: "p1",
  status: "in_progress", disposition: null, remediation_status: null, due_at: "2026-11-03T10:00:00Z", overdue: true, source: "automatic", round: 1,
  finding_status: "needs_review", created_at: "2026-11-01T10:00:00Z", completed_at: null, updated_at: "2026-11-01T10:00:00Z", ...over,
});

const can = (over: Partial<Capabilities> = {}): Capabilities => ({
  assess: true, start: false, assign: false, approve: false, comment: true, reopen: false, remediate: false, upload_files: true, ai: false,
  ai_unavailable_reason: "No AI provider is configured", accept_risk: false, source_viewer: true, ...over,
});

const detail = (over: Partial<ReviewDetail> = {}): ReviewDetail => ({
  ...item(),
  finding: {
    id: "f1", title: "SQL injection in OrderController.search", description: "User input reaches cursor.execute", category: "sast", rule_id: "python.sqli",
    scanner_keys: ["opengrep"], severity: "critical", cvss: null, cwe: ["CWE-89"], cve: "", owasp: ["A03:2021 Injection"], package_name: "", package_version: "",
    fixed_version: "", file_path: "app/db.py", start_line: 4, end_line: 4, snippet: "", snippet_start_line: null, status: "needs_review", ai_status: "none",
    first_seen_at: "2026-11-01T10:00:00Z", last_seen_at: "2026-11-01T10:00:00Z", sla_due_at: null, assignee_name: null,
  },
  default_branch: "main", source_type: "scm", scan_job_id: "j1", scan_key: "QD-SCAN-000007", source_reason: "Automated triage marked the finding as needing human review",
  created_by_name: null,
  original: { severity: "critical", cvss: null, cvss_vector: "", output: { ruleId: "python.sqli" }, rule: null, captured_at: "2026-11-01T10:01:00Z", capture_error: "" },
  assessment: { round: 1, answers: {}, fields: {}, reproduction: {}, risk: {}, remediation: {}, dataflow_notes: {}, updated_by: null, updated_at: null },
  assessed_cvss: null, assessed_cvss_vector: "", severity_justification: "", remediation_owner_id: null, remediation_owner_name: null, remediation_due_at: null,
  remediation_priority: null, remediation_link: "", risk_acceptance_id: null, started_at: null, submitted_at: null, ai_review: null,
  triage: { status: "needs_review", source: "ai", reason: "AI review (automated): needs_review", changed_at: "2026-11-01T10:00:00Z" },
  decisions: [], evidence_count: 0, requires_independent_review: true, required_fields: ["reachable"], evidence_required_for: false,
  evidence_required_dispositions: [], can: can(), ...over,
});

const catalog: Catalog = {
  statuses: [], dispositions: [], remediation_statuses: [], priorities: ["p1", "p2", "p3", "p4"], answers: ["yes", "no", "unknown", "not_applicable"],
  questions: [{ key: "reachable", label: "Is the vulnerable code reachable?" }, { key: "exploitable", label: "Is exploitation practically possible?" }],
  assessment_fields: [{ key: "attack_scenario", label: "Attack scenario" }, { key: "attack_complexity", label: "Attack complexity", options: ["low", "high"] }],
  reproduction_fields: [{ key: "steps", label: "Steps to reproduce" }], risk_fields: [], remediation_fields: [{ key: "recommendation", label: "Recommended remediation" }],
  evidence_types: ["screenshot"], evidence_classifications: ["confidential"], ai_kinds: [],
};

const sourceView = {
  available: true, origin: "scm", repository_id: "r1", repository: "acme/payments", branch: "main", commit_sha: "0123456789abcdef0123456789abcdef01234567",
  scanned: true, path: "app/db.py", language: "python", lines: ["def find(q):", "    cur = db.cursor()", "    sql = 'SELECT * FROM t WHERE id=' + q", "    cur.execute(sql)"],
  focus_line: 4, truncated: false, redacted: false,
};

describe("navigation", () => {
  // 3.0 sidebar (prompt §5): Human Eye is a section of "7 · Validate & intelligence"; its configuration moved to Configurations.
  it("Human Eye is a section of Validate & intelligence", async () => {
    const hr = groups.find((g) => g.label === "7 · Validate & intelligence")!.items.filter((i) => i.section === "Human Eye");
    expect(hr.map((i) => [i.label, i.to])).toEqual([
      ["Human Eye overview", "/human-review"],
      ["Review queue", "/human-review/queue"],
      ["Assessments", "/human-review/assessments"],
      ["Assignments", "/human-review/assignments"],
      ["Review reports", "/human-review/reports"],
    ]);
    expect(groups.find((g) => g.label === "Configurations")!.items.some((i) => i.to === "/human-review/configurations")).toBe(true);
    expect(groups.find((g) => g.label === "6 · Assess")!.items.some((i) => i.to?.startsWith("/human-review"))).toBe(false);
    mockApi({});
    renderApp(<AppShell><div /></AppShell>, { permissions: ["reviews.read"] });
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Review queue" })).toBeInTheDocument();
    expect(within(nav).getByText("Human Eye")).toBeInTheDocument();
  });

  it("is hidden without reviews.read", async () => {
    mockApi({});
    renderApp(<AppShell><div /></AppShell>, { permissions: ["findings.read"] });
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).queryByRole("link", { name: "Review queue" })).toBeNull();
  });
});

describe("review queue", () => {
  it("renders the required columns and sorts on the server", async () => {
    const api = mockApi({
      "GET /api/v1/human-reviews": () => ({ items: [item()], total: 1, page: 1, page_size: 25 }),
      "GET /api/v1/human-review/reviewers": () => ({ items: [] }),
      "GET /api/v1/scanners": () => ({ items: [] }),
      "GET /api/v1/applications": () => ({ items: [] }),
    });
    renderApp(<QueuePage />, { permissions: ["reviews.read", "reviews.assign"], path: "/human-review/queue" });
    expect(await screen.findByText("QD-HR-000001")).toBeInTheDocument();
    for (const h of ["Finding ID", "Vulnerability", "Severity", "Scanner", "Repository", "Application", "Branch", "File path", "Detected", "Reviewer", "Priority", "Review status", "Due"]) {
      expect(screen.getByRole("button", { name: `Sort by ${h}` })).toBeInTheDocument();
    }
    expect(screen.getByText("(overdue)")).toBeInTheDocument();
    expect(api.calls.find((c) => c.path === "/api/v1/human-reviews")!.url.searchParams.get("status")).toBe("open");
    fireEvent.click(screen.getByRole("button", { name: "Sort by Severity" }));
    await waitFor(() => expect(api.calls.some((c) => c.url.searchParams.get("sort") === "severity")).toBe(true));
    // Bulk actions appear on selection for review managers.
    fireEvent.click(screen.getByRole("checkbox", { name: "Select QD-HR-000001" }));
    expect(screen.getByRole("button", { name: /Update 1 selected/ })).toBeInTheDocument();
  });
});

describe("assessment workspace", () => {
  const routes = (d: ReviewDetail, extra: Record<string, (u: URL, i: RequestInit & { json?: unknown }) => unknown> = {}) => ({
    "GET /api/v1/human-reviews/rv1": () => d,
    "GET /api/v1/human-review/catalog": () => catalog,
    "GET /api/v1/human-reviews/rv1/ai": () => ({ items: [] }),
    "GET /api/v1/human-review/reviewers": () => ({ items: [] }),
    ...extra,
  });

  it("shows the eight tabs, the scanned context and actions by capability", async () => {
    mockApi(routes(detail()));
    renderApp(<Workspace id="rv1" />, { permissions: ["reviews.read", "reviews.assess"] });
    expect(await screen.findByRole("heading", { name: "SQL injection in OrderController.search" })).toBeInTheDocument();
    const tabs = screen.getByRole("tablist", { name: "Assessment sections" });
    expect(within(tabs).getAllByRole("tab").map((t) => t.textContent)).toEqual([
      "Overview", "Source code", "Data flow", "Exploitability", "Evidence", "Risk assessment", "Remediation", "History",
    ]);
    expect(screen.getByText("A03:2021 Injection")).toBeInTheDocument();
    expect(screen.getByText(/"ruleId": "python.sqli"/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Submit decision/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Independent review/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Reopen/ })).toBeNull();
  });

  it("hides workflow actions for read-only users", async () => {
    mockApi(routes(detail({ status: "completed", disposition: "false_positive", can: can({ assess: false, comment: false, upload_files: false }) })));
    renderApp(<Workspace id="rv1" />, { permissions: ["reviews.read"] });
    await screen.findByRole("heading", { name: "SQL injection in OrderController.search" });
    expect(screen.queryByRole("button", { name: /Submit decision/ })).toBeNull();
    expect(screen.getAllByText("False positive").length).toBeGreaterThan(0);
  });

  it("submits a decision and shows the API's field errors", async () => {
    const api = mockApi(
      routes(detail(), {
        "POST /api/v1/human-reviews/rv1/decision": () =>
          jsonResponse({ error: { code: "validation_failed", message: "x", fields: { assessment: "Complete the required assessment fields: Is the vulnerable code reachable?." } } }, 422),
      }),
    );
    renderApp(<Workspace id="rv1" />, { permissions: ["reviews.read", "reviews.assess"] });
    fireEvent.click(await screen.findByRole("button", { name: /Submit decision/ }));
    fireEvent.click(screen.getByRole("radio", { name: /False positive/ }));
    const submit = screen.getByRole("button", { name: "Submit for independent review" });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Why is the scanner detection incorrect/), { target: { value: "The value comes from a constant allow-list." } });
    fireEvent.click(submit);
    expect(await screen.findByText(/Complete the required assessment fields/)).toBeInTheDocument();
    expect(api.calls.find((c) => c.method === "POST")!.body).toMatchObject({ disposition: "false_positive" });
  });

  it("source tab highlights the vulnerable line of the scanned commit", async () => {
    const api = mockApi(
      routes(detail(), {
        "GET /api/v1/human-reviews/rv1/source": () => sourceView,
        "GET /api/v1/human-reviews/rv1/source/commits": () => ({ scanned: { sha: sourceView.commit_sha, label: "Scanned" }, occurrences: [], history: [], head: null, history_unavailable: "" }),
      }),
    );
    renderApp(<Workspace id="rv1" />, { permissions: ["reviews.read", "reviews.assess"], path: "/?tab=source" });
    expect(await screen.findByText("(vulnerable line)")).toBeInTheDocument();
    expect(screen.getByText("Scanned version")).toBeInTheDocument();
    expect(screen.getByText(sourceView.commit_sha)).toBeInTheDocument();
    expect(api.calls.find((c) => c.path.endsWith("/source"))!.url.searchParams.get("commit")).toBe(sourceView.commit_sha);
    // Symbol navigation and references.
    expect(screen.getByRole("button", { name: /find\s*1/ })).toBeInTheDocument();
    fireEvent.click(screen.getAllByText("sql")[0]!);
    expect(screen.getByText(/appears on 2 lines/)).toBeInTheDocument();
  });

  it("source tab explains when source code is unavailable", async () => {
    mockApi(
      routes(detail(), {
        "GET /api/v1/human-reviews/rv1/source": () => ({ ...sourceView, available: false, lines: [], unavailable_message: "The SCM connection is not allowed to read this repository." }),
        "GET /api/v1/human-reviews/rv1/source/commits": () => ({ scanned: { sha: "", label: "" }, occurrences: [], history: [], head: null, history_unavailable: "x" }),
      }),
    );
    renderApp(<Workspace id="rv1" />, { permissions: ["reviews.read"], path: "/?tab=source" });
    expect(await screen.findByText(/Source code unavailable: The SCM connection is not allowed/)).toBeInTheDocument();
  });

  it("data flow distinguishes inferred locations from confirmed flows", async () => {
    mockApi(
      routes(detail(), {
        "GET /api/v1/human-reviews/rv1/dataflow": () => ({
          status: "inferred", reason: "The scanner associated these locations with the finding but did not report a data flow between them.", scanner: "opengrep",
          paths: [], related: [{ file_path: "app/models.py", line: 5, role: "related" }], notes: {}, sink: { file_path: "app/db.py", line: 4 },
        }),
      }),
    );
    renderApp(<Workspace id="rv1" />, { permissions: ["reviews.read", "reviews.assess"], path: "/?tab=dataflow" });
    expect(await screen.findByText("Inferred (unverified).")).toBeInTheDocument();
    expect(screen.getByText("app/models.py:5")).toBeInTheDocument();
  });

  it("exploitability answers save only the changed keys", async () => {
    const api = mockApi(routes(detail(), { "PUT /api/v1/human-reviews/rv1/assessment": () => ({}) }));
    renderApp(<Workspace id="rv1" />, { permissions: ["reviews.read", "reviews.assess"], path: "/?tab=exploitability" });
    const group = await screen.findByRole("radiogroup", { name: "Is the vulnerable code reachable?" });
    fireEvent.click(within(group).getByText("Unknown"));
    fireEvent.click(screen.getByRole("button", { name: /Save assessment/ }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "PUT")).toBe(true));
    expect(api.calls.find((c) => c.method === "PUT")!.body).toEqual({ answers: { reachable: "unknown" } });
  });

  it("explains why AI assistance is unavailable", async () => {
    mockApi(routes(detail()));
    renderApp(<Workspace id="rv1" />, { permissions: ["reviews.read", "reviews.assess"] });
    fireEvent.click(await screen.findByRole("button", { name: /AI assist/ }));
    expect(await screen.findByText("No AI provider is configured")).toBeInTheDocument();
    expect(screen.getByText(/AI never completes a review/)).toBeInTheDocument();
  });
});

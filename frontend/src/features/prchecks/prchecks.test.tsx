import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { PullRequestChecksPage, type PRCheck } from "./PullRequestChecksPage";

afterEach(() => vi.unstubAllGlobals());

const check: PRCheck = {
  id: "c1", repository_id: "r1", repository_name: "acme/payments", scan_job_id: "j1", scan_status: "succeeded", pull_request: 42,
  head_ref: "feature/login", head_sha: "0123456789abcdef0123456789abcdef01234567", status: "failed", gate_severity: "high",
  new_findings: 1, new_by_severity: { high: 1 }, existing_findings: 1, summary: "Blocked: 1 new: 1 high (gate: high and above)",
  status_posted: "final", status_error: "", created_at: "2026-11-18T01:00:00Z", finished_at: "2026-11-18T01:05:00Z",
};
const findings = [
  { id: "p1", title: "SQL injection", severity: "high", category: "sast", scanner_key: "opengrep", rule_id: "sqli", file_path: "api/db.go", start_line: 12, cve: null, is_new: true, existing_finding_id: null, policies: ["No SQL injection"] },
  { id: "p2", title: "lodash prototype pollution", severity: "critical", category: "sca", scanner_key: "trivy-fs", rule_id: "CVE-2021-23337", file_path: "package-lock.json", start_line: null, cve: "CVE-2021-23337", is_new: false, existing_finding_id: "f9", policies: [] },
];

describe("pull request checks", () => {
  it("lists checks and separates what the PR introduces from what is already known", async () => {
    const api = mockApi({
      "GET /api/v1/pr-checks": () => ({ items: [check] }),
      "GET /api/v1/pr-checks/c1": () => ({ check, findings }),
      "POST /api/v1/pr-checks/c1/repost": () => check,
    });
    renderApp(<PullRequestChecksPage />, { permissions: ["scans.read", "scans.run"], path: "/?check=c1" });
    expect((await screen.findAllByText("acme/payments #42")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("Blocked").length).toBeGreaterThan(0);
    expect(await screen.findByText("Introduced by this pull request (1)")).toBeInTheDocument();
    expect(screen.getByText("SQL injection")).toBeInTheDocument();
    expect(screen.getByText("policy: No SQL injection")).toBeInTheDocument();
    expect(screen.getByText("Already known on the scan branch (1)")).toBeInTheDocument();
    expect(screen.getByText("Result posted to the pull request")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Post status again/ }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/pr-checks/c1/repost")).toBe(true));
  });

  it("hides reposting without scans.run and explains the empty state", async () => {
    mockApi({ "GET /api/v1/pr-checks": () => ({ items: [] }) });
    renderApp(<PullRequestChecksPage />, { permissions: ["scans.read"] });
    expect(await screen.findByText("No pull request checks")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Post status again/ })).not.toBeInTheDocument();
  });

  it("requires choosing block or warn before enabling checks (no blocking without an explicit policy)", async () => {
    const api = mockApi({
      "GET /api/v1/pr-checks": () => ({ items: [] }),
      "GET /api/v1/repositories": () => ({ items: [{ id: "r1", full_name: "acme/payments", repository_key: "R-1" }], next_cursor: null }),
      "GET /api/v1/repositories/r1/pr-settings": () => ({ enabled: false, gate_severity: "high", gate_mode: null, policy_id: null, source_type: "scm" }),
      "PUT /api/v1/repositories/r1/pr-settings": (_u, init) => ({ ...(init.json as object), policy_id: "p1", source_type: "scm" }),
    });
    renderApp(<PullRequestChecksPage />, { permissions: ["scans.read", "repos.manage"] });
    fireEvent.focus((await screen.findAllByLabelText("Filter by repository"))[0]!);
    fireEvent.click(await screen.findByRole("option", { name: /acme\/payments/ }));
    fireEvent.click(await screen.findByLabelText("Check pull requests"));
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(screen.getByText(/Choose Block or Warn to enable pull request checks/)).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText("Warn only"));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => {
      const put = api.calls.find((c) => c.method === "PUT" && c.path === "/api/v1/repositories/r1/pr-settings");
      expect(put?.body).toEqual({ enabled: true, gate_severity: "high", gate_mode: "warn" });
    });
  });
});

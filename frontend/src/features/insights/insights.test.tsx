import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { RepositoryMaterialChanges, ScanMaterialChanges } from "./MaterialChanges";
import { DeveloperInsightsPage } from "./DeveloperInsightsPage";
import { AttributionSettingsPage } from "./AttributionSettingsPage";
import { formatHours } from "./api";

afterEach(() => vi.unstubAllGlobals());

const run = {
  scan_job_id: "j2", repository_id: "r1", status: "computed", reason: "", base_sha: "1111111111aaaa", head_sha: "2222222222bbbb",
  files_changed: 3, truncated: false, change_count: 2, dependency_status: "computed", commits_complete: true, created_at: "2026-11-18T10:00:00Z",
};
const change = (o: object) => ({
  id: "c1", scan_job_id: "j2", category: "auth", category_label: "Authentication / authorization", rule_id: "auth.spring-security",
  rule_title: "Spring Security configuration changed", level: "high", file_path: "src/Security.java", change_type: "modified", side: "added",
  start_line: 12, end_line: 14, match_count: 2, snippet: ".permitAll()", explanation: "Can open endpoints.", detail: "", created_at: "2026-11-18T10:00:00Z",
  commit_sha: "2222222222bbbb", ...o,
});

describe("material changes", () => {
  it("shows the comparison and explainable changes of a scan, filterable by category", async () => {
    mockApi({
      "GET /api/v1/scans/j2/material-changes": () => ({ run, items: [change({}), change({ id: "c2", category: "dependency", category_label: "New dependency",
        rule_id: "dependency.new", rule_title: "New dependency", level: "medium", file_path: "", start_line: null, end_line: null, detail: "left-pad 1.3.0 (npm)",
        snippet: "left-pad 1.3.0 (npm)" })] }),
    });
    renderApp(<ScanMaterialChanges jobId="j2" />, { permissions: ["scans.read"] });
    expect(await screen.findByText("Spring Security configuration changed")).toBeInTheDocument();
    expect(screen.getByText(/Compared commits/)).toHaveTextContent("1111111111 → 2222222222");
    expect(screen.getByText("src/Security.java:12-14")).toBeInTheDocument();
    expect(screen.getAllByText("left-pad 1.3.0 (npm)").length).toBeGreaterThan(0);
    expect(screen.queryByText("Last author")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "dependency" } });
    await waitFor(() => expect(screen.queryByText("Spring Security configuration changed")).not.toBeInTheDocument());
  });

  it("says why a comparison is unavailable", async () => {
    mockApi({ "GET /api/v1/scans/j3/material-changes": () => ({ run: { ...run, status: "unavailable", reason: "rewritten history", change_count: 0 }, items: [] }) });
    renderApp(<ScanMaterialChanges jobId="j3" />, { permissions: ["scans.read"] });
    expect(await screen.findByText(/Change comparison unavailable: rewritten history/)).toBeInTheDocument();
  });

  it("lists a repository's changes with authors when attribution is visible", async () => {
    const api = mockApi({ "GET /api/v1/repositories/r1/material-changes": () => ({ items: [change({ author_name: "Bob Dev" })], truncated: false, runs: [run] }) });
    renderApp(<RepositoryMaterialChanges repoId="r1" />, { permissions: ["scans.read"] });
    expect(await screen.findByText("Bob Dev")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "auth" } });
    await waitFor(() => expect(api.calls.some((c) => c.url.search.includes("category=auth"))).toBe(true));
  });
});

describe("developer insights", () => {
  it("explains that attribution is off", async () => {
    mockApi({ "GET /api/v1/insights/settings": () => ({ attribution_enabled: false, updated_at: null, can_manage: true, can_view_people: true, can_link_identities: true }) });
    renderApp(<DeveloperInsightsPage />, { permissions: ["insights.people", "settings.manage"] });
    expect(await screen.findByText("Developer attribution is off")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open the attribution settings" })).toBeInTheDocument();
  });

  it("needs insights.people", async () => {
    mockApi({});
    renderApp(<DeveloperInsightsPage />, { permissions: ["findings.read"] });
    expect(await screen.findByText(/insights.people permission/)).toBeInTheDocument();
  });

  it("shows developers and teams", async () => {
    mockApi({
      "GET /api/v1/insights/settings": () => ({ attribution_enabled: true, updated_at: null, can_manage: false, can_view_people: true, can_link_identities: false }),
      "GET /api/v1/insights/developers": () => ({ items: [{ author_name: "Alice Dev", user: { id: "u1", name: "Alice" }, introduced: 4, introduced_critical_high: 1,
        fixed: 6, still_open: 2, mean_time_to_fix_hours: 30, repositories: 2 }] }),
      "GET /api/v1/insights/teams": () => ({ items: [{ id: "t1", name: "Payments", developers: 1, introduced: 4, introduced_critical_high: 1, fixed: 6, still_open: 2,
        mean_time_to_fix_hours: 72 }] }),
    });
    renderApp(<DeveloperInsightsPage />, { permissions: ["insights.people"] });
    expect(await screen.findByText("Alice Dev")).toBeInTheDocument();
    expect(screen.getByText("30.0 h")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Teams" }));
    expect(await screen.findByText("Payments")).toBeInTheDocument();
    expect(screen.getByText("3.0 d")).toBeInTheDocument();
  });

  it("formats hours", () => {
    expect(formatHours(null)).toBe("—");
    expect(formatHours(5)).toBe("5.0 h");
    expect(formatHours(96)).toBe("4.0 d");
  });
});

describe("attribution settings", () => {
  it("turns attribution on, links an author and confirms before erasing", async () => {
    let on = false;
    const api = mockApi({
      "GET /api/v1/insights/settings": () => ({ attribution_enabled: on, updated_at: null, can_manage: true, can_view_people: true, can_link_identities: true }),
      "PUT /api/v1/insights/settings": (_u, init) => {
        on = (init.json as { attribution_enabled: boolean }).attribution_enabled;
        return { attribution_enabled: on, updated_at: null, can_manage: true, can_view_people: true, can_link_identities: true };
      },
      "GET /api/v1/insights/identities": () => ({ items: [{ id: "i1", author_name: "Bob Dev", user_id: "u2", user_name: "Bob", created_at: "2026-11-18T10:00:00Z" }],
        unlinked_authors: ["Alice Dev"] }),
      "DELETE /api/v1/insights/identities/i1": () => undefined,
    });
    renderApp(<AttributionSettingsPage />, { permissions: ["settings.manage", "users.manage"] });
    fireEvent.click(await screen.findByRole("button", { name: "Turn on developer attribution" }));
    expect(await screen.findByText("Bob Dev")).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Alice Dev" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Unlink Bob Dev" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "DELETE")).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Turn off and erase attribution data" }));
    fireEvent.click(await screen.findByRole("button", { name: "Turn off and erase" }));
    await waitFor(() => expect(api.calls.filter((c) => c.method === "PUT").length).toBe(2));
    expect(on).toBe(false);
  });
});

import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import type { Repository } from "@/api/types";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import { FindingFixPR, FixPRSettingsPanel, type FixEligibility, type FixPR } from "./FixPRPanel";

afterEach(() => vi.unstubAllGlobals());

const eligible: FixEligibility = {
  eligible: true, ecosystem: "pypi", package_name: "django", target_version: "4.2.11",
  support: { supported: true, edits: "pins the package in requirements/constraints files" },
  enabled: true, grouping: "package", can_request: true, requests: [],
};
const opened: FixPR = {
  id: "x1", repository_id: "r1", repository_name: "acme/api", ecosystem: "pypi", package_name: "django", current_version: "4.2.1",
  target_version: "4.2.11", grouping: "package", status: "open", error: "", base_branch: "main", branch: "pathos/fix/pypi-django-4.2.11-abcd1234",
  changed_files: ["requirements.txt"], pr_number: "12", pr_url: "https://github.com/acme/api/pull/12", finding_ids: ["f1", "f2"],
  requested_by: "ada@example.com", created_at: "2026-11-19T10:00:00Z", updated_at: "2026-11-19T10:01:00Z", state_checked_at: null,
};

describe("fix pull requests", () => {
  it("requests a fix PR with the chosen target and grouping, then shows it", async () => {
    let state: FixEligibility = eligible;
    const api = mockApi({
      "GET /api/v1/findings/f1/fix-pr": () => state,
      "POST /api/v1/findings/f1/fix-pr": () => {
        state = { ...eligible, requests: [opened] };
        return opened;
      },
    });
    renderApp(<FindingFixPR findingId="f1" category="sca" />, { permissions: ["findings.read", "findings.triage", "repos.manage"] });
    const btn = await screen.findByRole("button", { name: /Open fix PR/ });
    fireEvent.change(screen.getByLabelText("Target version"), { target: { value: "4.2.12" } });
    fireEvent.change(screen.getByLabelText("Grouping"), { target: { value: "finding" } });
    fireEvent.click(btn);
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST")).toBe(true));
    expect(api.calls.find((c) => c.method === "POST")?.body).toEqual({ target_version: "4.2.12", grouping: "finding" });
    const link = await screen.findByRole("link", { name: /#12/ });
    expect(link).toHaveAttribute("href", "https://github.com/acme/api/pull/12");
    expect(screen.getByText("covers 2 findings")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Open fix PR/ })).not.toBeInTheDocument();
  });

  it("explains honestly why a fix PR is not available", async () => {
    mockApi({
      "GET /api/v1/findings/f1/fix-pr": () => ({ ...eligible, eligible: false, reason: "not supported: go.sum must be updated with checksums from the Go toolchain" }),
    });
    renderApp(<FindingFixPR findingId="f1" category="sca" />, { permissions: ["findings.read", "findings.triage", "repos.manage"] });
    expect(await screen.findByText(/go.sum must be updated/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Open fix PR/ })).not.toBeInTheDocument();
  });

  it("shows request errors (for example a credential without write access)", async () => {
    mockApi({
      "GET /api/v1/findings/f1/fix-pr": () => eligible,
      "POST /api/v1/findings/f1/fix-pr": () => jsonResponse({ error: { code: "conflict", message: "a fix pull request for this finding is already in progress" } }, 409),
    });
    renderApp(<FindingFixPR findingId="f1" category="sca" />, { permissions: ["findings.read", "findings.triage", "repos.manage"] });
    fireEvent.click(await screen.findByRole("button", { name: /Open fix PR/ }));
    expect(await screen.findByText(/already in progress/)).toBeInTheDocument();
  });

  it("renders nothing for non-dependency findings", () => {
    const api = mockApi({});
    const { container } = renderApp(<FindingFixPR findingId="f1" category="sast" />, { permissions: ["findings.read"] });
    expect(container.textContent).toBe("");
    expect(api.calls).toHaveLength(0);
  });

  it("saves the repository opt-in", async () => {
    const api = mockApi({
      "GET /api/v1/repositories/r1/fix-pr-settings": () => ({ enabled: false, grouping: "package", source_type: "scm", provider: "github" }),
      "PUT /api/v1/repositories/r1/fix-pr-settings": (_u, init) => ({ ...(init.json as object), source_type: "scm", provider: "github" }),
    });
    renderApp(<FixPRSettingsPanel r={{ id: "r1" } as Repository} />, { permissions: ["scans.read", "repos.manage"] });
    fireEvent.click(await screen.findByLabelText(/Allow fix pull requests/));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.calls.find((c) => c.method === "PUT")?.body).toEqual({ enabled: true, grouping: "package" }));
  });
});

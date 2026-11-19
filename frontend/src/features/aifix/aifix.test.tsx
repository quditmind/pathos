import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import type { Repository } from "@/api/types";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import { AIFixSettingsPanel, FindingAIFix, type AIFix, type AIFixEligibility } from "./AIFixPanel";

afterEach(() => vi.unstubAllGlobals());

const diff = "--- a/app.py\n+++ b/app.py\n@@ -2,2 +2,2 @@\n def run(cmd):\n-    subprocess.call(cmd, shell=True)\n+    subprocess.call(shlex.split(cmd))\n";

const base: AIFixEligibility = {
  available: true, scanner: "opengrep", test_runner: "", fix_prs_enabled: true, can_request: true, can_open_pr: true, proposals: [],
};

const verified: AIFix = {
  id: "x1", finding_id: "f1", repository_id: "r1", status: "verified", failure_reason: "", scanner_key: "opengrep", rule_id: "python.shell-true",
  file_path: "app.py", commit_sha: "a".repeat(40), base_commit: "a".repeat(40), test_runner: "", provider: "self_hosted", model: "qwen-coder",
  transmitted_sha256: "b".repeat(64), summary: "Pass an argument list instead of a shell string.", diff, changed_files: ["app.py"],
  steps: [
    { key: "policy", label: "Diff confined to the finding's file", status: "passed", detail: "changes app.py (+1 −1 lines)" },
    { key: "apply", label: "Applied to a fresh checkout", status: "passed", detail: "1 hunk(s) applied" },
    { key: "scan", label: "Scanner opengrep re-run on the changed files", status: "passed", detail: "reported once before the fix and not after" },
    { key: "tests", label: "Repository tests", status: "skipped", detail: "no test runner is enabled for this repository" },
  ],
  scan_evidence: { scanner: "opengrep", scanner_version: "1.0", verdict: { reproduced: true, removed: true, new: [], before: [{ rule_id: "python.shell-true", file: "app.py", line: 3 }], after: [] } },
  has_reports: true, pull_request: null, requested_by: "ada@example.com", created_at: "2026-11-19T10:00:00Z", updated_at: "2026-11-19T10:01:00Z",
  finished_at: "2026-11-19T10:01:00Z",
};

describe("AI-proposed fixes", () => {
  it("proposes a fix, shows the diff and the verification steps, and opens a pull request only when asked", async () => {
    let state: AIFixEligibility = base;
    const api = mockApi({
      "GET /api/v1/findings/f1/ai-fixes": () => state,
      "POST /api/v1/findings/f1/ai-fixes": () => {
        state = { ...base, proposals: [verified] };
        return { ...verified, status: "generating" };
      },
      "POST /api/v1/ai-fixes/x1/pull-request": () => {
        state = { ...base, proposals: [{ ...verified, pull_request: { status: "open", pr_url: "https://github.com/acme/api/pull/7", pr_number: "7", error: "" } as never }] };
        return {};
      },
    });
    renderApp(<FindingAIFix findingId="f1" category="sast" />, { permissions: ["findings.read", "ai.fix"] });
    fireEvent.click(await screen.findByRole("button", { name: /Propose fix/ }));
    expect(await screen.findByText("Verified")).toBeInTheDocument();
    expect(screen.getByLabelText("Proposed diff")).toHaveTextContent("+ subprocess.call(shlex.split(cmd))");
    const steps = screen.getByRole("list", { name: "Verification steps" });
    expect(steps).toHaveTextContent("Scanner opengrep re-run on the changed files");
    expect(steps).toHaveTextContent("no test runner is enabled");
    expect(screen.getByRole("link", { name: /report before/ })).toHaveAttribute("href", "/api/v1/ai-fixes/x1/reports/before");
    expect(api.calls.some((c) => c.path.endsWith("/pull-request"))).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: /Open pull request/ }));
    const link = await screen.findByRole("link", { name: /#7/ });
    expect(link).toHaveAttribute("href", "https://github.com/acme/api/pull/7");
    expect(screen.queryByRole("button", { name: /Open pull request/ })).not.toBeInTheDocument();
    expect(screen.getByText(/resolved when a later scan/)).toBeInTheDocument();
  });

  it("shows a clear failure reason and no pull request button for a failed fix", async () => {
    const failed: AIFix = {
      ...verified, status: "failed", failure_reason: "the scanner still reports rule python.shell-true in app.py after the fix",
      steps: verified.steps.map((s) => (s.key === "scan" ? { ...s, status: "failed", detail: "the scanner still reports rule python.shell-true" } : s)),
    };
    mockApi({ "GET /api/v1/findings/f1/ai-fixes": () => ({ ...base, proposals: [failed] }) });
    renderApp(<FindingAIFix findingId="f1" category="sast" />, { permissions: ["findings.read", "ai.fix"] });
    expect(await screen.findByText("Verification failed")).toBeInTheDocument();
    expect(screen.getByText(/still reports rule python.shell-true in app.py after the fix/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Open pull request/ })).not.toBeInTheDocument();
  });

  it("explains why it is unavailable when no AI provider is configured", async () => {
    mockApi({
      "GET /api/v1/findings/f1/ai-fixes": () => ({ ...base, available: false, reason: "No AI provider is configured. AI fixes stay off until an administrator adds a provider." }),
    });
    renderApp(<FindingAIFix findingId="f1" category="secrets" />, { permissions: ["findings.read", "ai.fix"] });
    expect(await screen.findByText(/No AI provider is configured/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Propose fix/ })).not.toBeInTheDocument();
  });

  it("shows request errors such as the rate limit", async () => {
    mockApi({
      "GET /api/v1/findings/f1/ai-fixes": () => base,
      "POST /api/v1/findings/f1/ai-fixes": () => jsonResponse({ error: { code: "rate_limited", message: "the limit of 10 AI fix requests per user per hour was reached" } }, 429),
    });
    renderApp(<FindingAIFix findingId="f1" category="iac" />, { permissions: ["findings.read", "ai.fix"] });
    fireEvent.click(await screen.findByRole("button", { name: /Propose fix/ }));
    expect(await screen.findByText(/10 AI fix requests per user per hour/)).toBeInTheDocument();
  });

  it("renders nothing for dependency findings", () => {
    const api = mockApi({});
    const { container } = renderApp(<FindingAIFix findingId="f1" category="sca" />, { permissions: ["findings.read"] });
    expect(container.textContent).toBe("");
    expect(api.calls).toHaveLength(0);
  });

  it("saves the repository's test runner opt-in", async () => {
    const api = mockApi({
      "GET /api/v1/repositories/r1/ai-fix-settings": () => ({ test_runner: "" }),
      "PUT /api/v1/repositories/r1/ai-fix-settings": (_u, init) => init.json as object,
    });
    renderApp(<AIFixSettingsPanel r={{ id: "r1" } as Repository} />, { permissions: ["scans.read", "repos.manage"] });
    fireEvent.change(await screen.findByLabelText("Test runner"), { target: { value: "go" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.calls.find((c) => c.method === "PUT")?.body).toEqual({ test_runner: "go" }));
  });
});

import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import type { Repository } from "@/api/types";
import { mockApi, renderApp } from "@/test/harness";
import { PushProtectionPanel, type PushedSecret, type PushScan } from "./PushProtectionPanel";

afterEach(() => vi.unstubAllGlobals());

const repo = { id: "r1", full_name: "acme/payments", source_type: "scm" } as unknown as Repository;
const alert: PushedSecret = {
  id: "a1", push_scan_id: "p1", ref: "main", commit_sha: "0123456789abcdef0123456789abcdef01234567", file_path: "config/app.env", line: 3,
  rule_id: "github-token", description: "GitHub token", created_at: "2026-11-19T10:00:00Z",
};
const scan: PushScan = {
  id: "p1", ref: "main", before_sha: "", after_sha: "0123456789abcdef0123456789abcdef01234567", status: "done", error: "",
  files_scanned: 4, alerts: 1, created_at: "2026-11-19T10:00:00Z", finished_at: "2026-11-19T10:00:02Z",
};

describe("secret push protection panel", () => {
  it("shows alerts without values and lets a manager enable scanning", async () => {
    const api = mockApi({
      "GET /api/v1/repositories/r1/push-protection": () => ({ enabled: false, supported: true, provider: "github", source_type: "scm" }),
      "PUT /api/v1/repositories/r1/push-protection": () => ({ enabled: true, supported: true, provider: "github", source_type: "scm" }),
      "GET /api/v1/repositories/r1/pushed-secrets": () => ({ items: [alert], scans: [scan] }),
    });
    renderApp(<PushProtectionPanel r={repo} />, { permissions: ["scans.read", "findings.read", "repos.manage"] });
    expect(await screen.findByText("GitHub token")).toBeInTheDocument();
    expect(screen.getByText("config/app.env:3")).toBeInTheDocument();
    expect(screen.getByText(/4 files, 1 alerts/)).toBeInTheDocument();
    const box = await screen.findByRole("checkbox", { name: "Scan pushes for secrets" });
    fireEvent.click(box);
    await waitFor(() => expect(api.calls.some((c) => c.method === "PUT" && (c.body as { enabled: boolean }).enabled === true)).toBe(true));
    await waitFor(() => expect(screen.getByRole("checkbox", { name: "Scan pushes for secrets" })).toBeChecked());
  });

  it("is read-only without repos.manage and explains unsupported providers", async () => {
    mockApi({
      "GET /api/v1/repositories/r1/push-protection": () => ({ enabled: false, supported: false, provider: "bitbucket", source_type: "scm" }),
      "GET /api/v1/repositories/r1/pushed-secrets": () => ({ items: [], scans: [] }),
    });
    renderApp(<PushProtectionPanel r={repo} />, { permissions: ["scans.read", "findings.read"] });
    expect(await screen.findByRole("checkbox", { name: "Scan pushes for secrets" })).toBeDisabled();
    expect(screen.getByText(/use the pre-receive hook for other servers/)).toBeInTheDocument();
  });
});

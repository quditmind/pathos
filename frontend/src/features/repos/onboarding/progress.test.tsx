import { afterEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import type { ImportItem, ImportJob, ImportStatus } from "@/api/types";
import { mockApi, renderApp } from "@/test/harness";
import { importPollInterval } from "./api";
import { ImportJobView } from "./ImportJobPage";

function item(status: ImportStatus, over: Partial<ImportItem> = {}): ImportItem {
  return {
    id: "i1", position: 0, display_name: "payments-api", status, result: status === "completed" ? "imported" : "", progress: 40, progress_message: "Fetching metadata",
    error_code: "", error_message: "", attempts: 1, max_attempts: 3, repository_id: status === "completed" ? "r1" : null, snapshot_id: null, started_at: null,
    completed_at: null, can_retry: false, ...over,
  };
}

function job(status: ImportStatus, items: ImportItem[]): ImportJob {
  return {
    id: "j1", source_type: "git", scm_connection_id: "c1", scm_connection_name: "GitHub", status, requested_by: { id: "u1", name: "Ada", email: "ada@example.com" },
    total_items: items.length, completed_items: items.filter((i) => i.status === "completed").length, failed_items: items.filter((i) => i.status === "failed").length,
    attention_items: 0, start_scan: false, created_at: "2026-01-01T00:00:00Z", started_at: null, completed_at: null, items,
    can_cancel: status !== "completed", can_retry: items.some((i) => i.can_retry),
  };
}

describe("import progress", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("polls every 2 s only while the job or an item is active", () => {
    expect(importPollInterval(job("importing", [item("importing")]))).toBe(2000);
    expect(importPollInterval(job("queued", [item("queued")]))).toBe(2000);
    expect(importPollInterval(job("completed", [item("completed")]))).toBe(false);
    expect(importPollInterval(job("failed", [item("failed")]))).toBe(false);
    expect(importPollInterval(job("needs_attention", [item("needs_attention")]))).toBe(false);
    expect(importPollInterval(job("cancelled", [item("cancelled")]))).toBe(false);
    // A terminal job status with a still-running item keeps polling.
    expect(importPollInterval(job("completed", [item("registering")]))).toBe(2000);
    expect(importPollInterval(undefined)).toBe(false);
  });

  it("stops polling when every item reaches a terminal status", async () => {
    let n = 0;
    const { calls } = mockApi({
      "GET /api/v1/repository-imports/j1": () => {
        n++;
        return n === 1 ? job("importing", [item("importing")]) : job("completed", [item("completed")]);
      },
    });
    renderApp(<ImportJobView id="j1" />);
    expect(await screen.findByText("Updating every 2 seconds…")).toBeInTheDocument();
    expect(screen.getByText("Fetching metadata")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Up to date")).toBeInTheDocument(), { timeout: 4000 });
    expect(screen.getByRole("link", { name: /Repository/ })).toBeInTheDocument();
    const after = calls.length;
    await new Promise((r) => setTimeout(r, 2600));
    expect(calls.length).toBe(after);
    expect(after).toBe(2);
  }, 12_000);

  it("offers per-item retry and duplicate override", async () => {
    mockApi({
      "GET /api/v1/repository-imports/j1": () =>
        job("needs_attention", [item("needs_attention", { error_code: "duplicate", error_message: "Same archive already imported", can_retry: true })]),
    });
    renderApp(<ImportJobView id="j1" />);
    expect(await screen.findByText("Same archive already imported")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import anyway" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Retry all failed/ })).toBeInTheDocument();
    expect(screen.getAllByText("Needs attention").length).toBeGreaterThan(0);
  });
});

import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { ImportResultsPage } from "./ImportResultsPage";
import { CustomRulesPage } from "./CustomRulesPage";

afterEach(() => vi.unstubAllGlobals());

describe("import results", () => {
  it("lists imports with their outcome and execution", async () => {
    mockApi({
      "GET /api/v1/imports/history": () => ({
        items: [
          { id: "i1", kind: "results", format: "sarif", tool: "Snyk Code", category: "sast", repository_id: "r1", repository_name: "acme/api", scan_job_id: "j1",
            scan_key: "QD-SCAN-000042", file_name: "snyk.sarif", sha256: "x", size_bytes: 10, commit_sha: "", resolve_missing: false, status: "succeeded", records: 12,
            error: "", created_by: "Ada", created_at: "2026-11-17T10:00:00Z" },
          { id: "i2", kind: "sbom", format: "cyclonedx", tool: "", category: "", repository_id: "r1", repository_name: "acme/api", scan_job_id: null, scan_key: null,
            file_name: "bom.json", sha256: "y", size_bytes: 10, commit_sha: "", resolve_missing: false, status: "failed", records: 0,
            error: "unrecognised SBOM", created_by: "Ada", created_at: "2026-11-17T09:00:00Z" },
        ],
      }),
    });
    renderApp(<ImportResultsPage />, { permissions: ["scans.read", "scans.run"] });
    expect(await screen.findByText("12 findings")).toBeInTheDocument();
    expect(screen.getByText("QD-SCAN-000042")).toBeInTheDocument();
    expect(screen.getByText(/Failed: unrecognised SBOM/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Import results/ })).toBeDisabled();
  });

  it("is read-only without scans.run", async () => {
    mockApi({ "GET /api/v1/imports/history": () => ({ items: [] }) });
    renderApp(<ImportResultsPage />, { permissions: ["scans.read"] });
    expect(await screen.findByText(/Importing needs the scans.run permission/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Import results/ })).toBeNull();
  });
});

describe("custom rules", () => {
  it("validates and creates a rule file", async () => {
    const api = mockApi({
      "GET /api/v1/custom-rules": () => ({ items: [] }),
      "POST /api/v1/custom-rules/validate": () => ({ valid: true, rule_ids: ["acme.java.hardcoded-secret-key"] }),
      "POST /api/v1/custom-rules": (_u, init) => ({ id: "c1", name: (init.json as { name: string }).name, rule_ids: ["acme.java.hardcoded-secret-key"], enabled: true, version: 1,
        engine: "opengrep", description: "", updated_by: "Ada", updated_at: "2026-11-17T10:00:00Z" }),
      "GET /api/v1/custom-rules/c1": () => ({ id: "c1", name: "Acme", content: "rules: []", rule_ids: [], enabled: true, version: 1, engine: "opengrep", description: "",
        updated_by: "Ada", updated_at: "" }),
      "GET /api/v1/custom-rules/c1/versions": () => ({ items: [] }),
    });
    renderApp(<CustomRulesPage />, { permissions: ["scanners.read", "profiles.manage"] });
    fireEvent.click(await screen.findByRole("button", { name: /New rule file/ }));
    fireEvent.click(screen.getByRole("button", { name: "Validate" }));
    expect(await screen.findByText(/Valid: acme.java.hardcoded-secret-key/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Acme" } });
    fireEvent.click(screen.getByRole("button", { name: "Create rule file" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/custom-rules")).toBe(true));
    expect(api.calls.find((c) => c.method === "POST" && c.path === "/api/v1/custom-rules")!.body).toMatchObject({ name: "Acme", enabled: true });
  });

  it("hides editing without profiles.manage", async () => {
    mockApi({ "GET /api/v1/custom-rules": () => ({ items: [] }) });
    renderApp(<CustomRulesPage />, { permissions: ["scanners.read"] });
    expect(await screen.findByText("No custom rules")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /New rule file/ })).toBeNull();
  });
});

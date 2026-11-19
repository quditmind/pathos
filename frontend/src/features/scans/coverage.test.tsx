import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import type { CatalogScanner, ScanTypeCoverage, ScanTypesResponse } from "@/api/types";
import { mockApi, renderApp } from "@/test/harness";
import { ScanCoveragePage } from "./ScanCoveragePage";
import { ScanTargetsPage, targetTools, type ScanTarget } from "./ScanTargetsPage";

afterEach(() => vi.unstubAllGlobals());

const tool = (key: string, name: string, extra: Partial<ScanTypeCoverage["tools"][number]> = {}) => ({
  key, name, category: "sast", license_spdx: "Apache-2.0", source: "catalog" as const, adapter_available: true, runnable: false, workers: 0,
  network: "none", intrusive: false, targets: ["repository"], decision: "use", ...extra,
});

const types: ScanTypesResponse = {
  workers_online: 2,
  generic_import_formats: [{ id: "sarif", label: "SARIF 2.1", tool: "" }],
  items: [
    {
      id: "sast", name: "SAST", description: "Static analysis", categories: ["sast"], tools: [tool("opengrep", "Opengrep", { runnable: true, workers: 2 }), tool("bandit", "Bandit")],
      import_formats: [{ id: "semgrep", label: "Semgrep / Opengrep JSON", tool: "Semgrep" }], runnable_tools: 1, runnable: true, importable: true,
    },
    { id: "iast", name: "IAST", description: "Interactive testing", categories: ["iast"], tools: [], import_formats: [], runnable_tools: 0, runnable: false, importable: false },
    {
      id: "fuzzing", name: "Fuzzing", description: "Generated inputs", categories: ["fuzz"],
      tools: [tool("plugin-dast-fuzz", "Fuzz", { source: "plugin", runnable: true, workers: 1, intrusive: true, network: "target", targets: ["url"] })],
      import_formats: [], runnable_tools: 1, runnable: true, importable: false,
    },
  ],
};

describe("scan coverage", () => {
  it("shows each scan type with its tools, import formats and live workers from the API", async () => {
    mockApi({ "GET /api/v1/scan-types": () => types });
    renderApp(<ScanCoveragePage />, { permissions: ["scanners.read"] });
    expect(await screen.findByText("SAST")).toBeInTheDocument();
    expect(screen.getByText("2 of 3")).toBeInTheDocument(); // runnable scan types
    expect(screen.getByText("1 of 2 runnable")).toBeInTheDocument();
    expect(screen.getByText("Semgrep / Opengrep JSON")).toBeInTheDocument();
    expect(screen.getByText("No tool integrated")).toBeInTheDocument();
    expect(screen.getByText(/Generic formats for every type: SARIF 2.1/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Fuzzing details" }));
    expect(await screen.findByText("intrusive")).toBeInTheDocument();
    expect(screen.getByText("operator plugin")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Filter scan types"), { target: { value: "none" } });
    await waitFor(() => expect(screen.queryByText("SAST")).toBeNull());
    expect(screen.getByText("IAST")).toBeInTheDocument();
  });
});

const catalog: Partial<CatalogScanner>[] = [
  { key: "nuclei", name: "Nuclei", worker_family: "core", adapter_available: true, targets: ["url", "api"], network: "target" },
  { key: "plugin-dast-fuzz", name: "Fuzz", worker_family: "plugin", adapter_available: true, runnable: true, targets: ["url"], network: "target", intrusive: true },
  { key: "bandit", name: "Bandit", worker_family: "sast", adapter_available: true, targets: ["repository"] },
];

const web: ScanTarget = {
  id: "t1", kind: "url", name: "Payments staging", reference: "https://staging.payments.example", repository_id: "r1", repository_name: "acme/payments",
  egress_host: "staging.payments.example", config: {}, sbom_format: "", sbom_components: 0, sbom_size: 0, auth_type: "none", auth_username: "",
  auth_header_name: "", has_secret: false, authorized_by: "Ada", authorized_at: "2026-11-17T10:00:00Z", authorization_note: "", enabled: true,
  scanners: ["nuclei"], created_by: "Ada", created_at: "2026-11-17T10:00:00Z", updated_at: "2026-11-17T10:00:00Z", open_findings: 0, last_scan: null,
};

describe("target tools", () => {
  it("offers family and plugin tools for the target kind only", () => {
    const list = catalog as CatalogScanner[];
    expect(targetTools(list, "url").map((t) => t.key)).toEqual(["plugin-dast-fuzz"]);
    expect(targetTools(list, "image")).toEqual([]);
  });

  it("selects an intrusive tool and authorizes intrusive testing separately", async () => {
    const api = mockApi({
      "GET /api/v1/scan-targets": () => ({ items: [web] }),
      "GET /api/v1/scan-targets/t1": () => web,
      "GET /api/v1/scanners": () => ({ items: catalog }),
      "PUT /api/v1/scan-targets/t1": (_u, init) => ({ ...web, ...(init.json as object) }),
    });
    renderApp(<ScanTargetsPage />, { permissions: ["scans.read", "repos.manage"] });
    fireEvent.click(await screen.findByRole("button", { name: "Edit Payments staging" }));
    fireEvent.click(await screen.findByLabelText(/Fuzz/));
    expect(screen.getByText(/scans of this target are refused until intrusive testing is authorized/)).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/Intrusive testing of this application is authorized/));
    fireEvent.change(screen.getByLabelText(/Intrusive testing reference/), { target: { value: "PT-77" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "PUT")).toBe(true));
    const body = api.calls.find((c) => c.method === "PUT")!.body as Record<string, unknown>;
    expect(body).toMatchObject({ intrusive_authorized: true, intrusive_authorization_note: "PT-77", config: { tools: ["plugin-dast-fuzz"] } });
  });
});

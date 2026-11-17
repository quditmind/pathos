import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { ScanTargetsPage, type ScanTarget } from "./ScanTargetsPage";

afterEach(() => vi.unstubAllGlobals());

const base: Omit<ScanTarget, "id" | "kind" | "name" | "reference"> = {
  repository_id: "r1", repository_name: "acme/payments", egress_host: "", config: {}, sbom_format: "", sbom_components: 0, sbom_size: 0,
  auth_type: "none", auth_username: "", auth_header_name: "", has_secret: false, authorized_by: null, authorized_at: null, authorization_note: "",
  enabled: true, scanners: [], created_by: "Ada", created_at: "2026-11-17T10:00:00Z", updated_at: "2026-11-17T10:00:00Z", open_findings: 0, last_scan: null,
};

const web: ScanTarget = {
  ...base, id: "t1", kind: "url", name: "Payments staging", reference: "https://staging.payments.example", egress_host: "staging.payments.example",
  auth_type: "header", auth_header_name: "Authorization", has_secret: true, authorized_by: "Ada", authorized_at: "2026-11-17T10:00:00Z",
  authorization_note: "CHG-1", open_findings: 3, scanners: ["nuclei"],
  last_scan: { id: "j9", scan_key: "QD-SCAN-000090", status: "succeeded", queued_at: "2026-11-17T10:00:00Z", finished_at: "2026-11-17T10:05:00Z", error: "" },
};
const sbom: ScanTarget = { ...base, id: "t2", kind: "sbom", name: "Vendor appliance", reference: "vendor.cdx.json", sbom_format: "cyclonedx", sbom_components: 412, scanners: ["grype"] };

describe("scan targets", () => {
  it("lists targets with authorization, findings and last scan, and queues a scan", async () => {
    const api = mockApi({
      "GET /api/v1/scan-targets": () => ({ items: [web, sbom] }),
      "POST /api/v1/scan-targets/t1/scan": () => ({ job_id: "j10", coalesced: false }),
    });
    renderApp(<ScanTargetsPage />, { permissions: ["scans.read", "scans.run", "repos.manage"] });
    expect(await screen.findByText("Payments staging")).toBeInTheDocument();
    expect(screen.getByText(/Authorized by Ada/)).toBeInTheDocument();
    expect(screen.getByText("3 open")).toBeInTheDocument();
    expect(screen.getByText("QD-SCAN-000090")).toBeInTheDocument();
    expect(screen.getByText(/CYCLONEDX · 412 components/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Scan Payments staging" }));
    expect(await screen.findByText(/Scan queued/)).toBeInTheDocument();
    expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/scan-targets/t1/scan")).toBe(true);
  });

  it("requires a new authorization when a DAST target's address changes and never resends the stored secret", async () => {
    const api = mockApi({
      "GET /api/v1/scan-targets": () => ({ items: [web] }),
      "GET /api/v1/scan-targets/t1": () => web,
      "PUT /api/v1/scan-targets/t1": (_u, init) => ({ ...web, ...(init.json as object) }),
    });
    renderApp(<ScanTargetsPage />, { permissions: ["scans.read", "repos.manage"] });
    fireEvent.click(await screen.findByRole("button", { name: "Edit Payments staging" }));
    const ref = await screen.findByLabelText("Base URL");
    fireEvent.change(ref, { target: { value: "https://prod.payments.example" } });
    const save = screen.getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I am authorized to security-test this application at its new address/));
    expect(save).toBeEnabled();
    fireEvent.click(save);
    await waitFor(() => expect(api.calls.some((c) => c.method === "PUT")).toBe(true));
    const body = api.calls.find((c) => c.method === "PUT")!.body as Record<string, unknown>;
    expect(body).toMatchObject({ reference: "https://prod.payments.example", authorized: true });
    expect(body).not.toHaveProperty("auth_secret");
  });

  it("is read-only without management permissions", async () => {
    mockApi({ "GET /api/v1/scan-targets": () => ({ items: [web] }) });
    renderApp(<ScanTargetsPage />, { permissions: ["scans.read"] });
    expect(await screen.findByText("Payments staging")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Add target/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Scan Payments staging/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Edit/ })).toBeNull();
  });
});

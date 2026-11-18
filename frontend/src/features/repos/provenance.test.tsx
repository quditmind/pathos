import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { render } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import type { Repository, ScanChangeSummary } from "@/api/types";
import { EndpointVerificationSection, type EndpointVerificationState } from "./EndpointVerification";
import { EndOfLifePanel, type RepositoryEOL } from "@/features/posture/EndOfLifePanel";
import { IntroducedBy } from "@/features/findings/IntroducedBy";
import { ChangeSummaryCard } from "@/features/scans/details/OverviewTab";
import { ScanTargetsPage, signaturePayload, type ScanTarget } from "@/features/scans/ScanTargetsPage";

afterEach(() => vi.unstubAllGlobals());

const repo = { id: "r1", full_name: "acme/shop", archived_at: null, can_manage: true } as unknown as Repository;

const state = (over: Partial<EndpointVerificationState> = {}): EndpointVerificationState => ({
  configured: false, enabled: false, scan_target_id: null, authorized_by: null, authorized_at: null, authorization_note: "", rate_limit: 2,
  nuclei: false, offline: false, open_findings: 0, last_scan: null, unauthorized: 0,
  endpoints: [
    { kind: "url", value: "https://shop.acme.example", authorized: false, status: "not_checked", detail: "", checks: {}, checked_at: null, scan_job_id: null },
    { kind: "domain", value: "api.acme.example", authorized: false, status: "not_checked", detail: "", checks: {}, checked_at: null, scan_job_id: null },
  ],
  ...over,
});

describe("endpoint verification", () => {
  it("is enabled only with an authorization statement", async () => {
    const api = mockApi({
      "GET /api/v1/repositories/r1/endpoint-verification": () => state(),
      "PUT /api/v1/repositories/r1/endpoint-verification": () => state({ configured: true, enabled: true }),
    });
    renderApp(<EndpointVerificationSection r={repo} />, { permissions: ["repos.manage", "scans.run", "scans.read"] });
    expect(await screen.findByText("https://shop.acme.example")).toBeInTheDocument();
    expect(screen.getAllByText("Not checked")).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: /Enable/ }));
    const enable = await screen.findByRole("button", { name: "Enable verification" });
    expect(enable).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I am authorized to test these endpoints/));
    fireEvent.change(screen.getByLabelText(/Authorization reference/), { target: { value: "CHG-9" } });
    expect(enable).toBeEnabled();
    fireEvent.click(enable);
    await waitFor(() => expect(api.calls.some((c) => c.method === "PUT")).toBe(true));
    expect(api.calls.find((c) => c.method === "PUT")!.body).toMatchObject({ enabled: true, authorized: true, authorization_note: "CHG-9", rate_limit: 2, nuclei: false });
  });

  it("shows results, unauthorized endpoints and runs a verification", async () => {
    const api = mockApi({
      "GET /api/v1/repositories/r1/endpoint-verification": () =>
        state({
          configured: true, enabled: true, scan_target_id: "t9", authorized_by: "Ada", authorized_at: "2026-11-18T10:00:00Z", open_findings: 2, unauthorized: 1,
          endpoints: [
            { kind: "url", value: "https://shop.acme.example", authorized: true, status: "verified", detail: "", checked_at: "2026-11-18T11:00:00Z", scan_job_id: "j1",
              checks: { tls: { protocol: "TLS 1.3", legacy_protocols: ["TLS 1.0"], certificate: { days_remaining: 12, trusted: true, hostname_match: true } } } },
            { kind: "domain", value: "api.acme.example", authorized: true, status: "dns_failed", detail: "egress proxy answered 503", checks: {}, checked_at: "2026-11-18T11:00:00Z", scan_job_id: "j1" },
            { kind: "ip", value: "203.0.113.7", authorized: false, status: "skipped", detail: "not covered", checks: {}, checked_at: null, scan_job_id: null },
          ],
        }),
      "POST /api/v1/repositories/r1/endpoint-verification/run": () => ({ job_id: "j2", coalesced: false }),
    });
    renderApp(<EndpointVerificationSection r={repo} />, { permissions: ["repos.manage", "scans.run", "scans.read"] });
    expect(await screen.findByText("Verified")).toBeInTheDocument();
    expect(screen.getByText("DNS failure")).toBeInTheDocument();
    expect(screen.getByText(/TLS 1.3 · certificate 12 days left · accepts TLS 1.0/)).toBeInTheDocument();
    expect(screen.getByText(/1 declared endpoint is not covered/)).toBeInTheDocument();
    expect(screen.getByText("2 open findings")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Verify now/ }));
    expect(await screen.findByText(/Verification queued/)).toBeInTheDocument();
    expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/repositories/r1/endpoint-verification/run")).toBe(true);
  });

  it("is disabled offline and read-only without permissions", async () => {
    mockApi({ "GET /api/v1/repositories/r1/endpoint-verification": () => state({ configured: true, enabled: true, offline: true }) });
    renderApp(<EndpointVerificationSection r={{ ...repo, can_manage: false } as Repository} />, { permissions: ["scans.read"] });
    expect(await screen.findByText(/PATHOS runs offline/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Verify now/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Settings|Enable/ })).toBeNull();
  });
});

describe("end of life", () => {
  it("lists end-of-life and approaching releases", async () => {
    const data: RepositoryEOL = {
      feed_loaded: true, feed_as_of: "2026-11-18", eol: 1, approaching: 1, supported: 3, computed_at: "2026-11-18T12:00:00Z",
      items: [
        { source: "runtime", component: "node", version: "16.20.0", path: ".nvmrc", product: "nodejs", product_label: "Node.js", cycle: "16", eol_date: "2023-09-11", status: "eol" },
        { source: "sbom", component: "django", version: "4.2.1", product: "django", product_label: "Django", cycle: "4.2", eol_date: "2027-04-07", status: "approaching", latest_in_cycle: "4.2.20" },
        { source: "image", component: "python:3.13", version: "3.13", product: "python", product_label: "Python", cycle: "3.13", eol_date: "2029-10-31", status: "supported" },
      ],
    };
    mockApi({ "GET /api/v1/repositories/r1/eol": () => data });
    renderApp(<EndOfLifePanel repoId="r1" />, { permissions: ["sbom.read"] });
    expect(await screen.findByRole("heading", { name: /End of life/ })).toBeInTheDocument();
    expect(screen.getByText(/1 end-of-life · 1 within six months · 3 supported/)).toBeInTheDocument();
    expect(screen.getByText("Node.js 16")).toBeInTheDocument();
    expect(screen.getByText(/Declared runtime/)).toBeInTheDocument();
    expect(screen.getByText("EOL 2027-04-07")).toBeInTheDocument();
    expect(screen.queryByText("python:3.13")).toBeNull();
  });

  it("explains when the feed is not loaded", async () => {
    mockApi({ "GET /api/v1/repositories/r1/eol": () => ({ feed_loaded: false, feed_as_of: "", eol: 0, approaching: 0, supported: 0, computed_at: null, items: [] }) });
    renderApp(<EndOfLifePanel repoId="r1" />, { permissions: ["sbom.read"] });
    expect(await screen.findByText(/enables the endoflife.date feed/)).toBeInTheDocument();
  });
});

describe("introducing commits and change summaries", () => {
  it("shows the introducing commit or why it is unknown", () => {
    const { rerender } = render(
      <dl><IntroducedBy f={{ introduced_status: "known", introduced_commit_sha: "3f6c1d2e9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d", introduced_author: "Dana", introduced_at: "2026-01-02T03:04:05Z" }} /></dl>,
    );
    expect(screen.getByTestId("introduced-by")).toHaveTextContent("commit 3f6c1d2e9a8b by Dana");
    rerender(<dl><IntroducedBy f={{ introduced_status: "shallow_clone" }} /></dl>);
    expect(screen.getByText("Unknown (shallow clone)")).toBeInTheDocument();
    rerender(<dl><IntroducedBy f={{ introduced_status: "" }} /></dl>);
    expect(screen.queryByTestId("introduced-by")).toBeNull();
  });

  it("summarizes new and fixed findings since the previous commit", async () => {
    const c: ScanChangeSummary = { base_commit: "a".repeat(40), base_scan_id: "j0", head_commit: "b".repeat(40), new: { critical: 1, high: 2 }, fixed: { medium: 4 }, new_total: 3, fixed_total: 4 };
    renderApp(<ChangeSummaryCard c={c} />);
    const card = await screen.findByTestId("change-summary");
    expect(card).toHaveTextContent("aaaaaaaaaaaa");
    expect(card).toHaveTextContent("bbbbbbbbbbbb");
    expect(card).toHaveTextContent("+3");
    expect(card).toHaveTextContent("−4");
    expect(screen.getByRole("link", { name: "previous scan" })).toBeInTheDocument();
  });
});

describe("signature verification", () => {
  const image: ScanTarget = {
    id: "t1", kind: "image", name: "API image", reference: "ghcr.io/acme/api:1", repository_id: "r1", repository_name: "acme/api", egress_host: "ghcr.io",
    config: {}, sbom_format: "", sbom_components: 0, sbom_size: 0, auth_type: "none", auth_username: "", auth_header_name: "", has_secret: false,
    authorized_by: null, authorized_at: null, authorization_note: "", enabled: true, scanners: ["trivy-image"], created_by: null,
    created_at: "2026-11-17T10:00:00Z", updated_at: "2026-11-17T10:00:00Z", open_findings: 0, last_scan: null,
    last_verification: { status: "unsigned", mode: "keyless", required: true, attestation_status: "", details: { detail: "no signatures found" }, scan_job_id: "j1", verified_at: "2026-11-18T10:00:00Z" },
  };

  it("shows the latest evidence and saves a keyless policy", async () => {
    const api = mockApi({
      "GET /api/v1/scan-targets": () => ({ items: [image] }),
      "GET /api/v1/scan-targets/t1": () => image,
      "PUT /api/v1/scan-targets/t1": () => image,
    });
    renderApp(<ScanTargetsPage />, { permissions: ["scans.read", "repos.manage"] });
    expect(await screen.findByText("Signature unsigned")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Edit API image" }));
    fireEvent.change(await screen.findByLabelText("Verify"), { target: { value: "keyless" } });
    const save = screen.getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Identity regular expression/), { target: { value: "^https://github.com/acme/" } });
    fireEvent.change(screen.getByLabelText("OIDC issuer"), { target: { value: "https://token.actions.githubusercontent.com" } });
    fireEvent.change(screen.getByLabelText(/Attestation to verify/), { target: { value: "slsaprovenance" } });
    fireEvent.click(screen.getByLabelText(/Require a valid signature/));
    expect(save).toBeEnabled();
    fireEvent.click(save);
    await waitFor(() => expect(api.calls.some((c) => c.method === "PUT")).toBe(true));
    expect(api.calls.find((c) => c.method === "PUT")!.body).toMatchObject({
      config: { signature: { mode: "keyless", identity_regexp: "^https://github.com/acme/", issuer: "https://token.actions.githubusercontent.com", require: true, attestation: "slsaprovenance" } },
    });
  });

  it("sends only the fields of the selected mode", () => {
    expect(signaturePayload({ mode: "" })).toBeUndefined();
    expect(signaturePayload({ mode: "key", public_key: "PEM", identity: "x", issuer: "y" })).toEqual({ mode: "key", public_key: "PEM", require: false, attestation: undefined, ignore_tlog: false });
  });
});

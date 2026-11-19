import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import type { AssetSettings, Classification, Repository, RepositoryInsights } from "@/api/types";
import { mockApi, renderApp } from "@/test/harness";
import { AssetSettingsPage } from "@/features/assets/AssetSettingsPage";
import { ScmConnectionsPage } from "@/features/settings/ScmConnectionsPage";
import { RepositoriesPage } from "./RepositoriesPage";
import { ImportLandingPage } from "./onboarding/ImportLandingPage";

const cls = (kind: Classification["kind"], key: string, label: string, color = ""): Classification => ({
  id: `${kind}-${key}`, kind, key, label, description: `${label} description`, color, sort_order: 10, is_system: true, archived: false,
});

const settings: AssetSettings = {
  required_fields: ["business_owner"],
  always_required: ["criticality"],
  scan_on_import: true,
  classifications: {
    criticality: [cls("criticality", "critical", "Mission critical", "#b42318")],
    data_classification: [cls("data_classification", "confidential", "Confidential")],
    environment: [cls("environment", "production", "Production")],
    application_type: [],
    internet_exposure: [],
    compliance: [cls("compliance", "pci", "PCI DSS")],
    hosting_region: [cls("hosting_region", "eu-west-1", "AWS eu-west-1")],
    lifecycle_status: [cls("lifecycle_status", "active", "Active", "#1e7b45")],
    authentication_model: [],
  },
  upload: { max_bytes: 2 ** 31, chunk_size: 8 * 2 ** 20, formats: ["zip", "tar", "tar.gz"] },
  suggested_colors: [{ key: "critical", label: "Mission critical", color: "#b42318" }],
  repository_key_prefix: "QD-REPO",
};

const insights: RepositoryInsights = {
  totals: {
    total: 12, active: 10, archived: 2, critical: 3, without_business_owner: 4, without_technical_owner: 5, production: 6, confidential_or_restricted: 2,
    pending_imports: 1, failed_imports: 1, sync_failures: 0, last_successful_sync_at: null,
    publicly_exposed: 7, not_public: 3, exposure_unknown: 2, missing_production_url: 8, missing_ownership: 6,
  },
  by_provider: [{ key: "github", label: "GitHub", count: 7 }], by_business_region: [], by_business_unit: [], by_business_owner: [],
  by_criticality: [{ key: "critical", label: "Mission critical", count: 3, color: "#b42318" }], by_data_classification: [], by_environment: [], by_compliance: [], by_lifecycle: [],
  by_public_exposure: [{ key: "yes", label: "Yes", count: 7, color: "#cf222e" }, { key: "no", label: "No", count: 3, color: "#2da44e" }],
};

const repo = {
  id: "r1", scm_connection_id: null, scm_connection_name: "", provider: "upload", source_type: "upload", scm_organization: "", scm_project: "", external_id: "", full_name: "payments-api",
  name: "payments-api", url: "", default_branch: "", scan_branch: "", visibility: "private", description: "", technologies: [], application: null, business_unit: null, country: null,
  region: null, environment: "production", criticality: "critical", scan_enabled: true, scan_profile_id: null, remote_archived: false, last_pushed_at: null, archived_at: null,
  created_at: "2026-01-01T00:00:00Z", tags: [], display_name: "Payments API", asset_name: "payments-api", business_purpose: "", application_type: "", business_owner: { id: "u2", name: "Grace", email: "g@x" },
  technical_owner: null, application_owner: null, responsible_team: null, supporting_team: null, department: null, cost_centre: "", business_region: null, data_residency_region: null,
  hosting_region: "", operational_location: "", data_classification: "confidential", internet_exposure: "", compliance_scopes: ["pci"], lifecycle_status: "active", go_live_date: null,
  retirement_date: null, color: "#1f6feb", full_history: false, latest_commit_sha: "", latest_commit_at: null, size_bytes: 1024, file_count: 3, languages: { Go: 100 }, last_sync_at: null,
  last_sync_ok_at: null, sync_status: "ok", sync_error: "", current_snapshot: null, can_edit: true, can_manage: true,
  repository_key: "QD-REPO-000042", staging_url: "https://staging.pay.example.com", production_url: "https://pay.example.com", public_exposure: "yes",
  public_urls: ["https://pay.example.com"], public_domains: ["*.pay.example.com"], public_ips: [], exposure_notes: "Behind the CDN",
  registered_by: { id: "u1", name: "Ada", email: "ada@example.com" }, updated_at: "2026-02-01T00:00:00Z", last_scan_status: "succeeded", last_scan_at: "2026-02-02T00:00:00Z",
} satisfies Repository;

function routes() {
  return {
    "GET /api/v1/asset-settings": () => settings,
    "GET /api/v1/repositories": () => ({ items: [repo] }),
    "GET /api/v1/repositories/insights": () => insights,
    "GET /api/v1/repositories/r1": () => repo,
    "GET /api/v1/repositories/r1/sync-runs": () => ({ items: [] }),
    "GET /api/v1/repositories/r1/snapshots": () => ({ items: [] }),
    "GET /api/v1/scm-providers": () => ({ items: [] }),
    "GET /api/v1/scm-connections": () => ({ items: [] }),
    "GET /api/v1/scm-oauth-apps": () => ({ items: [] }),
    "GET /api/v1/applications": () => ({ items: [] }),
    "GET /api/v1/business-units": () => ({ items: [] }),
    "GET /api/v1/regions": () => ({ items: [] }),
    "GET /api/v1/tag-categories": () => ({ items: [] }),
  };
}

describe("page smoke tests", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("repositories page shows KPIs, new columns and the drawer metadata", async () => {
    mockApi(routes());
    const { router } = renderApp(<RepositoriesPage />, { permissions: ["repos.read", "repos.manage"], path: "/repositories" });
    expect((await screen.findAllByText("Payments API")).length).toBeGreaterThan(0);
    expect(await screen.findByRole("link", { name: /No business owner: 4/ })).toBeInTheDocument();
    expect(screen.getAllByText("Confidential").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Mission critical").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Grace").length).toBeGreaterThan(0);
    await router.navigate({ to: "/repositories", search: { repo: "r1" } as never });
    expect(await screen.findByRole("button", { name: /Edit metadata/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Source" }));
    expect(await screen.findByRole("button", { name: /Upload new version/ })).toBeInTheDocument();
  });

  it("repositories page shows the Repository ID, application URL, exposure and last scan, with copy", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    mockApi(routes());
    const { router } = renderApp(<RepositoriesPage />, { permissions: ["repos.read", "repos.manage"], path: "/repositories" });
    expect(await screen.findByRole("columnheader", { name: "Repository ID" })).toBeInTheDocument();
    const headers = screen.getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers.indexOf("Repository ID")).toBe(headers.indexOf("Repository") - 1);
    expect(headers).toEqual(expect.arrayContaining(["Production URL", "Public exposure", "Last scan"]));
    expect(headers).not.toContain("Staging URL");
    const row = screen.getByText("QD-REPO-000042").closest("tr")!;
    expect(within(row).getByText("QD-REPO-000042")).toHaveClass("font-mono");
    const prod = within(row).getByRole("link", { name: /pay\.example\.com/ });
    expect(prod).toHaveAttribute("href", "https://pay.example.com");
    expect(prod).toHaveAttribute("target", "_blank");
    expect(prod).toHaveAttribute("rel", "noopener noreferrer");
    expect(within(row).getByText("Public")).toBeInTheDocument();
    expect(within(row).getByText("succeeded")).toBeInTheDocument();

    // Copying the ID does not open the drawer.
    fireEvent.click(within(row).getByRole("button", { name: "Copy Repository ID QD-REPO-000042" }));
    expect(writeText).toHaveBeenCalledWith("QD-REPO-000042");
    expect(router.state.location.search).not.toHaveProperty("repo");

    // KPI cards link to the filtered list.
    expect(screen.getByRole("link", { name: /Publicly exposed: 7/ })).toHaveAttribute("href", "/repositories?public_exposure=yes");
    expect(screen.getByRole("link", { name: /Unknown exposure: 2/ })).toHaveAttribute("href", "/repositories?public_exposure=unknown");
    expect(screen.getByRole("link", { name: /Missing production URL: 8/ })).toHaveAttribute("href", "/repositories?missing_production_url=true");
    expect(screen.getByRole("link", { name: /Missing ownership: 6/ })).toHaveAttribute("href", "/repositories?missing_owner=any");

    // The drawer shows the ID read-only with a copy button, plus exposure details.
    await router.navigate({ to: "/repositories", search: { repo: "r1" } as never });
    const idGroup = await screen.findByRole("group", { name: "Repository ID" });
    expect(within(idGroup).getByText("QD-REPO-000042")).toBeInTheDocument();
    expect(within(idGroup).getByRole("button", { name: /Copy Repository ID/ })).toBeInTheDocument();
    expect(within(idGroup).queryByRole("textbox")).toBeNull();
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Behind the CDN")).toBeInTheDocument();
    expect(within(dialog).getByText("*.pay.example.com")).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: /staging\.pay\.example\.com/ })).toHaveAttribute("rel", "noopener noreferrer");
    expect(within(dialog).getByText("Ada")).toBeInTheDocument();
    // Editing never offers the ID as an input.
    fireEvent.click(within(dialog).getByRole("button", { name: /Edit metadata/ }));
    expect(await within(dialog).findByRole("textbox", { name: /Production URL/ })).toHaveValue("https://pay.example.com");
    expect(within(dialog).queryByDisplayValue("QD-REPO-000042")).toBeNull();
    expect(within(dialog).getByRole("radio", { name: /^Yes/ })).toBeChecked();
  });

  it("repository filters for exposure and Repository ID reach the API", async () => {
    const { calls } = mockApi(routes());
    renderApp(<RepositoriesPage />, { permissions: ["repos.read"], path: "/repositories?public_exposure=no&missing_production_url=true" });
    expect(await screen.findByRole("combobox", { name: "Public exposure" })).toHaveValue("no");
    expect(screen.getByRole("checkbox", { name: "Missing production URL" })).toBeChecked();
    fireEvent.click(screen.getByRole("button", { name: /More filters/ }));
    const key = screen.getByRole("textbox", { name: "Repository ID (exact)" });
    fireEvent.change(key, { target: { value: "QD-REPO-000042" } });
    fireEvent.keyDown(key, { key: "Enter" });
    await waitFor(() =>
      expect(calls.some((c) => c.path === "/api/v1/repositories" && c.url.searchParams.get("repository_key") === "QD-REPO-000042" && c.url.searchParams.get("public_exposure") === "no" && c.url.searchParams.get("missing_production_url") === "true")).toBe(true),
    );
    expect(screen.getByRole("option", { name: "Repository ID (ascending)" })).toBeInTheDocument();
  });

  it("import landing shows the three source cards", async () => {
    mockApi(routes());
    renderApp(<ImportLandingPage />, { permissions: ["repos.manage"] });
    expect(await screen.findByRole("link", { name: /Import from Local PC/ })).toHaveAttribute("href", "/repositories/import/local");
    expect(screen.getByRole("link", { name: /Import from Git/ })).toHaveAttribute("href", "/repositories/import/git");
    expect(screen.getByRole("link", { name: /Import from DevOps Project/ })).toHaveAttribute("href", "/repositories/import/devops");
    expect(screen.getByRole("link", { name: /Open bulk import/ })).toHaveAttribute("href", "/repositories/import/csv");
  });

  it("asset settings lock always-required fields", async () => {
    mockApi(routes());
    renderApp(<AssetSettingsPage />, { permissions: ["assets.configure"] });
    const crit = await screen.findByRole("checkbox", { name: /^Criticality/ });
    expect(crit).toBeChecked();
    expect(crit).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: "Business owner" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: /Scan on import/ })).toBeChecked();
    // Public exposure is always required; application URLs can be made mandatory.
    expect(screen.getByRole("checkbox", { name: /^Public exposure/ })).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: /^Public exposure/ })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Staging URL" })).not.toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Production URL" })).toBeEnabled();
  });

  it("asset settings validate and save the Repository ID prefix", async () => {
    let patched: unknown;
    mockApi({
      ...routes(),
      "PATCH /api/v1/asset-settings": (_u: URL, init: { json?: unknown }) => {
        patched = init.json;
        return settings;
      },
    });
    renderApp(<AssetSettingsPage />, { permissions: ["assets.configure"] });
    const prefix = await screen.findByRole("textbox", { name: "Repository ID prefix" });
    expect(prefix).toHaveValue("QD-REPO");
    expect(screen.getByText(/existing IDs never change/)).toBeInTheDocument();
    fireEvent.change(prefix, { target: { value: "acme--x" } });
    expect(prefix).toHaveValue("ACME--X");
    expect(await screen.findByText(/single hyphens/, { selector: "[role=alert]" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    fireEvent.change(prefix, { target: { value: "ACME-APP" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(patched).toMatchObject({ repository_key_prefix: "ACME-APP" }));
  });

  it("SCM page reports the OAuth callback result", async () => {
    mockApi(routes());
    renderApp(<ScmConnectionsPage />, { permissions: ["scm.manage"], path: "/admin/scm?oauth=error&message=access_denied" });
    expect(await screen.findByText(/did not complete: access_denied/)).toBeInTheDocument();
  });
});

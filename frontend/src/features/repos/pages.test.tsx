import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
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
  },
  upload: { max_bytes: 2 ** 31, chunk_size: 8 * 2 ** 20, formats: ["zip", "tar", "tar.gz"] },
  suggested_colors: [{ key: "critical", label: "Mission critical", color: "#b42318" }],
};

const insights: RepositoryInsights = {
  totals: {
    total: 12, active: 10, archived: 2, critical: 3, without_business_owner: 4, without_technical_owner: 5, production: 6, confidential_or_restricted: 2,
    pending_imports: 1, failed_imports: 1, sync_failures: 0, last_successful_sync_at: null,
  },
  by_provider: [{ key: "github", label: "GitHub", count: 7 }], by_business_region: [], by_business_unit: [], by_business_owner: [],
  by_criticality: [{ key: "critical", label: "Mission critical", count: 3, color: "#b42318" }], by_data_classification: [], by_environment: [], by_compliance: [], by_lifecycle: [],
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
  });

  it("SCM page reports the OAuth callback result", async () => {
    mockApi(routes());
    renderApp(<ScmConnectionsPage />, { permissions: ["scm.manage"], path: "/admin/scm?oauth=error&message=access_denied" });
    expect(await screen.findByText(/did not complete: access_denied/)).toBeInTheDocument();
  });
});

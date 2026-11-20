import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import type { Application, AssetSettings, Classification, DiscoveredRepo, ProviderInfo, ScmConnection } from "@/api/types";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import { ApplicationsPage } from "@/features/repos/ApplicationsPage";
import { ApplicationProfile } from "./ApplicationProfilePage";
import { draftFrom, patchFrom } from "./ClassificationForm";
import { LifecyclePage } from "./LifecyclePage";
import { OnboardingFlowPage, importMetadata } from "./OnboardingFlowPage";
import { moveDecision, type AppLifecycle, type ApplicationProfile as Profile, type OnboardingSource, type Phase } from "./api";

// Example data for tests only (not real assets).
const meta = (flags: Record<string, boolean>) => () => ({ product: "PATHOS", vendor: "Quditmind", version: "dev", feature_flags: flags });

const cls = (kind: Classification["kind"], key: string, label: string): Classification => ({
  id: `${kind}-${key}`, kind, key, label, description: "", color: "", sort_order: 1, is_system: false, archived: false,
});

const settings: AssetSettings = {
  required_fields: [], always_required: [], scan_on_import: true, repository_key_prefix: "QD-REPO", suggested_colors: [],
  upload: { max_bytes: 1, chunk_size: 1, formats: ["zip"] },
  classifications: {
    criticality: [], environment: [], lifecycle_status: [], internet_exposure: [cls("internet_exposure", "public", "Publicly accessible")],
    data_classification: [cls("data_classification", "confidential", "Confidential")], application_type: [cls("application_type", "api", "API")],
    compliance: [cls("compliance", "pci_dss", "PCI DSS")], hosting_region: [cls("hosting_region", "europe", "Europe")],
    authentication_model: [cls("authentication_model", "oidc_sso", "Single sign-on (OpenID Connect)")],
  },
};

const profile: Profile = {
  id: "a1", application_key: "QD-APP-000142", name: "Payments Platform", description: "", external_ref: "",
  business_unit: null, owner: null, security_owner: null, technical_owner: null, criticality: "high", lifecycle: "active", environment: "production",
  application_type: "api", languages: ["Go", "TypeScript"], frameworks: ["chi", "React"], runtimes: [], data_classification: "",
  internet_exposure: "", compliance_scopes: [], authentication_model: "", hosting_region: "europe", data_residency_region: null,
  onboarding_status: "draft",
  detected: { languages: { source: "repository", detail: "Language statistics of acme/payments-api" }, frameworks: { source: "sbom", detail: "Packages in the SBOM" } },
  progress: { filled: 6, required: 9, missing: ["owner", "business_unit", "data_classification"], missing_tag_categories: [], label: "Onboarding: 6 of 9 fields" },
  tags: [], repository_count: 0, can_manage: true, archived_at: null, created_at: "", updated_at: "",
};

const phase = (number: number, key: string, title: string, has: boolean, available = true): Phase => ({
  number, key, title, available, has_data: has, restricted: false, metrics: {},
  summary: available ? (has ? `${title} data` : `No ${title.toLowerCase()} data yet`) : `${title}: arrives later`,
});
const phases = [
  phase(1, "connect", "Connect", true), phase(2, "inventory", "Inventory", true), phase(3, "discover", "Discover", true),
  phase(4, "threat_model", "Threat model", false, false), phase(5, "reverse_engineering", "Reverse engineering", false, false),
  phase(6, "assess", "Assess", false), phase(7, "validate", "Validate & intelligence", false), phase(8, "remediate", "Remediate & gate", false),
  phase(9, "report", "Report & monitor", false),
];
const life: AppLifecycle = { id: "a1", application_key: "QD-APP-000142", name: "Payments Platform", onboarding_status: "draft", criticality: "high", last_scan_at: null, phases, phases_with_data: 3 };

const common = {
  "GET /api/v1/asset-settings": () => settings,
  "GET /api/v1/application-settings": () => ({ required_fields: ["owner", "business_unit", "data_classification"], fields: [], labels: {} }),
  "GET /api/v1/tag-categories": () => ({ items: [] }),
  "GET /api/v1/business-units": () => ({ items: [] }),
  "GET /api/v1/regions": () => ({ items: [] }),
  "GET /api/v1/users": () => ({ items: [] }),
};

afterEach(() => vi.unstubAllGlobals());

describe("application profile hub", () => {
  it("says the feature is off while the onboarding flag is off", async () => {
    mockApi({ "GET /api/v1/meta": meta({}) });
    renderApp(<ApplicationProfile id="a1" />, { permissions: ["repos.read"] });
    expect(await screen.findByText("The application profile is not enabled")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Edit the application on the Applications page/ })).toHaveAttribute("href", "/applications?app=a1");
  });

  it("shows the tabs, the draft status and the lifecycle strip", async () => {
    mockApi({
      ...common,
      "GET /api/v1/meta": meta({ onboarding: true }),
      "GET /api/v1/applications/a1": () => profile,
      "GET /api/v1/applications/a1/lifecycle": () => life,
      "GET /api/v1/posture/applications": () => ({ items: [] }),
    });
    renderApp(<ApplicationProfile id="a1" />, { permissions: ["repos.read", "findings.read"] });
    expect(await screen.findByRole("heading", { name: "Payments Platform" })).toBeInTheDocument();
    expect(screen.getByText("Onboarding: 6 of 9 fields")).toBeInTheDocument();
    const tabs = screen.getByRole("tablist", { name: "Application profile" });
    expect(within(tabs).getAllByRole("tab").map((t) => t.textContent?.replace(/,.*$/, ""))).toHaveLength(10);
    for (const [label, m] of [["Remediation", "M8"]]) {
      const t = within(tabs).getByRole("tab", { name: new RegExp(`^${label}`) });
      expect(t).toHaveAttribute("aria-disabled", "true");
      expect(t).toHaveAttribute("title", `${label}: arrives in ${m}`);
    }
    // CodeGraph (M4) and Threat model (M5) are live tabs; their panels check their flags.
    expect(within(tabs).getByRole("tab", { name: "CodeGraph" })).not.toHaveAttribute("aria-disabled");
    expect(within(tabs).getByRole("tab", { name: "Threat model" })).not.toHaveAttribute("aria-disabled");
    const strip = await screen.findByRole("list", { name: "Lifecycle progress" });
    expect(within(strip).getAllByRole("listitem")).toHaveLength(9);
    const items = within(strip).getAllByRole("listitem");
    expect(items[3]).toHaveTextContent(/Threat model.*not available yet/);
    expect(items[0]).toHaveTextContent(/Connect.*has data/);
    expect(screen.getByText("No posture data yet: the application has no scanned repositories.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Continue onboarding" })).toHaveAttribute("href", "/onboarding?app=a1");
  });

  it("marks detected fields and saves only what changed", async () => {
    const { calls } = mockApi({
      ...common,
      "GET /api/v1/meta": meta({ onboarding: true }),
      "GET /api/v1/applications/a1": () => profile,
      "PATCH /api/v1/applications/a1/classification": () => ({ ...profile, data_classification: "confidential" }),
    });
    renderApp(<ApplicationProfile id="a1" />, { permissions: ["repos.read", "repos.manage"], path: "/?tab=classification" });
    const form = await screen.findByRole("form", { name: "Classification" });
    expect(within(form).getAllByText("detected")).toHaveLength(2);
    expect((await within(form).findAllByText("Needed to save to the inventory")).length).toBe(3);
    fireEvent.change(within(form).getByRole("combobox", { name: /Data classification/ }), { target: { value: "confidential" } });
    fireEvent.click(within(form).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(calls.find((c) => c.method === "PATCH")!.body).toEqual({ data_classification: "confidential" });
  });
});

describe("classification patch", () => {
  it("contains only changed fields, so detected values keep their mark", () => {
    const d = { ...draftFrom(profile), languages: "Go,  TypeScript", frameworks: "chi, React, Next.js", compliance_scopes: ["pci_dss"] };
    expect(patchFrom(profile, d, true)).toEqual({ frameworks: ["chi", "React", "Next.js"], compliance_scopes: ["pci_dss"] });
    expect(patchFrom(profile, draftFrom(profile), true)).toEqual({});
  });

  it("maps the classification onto the repository registration", () => {
    const m = importMetadata({ ...profile, owner: { id: "u1", name: "Ada", email: "ada@example.com" }, tags: [] }, { business_region_id: "r1", public_exposure: "unknown" });
    expect(m).toMatchObject({ application_id: "a1", business_owner_id: "u1", criticality: "high", hosting_region: "europe", business_region_id: "r1", public_exposure: "unknown" });
    expect(m).not.toHaveProperty("data_classification");
  });
});

describe("applications inventory", () => {
  const app: Application = {
    id: "a1", application_key: "QD-APP-000142", name: "Payments Platform", description: "", business_unit: null, owner: null, security_owner: null,
    technical_owner: null, lifecycle: "active", environment: "production", criticality: "high", external_ref: "", repository_count: 0, archived_at: null, created_at: "",
  };

  it("links the name to the profile and shows the draft status when onboarding is on", async () => {
    mockApi({
      "GET /api/v1/meta": meta({ onboarding: true }),
      "GET /api/v1/applications": () => ({ items: [app, { ...app, id: "a2", name: "HR Portal", application_key: "QD-APP-000143" }] }),
      "GET /api/v1/onboarding": () => ({ items: [{ id: "a1", application_key: app.application_key, name: app.name, progress: profile.progress, repository_count: 1, updated_at: "" }] }),
      "GET /api/v1/business-units": () => ({ items: [] }),
      "GET /api/v1/users": () => ({ items: [] }),
    });
    renderApp(<ApplicationsPage />, { permissions: ["repos.read", "repos.manage"] });
    expect(await screen.findByRole("link", { name: "Payments Platform" })).toHaveAttribute("href", "/applications/a1");
    expect(await screen.findByText("Onboarding: 6 of 9 fields")).toBeInTheDocument();
    expect(screen.getByText("Registered")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Onboard an application/ })).toHaveAttribute("href", "/onboarding");
    // A row click still opens the edit dialog.
    fireEvent.click(screen.getByText("QD-APP-000143"));
    expect(await screen.findByRole("dialog", { name: /Edit HR Portal/ })).toBeInTheDocument();
  });

  it("keeps the plain list while the flag is off", async () => {
    mockApi({ "GET /api/v1/meta": meta({}), "GET /api/v1/applications": () => ({ items: [app] }), "GET /api/v1/business-units": () => ({ items: [] }), "GET /api/v1/users": () => ({ items: [] }) });
    renderApp(<ApplicationsPage />, { permissions: ["repos.read", "repos.manage"] });
    expect(await screen.findByText("Payments Platform")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Payments Platform" })).toBeNull();
    expect(screen.queryByText("Registered")).toBeNull();
  });
});

describe("lifecycle overview", () => {
  it("shows which phases hold data, with links only where there is data", async () => {
    mockApi({ "GET /api/v1/meta": meta({ lifecycle_overview: true, onboarding: true }), "GET /api/v1/lifecycle/overview": () => ({ items: [life], phase_totals: [1, 1, 1, 0, 0, 0, 0, 0, 0], truncated: false }) });
    renderApp(<LifecyclePage />, { permissions: ["repos.read"] });
    expect(await screen.findByRole("link", { name: "Payments Platform" })).toHaveAttribute("href", "/applications/a1");
    expect(screen.getByText("3 / 9")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Payments Platform: Connect" })).toHaveAttribute("href", "/repositories?application_id=a1");
    expect(screen.queryByRole("link", { name: "Payments Platform: Assess" })).toBeNull();
    expect(screen.getByText(/Threat model: not available yet/)).toBeInTheDocument();
    expect(screen.getByText(/Assess: no data yet/)).toBeInTheDocument();
  });

  it("is off without its flag", async () => {
    mockApi({ "GET /api/v1/meta": meta({}) });
    renderApp(<LifecyclePage />, { permissions: ["repos.read"] });
    expect(await screen.findByText("The lifecycle overview is not enabled")).toBeInTheDocument();
  });
});

describe("onboarding flow", () => {
  const conn = {
    id: "c1", name: "GitHub Acme", provider: "github", base_url: "https://api.github.com", auth_type: "pat", owner: "", github_app_id: null,
    github_installation_id: null, oauth_app_id: null, account: "acme-bot", organizations: [], token_expires_at: null, status: "ok", status_message: "",
    last_checked_at: null, webhook_url: "", repository_count: 0, created_at: "", capabilities: { organizations: true, projects: false, server_search: true },
  } as unknown as ScmConnection;
  const provider = {
    key: "github", label: "GitHub", category: "git", default_base_url: "https://api.github.com", base_url_required: false, base_url_help: "", owner_label: "Owner",
    capabilities: conn.capabilities, auth_methods: [],
  } as unknown as ProviderInfo;
  const repo: DiscoveredRepo = {
    external_id: "101", full_name: "acme/payments-api", name: "payments-api", organization: "acme", project: "", url: "https://github.com/acme/payments-api",
    clone_url: "", default_branch: "main", visibility: "private", description: "", language: "Go", archived: false, pushed_at: null, size_bytes: 0, imported_id: null,
  };
  const routes = (register: (body: unknown) => unknown) => ({
    ...common,
    "GET /api/v1/meta": meta({ onboarding: true }),
    "GET /api/v1/scm-connections": () => ({ items: [conn] }),
    "GET /api/v1/scm-providers": () => ({ items: [provider] }),
    "GET /api/v1/scm-connections/c1/organizations": () => ({ items: [{ id: "1", name: "acme", display_name: "Acme", kind: "organization" }] }),
    "GET /api/v1/scm-connections/c1/remote-repositories": () => ({ items: [repo], next_page_token: "" }),
    "POST /api/v1/onboarding/match": () => ({
      sources: [{ scm_connection_id: "c1", external_id: "101", full_name: repo.full_name, url: repo.url, organization: "acme", project: "", language: "Go",
        source_key: "github.com/acme/payments-api", existing_repository: null, registered_elsewhere: false, onboarding: null }],
      candidates: [{ id: "a9", application_key: "QD-APP-000009", name: "Payments Platform", onboarding_status: "complete", repository_count: 2, score: 0.83,
        reasons: ["Shares the owner or team acme", 'Name similar to "payments-api" (75%)'] }],
      suggested_name: "Payments API",
    }),
    "POST /api/v1/onboarding": (_u: URL, init: { json?: unknown }) => register(init.json),
  });

  it("walks connect → discover → find existing and offers link or register", async () => {
    let body: unknown;
    const { calls } = mockApi(routes((b) => { body = b; return { application: { ...profile, id: "a2" }, sources: [] }; }));
    renderApp(<OnboardingFlowPage />, { permissions: ["repos.read", "repos.manage"] });
    const steps = await screen.findByRole("list", { name: "Onboarding steps" });
    expect(within(steps).getAllByRole("listitem")).toHaveLength(7);
    fireEvent.click(await screen.findByRole("checkbox", { name: "Select acme/payments-api" }));
    fireEvent.click(screen.getByRole("button", { name: /Find existing assets/ }));
    expect(await screen.findByText("Possible existing applications")).toBeInTheDocument();
    expect(screen.getByText("Shares the owner or team acme")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Link to QD-APP-000009/ })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Application name" })).toHaveValue("Payments API");
    expect(calls.find((c) => c.path === "/api/v1/onboarding/match")!.body).toMatchObject({
      repositories: [{ scm_connection_id: "c1", external_id: "101", full_name: "acme/payments-api", language: "Go" }],
    });
    fireEvent.click(screen.getByRole("button", { name: /Register as new/ }));
    await waitFor(() => expect(body).toBeDefined());
    expect(body).toMatchObject({ mode: "new", application: { name: "Payments API" }, repositories: [{ external_id: "101" }] });
  });

  it.each([
    [false, []],
    [true, ["r1"]],
  ])("never moves a repository of another application unless the box is ticked (ticked: %s)", async (tick, expected) => {
    const bodies: unknown[] = [];
    const base = routes((b) => {
      bodies.push(b);
      return { application: { ...profile, id: "a2" }, sources: [] };
    });
    const r = { ...base, "POST /api/v1/onboarding/match": () => ({
      sources: [{ scm_connection_id: "c1", external_id: "101", full_name: repo.full_name, url: repo.url, organization: "acme", project: "", language: "Go",
        source_key: "github.com/acme/payments-api", registered_elsewhere: false, onboarding: null,
        existing_repository: { id: "r1", name: "payments-api", full_name: repo.full_name, url: repo.url, application: { id: "x1", name: "App X" } } }],
      candidates: [], suggested_name: "Payments API",
    }) };
    mockApi(r);
    renderApp(<OnboardingFlowPage />, { permissions: ["repos.read", "repos.manage"] });
    fireEvent.click(await screen.findByRole("checkbox", { name: "Select acme/payments-api" }));
    fireEvent.click(screen.getByRole("button", { name: /Find existing assets/ }));
    const box = await screen.findByRole("checkbox", { name: "acme/payments-api belongs to App X. Move it to Payments API?" });
    expect(box).not.toBeChecked();
    expect(screen.getByText("kept in App X")).toBeInTheDocument();
    if (tick) {
      fireEvent.click(box);
      expect(screen.queryByText("kept in App X")).toBeNull();
    }
    fireEvent.click(screen.getByRole("button", { name: /Register as new/ }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({ move_repositories: expected });
  });

  it("explains a duplicate onboarding and links to the existing application", async () => {
    mockApi(
      routes(() =>
        jsonResponse(
          { error: { code: "already_onboarding", message: "acme/payments-api is already being onboarded", error_code: "PTH-ONB-1008", title: "Repository already being onboarded",
            cause: { confirmed: true, text: "An onboarding record already exists." }, probable_causes: [], impact: "Nothing was created.", actions: [], verify: [],
            docs_url: "/help/troubleshooting/onb#PTH-ONB-1008", ai_help: false, details: { application_id: "a1", application_name: "Payments Platform" } } },
          409,
        ),
      ),
    );
    renderApp(<OnboardingFlowPage />, { permissions: ["repos.read", "repos.manage"] });
    fireEvent.click(await screen.findByRole("checkbox", { name: "Select acme/payments-api" }));
    fireEvent.click(screen.getByRole("button", { name: /Find existing assets/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Register as new/ }));
    expect(await screen.findByText("PTH-ONB-1008")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open the existing application" })).toHaveAttribute("href", "/onboarding?app=a1");
  });
});

describe("tag framework", () => {
  const fw = {
    categories: [{ id: "k1", name: "Compliance", color: "#cf222e", is_mandatory: false, allow_multiple: true, mandatory_asset_types: ["api"],
      tags: [{ id: "t1", name: "pci-dss", color: "red", repository_count: 0, application_count: 1 }], noncompliant_applications: 2 }],
    rules: [{ id: "r1", name: "PCI scope", tag_id: "t1", tag_name: "pci-dss", tag_color: "red", category_name: "Compliance", target_type: "application",
      condition: "classification", field: "compliance_scopes", value: "pci_dss", enabled: true, created_at: "" }],
    rule_fields: ["compliance_scopes", "environment"],
  };

  it("shows category settings, rules and history, and creates a path rule", async () => {
    const { TagFrameworkPanel } = await import("./TagFrameworkPanel");
    const { calls } = mockApi({
      ...common,
      "GET /api/v1/tag-framework": () => fw,
      "GET /api/v1/tag-history": () => ({ items: [{ id: "h1", target_type: "application", target_id: "a1", target_name: "Payments Platform", category_id: "k1",
        category_name: "Compliance", old_tags: [], new_tags: ["pci-dss"], source: "rule", rule_id: "r1", actor_email: "ada@example.com", created_at: "2026-11-20T10:00:00Z" }] }),
      "GET /api/v1/applications": () => ({ items: [] }),
      "GET /api/v1/repositories": () => ({ items: [] }),
      "POST /api/v1/tag-rules": () => ({ rule: { ...fw.rules[0], id: "r2", name: "Web repos" }, applied: 3 }),
    });
    renderApp(<TagFrameworkPanel />, { permissions: ["repos.read", "tags.manage"] });
    expect(await screen.findByText("2 active applications of a mandatory type have no tag in this category.")).toBeInTheDocument();
    expect(await screen.findByRole("checkbox", { name: "API" })).toBeChecked();
    expect(screen.getByText("PCI scope")).toBeInTheDocument();
    expect(await screen.findByText("Payments Platform")).toBeInTheDocument();
    fireEvent.change(screen.getByRole("textbox", { name: "Name" }), { target: { value: "Web repos" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Tag to add" }), { target: { value: "t1" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Applies to" }), { target: { value: "repository" } });
    fireEvent.change(screen.getByRole("textbox", { name: "Pattern" }), { target: { value: "acme/web-*" } });
    fireEvent.click(screen.getByRole("button", { name: /Create rule/ }));
    expect(await screen.findByText("Rule “Web repos” created; 3 assets tagged.")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST" && c.path === "/api/v1/tag-rules")!.body).toEqual({
      name: "Web repos", tag_id: "t1", target_type: "repository", condition: "path_pattern", field: "", value: "acme/web-*", apply: true,
    });
  });
});

describe("save to inventory with repositories of other applications", () => {
  const src = (over: Partial<OnboardingSource>): OnboardingSource => ({
    id: "s1", full_name: "acme/payments-api", url: "", scm_connection_id: "c1", external_id: "101", organization: "acme", project: "",
    decision: "linked_existing", status: "draft", repository_id: "r1", repository_name: "payments-api", import_job_id: null, import_status: null,
    language: "", created_at: "", current_application: { id: "x1", name: "App X" }, move_requested: false, ...over,
  });

  it("lists every such repository as moved or kept", () => {
    const sources = [src({}), src({ id: "s2", repository_id: "r2", move_requested: true }), src({ id: "s3", repository_id: "r3", current_application: null })];
    expect(moveDecision(sources, new Set(["r2"]))).toEqual({ move_repositories: ["r2"], keep_repositories: ["r1"] });
  });

  it("keeps by default and moves only what is ticked", async () => {
    const draft: Profile = { ...profile, progress: { ...profile.progress, missing: [], filled: 9 } };
    const bodies: unknown[] = [];
    mockApi({
      ...common,
      "GET /api/v1/meta": meta({ onboarding: true }),
      "GET /api/v1/applications/a1/onboarding": () => ({ application: draft, sources: [src({})] }),
      "POST /api/v1/applications/a1/onboarding/complete": (_u: URL, init: { json?: unknown }) => {
        bodies.push(init.json);
        return { application: { ...draft, onboarding_status: "complete" }, sources: [src({ status: "kept" })] };
      },
    });
    renderApp(<OnboardingFlowPage />, { permissions: ["repos.read", "repos.manage"], path: "/?app=a1" });
    fireEvent.click(await screen.findByRole("button", { name: /Continue/ }));
    const box = await screen.findByRole("checkbox", { name: "acme/payments-api belongs to App X. Move it to Payments Platform?" });
    expect(box).not.toBeChecked();
    expect(screen.getByText("kept in App X")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save to inventory" }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({ move_repositories: [], keep_repositories: ["r1"] });
  });
});

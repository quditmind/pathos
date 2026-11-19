import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import type { AssetSettings, DiscoveredRepo, ImportValidation, ProviderInfo, ScmConnection } from "@/api/types";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import { OnboardingWizard } from "./OnboardingWizard";

const settings: AssetSettings = {
  required_fields: ["description"],
  always_required: [],
  scan_on_import: false,
  classifications: {
    criticality: [], data_classification: [], environment: [], application_type: [], internet_exposure: [], compliance: [], hosting_region: [], lifecycle_status: [], authentication_model: [],
  },
  upload: { max_bytes: 1024 * 1024, chunk_size: 8 * 1024 * 1024, formats: ["zip", "tar", "tar.gz"] },
  suggested_colors: [],
  repository_key_prefix: "QD-REPO",
};

const conn: ScmConnection = {
  id: "c1", name: "GitHub Acme", provider: "github", base_url: "https://api.github.com", auth_type: "pat", owner: "", github_app_id: null,
  github_installation_id: null, oauth_app_id: null, account: "acme-bot", organizations: [], token_expires_at: null, status: "ok", status_message: "",
  last_checked_at: null, webhook_url: "", repository_count: 0, created_at: "", capabilities: { organizations: true, projects: false, server_search: true },
};

const provider: ProviderInfo = {
  key: "github", label: "GitHub", category: "git", default_base_url: "https://api.github.com", base_url_required: false, base_url_help: "", owner_label: "Owner",
  capabilities: conn.capabilities, auth_methods: [],
};

const repo: DiscoveredRepo = {
  external_id: "101", full_name: "acme/api", name: "api", organization: "acme", project: "", url: "https://github.com/acme/api", clone_url: "",
  default_branch: "main", visibility: "private", description: "", language: "Go", archived: false, pushed_at: null, size_bytes: 0, imported_id: null,
};

function baseRoutes(validate: (body: unknown) => ImportValidation | Response) {
  return {
    "GET /api/v1/asset-settings": () => settings,
    "GET /api/v1/tag-categories": () => ({ items: [] }),
    "GET /api/v1/scm-connections": () => ({ items: [conn] }),
    "GET /api/v1/scm-providers": () => ({ items: [provider] }),
    "GET /api/v1/applications": () => ({ items: [] }),
    "GET /api/v1/business-units": () => ({ items: [] }),
    "GET /api/v1/regions": () => ({ items: [] }),
    "GET /api/v1/scm-connections/c1/organizations": () => ({ items: [{ id: "1", name: "acme", display_name: "Acme", kind: "organization" }] }),
    "GET /api/v1/scm-connections/c1/remote-repositories": () => ({ items: [repo], next_page_token: "" }),
    "POST /api/v1/repository-imports/validate": (_u: URL, init: { json?: unknown }) => validate(init.json),
  };
}

async function toGeneral() {
  fireEvent.click(await screen.findByRole("checkbox", { name: "Select acme/api" }));
  fireEvent.click(screen.getByRole("button", { name: /^Next/ }));
  await screen.findByRole("heading", { name: "General" });
}

function next() {
  fireEvent.click(screen.getByRole("button", { name: /^Next|Check and review/ }));
}

/** Walks through the given steps; the mandatory exposure question is answered "Unknown". */
async function walk(titles: string[]) {
  for (const title of titles) {
    const q = screen.queryByRole("radiogroup", { name: /publicly exposed/ });
    if (q && !within(q).getAllByRole<HTMLInputElement>("radio").some((r) => r.checked)) fireEvent.click(within(q).getByRole("radio", { name: /^Unknown/ }));
    next();
    await screen.findByRole("heading", { name: title });
  }
}

async function toClassification() {
  await toGeneral();
  fireEvent.change(screen.getByRole("textbox", { name: /^Description/ }), { target: { value: "Payments API" } });
  for (const title of ["Business ownership", "Geography", "Classification"]) {
    next();
    await screen.findByRole("heading", { name: title });
  }
}

const throughReview = ["Tags & colour", "Lifecycle"];

describe("onboarding wizard", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("blocks Next until required fields are filled", async () => {
    mockApi(baseRoutes(() => ({ valid: true, fields: {}, items: [] })));
    renderApp(<OnboardingWizard source="git" onSubmitted={() => undefined} />, { permissions: ["repos.manage"] });
    await toGeneral();
    // The single repository's names are pre-filled from the source.
    expect(screen.getByRole("textbox", { name: /Display name/ })).toHaveValue("api");
    expect(screen.getByRole("textbox", { name: /Asset name/ })).toHaveValue("api");

    next();
    expect(await screen.findByText("Description is required")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "General" })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: /^Description/ })).toHaveAttribute("aria-invalid", "true");

    fireEvent.change(screen.getByRole("textbox", { name: /^Description/ }), { target: { value: "Payments API" } });
    next();
    expect(await screen.findByRole("heading", { name: "Business ownership" })).toBeInTheDocument();
  });

  it("shows server field errors inline on the right step", async () => {
    let body: unknown;
    mockApi(
      baseRoutes((b) => {
        body = b;
        return { valid: false, fields: { business_owner_id: "This user cannot own assets" }, items: [] };
      }),
    );
    renderApp(<OnboardingWizard source="git" onSubmitted={() => undefined} />, { permissions: ["repos.manage"] });
    await toGeneral();
    fireEvent.change(screen.getByRole("textbox", { name: /^Description/ }), { target: { value: "Payments API" } });
    await walk(["Business ownership", "Geography", "Classification", "Tags & colour", "Lifecycle"]);
    next(); // Check and review → validate
    expect(await screen.findByText("This user cannot own assets")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Business ownership" })).toBeInTheDocument();
    expect(body).toMatchObject({
      source: "git",
      scm_connection_id: "c1",
      metadata: { description: "Payments API", public_exposure: "unknown", internet_exposure: "unknown", public_urls: [], public_domains: [], public_ips: [] },
      items: [{ ref: { external_id: "101", full_name: "acme/api", organization: "acme" }, display_name: "api", asset_name: "api", branch: "", full_history: false }],
    });
  });

  it("reuses the idempotency key when a submission is retried after a network error", async () => {
    const keys: string[] = [];
    let attempt = 0;
    const routes = {
      ...baseRoutes(() => ({ valid: true, fields: {}, items: [] })),
      "POST /api/v1/repository-imports": (_u: URL, init: { json?: unknown }) => {
        keys.push((init.json as { idempotency_key: string }).idempotency_key);
        attempt++;
        if (attempt === 1) return jsonResponse({ error: { code: "unavailable", message: "gateway timeout" } }, 503);
        return jsonResponse({ id: "job-1" }, 202);
      },
    };
    mockApi(routes);
    const onSubmitted = vi.fn();
    renderApp(<OnboardingWizard source="git" onSubmitted={onSubmitted} />, { permissions: ["repos.manage"] });
    await toGeneral();
    fireEvent.change(screen.getByRole("textbox", { name: /^Description/ }), { target: { value: "x" } });
    await walk(["Business ownership", "Geography", "Classification", "Tags & colour", "Lifecycle", "Review"]);
    const start = await screen.findByRole("button", { name: /Start import/ });
    fireEvent.click(start);
    expect(await screen.findByText(/could not be started/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Start import/ }));
    await waitFor(() => expect(onSubmitted).toHaveBeenCalledWith("job-1"));
    expect(keys).toHaveLength(2);
    expect(keys[0]).toBe(keys[1]);
    expect(keys[0]!.length).toBeGreaterThan(10);
  });

  it("requires the public exposure answer and shows endpoint lists only for Yes", async () => {
    let body: { metadata: Record<string, unknown> } | undefined;
    mockApi(
      baseRoutes((b) => {
        body = b as typeof body;
        return { valid: true, fields: {}, items: [] };
      }),
    );
    renderApp(<OnboardingWizard source="git" onSubmitted={() => undefined} />, { permissions: ["repos.manage"] });
    await toClassification();
    expect(screen.getByRole("radiogroup", { name: /publicly exposed to the internet/ })).toBeInTheDocument();
    for (const r of ["Yes", "No", "Unknown"]) expect(screen.getByRole("radio", { name: new RegExp(`^${r}`) })).not.toBeChecked();
    expect(screen.getByText(/PATHOS does not crawl or scan these addresses/)).toBeInTheDocument();

    // No default: Next is blocked until the question is answered.
    next();
    expect(await screen.findByText(/Answer whether the application or asset is publicly exposed/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Classification" })).toBeInTheDocument();
    expect(screen.getByRole("radiogroup", { name: /publicly exposed/ })).toHaveAttribute("aria-invalid", "true");

    // No: endpoint lists hidden, optional network detail shown.
    fireEvent.click(screen.getByRole("radio", { name: /^No/ }));
    expect(screen.queryByRole("group", { name: "Public-facing URLs" })).toBeNull();
    expect(screen.getByRole("combobox", { name: /Network reachability detail/ })).toBeInTheDocument();

    // Unknown: neither.
    fireEvent.click(screen.getByRole("radio", { name: /^Unknown/ }));
    expect(screen.queryByRole("group", { name: "Public-facing URLs" })).toBeNull();
    expect(screen.queryByRole("combobox", { name: /Network reachability detail/ })).toBeNull();

    // Yes: three endpoint lists; the URL list starts with one row.
    fireEvent.click(screen.getByRole("radio", { name: /^Yes/ }));
    const urls = screen.getByRole("group", { name: "Public-facing URLs" });
    expect(screen.getByRole("group", { name: "Public domain names" })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Public IP addresses" })).toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: /Network reachability detail/ })).toBeNull();
    expect(within(urls).getAllByRole("textbox")).toHaveLength(1);

    // At least one endpoint is required for Yes.
    next();
    expect(await screen.findByText("Add at least one public URL, domain name or IP address")).toBeInTheDocument();

    // Simple format checks per list.
    fireEvent.change(screen.getByRole("textbox", { name: "Public-facing URL 1" }), { target: { value: "ftp://files.example.com" } });
    next();
    expect(await screen.findByText(/absolute http:\/\/ or https:\/\/ URL/)).toBeInTheDocument();
    fireEvent.change(screen.getByRole("textbox", { name: "Public-facing URL 1" }), { target: { value: "https://pay.example.com" } });

    // Add and remove rows.
    fireEvent.click(screen.getByRole("button", { name: "Add URL" }));
    expect(within(urls).getAllByRole("textbox")).toHaveLength(2);
    fireEvent.change(screen.getByRole("textbox", { name: "Public-facing URL 2" }), { target: { value: "https://api.example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Remove Public-facing URL 1" }));
    expect(within(urls).getAllByRole("textbox")).toHaveLength(1);
    expect(screen.getByRole("textbox", { name: "Public-facing URL 1" })).toHaveValue("https://api.example.com");
    fireEvent.click(screen.getByRole("button", { name: "Add IP address" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Public IP address 1" }), { target: { value: "10.1.2.3" } });
    next();
    expect(await screen.findByText(/not a public address/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Remove Public IP address 1" }));
    fireEvent.click(screen.getByRole("button", { name: "Add domain" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Public domain name 1" }), { target: { value: "*.example.com" } });

    await walk(throughReview);
    next(); // Check and review
    await screen.findByRole("heading", { name: "Review" });
    expect(body!.metadata).toMatchObject({
      public_exposure: "yes",
      public_urls: ["https://api.example.com"],
      public_domains: ["*.example.com"],
      public_ips: [],
      internet_exposure: "public",
    });
    // The review summary shows the answer and endpoints.
    expect(screen.getByText("Public")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /api\.example\.com/ })).toHaveAttribute("rel", "noopener noreferrer");
    expect(screen.getByText("*.example.com")).toBeInTheDocument();
  });

  it("switching to No sends empty endpoint lists", async () => {
    let body: { metadata: Record<string, unknown> } | undefined;
    mockApi(
      baseRoutes((b) => {
        body = b as typeof body;
        return { valid: true, fields: {}, items: [] };
      }),
    );
    renderApp(<OnboardingWizard source="git" onSubmitted={() => undefined} />, { permissions: ["repos.manage"] });
    await toClassification();
    fireEvent.click(screen.getByRole("radio", { name: /^Yes/ }));
    fireEvent.change(screen.getByRole("textbox", { name: "Public-facing URL 1" }), { target: { value: "https://pay.example.com" } });
    fireEvent.click(screen.getByRole("radio", { name: /^No/ }));
    expect(screen.getByText(/removed when you save/)).toBeInTheDocument();
    await walk(throughReview);
    next();
    await screen.findByRole("heading", { name: "Review" });
    expect(body!.metadata).toMatchObject({ public_exposure: "no", public_urls: [], public_domains: [], public_ips: [] });
    expect(body!.metadata).not.toHaveProperty("internet_exposure");
    expect(screen.getByText("Not public")).toBeInTheDocument();
  });

  it("maps a server error on public_urls back to the Classification step", async () => {
    mockApi(baseRoutes(() => ({ valid: false, fields: { public_urls: "203.0.113.300 is not a valid host" }, items: [] })));
    renderApp(<OnboardingWizard source="git" onSubmitted={() => undefined} />, { permissions: ["repos.manage"] });
    await toGeneral();
    fireEvent.change(screen.getByRole("textbox", { name: /^Description/ }), { target: { value: "Payments API" } });
    fireEvent.change(screen.getByRole("textbox", { name: "Production URL" }), { target: { value: "https://pay.example.com" } });
    for (const title of ["Business ownership", "Geography", "Classification"]) {
      next();
      await screen.findByRole("heading", { name: title });
    }
    fireEvent.click(screen.getByRole("radio", { name: /^Yes/ }));
    fireEvent.change(screen.getByRole("textbox", { name: "Public-facing URL 1" }), { target: { value: "https://pay.example.com" } });
    await walk(throughReview);
    next(); // Check and review → server rejects
    expect(await screen.findByText("203.0.113.300 is not a valid host")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Classification" })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Public-facing URL 1" })).toHaveAttribute("aria-invalid", "true");
  });

  it("validates application URLs on the General step", async () => {
    mockApi(baseRoutes(() => ({ valid: true, fields: {}, items: [] })));
    renderApp(<OnboardingWizard source="git" onSubmitted={() => undefined} />, { permissions: ["repos.manage"] });
    await toGeneral();
    expect(screen.getByText(/PATHOS records them as metadata and never contacts them/)).toBeInTheDocument();
    fireEvent.change(screen.getByRole("textbox", { name: /^Description/ }), { target: { value: "Payments API" } });
    const staging = screen.getByRole("textbox", { name: "Staging URL" });
    expect(staging).toHaveAttribute("placeholder", "https://");
    fireEvent.change(staging, { target: { value: "https://user:pw@staging.example.com" } });
    next();
    expect(await screen.findByText(/must not contain user names or passwords/)).toBeInTheDocument();
    expect(staging).toHaveAttribute("aria-invalid", "true");
  });
});

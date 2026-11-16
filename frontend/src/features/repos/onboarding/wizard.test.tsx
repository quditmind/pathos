import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import type { AssetSettings, DiscoveredRepo, ImportValidation, ProviderInfo, ScmConnection } from "@/api/types";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import { OnboardingWizard } from "./OnboardingWizard";

const settings: AssetSettings = {
  required_fields: ["description"],
  always_required: [],
  scan_on_import: false,
  classifications: {
    criticality: [], data_classification: [], environment: [], application_type: [], internet_exposure: [], compliance: [], hosting_region: [], lifecycle_status: [],
  },
  upload: { max_bytes: 1024 * 1024, chunk_size: 8 * 1024 * 1024, formats: ["zip", "tar", "tar.gz"] },
  suggested_colors: [],
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
    for (const title of ["Business ownership", "Geography", "Classification", "Tags & colour", "Lifecycle"]) {
      next();
      await screen.findByRole("heading", { name: title });
    }
    next(); // Check and review → validate
    expect(await screen.findByText("This user cannot own assets")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Business ownership" })).toBeInTheDocument();
    expect(body).toMatchObject({
      source: "git",
      scm_connection_id: "c1",
      metadata: { description: "Payments API" },
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
    for (const title of ["Business ownership", "Geography", "Classification", "Tags & colour", "Lifecycle", "Review"]) {
      next();
      await screen.findByRole("heading", { name: title });
    }
    const start = await screen.findByRole("button", { name: /Start import/ });
    fireEvent.click(start);
    expect(await screen.findByText(/could not be started/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Start import/ }));
    await waitFor(() => expect(onSubmitted).toHaveBeenCalledWith("job-1"));
    expect(keys).toHaveLength(2);
    expect(keys[0]).toBe(keys[1]);
    expect(keys[0]!.length).toBeGreaterThan(10);
  });
});

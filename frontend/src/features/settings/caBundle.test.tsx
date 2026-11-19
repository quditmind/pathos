import { afterEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ScmConnection } from "@/api/types";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import { caBundleApplies, formatFingerprint } from "./CABundleSection";
import { ScmConnectionsPage } from "./ScmConnectionsPage";

afterEach(() => vi.unstubAllGlobals());

const fp = "ab".repeat(32);

const base: ScmConnection = {
  id: "s1",
  name: "Internal GitLab",
  provider: "gitlab",
  base_url: "https://gitlab.corp.example",
  auth_type: "pat",
  owner: "",
  github_app_id: null,
  github_installation_id: null,
  oauth_app_id: null,
  account: "pathos-bot",
  organizations: [],
  token_expires_at: null,
  status: "ok",
  status_message: "",
  last_checked_at: null,
  webhook_url: "",
  repository_count: 0,
  created_at: "2026-11-01T00:00:00Z",
  capabilities: { organizations: false, projects: false, server_search: true },
  has_ca_bundle: true,
  ca_certificates: [
    { subject: "CN=Corp Root CA,O=Example", issuer: "CN=Corp Root CA,O=Example", not_after: "2030-01-01T00:00:00Z", sha256_fingerprint: fp, is_ca: true, expired: false },
    { subject: "CN=Old Issuing CA", issuer: "CN=Corp Root CA,O=Example", not_after: "2024-01-01T00:00:00Z", sha256_fingerprint: "cd".repeat(32), is_ca: true, expired: true },
  ],
};

function routes(conn: ScmConnection, flag: boolean, extra: Parameters<typeof mockApi>[0] = {}) {
  return mockApi({
    "GET /api/v1/meta": () => ({ product: "PATHOS", vendor: "Quditmind", version: "dev", feature_flags: { connectors: flag } }),
    "GET /api/v1/scm-connections": () => ({ items: [conn] }),
    "GET /api/v1/scm-providers": () => ({ items: [] }),
    "GET /api/v1/scm-oauth-apps": () => ({ items: [] }),
    ...extra,
  });
}

describe("CA bundle of an SCM connection", () => {
  it("applies to self-hosted servers and to any connection that already has a bundle", () => {
    expect(caBundleApplies({ provider: "gitlab", base_url: "https://gitlab.com", has_ca_bundle: false })).toBe(false);
    expect(caBundleApplies({ provider: "gitlab", base_url: "https://gitlab.corp.example", has_ca_bundle: false })).toBe(true);
    expect(caBundleApplies({ provider: "github", base_url: "https://api.github.com", has_ca_bundle: false })).toBe(false);
    expect(caBundleApplies({ provider: "github", base_url: "https://api.github.com", has_ca_bundle: true })).toBe(true);
    for (const p of ["github_enterprise", "bitbucket_data_center", "azure_devops_server", "generic_git"]) expect(caBundleApplies({ provider: p as never, base_url: "https://x.example", has_ca_bundle: false })).toBe(true);
    expect(formatFingerprint("ab01")).toBe("AB:01");
  });

  it("shows each certificate's subject, expiry and fingerprint, never the PEM", async () => {
    routes(base, true);
    renderApp(<ScmConnectionsPage />, { permissions: ["scm.manage", "repos.read"], path: "/admin/scm" });
    const sec = await screen.findByRole("region", { name: "Private CA bundle of Internal GitLab" });
    expect(within(sec).getByText("2 certificates")).toBeInTheDocument();
    expect(within(sec).getByText("CN=Corp Root CA,O=Example")).toBeInTheDocument();
    expect(within(sec).getByText(formatFingerprint(fp))).toBeInTheDocument();
    expect(within(sec).getByText(/Expired/).className).toContain("text-danger");
    expect(sec.textContent).not.toContain("BEGIN CERTIFICATE");
  });

  it("is hidden while the connectors feature is off", async () => {
    routes(base, false);
    renderApp(<ScmConnectionsPage />, { permissions: ["scm.manage", "repos.read"], path: "/admin/scm" });
    expect(await screen.findByText("Internal GitLab")).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByRole("region", { name: /Private CA bundle/ })).not.toBeInTheDocument();
  });

  it("replaces the bundle with PATCH ca_bundle_pem and shows a field error", async () => {
    const patches: unknown[] = [];
    let fail = true;
    routes({ ...base, has_ca_bundle: false, ca_certificates: [] }, true, {
      "PATCH /api/v1/scm-connections/s1": (_u, init) => {
        patches.push(init.json);
        if (fail) {
          fail = false;
          return jsonResponse({ error: { code: "validation_failed", message: "ca_bundle_pem: never paste a private key", fields: { ca_bundle_pem: "never paste a private key" } } }, 422);
        }
        return { ...base, status: "untested" };
      },
    });
    renderApp(<ScmConnectionsPage />, { permissions: ["scm.manage", "repos.read"], path: "/admin/scm" });
    const sec = await screen.findByRole("region", { name: "Private CA bundle of Internal GitLab" });
    expect(within(sec).getByText("Not set")).toBeInTheDocument();
    await userEvent.click(within(sec).getByRole("button", { name: "Add CA bundle" }));
    const dlg = await screen.findByRole("dialog", { name: /CA bundle of/ });
    const save = within(dlg).getByRole("button", { name: "Save CA bundle" });
    expect(save).toBeDisabled();
    await userEvent.type(within(dlg).getByLabelText(/CA certificates/), "-----BEGIN PRIVATE KEY-----");
    await userEvent.click(save);
    expect(await within(dlg).findByText("never paste a private key")).toBeInTheDocument();
    await userEvent.clear(within(dlg).getByLabelText(/CA certificates/));
    await userEvent.type(within(dlg).getByLabelText(/CA certificates/), "  -----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----  ");
    await userEvent.click(save);
    await waitFor(() => expect(patches).toHaveLength(2));
    expect(patches[1]).toEqual({ ca_bundle_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----" });
    expect(await screen.findByText(/CA bundle of “Internal GitLab” saved/)).toBeInTheDocument();
  });

  it("removes the bundle with PATCH ca_bundle_pem \"\" after confirmation", async () => {
    const patches: unknown[] = [];
    routes(base, true, { "PATCH /api/v1/scm-connections/s1": (_u, init) => (patches.push(init.json), { ...base, has_ca_bundle: false, ca_certificates: [] }) });
    renderApp(<ScmConnectionsPage />, { permissions: ["scm.manage", "repos.read"], path: "/admin/scm" });
    const sec = await screen.findByRole("region", { name: "Private CA bundle of Internal GitLab" });
    await userEvent.click(within(sec).getByRole("button", { name: "Remove" }));
    await userEvent.click(await screen.findByRole("button", { name: "Remove CA bundle" }));
    await waitFor(() => expect(patches).toEqual([{ ca_bundle_pem: "" }]));
    expect(await screen.findByText(/CA bundle of “Internal GitLab” removed/)).toBeInTheDocument();
  });

  it("is read-only without scm.manage", async () => {
    routes(base, true);
    renderApp(<ScmConnectionsPage />, { permissions: ["repos.read"], path: "/admin/scm" });
    const sec = await screen.findByRole("region", { name: "Private CA bundle of Internal GitLab" });
    expect(within(sec).queryByRole("button")).not.toBeInTheDocument();
  });
});

import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider } from "@tanstack/react-router";
import { SessionProvider } from "@/features/auth/session";
import userEvent from "@testing-library/user-event";
import { jsonResponse, me, mockApi, renderApp } from "@/test/harness";
import { Toaster } from "@/components/ui/toast";
import { checkError, type Connector, type ConnectorDetail, type ConnectorKind, type HealthCheck } from "./api";
import { ConnectorsPage } from "./ConnectorsPage";
import { displayStatus, existingFlow, isHubKind, isSecretKey, manageLinkFor, timeSince, validateConnectorsSearch } from "./model";
import { IntegrationsRoute, ScmConnectionsRoute } from "./redirects";

afterEach(() => vi.unstubAllGlobals());

const meta = (on: boolean) => () => ({ product: "PATHOS", vendor: "Quditmind", version: "dev", feature_flags: { connectors: on } });

const kinds: ConnectorKind[] = [
  { kind: "github", category: "scm_ide", label: "GitHub", status: "existing", auth_methods: ["github_app", "pat"], docs_slug: "provider-integrations", offline_ok: false },
  { kind: "gitlab", category: "scm_ide", label: "GitLab", status: "existing", auth_methods: ["pat", "oauth"], docs_slug: "provider-integrations", offline_ok: true },
  {
    kind: "bitbucket_data_center",
    category: "scm_ide",
    label: "Bitbucket Data Center",
    status: "existing",
    auth_methods: ["pat", "api_token"],
    docs_slug: "connectors#bitbucket_data_center",
    offline_ok: true,
    secret_refs: true,
    creatable: true,
    managed_at: "/admin/scm",
    config_fields: [
      { key: "base_url", label: "Instance URL", type: "url", required: true },
      { key: "auth_method", label: "Token type", type: "select", required: true, options: ["http_access_token", "user_token"] },
      { key: "username", label: "User name (user tokens only)", type: "text", required: false },
      { key: "ca_bundle_pem", label: "Private CA bundle (PEM)", type: "pem", required: false },
      { key: "credential_ref", label: "Credential as a Vault/OpenBao reference", type: "secret_ref", required: false },
    ],
  },
  { kind: "jira", category: "monitoring", label: "Jira", status: "existing", auth_methods: ["api_token"], docs_slug: "reporting-and-integrations", offline_ok: false },
  { kind: "cloud_aws", category: "cloud", label: "AWS", status: "planned", auth_methods: ["assume_role"], docs_slug: "connectors", offline_ok: false },
  {
    kind: "generic_git",
    category: "scm_ide",
    label: "Generic Git (HTTPS/SSH)",
    status: "existing",
    auth_methods: ["api_token", "ssh_key"],
    docs_slug: "connectors#generic_git",
    offline_ok: true,
    secret_refs: true,
    creatable: true,
    managed_at: "/admin/scm",
    config_fields: [
      { key: "base_url", label: "Repository URL", type: "url", required: true },
      { key: "auth_method", label: "Authentication", type: "select", required: true, options: ["https_token", "ssh_key"] },
      { key: "ssh_known_hosts", label: "known_hosts entry (SSH)", type: "textarea", required: false },
      { key: "credential_ref", label: "Credential as a Vault/OpenBao reference", type: "secret_ref", required: false },
    ],
  },
  {
    kind: "vault",
    category: "iam_secrets",
    label: "HashiCorp Vault / OpenBao",
    status: "existing",
    auth_methods: ["approle", "kubernetes"],
    docs_slug: "connectors#vault",
    offline_ok: true,
    secret_refs: false,
    creatable: true,
    config_fields: [
      { key: "base_url", label: "Vault address", type: "url", required: true },
      { key: "auth_method", label: "Authentication", type: "select", required: true, options: ["approle", "kubernetes"] },
      { key: "role_id", label: "AppRole role ID", type: "text", required: false },
      { key: "kubernetes_role", label: "Kubernetes auth role", type: "text", required: false },
      { key: "allow_private", label: "Allow private network", type: "boolean", required: false },
    ],
  },
];

const now = Date.now();
const ago = (min: number) => new Date(now - min * 60_000).toISOString();

const conns: Connector[] = [
  { id: "c1", kind: "github", category: "scm_ide", name: "GitHub (acme)", status: "healthy", last_check_at: ago(2), last_error_code: "", last_sync_at: ago(30), source: { table: "scm_connections", id: "s1" } },
  // A row that says healthy but was never checked must read "Never checked".
  { id: "c2", kind: "github", category: "scm_ide", name: "GitHub (never)", status: "healthy", last_check_at: null, last_error_code: "", last_sync_at: null, source: { table: "scm_connections", id: "s2" } },
  { id: "c3", kind: "jira", category: "monitoring", name: "Jira SEC", status: "failing", last_check_at: ago(180), last_error_code: "PTH-CONN-1004", last_sync_at: null, source: { table: "ticket_connections", id: "t1" } },
];

const failure = {
  code: "scm_error",
  error_code: "PTH-CONN-1004",
  title: "Connection uses an untrusted certificate",
  message: "x509: certificate signed by unknown authority",
  cause: { confirmed: true, text: "The server certificate is issued by a private CA." },
  probable_causes: [],
  impact: "No tickets can be created.",
  actions: ["Add the CA certificate in Configuration."],
  verify: ["Run Check now."],
  docs_url: "/help/troubleshooting/conn#PTH-CONN-1004",
  request_id: "req-1",
  ai_help: true,
};

function routes(extra: Record<string, Parameters<typeof mockApi>[0][string]> = {}) {
  return mockApi({
    "GET /api/v1/meta": meta(true),
    "GET /api/v1/connectors/kinds": () => ({ items: kinds }),
    "GET /api/v1/connectors": () => ({ items: conns }),
    "GET /api/v1/connectors/c1": () => ({ ...conns[0], auth_method: "github_app", config: { base_url: "https://api.github.com", allow_private: false, ca_bundle_set: false, webhook_secret: "do-not-show" }, credential: { set: true, updated_at: ago(1000) }, scopes: ["contents:read", "checks:write"] }) as ConnectorDetail,
    // Existing kinds describe themselves in `metadata` (the API's shape); config is {}.
    "GET /api/v1/connectors/c2": () => ({ ...conns[1], metadata: { auth_method: "pat", host: "https://github.example.com", proxy_url: "http://proxy:3128" }, config: {}, credential: { set: false } }),
    "GET /api/v1/connectors/c3": () => ({ ...conns[2], auth_method: "api_token", config: { base_url: "https://jira.example.com", ca_pem: "-----BEGIN CERTIFICATE-----x" }, credential: { set: true, ref: { provider: "vault", path: "secret/data/jira", key: "token" } } }),
    "GET /api/v1/connectors/c1/checks": () => ({ items: [] }),
    "GET /api/v1/connectors/c3/checks": () => ({ items: [{ id: "h1", status: "failing", checked_at: ago(180), duration_ms: 812, error: failure }] satisfies HealthCheck[] }),
    ...extra,
  });
}

describe("connectors model", () => {
  it("never shows a status that no check produced", () => {
    expect(displayStatus({ status: "healthy", last_check_at: null }).label).toBe("Never checked");
    expect(displayStatus({ status: "unknown", last_check_at: null }).label).toBe("Never checked");
    expect(displayStatus({ status: "healthy", last_check_at: ago(1) }).label).toBe("Healthy");
    expect(displayStatus({ status: "failing", last_check_at: ago(1) }).tone).toBe("danger");
    expect(displayStatus({ status: "disabled", last_check_at: null }).label).toBe("Disabled");
  });

  it("formats the time since a check", () => {
    expect(timeSince(null)).toBe("Never");
    expect(timeSince(new Date(now - 5 * 60_000).toISOString(), now)).toBe("5 min ago");
    expect(timeSince(new Date(now - 3 * 3600_000).toISOString(), now)).toBe("3 h ago");
    expect(timeSince(new Date(now - 5 * 86400_000).toISOString(), now)).toBe("5 days ago");
  });

  it("routes existing kinds to their existing pages and new kinds to the hub", () => {
    expect(existingFlow("github", { connect: true })).toMatchObject({ to: "/connectors", search: { manage: "scm", connect: "any" } });
    expect(existingFlow("jira")).toMatchObject({ search: { manage: "integrations" } });
    expect(existingFlow("kubernetes")?.to).toBe("/runtime");
    expect(existingFlow("ai_provider")?.to).toBe("/admin/ai");
    expect(existingFlow("slack")).toMatchObject({ to: "/admin/notifications", search: { tab: "webhooks" } });
    expect(existingFlow("vault")).toBeUndefined();
    expect(isHubKind(kinds[2]!)).toBe(true);
    expect(isHubKind(kinds[0]!)).toBe(false);
    expect(isHubKind(kinds[4]!)).toBe(false); // planned
    expect(manageLinkFor(conns[0]!)).toMatchObject({ search: { manage: "scm", connection: "s1" } });
  });

  it("reads a check failure from the envelope or from a flat error code", () => {
    expect(checkError({ error: failure })?.errorCode).toBe("PTH-CONN-1004");
    expect(checkError({ error: { error: failure } })?.envelope?.title).toBe("Connection uses an untrusted certificate");
    const flat = checkError({ error_code: "PTH-CONN-1007", message: "401 from gitlab.invalid" });
    expect(flat?.errorCode).toBe("PTH-CONN-1007");
    expect(flat?.message).toBe("401 from gitlab.invalid");
    expect(checkError({ error: null })).toBeUndefined();
    expect(checkError({})).toBeUndefined();
  });

  it("treats credential-like configuration keys as secret", () => {
    for (const k of ["webhook_secret", "password", "api_key", "token", "private_key", "client_secret", "access_key"]) expect(isSecretKey(k), k).toBe(true);
    for (const k of ["base_url", "proxy_url", "allow_private", "scopes"]) expect(isSecretKey(k), k).toBe(false);
  });

  it("validates the hub search", () => {
    expect(validateConnectorsSearch({ tab: "health", status: "never", manage: "scm", connect: "git", scm_tab: "oauth", x: 1 })).toMatchObject({ tab: "health", status: "never", manage: "scm", connect: "git", scm_tab: "oauth" });
    expect(validateConnectorsSearch({ tab: "nope", status: "bad", manage: "other" })).toEqual(expect.objectContaining({ tab: undefined, status: undefined, manage: undefined }));
  });
});

describe("connectors hub", () => {
  it("shows the feature-disabled state when the connectors flag is off", async () => {
    const api = mockApi({ "GET /api/v1/meta": meta(false) });
    renderApp(<ConnectorsPage />, { path: "/connectors" });
    expect(await screen.findByText("Connectors is not enabled")).toBeInTheDocument();
    expect(screen.getByText("connectors")).toBeInTheDocument();
    expect(api.calls.some((c) => c.path.startsWith("/api/v1/connectors"))).toBe(false);
  });

  it("shows the feature-disabled state when the API answers feature_disabled", async () => {
    const off = () => jsonResponse({ error: { code: "feature_disabled", error_code: "PTH-PLAT-1007", message: "Connectors is not enabled" } }, 404);
    routes({ "GET /api/v1/connectors/kinds": off, "GET /api/v1/connectors": off });
    renderApp(<ConnectorsPage />, { path: "/connectors" });
    expect(await screen.findByText("Connectors is not enabled")).toBeInTheDocument();
  });

  it("lists the nine categories with counts and real status only", async () => {
    routes();
    renderApp(<ConnectorsPage />, { path: "/connectors" });
    const rail = await screen.findByRole("navigation", { name: "Connector categories" });
    await waitFor(() => expect(within(rail).getByRole("button", { name: /^SCM & IDE/ })).toHaveTextContent("2/4"));
    const buttons = within(rail).getAllByRole("button");
    expect(buttons.map((b) => b.firstElementChild?.textContent?.replace(", has failing connectors", "").trim())).toEqual([
      "All categories", "SCM & IDE", "CI/CD", "Cloud", "Containers", "Security", "IAM & Secrets", "APIs", "Databases", "Monitoring",
    ]);
    await waitFor(() => expect(within(rail).getByRole("button", { name: /^SCM & IDE/ })).toHaveTextContent("2/4"));
    expect(within(rail).getByRole("button", { name: /^All categories/ })).toHaveTextContent("3/7");
    const connected = screen.getByRole("region", { name: "Connected" });
    const never = within(connected).getByRole("button", { name: /GitHub \(never\)/ });
    expect(within(never).getByText("Never checked")).toBeInTheDocument();
    expect(within(never).queryByText("Healthy")).not.toBeInTheDocument();
    expect(within(connected).getByRole("button", { name: /GitHub \(acme\)/ })).toHaveTextContent("Healthy");
    expect(within(connected).getByRole("button", { name: /Jira SEC/ })).toHaveTextContent("PTH-CONN-1004");
    // Health tab badge counts the failing connector.
    expect(screen.getByRole("tab", { name: /Health/ })).toHaveTextContent("1");
  });

  it("offers Connect: existing kinds deep-link, new kinds open the dialog, planned kinds none", async () => {
    routes();
    renderApp(<ConnectorsPage />, { path: "/connectors" });
    const nc = await screen.findByRole("region", { name: "Not connected" });
    // GitLab is an existing SCM kind: the SCM connections page inside the hub with the connect dialog.
    const gitlab = within(nc).getByRole("link", { name: /Connect GitLab/ });
    expect(gitlab.getAttribute("href")).toContain("/connectors?");
    expect(gitlab.getAttribute("href")).toContain("manage=scm");
    expect(gitlab.getAttribute("href")).toContain("connect=any");
    expect(within(nc).getByText("AWS").closest("div")).toHaveTextContent("Not available yet");
    await userEvent.click(within(nc).getByRole("button", { name: "Connect Bitbucket Data Center" }));
    expect(await screen.findByRole("dialog", { name: "Add connector" })).toBeInTheDocument();
  });

  it("creates a new-kind connector with a Vault reference instead of a stored secret", async () => {
    let posted: unknown;
    routes({ "POST /api/v1/connectors": (_u, init) => ((posted = init.json), { ...conns[0], id: "n1", kind: "bitbucket_data_center", name: "BBDC" }) });
    renderApp(
      <>
        <ConnectorsPage />
        <Toaster />
      </>,
      { path: "/connectors" },
    );
    await userEvent.click(await screen.findByRole("button", { name: "Add connector" }));
    const dlg = await screen.findByRole("dialog", { name: "Add connector" });
    await userEvent.type(within(dlg).getByLabelText("Name"), "BBDC");
    await userEvent.selectOptions(within(dlg).getByLabelText("Kind"), "bitbucket_data_center");
    await userEvent.type(within(dlg).getByLabelText(/Instance URL/), "https://bitbucket.example.com");
    await userEvent.click(within(dlg).getByLabelText(/Reference a secret in Vault or OpenBao/));
    const submit = within(dlg).getByRole("button", { name: "Add connector" });
    await userEvent.type(within(dlg).getByLabelText(/Secret reference/), "kv/pathos/bbdc");
    expect(within(dlg).getByText(/Use vault:/)).toBeInTheDocument();
    expect(submit).toBeDisabled();
    await userEvent.clear(within(dlg).getByLabelText(/Secret reference/));
    await userEvent.type(within(dlg).getByLabelText(/Secret reference/), "vault:kv/pathos/bbdc#token");
    await userEvent.click(submit);
    await waitFor(() => expect(posted).toBeDefined());
    expect(posted).toEqual({
      kind: "bitbucket_data_center",
      name: "BBDC",
      config: { base_url: "https://bitbucket.example.com", auth_method: "http_access_token", credential_ref: "vault:kv/pathos/bbdc#token" },
    });
    expect(JSON.stringify(posted)).not.toContain("credential\":");
    expect(await screen.findByText(/Connector “BBDC” added/)).toBeInTheDocument();
  });

  it("builds the form from the kind's config fields: SSH deploy key, and Vault with Kubernetes auth needs no credential", async () => {
    const posted: unknown[] = [];
    routes({ "POST /api/v1/connectors": (_u, init) => (posted.push(init.json), { ...conns[0], id: "n2", kind: "generic_git", name: "x" }) });
    renderApp(<ConnectorsPage />, { path: "/connectors" });
    await userEvent.click(await screen.findByRole("button", { name: "Add connector" }));
    let dlg = await screen.findByRole("dialog", { name: "Add connector" });
    await userEvent.selectOptions(within(dlg).getByLabelText("Kind"), "generic_git");
    await userEvent.type(within(dlg).getByLabelText("Name"), "Infra repo");
    await userEvent.type(within(dlg).getByLabelText(/Repository URL/), "ssh://git@git.example.com/infra.git");
    await userEvent.selectOptions(within(dlg).getByLabelText(/Authentication/), "ssh_key");
    // An SSH key is pasted (multi-line) and cannot be a Vault reference.
    expect(within(dlg).queryByLabelText(/Reference a secret/)).not.toBeInTheDocument();
    const key = within(dlg).getByLabelText(/SSH private key \(deploy key\)/);
    expect(key.tagName).toBe("TEXTAREA");
    await userEvent.type(within(dlg).getByLabelText(/known_hosts/), "git.example.com ssh-ed25519 AAAAC3");
    await userEvent.type(key, "KEY-MATERIAL");
    await userEvent.click(within(dlg).getByRole("button", { name: "Add connector" }));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]).toEqual({
      kind: "generic_git",
      name: "Infra repo",
      config: { base_url: "ssh://git@git.example.com/infra.git", auth_method: "ssh_key", ssh_known_hosts: "git.example.com ssh-ed25519 AAAAC3" },
      credential: "KEY-MATERIAL",
    });

    await userEvent.click(await screen.findByRole("button", { name: "Add connector" }));
    dlg = await screen.findByRole("dialog", { name: "Add connector" });
    await userEvent.selectOptions(within(dlg).getByLabelText("Kind"), "vault");
    await userEvent.type(within(dlg).getByLabelText("Name"), "Vault");
    await userEvent.type(within(dlg).getByLabelText(/Vault address/), "https://vault.example.com:8200");
    expect(within(dlg).getByLabelText(/AppRole secret ID/)).toBeInTheDocument();
    expect(within(dlg).getByRole("button", { name: "Add connector" })).toBeDisabled();
    await userEvent.selectOptions(within(dlg).getByLabelText(/Authentication/), "kubernetes");
    expect(within(dlg).queryByLabelText(/AppRole secret ID/)).not.toBeInTheDocument();
    await userEvent.type(within(dlg).getByLabelText(/Kubernetes auth role/), "pathos");
    await userEvent.click(within(dlg).getByLabelText(/Allow private network/));
    await userEvent.click(within(dlg).getByRole("button", { name: "Add connector" }));
    await waitFor(() => expect(posted).toHaveLength(2));
    expect(posted[1]).toEqual({
      kind: "vault",
      name: "Vault",
      config: { base_url: "https://vault.example.com:8200", auth_method: "kubernetes", kubernetes_role: "pathos", allow_private: true },
    });
  });

  it("opens the detail panel with history, a failure in the ErrorPanel and Check now", async () => {
    const api = routes({
      "POST /api/v1/connectors/c3/check": () => ({ status: "failing", connector: conns[2], result: { id: "h2", status: "failing", checked_at: new Date().toISOString(), duration_ms: 900, steps: [{ check: "tls", status: "fail", error_code: "PTH-CONN-1004", detail: "unknown authority" }], error: failure } }),
    });
    renderApp(<ConnectorsPage />, { path: "/connectors?connector=c3" });
    const panel = await screen.findByRole("region", { name: "Jira SEC details" });
    const alert = await within(panel).findByRole("alert", { name: "Connection uses an untrusted certificate" });
    expect(within(alert).getByText("PTH-CONN-1004")).toBeInTheDocument();
    expect(within(alert).getByRole("button", { name: /Troubleshoot with AI/ })).toBeInTheDocument();
    expect(within(panel).getByText("812 ms")).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: /Manage in Integrations/ }).getAttribute("href")).toContain("manage=integrations");
    await userEvent.click(within(panel).getByRole("button", { name: "Check now" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/connectors/c3/check")).toBe(true));
    expect(await within(panel).findByRole("list", { name: "Last check steps" })).toHaveTextContent("unknown authority");
  });

  it("Check now of a jobs-run kind says the check is queued (202 pending)", async () => {
    routes({
      "GET /api/v1/connectors": () => ({ items: [{ ...conns[0], checked_by: "jobs", can_manage: true }] }),
      "POST /api/v1/connectors/c1/check": () => jsonResponse({ status: "pending", connector: conns[0], result: null, requested_at: new Date().toISOString() }, 202),
    });
    renderApp(
      <>
        <ConnectorsPage />
        <Toaster />
      </>,
      { path: "/connectors?connector=c1" },
    );
    const panel = await screen.findByRole("region", { name: "GitHub (acme) details" });
    await userEvent.click(within(panel).getByRole("button", { name: "Check now" }));
    expect(await screen.findByText(/requested\. The jobs service runs it/)).toBeInTheDocument();
    expect(within(panel).getByRole("status")).toHaveTextContent("A health check is queued");
  });

  it("hides Check now without the manage permission and for kinds without a check", async () => {
    routes({ "GET /api/v1/connectors": () => ({ items: [{ ...conns[0], can_manage: false }, { ...conns[2], checked_by: "" }] }) });
    renderApp(<ConnectorsPage />, { path: "/connectors?tab=health" });
    await screen.findByRole("table");
    expect(screen.queryByRole("button", { name: /Check .* now/ })).not.toBeInTheDocument();
  });

  it("Health tab: every connector, last error code, time since the last check and a status filter", async () => {
    routes();
    const { router } = renderApp(<ConnectorsPage />, { path: "/connectors?tab=health" });
    const table = await screen.findByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent("Failing");
    expect(rows[0]).toHaveTextContent("PTH-CONN-1004");
    expect(rows[0]).toHaveTextContent("3 h ago");
    expect(within(table).getByText("GitHub (never)").closest("tr")).toHaveTextContent("Never checked");
    await userEvent.selectOptions(screen.getByLabelText("Status"), "never");
    await waitFor(() => expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(2));
    expect(router.state.location.search).toMatchObject({ status: "never" });
  });

  it("Authentication tab shows set / not set and the Vault reference, never a value", async () => {
    routes();
    renderApp(<ConnectorsPage />, { path: "/connectors?tab=authentication" });
    const table = await screen.findByRole("table");
    const row = (name: string) => within(table).getByText(name).closest("tr")!;
    await waitFor(() => expect(row("GitHub (acme)")).toHaveTextContent("GitHub App"));
    expect(row("GitHub (acme)")).toHaveTextContent("Set");
    expect(row("GitHub (acme)")).toHaveTextContent("PATHOS (encrypted)");
    expect(row("GitHub (acme)")).toHaveTextContent("contents:read, checks:write");
    await waitFor(() => expect(row("GitHub (never)")).toHaveTextContent("Not set"));
    await waitFor(() => expect(row("Jira SEC")).toHaveTextContent("HashiCorp Vault · secret/data/jira#token"));
  });

  it("Configuration tab shows base URL, proxy and CA present, and hides secret values", async () => {
    routes();
    renderApp(<ConnectorsPage />, { path: "/connectors?tab=configuration" });
    expect(await screen.findByText("https://api.github.com")).toBeInTheDocument();
    expect(await screen.findByText("http://proxy:3128")).toBeInTheDocument();
    expect(screen.queryByText(/do-not-show/)).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN CERTIFICATE/)).not.toBeInTheDocument();
    const jira = screen.getByRole("heading", { name: "Jira SEC" }).closest("div.rounded-lg") as HTMLElement;
    expect(within(jira).getByText("Custom CA certificate").nextSibling).toHaveTextContent("Yes");
  });

  it("embeds Integrations with all its actions (manage=integrations)", async () => {
    routes({
      "GET /api/v1/ticket-connections": () => ({ items: [{ id: "t1", kind: "jira", name: "Jira SEC", base_url: "https://jira.example.com", enabled: true, config: { project_key: "SEC" } }] }),
    });
    renderApp(<ConnectorsPage />, { path: "/connectors?category=monitoring&manage=integrations", permissions: ["settings.manage"] });
    expect(await screen.findByRole("heading", { level: 2, name: "Integrations" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: /New connection/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Test/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit Jira SEC" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete Jira SEC" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /All connectors/ })).toBeInTheDocument();
  });
});

/** A router with the old route and a stub hub, so the redirect lands on a different component. */
function twoRoutes(ui: ReactNode, oldPath: string, at: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const root = createRootRoute({ component: Outlet });
  const tree = root.addChildren([
    createRoute({ getParentRoute: () => root, path: oldPath, component: () => <>{ui}</> }),
    createRoute({ getParentRoute: () => root, path: "/connectors", component: () => <p>hub</p> }),
  ]);
  const router = createRouter({ routeTree: tree, history: createMemoryHistory({ initialEntries: [at] }) });
  render(
    <QueryClientProvider client={qc}>
      <SessionProvider me={me([])}>
        <RouterProvider router={router} />
      </SessionProvider>
    </QueryClientProvider>,
  );
  return router;
}

describe("old URLs", () => {
  it("/admin/scm renders the old page while the flag is off", async () => {
    mockApi({ "GET /api/v1/meta": meta(false), "GET /api/v1/scm-connections": () => ({ items: [] }), "GET /api/v1/scm/providers": () => ({ items: [] }) });
    const { router } = renderApp(<ScmConnectionsRoute />, { path: "/admin/scm", permissions: ["scm.manage"] });
    expect(await screen.findByRole("heading", { level: 1, name: "SCM connections" })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/admin/scm");
  });

  it("/admin/scm redirects into the hub with its parameters while the flag is on", async () => {
    mockApi({ "GET /api/v1/meta": meta(true) });
    const router = twoRoutes(<ScmConnectionsRoute />, "/admin/scm", "/admin/scm?oauth=success&connection=s1&tab=oauth");
    expect(await screen.findByText("hub")).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/connectors");
    expect(router.state.location.search).toMatchObject({ category: "scm_ide", manage: "scm", oauth: "success", connection: "s1", scm_tab: "oauth" });
  });

  it("/admin/integrations redirects only while the flag is on", async () => {
    mockApi({ "GET /api/v1/meta": meta(false), "GET /api/v1/ticket-connections": () => ({ items: [] }) });
    const off = renderApp(<IntegrationsRoute />, { path: "/admin/integrations" });
    expect(await screen.findByRole("heading", { level: 1, name: "Integrations" })).toBeInTheDocument();
    expect(off.router.state.location.pathname).toBe("/admin/integrations");
    off.unmount();
    vi.unstubAllGlobals();
    mockApi({ "GET /api/v1/meta": meta(true) });
    const on = renderApp(<IntegrationsRoute />, { path: "/admin/integrations" });
    await waitFor(() => expect(on.router.state.location.pathname).toBe("/connectors"));
    expect(on.router.state.location.search).toMatchObject({ category: "monitoring", manage: "integrations" });
  });
});

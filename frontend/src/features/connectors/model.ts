import type { Connector, ConnectorKind, ConnectorStatus } from "./api";

/** Hub search parameters (/connectors). SCM keys pass through to the embedded SCM connections page. */
export interface ConnectorsSearch {
  tab?: "authentication" | "configuration" | "health";
  category?: string;
  connector?: string;
  /** Embedded management page of an existing kind. */
  manage?: "scm" | "integrations";
  /** Health tab filter. */
  status?: ConnectorStatus | "never";
  q?: string;
  // Passed through to the embedded SCM connections page (same meaning as on /admin/scm).
  scm_tab?: "oauth";
  connect?: "git" | "devops" | "any";
  oauth?: "success" | "error";
  connection?: string;
  message?: string;
}

const statuses: (ConnectorStatus | "never")[] = ["healthy", "degraded", "failing", "unknown", "disabled", "never"];

export function validateConnectorsSearch(s: Record<string, unknown>): ConnectorsSearch {
  const str = (v: unknown, max = 300) => (typeof v === "string" && v.length > 0 && v.length <= max ? v : undefined);
  return {
    tab: s.tab === "authentication" || s.tab === "configuration" || s.tab === "health" ? s.tab : undefined,
    category: str(s.category, 40),
    connector: str(s.connector, 64),
    manage: s.manage === "scm" || s.manage === "integrations" ? s.manage : undefined,
    status: statuses.includes(s.status as ConnectorStatus) ? (s.status as ConnectorStatus | "never") : undefined,
    q: str(s.q, 100),
    scm_tab: s.scm_tab === "oauth" ? "oauth" : undefined,
    connect: s.connect === "git" || s.connect === "devops" || s.connect === "any" ? s.connect : undefined,
    oauth: s.oauth === "success" || s.oauth === "error" ? s.oauth : undefined,
    connection: str(s.connection, 64),
    message: str(s.message),
  };
}

/**
 * The status shown for a connector. Real status only: a connector that was
 * never checked is "Never checked", whatever the row says.
 */
export function displayStatus(c: Pick<Connector, "status" | "last_check_at">): { key: ConnectorStatus | "never"; label: string; tone: "success" | "warning" | "danger" | "neutral" } {
  if (c.status === "disabled") return { key: "disabled", label: "Disabled", tone: "neutral" };
  if (!c.last_check_at) return { key: "never", label: "Never checked", tone: "neutral" };
  switch (c.status) {
    case "healthy":
      return { key: "healthy", label: "Healthy", tone: "success" };
    case "degraded":
      return { key: "degraded", label: "Degraded", tone: "warning" };
    case "failing":
      return { key: "failing", label: "Failing", tone: "danger" };
    default:
      return { key: "unknown", label: "Unknown", tone: "neutral" };
  }
}

/** "3 min ago" style age of a timestamp; "Never" when there is none. */
export function timeSince(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "Never";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "Never";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

export const kindStatusLabel: Record<ConnectorKind["status"], { label: string; tone: "success" | "warning" | "neutral" }> = {
  existing: { label: "Available", tone: "success" },
  partial: { label: "Partial", tone: "warning" },
  planned: { label: "Planned", tone: "neutral" },
};

/** Where an existing kind is created and managed today. `search` targets the hub when the page is embedded there. */
export interface ManageLink {
  to: string;
  search?: Record<string, string>;
  label: string;
}

const scmLink = (extra: Record<string, string> = {}): ManageLink => ({ to: "/connectors", search: { category: "scm_ide", manage: "scm", ...extra }, label: "SCM connections" });
const ticketLink: ManageLink = { to: "/connectors", search: { category: "monitoring", manage: "integrations" }, label: "Integrations" };

const rules: [RegExp, ManageLink | ((connect: boolean) => ManageLink)][] = [
  [/^(scm|github|gitlab|bitbucket_cloud|bitbucket|azure_devops|azure_repos|azure_devops_server)$/, (connect) => scmLink(connect ? { connect: "any" } : {})],
  [/^(ticketing|jira|servicenow|ticket.*)$/, ticketLink],
  [/^(outbound_webhook|webhook|webhooks|slack|teams|msteams|slack_teams|siem_webhook)$/, { to: "/admin/notifications", search: { tab: "webhooks" }, label: "Notifications › Webhooks" }],
  [/^(smtp|email)$/, { to: "/admin/notifications", search: { tab: "email" }, label: "Notifications › Email" }],
  [/^(kubernetes|k8s|runtime_cluster|container_registry|registry|runtime_registry)$/, { to: "/runtime", label: "Runtime" }],
  [/^(ai|ai_provider|ai_config|llm)$/, { to: "/admin/ai", label: "AI settings" }],
  [/^(secret_validation|secret_validator|secret_provider)s?$/, { to: "/admin/secret-validation", label: "Secret validation" }],
  [/^(feed|feeds|vulnerability_feeds|osv|epss|kev|cisa_kev|deps_dev|depsdev|endoflife|eol)$/, { to: "/admin/risk-intelligence", label: "Risk & intelligence" }],
  [/^(mcp|mcp_registry|mcp_server)$/, { to: "/admin/mcp", label: "MCP registry" }],
  [/^(pathos_cli|cli|vscode|jetbrains|pathos_api|pathos_mcp|api_token|github_actions|gitlab_ci|azure_pipelines|jenkins|pre_commit|pre_receive)$/, { to: "/settings/tokens", label: "API tokens" }],
];

/**
 * Where to connect an existing kind: the kind's `managed_at` page from the
 * catalogue (SCM connections and Integrations open inside the hub), else a
 * known page for the kind.
 */
export function connectFlow(k: Pick<ConnectorKind, "kind" | "managed_at">): ManageLink | undefined {
  const m = k.managed_at;
  if (m && m.startsWith("/")) {
    const [path, qs] = m.split("?", 2) as [string, string | undefined];
    const extra = Object.fromEntries(new URLSearchParams(qs ?? ""));
    if (path === "/admin/scm") return scmLink({ connect: "any", ...(extra.tab === "oauth" ? { scm_tab: "oauth" } : {}) });
    if (path === "/admin/integrations") return ticketLink;
    const known = existingFlow(k.kind);
    return { to: path, search: Object.keys(extra).length ? extra : undefined, label: known && known.to === path ? known.label : pageLabel(path) };
  }
  return existingFlow(k.kind, { connect: true });
}

const pageLabels: Record<string, string> = {
  "/admin/notifications": "Notifications",
  "/runtime": "Runtime",
  "/admin/ai": "AI settings",
  "/admin/secret-validation": "Secret validation",
  "/admin/risk-intelligence": "Risk & intelligence",
  "/admin/mcp": "MCP registry",
  "/settings/tokens": "API tokens",
  "/admin/organization": "Organization",
};
const pageLabel = (p: string) => pageLabels[p] ?? p;

/** Where to connect or manage an existing kind by its key; undefined for new kinds (created in the hub) and unknown kinds. */
export function existingFlow(kind: string, opts: { connect?: boolean } = {}): ManageLink | undefined {
  const k = kind.toLowerCase();
  for (const [re, link] of rules) if (re.test(k)) return typeof link === "function" ? link(!!opts.connect) : link;
  return undefined;
}

/** Where to manage a connected row of an existing table. */
export function manageLinkFor(c: Connector): ManageLink | undefined {
  const t = c.source?.table;
  if (t === "scm_connections" && c.source?.id) return scmLink({ connection: c.source.id });
  if (c.managed_at) {
    const l = connectFlow({ kind: c.kind, managed_at: c.managed_at });
    // Managing an existing row: no "connect" dialog.
    if (l?.search) {
      const { connect: _c, ...rest } = l.search;
      return { ...l, search: rest };
    }
    return l;
  }
  if (t === "scm_connections") return scmLink({ connection: c.source!.id });
  if (t === "ticket_connections") return ticketLink;
  if (t === "outbound_webhooks") return { to: "/admin/notifications", search: { tab: "webhooks" }, label: "Notifications › Webhooks" };
  if (t === "smtp_settings") return { to: "/admin/notifications", search: { tab: "email" }, label: "Notifications › Email" };
  if (t === "runtime_clusters" || t === "registry_connections") return { to: "/runtime", label: "Runtime" };
  if (t === "ai_providers" || t === "ai_configs") return { to: "/admin/ai", label: "AI settings" };
  if (t === "connectors") return undefined; // new kinds: managed in the hub
  return existingFlow(c.kind);
}

/** True when the kind is created in the hub (POST /connectors) rather than on an existing page. */
export function isHubKind(k: ConnectorKind): boolean {
  if (k.status === "planned") return false;
  if (typeof k.creatable === "boolean") return k.creatable;
  return !k.managed_at && !existingFlow(k.kind);
}

/** Configuration keys that may hold a secret: never shown, only "set" / "not set". */
export const isSecretKey = (k: string) => /(secret|password|passwd|token|private_?key|credential|api_?key|access_?key|client_?secret|passphrase|^key$)/i.test(k);

/** Known non-secret configuration fields, in display order. */
export const configLabels: [string, string][] = [
  ["base_url", "Base URL"],
  ["url", "URL"],
  ["api_url", "API URL"],
  ["api_version", "API version"],
  ["proxy", "HTTPS proxy"],
  ["proxy_url", "HTTPS proxy"],
  ["allow_private", "Private network allowed"],
  ["ca_bundle_set", "Custom CA certificate"],
  ["ca_set", "Custom CA certificate"],
  ["ca_pem_set", "Custom CA certificate"],
  ["tls_verify", "TLS verification"],
  ["timeout_seconds", "Timeout (s)"],
  ["sync_interval", "Sync interval"],
];

export const authMethodLabel = (m: string | undefined): string => {
  if (!m) return "—";
  const known: Record<string, string> = {
    pat: "Personal access token",
    token: "Access token",
    access_token: "Access token",
    oauth: "OAuth",
    oauth2: "OAuth 2.0",
    github_app: "GitHub App",
    app_password: "App password",
    api_token: "API token",
    basic: "User name and password",
    ssh_key: "SSH key",
    http_token: "HTTP access token",
    http_access_token: "HTTP access token",
    https_token: "HTTPS token",
    user_token: "User token",
    approle: "AppRole",
    kubernetes: "Kubernetes auth",
    kubeconfig: "kubeconfig",
    service_account: "Service account",
    hmac: "Signed HMAC secret",
    // "bearer" is also a scanner's name; rule 3 keeps tool names off this page.
    bearer: "Token in the Authorization header",
    none: "None",
  };
  return known[m] ?? m.replace(/_/g, " ");
};

import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, parseEnvelope } from "@/api/client";

/**
 * Typed client for the Connectors API (/api/v1/connectors, PATHOS 3.0 M2).
 * Every list endpoint accepts a bare array or `{items: [...]}`.
 */

/** The nine connector categories, in rail order. */
export const categories = [
  { id: "scm_ide", label: "SCM & IDE" },
  { id: "cicd", label: "CI/CD" },
  { id: "cloud", label: "Cloud" },
  { id: "containers", label: "Containers" },
  { id: "security", label: "Security" },
  { id: "iam_secrets", label: "IAM & Secrets" },
  { id: "apis", label: "APIs" },
  { id: "databases", label: "Databases" },
  { id: "monitoring", label: "Monitoring" },
] as const;
export type ConnectorCategory = (typeof categories)[number]["id"];
export const isCategory = (c: unknown): c is ConnectorCategory => categories.some((x) => x.id === c);
export const categoryLabel = (c: string) => categories.find((x) => x.id === c)?.label ?? c;

/** GET /connectors/kinds item: what PATHOS supports, from the code catalogue. */
export interface ConnectorKind {
  kind: string;
  category: string;
  label: string;
  status: "existing" | "partial" | "planned";
  auth_methods: string[];
  docs_slug: string;
  offline_ok: boolean;
  /** The credential may be a Vault/OpenBao reference (vault:<mount>/<path>#<key>) instead of a stored secret. */
  secret_refs?: boolean;
  /** The Add connector form of a creatable kind. */
  config_fields?: ConfigField[];
  /** True when the kind is created through POST /connectors (new kinds); existing kinds keep their own pages. */
  creatable?: boolean;
  /** Page where connections of an existing kind are created and edited (for example /admin/scm). */
  managed_at?: string;
  /** outbound (PATHOS calls the system), inbound (the system calls PATHOS) or platform. */
  direction?: "outbound" | "inbound" | "platform";
  /** Where health checks run: "api", "jobs" or "" (no connector rows). */
  checked_by?: string;
  /** Why a kind is planned or partial. */
  note?: string;
}

/** One input of a creatable kind's form (GET /connectors/kinds, `config_fields`). */
export interface ConfigField {
  key: string;
  label: string;
  type: "text" | "url" | "pem" | "textarea" | "secret_ref" | "select" | "boolean";
  required: boolean;
  options?: string[];
  help?: string;
}

export type ConnectorStatus = "healthy" | "degraded" | "failing" | "unknown" | "disabled";

/** GET /connectors item: one row of the unified view over every connection table. */
export interface Connector {
  id: string;
  kind: string;
  category: string;
  name: string;
  status: ConnectorStatus;
  last_check_at: string | null;
  last_error_code: string;
  last_sync_at: string | null;
  /** The underlying row: an existing table (scm_connections, ticket_connections, …) or "connectors" for new kinds. */
  source?: { table: string; id: string } | null;
  enabled?: boolean;
  last_ok_at?: string | null;
  /** A check was requested and the jobs service has not run it yet. */
  check_requested_at?: string | null;
  /** Where checks run: "api", "jobs" or "" (no health check). */
  checked_by?: string;
  /** Page that manages the connection (existing kinds). */
  managed_at?: string;
  /** Whether the caller may run checks and change the connection. */
  can_manage?: boolean;
}

/** Write-only credential: only whether it is set (never the value) and, optionally, an external reference. */
export interface CredentialInfo {
  set: boolean;
  updated_at?: string | null;
  expires_at?: string | null;
  /** Vault/OpenBao reference (path and key are not secret). */
  ref?: { provider: string; path?: string; key?: string; mount?: string } | null;
}

/** GET /connectors/{id}: the row plus non-secret configuration. */
export interface ConnectorDetail extends Connector {
  /** Non-secret metadata of the source (host, auth method, allow_private, api_version, …). */
  metadata?: Record<string, string>;
  auth_method?: string;
  config?: Record<string, unknown>;
  credential?: CredentialInfo;
  scopes?: string[];
  /** The latest health check. */
  last_check?: HealthCheck | null;
}

/** A health check result (POST /check and GET /checks). */
export interface HealthCheck {
  id?: string;
  status: ConnectorStatus;
  checked_at: string;
  duration_ms: number;
  /** The full error envelope (incl. error_code) of a failed check. */
  error?: Record<string, unknown> | null;
  /** Flat code and message of a failed check (when the record carries no envelope). */
  error_code?: string;
  message?: string;
  /** manual | scheduled | … */
  trigger?: string;
  /** The parts of the check (reachability, authentication, scopes, …). */
  steps?: HealthStep[];
}

export interface HealthStep {
  check: string;
  status: "pass" | "warn" | "fail" | "skipped" | string;
  error_code?: string;
  detail?: string;
}

/** The auth method of a connector: the field, or the source metadata. */
export const authMethodOf = (d: ConnectorDetail | undefined): string | undefined =>
  d?.auth_method ?? d?.metadata?.auth_method ?? d?.metadata?.auth_type ?? (typeof d?.config?.auth_method === "string" ? d.config.auth_method : undefined);

/** Non-secret configuration: the stored config of a new kind merged over the source metadata of an existing one. */
export const configOf = (d: ConnectorDetail | undefined): Record<string, unknown> => ({ ...(d?.metadata ?? {}), ...(d?.config ?? {}) });

function items<T>(r: unknown): T[] {
  if (Array.isArray(r)) return r as T[];
  if (r && typeof r === "object" && Array.isArray((r as { items?: unknown }).items)) return (r as { items: T[] }).items;
  return [];
}

/** The error envelope of a check, as an ApiError the ErrorPanel can render (undefined when the check passed). */
export function checkError(c: Pick<HealthCheck, "error" | "error_code" | "message"> | undefined): ApiError | undefined {
  let raw = c?.error;
  if ((!raw || typeof raw !== "object") && c?.error_code) raw = { code: "check_failed", error_code: c.error_code, message: c.message ?? "" };
  if (!raw || typeof raw !== "object") return undefined;
  // Accept the envelope itself or a response body {error: {...}}.
  const e = (raw.error && typeof raw.error === "object" ? raw.error : raw) as Record<string, unknown>;
  const env = parseEnvelope(e);
  const message = typeof e.message === "string" && e.message ? e.message : "The health check failed";
  return new ApiError(0, typeof e.code === "string" ? e.code : "check_failed", message, env?.request_id || undefined, undefined, e);
}

/** True when the API answered that the connectors module is switched off (PTH-PLAT-1007). */
export function isFeatureDisabled(err: unknown): boolean {
  return err instanceof ApiError && (err.code === "feature_disabled" || err.errorCode === "PTH-PLAT-1007");
}

const base = "/api/v1/connectors";
export const connectorKeys = {
  all: ["connectors"] as const,
  kinds: ["connectors", "kinds"] as const,
  list: ["connectors", "list"] as const,
  detail: (id: string) => ["connectors", "detail", id] as const,
  checks: (id: string) => ["connectors", "checks", id] as const,
};

export function useConnectorKinds(enabled = true) {
  return useQuery({ queryKey: connectorKeys.kinds, queryFn: () => api<unknown>(`${base}/kinds`).then((r) => items<ConnectorKind>(r)), enabled, staleTime: 5 * 60_000, retry: false });
}

export function useConnectors(enabled = true) {
  return useQuery({ queryKey: connectorKeys.list, queryFn: () => api<unknown>(base).then((r) => items<Connector>(r)), enabled, retry: false });
}

export function useConnector(id: string | undefined) {
  return useQuery({ queryKey: connectorKeys.detail(id ?? ""), queryFn: () => api<ConnectorDetail>(`${base}/${encodeURIComponent(id!)}`), enabled: !!id, retry: false });
}

/** Details of several connectors (Authentication and Configuration tabs). */
export function useConnectorDetails(ids: string[]) {
  return useQueries({
    queries: ids.map((id) => ({ queryKey: connectorKeys.detail(id), queryFn: () => api<ConnectorDetail>(`${base}/${encodeURIComponent(id)}`), retry: false })),
  });
}

export function useConnectorChecks(id: string | undefined) {
  return useQuery({
    queryKey: connectorKeys.checks(id ?? ""),
    queryFn: () => api<unknown>(`${base}/${encodeURIComponent(id!)}/checks`).then((r) => items<HealthCheck>(r)),
    enabled: !!id,
    retry: false,
  });
}

/**
 * POST /connectors/{id}/check answers {status, connector, result} (200), or
 * {status: "pending"} (202) when the jobs service runs the check; a bare
 * health result is accepted too.
 */
export type CheckOutcome = { pending: true; result?: undefined } | { pending: false; result: HealthCheck };

export function parseCheckResponse(r: unknown): CheckOutcome {
  const o = (r && typeof r === "object" ? r : {}) as Record<string, unknown>;
  if (o.status === "pending" && !o.result) return { pending: true };
  if (o.result && typeof o.result === "object") return { pending: false, result: o.result as HealthCheck };
  return { pending: false, result: o as unknown as HealthCheck };
}

/** POST /connectors/{id}/check: a real health check now; refreshes the row, its detail and its history. */
export function useCheckNow() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<unknown>(`${base}/${encodeURIComponent(id)}/check`, { method: "POST" }).then(parseCheckResponse),
    onSettled: (_r, _e, id) => {
      void qc.invalidateQueries({ queryKey: connectorKeys.list });
      void qc.invalidateQueries({ queryKey: connectorKeys.detail(id) });
      void qc.invalidateQueries({ queryKey: connectorKeys.checks(id) });
    },
  });
}

/**
 * POST /connectors body (new kinds only). The credential is write-only; the
 * auth method and a Vault/OpenBao reference travel in `config`
 * (`auth_method`, `credential_ref`), which each kind validates.
 */
export interface NewConnector {
  kind: string;
  name: string;
  config: Record<string, unknown>;
  enabled?: boolean;
  credential?: string;
}

export function useCreateConnector() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: NewConnector) => api<ConnectorDetail>(base, { method: "POST", body }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: connectorKeys.all }),
  });
}

export function useUpdateConnector() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<NewConnector> }) => api<ConnectorDetail>(`${base}/${encodeURIComponent(id)}`, { method: "PUT", body }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: connectorKeys.all }),
  });
}

export function useDeleteConnector() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(`${base}/${encodeURIComponent(id)}`, { method: "DELETE" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: connectorKeys.all }),
  });
}

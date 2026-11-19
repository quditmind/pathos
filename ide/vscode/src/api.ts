// PATHOS REST API client. Pure: no VS Code dependency; the fetch function is
// injected so it can be unit-tested. The token is only ever placed in the
// Authorization header and never included in errors or logs.

import type { Finding, FindingStatus, Repository } from "./types";

export type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

export type ApiErrorKind =
  | "unauthorized" // 401: token missing, invalid, expired or revoked
  | "read_only" // 403 token_read_only: api:read token on a write request
  | "token_not_allowed" // 403 token_not_allowed
  | "forbidden" // 403: role does not permit it
  | "not_found" // 404 (also outside the caller's scope)
  | "conflict" // 409
  | "invalid" // 400, 422
  | "rate_limited" // 429
  | "server" // 5xx
  | "timeout"
  | "network"
  | "bad_response"
  | "other";

export class PathosApiError extends Error {
  constructor(
    readonly kind: ApiErrorKind,
    message: string,
    readonly status?: number,
    readonly code?: string,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "PathosApiError";
  }
}

export class PathosConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PathosConfigError";
  }
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Validates the configured PATHOS base URL and returns it without trailing
 * slash. https is required; plain http only for localhost/127.0.0.1/[::1].
 * Credentials, query and fragment are refused.
 */
export function validateBaseUrl(raw: string | null | undefined): string {
  const s = String(raw ?? "").trim();
  if (!s) throw new PathosConfigError("The PATHOS URL is not set (setting pathos.url).");
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new PathosConfigError(`The PATHOS URL "${s}" is not a valid URL.`);
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") {
    throw new PathosConfigError("The PATHOS URL must start with https://.");
  }
  if (u.protocol === "http:" && !LOCAL_HOSTS.has(u.hostname.toLowerCase())) {
    throw new PathosConfigError(
      "Refusing plain http:// for a remote PATHOS server: the API token would be sent unencrypted. Use https:// (http is only allowed for localhost).",
    );
  }
  if (u.username || u.password) throw new PathosConfigError("The PATHOS URL must not contain credentials.");
  if (u.search || u.hash) throw new PathosConfigError("The PATHOS URL must not contain a query or fragment.");
  return (u.origin + u.pathname).replace(/\/+$/, "");
}

/** Web UI link of a finding (the format used in notification e-mails). */
export function findingWebUrl(baseUrl: string, findingId: string): string {
  return `${baseUrl}/findings?status=all&finding=${encodeURIComponent(findingId)}`;
}

/** User-facing explanation of an error, with guidance for auth problems. */
export function describeError(err: unknown, action = "The request"): string {
  if (err instanceof PathosConfigError) return err.message;
  if (err instanceof PathosApiError) {
    switch (err.kind) {
      case "unauthorized":
        return "PATHOS rejected the API token (missing, invalid, expired or revoked). Set a new token with \"PATHOS: Set API token\".";
      case "read_only":
        return `${action} needs an API token with the api:write scope; this token only has api:read. Create a token with api:write in PATHOS (user menu → API tokens (MCP), "REST API: read and write") and set it again.`;
      case "token_not_allowed":
        return `${action} cannot be done with an API token; use the PATHOS web UI.`;
      case "forbidden":
        return `${action} was refused: your PATHOS role does not permit this.`;
      case "not_found":
        return `${action} failed: not found in PATHOS, or outside your access scope.`;
      case "conflict":
        return `${action} is not possible in the current state: ${err.message}`;
      case "invalid":
        return `${action} was rejected: ${err.message}`;
      case "rate_limited":
        return "PATHOS rate limit reached; try again in a moment.";
      case "timeout":
        return "PATHOS did not answer in time.";
      case "network":
        return `Cannot reach PATHOS: ${err.message}`;
      default:
        return `${action} failed: ${err.message}`;
    }
  }
  return `${action} failed: ${err instanceof Error ? err.message : String(err)}`;
}

export interface ClientOptions {
  baseUrl: string;
  token: string;
  fetch: FetchFn;
  timeoutMs?: number;
}

export interface FindingsPage {
  items: Finding[];
  /** True when the cap stopped the listing before the last page. */
  truncated: boolean;
}

export interface ReviewRequestResult {
  created: string[];
  existing: string[];
}

const MAX_PAGES = 1000;

export class PathosClient {
  readonly baseUrl: string;
  private readonly token: string;
  private readonly fetchFn: FetchFn;
  private readonly timeoutMs: number;

  constructor(opts: ClientOptions) {
    this.baseUrl = validateBaseUrl(opts.baseUrl);
    if (!opts.token || /\s/.test(opts.token)) throw new PathosConfigError("The PATHOS API token is not set.");
    this.token = opts.token;
    this.fetchFn = opts.fetch;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  /** Every active repository the caller can see (keyset pagination, 200 per page). */
  async listRepositories(max = 20_000): Promise<Repository[]> {
    const out: Repository[] = [];
    await this.paginate<Repository>("/api/v1/repositories", { limit: "200", sort: "name" }, max, out);
    return out;
  }

  /**
   * Open findings (stored status open, in_progress or needs_review) of one
   * repository, highest severity first, at most `max`.
   */
  async listOpenFindings(repositoryId: string, max = 5000): Promise<FindingsPage> {
    const items: Finding[] = [];
    const truncated = await this.paginate<Finding>(
      "/api/v1/findings",
      { repository_id: repositoryId, status: "open", sort: "severity" },
      max,
      items,
    );
    return { items, truncated };
  }

  getFinding(id: string): Promise<Finding> {
    return this.request<Finding>("GET", `/api/v1/findings/${encodeURIComponent(id)}`);
  }

  async changeStatus(id: string, status: FindingStatus, reason?: string): Promise<void> {
    const body: Record<string, string> = { status };
    if (reason && reason.trim()) body.reason = reason.trim();
    await this.request<void>("POST", `/api/v1/findings/${encodeURIComponent(id)}/status`, body);
  }

  async requestHumanReview(findingId: string, reason?: string): Promise<ReviewRequestResult> {
    const body: Record<string, unknown> = { finding_ids: [findingId] };
    if (reason && reason.trim()) body.reason = reason.trim();
    const res = await this.request<Partial<ReviewRequestResult>>("POST", "/api/v1/human-reviews", body);
    return { created: res?.created ?? [], existing: res?.existing ?? [] };
  }

  /** Follows next_cursor until the last page or `max` items; returns true when truncated. */
  private async paginate<T>(path: string, params: Record<string, string>, max: number, out: T[]): Promise<boolean> {
    let cursor: string | null = null;
    const seen = new Set<string>();
    for (let page = 0; page < MAX_PAGES; page++) {
      const q = new URLSearchParams(params);
      if (cursor) q.set("cursor", cursor);
      const res = await this.request<{ items?: T[]; next_cursor?: string | null }>("GET", `${path}?${q.toString()}`);
      if (!res || !Array.isArray(res.items)) throw new PathosApiError("bad_response", "unexpected response from PATHOS (no items)");
      for (const item of res.items) {
        if (out.length >= max) return true;
        out.push(item);
      }
      cursor = res.next_cursor ?? null;
      if (!cursor) return false;
      if (out.length >= max) return true;
      if (seen.has(cursor)) throw new PathosApiError("bad_response", "PATHOS returned the same page cursor twice");
      seen.add(cursor);
    }
    return true;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {
      Accept: "application/json",
      Authorization: `Bearer ${this.token}`,
    };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let res: Response;
    try {
      res = await this.fetchFn(this.baseUrl + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
        // Never follow redirects: they could carry the token to another host.
        redirect: "error",
        credentials: "omit",
      });
    } catch (e) {
      clearTimeout(timer);
      if (controller.signal.aborted) throw new PathosApiError("timeout", `no answer within ${Math.round(this.timeoutMs / 1000)} s`);
      throw new PathosApiError("network", errorText(e));
    }
    try {
      if (!res.ok) throw await toApiError(res);
      if (res.status === 204) return undefined as T;
      const text = await res.text();
      if (!text) return undefined as T;
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new PathosApiError("bad_response", "PATHOS returned invalid JSON (is pathos.url the PATHOS address?)", res.status);
      }
    } catch (e) {
      if (e instanceof PathosApiError) throw e;
      if (controller.signal.aborted) throw new PathosApiError("timeout", `no answer within ${Math.round(this.timeoutMs / 1000)} s`);
      throw new PathosApiError("network", errorText(e));
    } finally {
      clearTimeout(timer);
    }
  }
}

function errorText(e: unknown): string {
  if (e instanceof Error) {
    const cause = (e as Error & { cause?: unknown }).cause;
    return cause instanceof Error && cause.message ? `${e.message} (${cause.message})` : e.message;
  }
  return String(e);
}

async function toApiError(res: Response): Promise<PathosApiError> {
  let code: string | undefined;
  let message: string | undefined;
  let requestId = res.headers.get("x-request-id") ?? undefined;
  try {
    const body = (await res.json()) as { error?: { code?: unknown; message?: unknown }; request_id?: unknown };
    if (typeof body?.error?.code === "string") code = body.error.code;
    if (typeof body?.error?.message === "string") message = body.error.message.slice(0, 500);
    if (typeof body?.request_id === "string") requestId = body.request_id;
  } catch {
    // not JSON
  }
  const msg = message ?? `HTTP ${res.status}`;
  let kind: ApiErrorKind;
  switch (res.status) {
    case 401:
      kind = "unauthorized";
      break;
    case 403:
      kind = code === "token_read_only" ? "read_only" : code === "token_not_allowed" ? "token_not_allowed" : "forbidden";
      break;
    case 404:
      kind = "not_found";
      break;
    case 409:
      kind = "conflict";
      break;
    case 400:
    case 422:
      kind = "invalid";
      break;
    case 429:
      kind = "rate_limited";
      break;
    default:
      kind = res.status >= 500 ? "server" : "other";
  }
  return new PathosApiError(kind, msg, res.status, code, requestId);
}

// Minimal typed API client. The session lives in an HttpOnly cookie; the
// CSRF token comes from GET /api/v1/me and is sent on every unsafe request.

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public requestId?: string,
    /** Per-field messages of a 422 validation error ({ error: { fields } }). */
    public fields?: Record<string, string>,
    /** The whole error object, for endpoint-specific extra fields. */
    public details?: Record<string, unknown>,
  ) {
    super(message);
  }

  /** Catalogue code (PTH-<AREA>-<NNNN>) from error.error_code, when the server sent one. */
  get errorCode(): string | undefined {
    const c = this.details?.error_code;
    return typeof c === "string" && isCatalogueCode(c) ? c : undefined;
  }

  /** The diagnostic envelope (catalogue code plus explanation), when present. */
  get envelope(): ErrorEnvelope | undefined {
    return parseEnvelope(this.details, this.requestId);
  }
}

/** Catalogue error codes: PTH-<AREA>-<NNNN>. */
export const isCatalogueCode = (c: string) => /^PTH-[A-Z]+-\d{4}$/.test(c);

/** An action or verification step; the server may send plain text or text with a link. */
export type EnvelopeStep = string | { text: string; href?: string };

/**
 * The diagnostic error envelope inside "error" (backward compatible: "code"
 * stays the snake_case slug, the catalogue code is "error_code").
 */
export interface ErrorEnvelope {
  code: string;
  error_code: string;
  title: string;
  message: string;
  cause?: { confirmed: boolean; text: string };
  probable_causes: string[];
  impact: string;
  actions: EnvelopeStep[];
  verify: EnvelopeStep[];
  docs_url: string;
  request_id: string;
  /** Whether AI troubleshooting is offered for this code. */
  ai_help: boolean;
}

const str = (v: unknown) => (typeof v === "string" ? v : "");
const strs = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
const steps = (v: unknown): EnvelopeStep[] =>
  Array.isArray(v)
    ? v.flatMap((x): EnvelopeStep[] => {
        if (typeof x === "string") return [x];
        if (x && typeof x === "object" && typeof (x as { text?: unknown }).text === "string") {
          const o = x as { text: string; href?: unknown };
          return [{ text: o.text, href: typeof o.href === "string" && o.href.startsWith("/") ? o.href : undefined }];
        }
        return [];
      })
    : [];

/** Reads the envelope from an error object; undefined for old-style errors. */
export function parseEnvelope(err: Record<string, unknown> | undefined, topRequestId?: string): ErrorEnvelope | undefined {
  if (!err) return undefined;
  const errorCode = str(err.error_code);
  if (!isCatalogueCode(errorCode)) return undefined;
  const cause = err.cause as { confirmed?: unknown; text?: unknown } | undefined;
  return {
    code: str(err.code),
    error_code: errorCode,
    title: str(err.title),
    message: str(err.message),
    cause: cause && typeof cause.text === "string" && cause.text ? { confirmed: cause.confirmed === true, text: cause.text } : undefined,
    probable_causes: strs(err.probable_causes),
    impact: str(err.impact),
    actions: steps(err.actions),
    verify: steps(err.verify),
    docs_url: str(err.docs_url).startsWith("/") ? str(err.docs_url) : "",
    request_id: str(err.request_id) || topRequestId || "",
    ai_help: err.ai_help === true,
  };
}

/** One API call, as kept for "Report a problem" (no query string, ids masked). */
export interface RequestRecord {
  at: string;
  method: string;
  path: string;
  status: number;
  request_id?: string;
  code?: string;
  error_code?: string;
}

const REQUEST_LOG_SIZE = 50;
const requestLog: RequestRecord[] = [];

/** Masks identifiers in a path; the query string and fragment are dropped. */
export function maskPath(path: string): string {
  const p = path.split(/[?#]/)[0] ?? "";
  return p
    .split("/")
    .map((seg) =>
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg) || /^\d+$/.test(seg) || seg.length > 40 ? ":id" : seg,
    )
    .join("/");
}

function record(r: RequestRecord) {
  requestLog.push(r);
  if (requestLog.length > REQUEST_LOG_SIZE) requestLog.splice(0, requestLog.length - REQUEST_LOG_SIZE);
}

/** The last 50 API calls of this page session (newest last). */
export function recentRequests(): RequestRecord[] {
  return requestLog.map((r) => ({ ...r }));
}

/** Test helper. */
export function clearRequestLog() {
  requestLog.length = 0;
}

let csrfToken = "";

export function setCsrfToken(t: string) {
  csrfToken = t;
}

export function getCsrfToken() {
  return csrfToken;
}

type Options = { method?: string; body?: unknown; signal?: AbortSignal };

export async function api<T>(path: string, opts: Options = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && method !== "HEAD") headers["X-CSRF-Token"] = csrfToken;

  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
  });
  const headerId = res.headers?.get?.("X-Request-Id") ?? undefined;
  if (res.status === 204) {
    record({ at: new Date().toISOString(), method, path: maskPath(path), status: res.status, request_id: headerId });
    return undefined as T;
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = data?.error ?? {};
    record({
      at: new Date().toISOString(),
      method,
      path: maskPath(path),
      status: res.status,
      request_id: (typeof data?.request_id === "string" ? data.request_id : undefined) ?? headerId,
      code: typeof err.code === "string" ? err.code.slice(0, 64) : undefined,
      error_code: typeof err.error_code === "string" && isCatalogueCode(err.error_code) ? err.error_code : undefined,
    });
    throw new ApiError(
      res.status,
      err.code ?? "error",
      err.message ?? res.statusText,
      data?.request_id,
      err.fields && typeof err.fields === "object" ? (err.fields as Record<string, string>) : undefined,
      err,
    );
  }
  record({ at: new Date().toISOString(), method, path: maskPath(path), status: res.status, request_id: headerId });
  return data as T;
}

export function loginUrl(returnTo = window.location.pathname + window.location.search) {
  return `/api/auth/login?return_to=${encodeURIComponent(returnTo)}`;
}

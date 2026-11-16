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
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = data?.error ?? {};
    throw new ApiError(
      res.status,
      err.code ?? "error",
      err.message ?? res.statusText,
      data?.request_id,
      err.fields && typeof err.fields === "object" ? (err.fields as Record<string, string>) : undefined,
      err,
    );
  }
  return data as T;
}

export function loginUrl(returnTo = window.location.pathname + window.location.search) {
  return `/api/auth/login?return_to=${encodeURIComponent(returnTo)}`;
}

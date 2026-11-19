import { maskPath, recentRequests, type RequestRecord } from "@/api/client";
import { bundleVersion, type Meta } from "./meta";

/**
 * "Report a problem": a redacted diagnostic bundle the user downloads and
 * attaches to a support request. It holds version, build, browser, route,
 * the last 50 request IDs and error codes, and feature flags. It never holds
 * tokens, secrets, cookies, source code or finding contents: only allow-listed
 * fields are copied, and every string passes redactText as a second line of
 * defence.
 */
export interface DiagnosticBundle {
  kind: "pathos-diagnostic-bundle";
  format: 1;
  generated_at: string;
  product: { name: string; vendor: string };
  frontend: { version: string };
  backend: { version: string; commit: string; build_date: string; api_version: string };
  browser: { user_agent: string; language: string; timezone: string; viewport: string; online: boolean };
  route: string;
  feature_flags: Record<string, boolean>;
  recent_requests: RequestRecord[];
  error_codes: string[];
}

const SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, // PEM keys
  /\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}\b/g, // JWT
  /\b(Bearer|Basic|token)\s+[\w~+/.=-]{8,}/gi, // auth headers
  /\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[\w-]{20,}|xox[abprs]-[\w-]{10,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|pth_[A-Za-z0-9_]{16,})\b/g, // provider tokens
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s@/]+@/gi, // credentials in URLs
  /\b(password|passwd|secret|token|api[_-]?key|client[_-]?secret|authorization|cookie|csrf)\b\s*[:=]\s*\S+/gi, // key=value
  /\b[A-Fa-f0-9]{40,}\b/g, // long hex (keys, hashes of secrets)
  /\b[A-Za-z0-9+/]{48,}={0,2}/g, // long base64 blobs
];

/** Replaces anything secret-shaped in free text with [REDACTED]. */
export function redactText(s: string): string {
  let out = s;
  for (const re of SECRET_PATTERNS) out = out.replace(re, "[REDACTED]");
  return out.length > 500 ? out.slice(0, 500) + "…" : out;
}

const SECRET_KEY = /token|secret|password|passwd|authorization|cookie|csrf|api[_-]?key|credential|session|private/i;

/** Deep copy without secret-named keys; strings are passed through redactText. */
export function redactValue(v: unknown, depth = 0): unknown {
  if (depth > 6) return "[TRUNCATED]";
  if (typeof v === "string") return redactText(v);
  if (Array.isArray(v)) return v.slice(0, 100).map((x) => redactValue(x, depth + 1));
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      if (SECRET_KEY.test(k)) continue;
      out[k] = redactValue(x, depth + 1);
    }
    return out;
  }
  return v;
}

export function buildDiagnosticBundle(opts: { meta?: Meta; pathname: string; now?: Date; requests?: RequestRecord[] }): DiagnosticBundle {
  const m = opts.meta;
  const requests = (opts.requests ?? recentRequests()).slice(-50).map((r) => ({
    at: r.at,
    method: r.method,
    path: maskPath(r.path),
    status: r.status,
    ...(r.request_id ? { request_id: r.request_id } : {}),
    ...(r.code ? { code: r.code } : {}),
    ...(r.error_code ? { error_code: r.error_code } : {}),
  }));
  const flags: Record<string, boolean> = {};
  for (const [k, v] of Object.entries(m?.feature_flags ?? {})) if (typeof v === "boolean") flags[k] = v;
  let tz = "";
  try {
    tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    /* unavailable */
  }
  const bundle: DiagnosticBundle = {
    kind: "pathos-diagnostic-bundle",
    format: 1,
    generated_at: (opts.now ?? new Date()).toISOString(),
    product: { name: m?.product ?? "PATHOS", vendor: m?.vendor ?? "Quditmind" },
    frontend: { version: bundleVersion },
    backend: { version: m?.version ?? "", commit: m?.commit ?? "", build_date: m?.build_date ?? "", api_version: m?.api_version ?? "" },
    browser: {
      user_agent: typeof navigator !== "undefined" ? navigator.userAgent : "",
      language: typeof navigator !== "undefined" ? navigator.language : "",
      timezone: tz,
      viewport: typeof window !== "undefined" ? `${window.innerWidth}x${window.innerHeight}` : "",
      online: typeof navigator !== "undefined" ? navigator.onLine : true,
    },
    route: maskPath(opts.pathname),
    feature_flags: flags,
    recent_requests: requests,
    error_codes: [...new Set(requests.flatMap((r) => [r.error_code, r.code].filter((c): c is string => !!c)))],
  };
  return redactValue(bundle) as DiagnosticBundle;
}

/** Downloads the bundle as a JSON file (no network request). */
export function downloadDiagnosticBundle(bundle: DiagnosticBundle) {
  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `pathos-diagnostics-${bundle.generated_at.replace(/[:.]/g, "-")}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

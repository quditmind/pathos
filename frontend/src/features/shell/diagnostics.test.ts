import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, clearRequestLog, recentRequests, type RequestRecord } from "@/api/client";
import { buildDiagnosticBundle, redactText, redactValue } from "./diagnostics";

const secrets = [
  "Bearer abcdefghijklmnop1234",
  "ghp_0123456789abcdefghijABCDEFGHIJ0123",
  "glpat-abcdefghijklmnopqrstuv",
  "AKIAABCDEFGHIJKLMNOP",
  "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuv",
  "https://user:hunter2pass@git.example.com/repo.git",
  "password=hunter2",
  "client_secret: s3cr3t-value",
  "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
  "0123456789abcdef0123456789abcdef0123456789abcdef",
];

describe("redaction", () => {
  it.each(secrets)("removes %s", (s) => {
    const out = redactText(`context ${s} more`);
    expect(out).toContain("[REDACTED]");
    expect(out).not.toContain(s);
  });

  it("keeps ordinary text, codes and request ids", () => {
    const t = "PTH-CONN-1004 x509: certificate signed by unknown authority (request abcdefghijklmnopqrstuvwx)";
    expect(redactText(t)).toBe(t);
  });

  it("drops secret-named keys at any depth", () => {
    const out = redactValue({ a: 1, token: "x", nested: { csrf_token: "y", Authorization: "z", password: "p", api_key: "k", ok: "fine", session_id: "s" } });
    expect(out).toEqual({ a: 1, nested: { ok: "fine" } });
  });
});

describe("diagnostic bundle", () => {
  beforeEach(() => clearRequestLog());

  const req = (over: Partial<RequestRecord> = {}): RequestRecord => ({ at: "2026-11-20T10:00:00Z", method: "GET", path: "/api/v1/findings", status: 200, ...over });

  it("holds version, build, browser, route, flags and the last 50 requests only", () => {
    const requests = Array.from({ length: 60 }, (_, i) => req({ request_id: `r${i}` }));
    const b = buildDiagnosticBundle({
      meta: { product: "PATHOS", vendor: "Quditmind", version: "3.0.0", commit: "abc", build_date: "d", api_version: "v1", feature_flags: { codegraph: true } },
      pathname: "/repositories/0190b3c5-1111-7222-8333-944455556666/branches",
      requests,
      now: new Date("2026-11-20T10:00:00Z"),
    });
    expect(Object.keys(b).sort()).toEqual(["backend", "browser", "error_codes", "feature_flags", "format", "frontend", "generated_at", "kind", "product", "recent_requests", "route"].sort());
    expect(b.backend).toEqual({ version: "3.0.0", commit: "abc", build_date: "d", api_version: "v1" });
    expect(b.route).toBe("/repositories/:id/branches");
    expect(b.recent_requests).toHaveLength(50);
    expect(b.recent_requests[0]!.request_id).toBe("r10");
    expect(b.feature_flags).toEqual({ codegraph: true });
    expect(b.browser.user_agent).toBeTypeOf("string");
  });

  it("never carries tokens, secrets, query strings or finding content", () => {
    const b = buildDiagnosticBundle({
      meta: {
        product: "PATHOS",
        vendor: "Quditmind",
        version: "3.0.0",
        // A misbehaving server field must not leak through.
        commit: "Bearer abcdefghijklmnopqrstuvwxyz",
        feature_flags: { codegraph: true, evil: "ghp_0123456789abcdefghijABCDEFGHIJ0123" as unknown as boolean },
      },
      pathname: "/findings?q=password%3Dhunter2#token",
      requests: [
        req({ path: "/api/v1/findings?search=AKIAABCDEFGHIJKLMNOP&snippet=select+*", status: 422, code: "validation_failed", error_code: "PTH-SCAN-2001", request_id: "abc" }),
      ],
    });
    const json = JSON.stringify(b);
    for (const bad of ["abcdefghijklmnopqrstuvwxyz", "ghp_", "AKIA", "hunter2", "snippet", "select", "?", "#token", "evil"]) expect(json).not.toContain(bad);
    expect(b.recent_requests[0]).toEqual({ at: "2026-11-20T10:00:00Z", method: "GET", path: "/api/v1/findings", status: 422, request_id: "abc", code: "validation_failed", error_code: "PTH-SCAN-2001" });
    expect(b.error_codes).toEqual(["PTH-SCAN-2001", "validation_failed"]);
  });
});

describe("api client request log", () => {
  beforeEach(() => clearRequestLog());

  it("records method, masked path, status, request id and both error codes", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(new Response("{}", { status: 200, headers: { "X-Request-Id": "okid" } }))
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ error: { code: "conflict", error_code: "PTH-CONN-1004", message: "x", request_id: "rid" }, request_id: "rid" }), { status: 409 }),
        ),
    );
    await api("/api/v1/repositories/0190b3c5-1111-7222-8333-944455556666?x=secret");
    const err = await api("/api/v1/repositories", { method: "POST", body: {} }).catch((e: unknown) => e);
    expect(recentRequests()).toEqual([
      expect.objectContaining({ method: "GET", path: "/api/v1/repositories/:id", status: 200, request_id: "okid" }),
      expect.objectContaining({ method: "POST", path: "/api/v1/repositories", status: 409, request_id: "rid", code: "conflict", error_code: "PTH-CONN-1004" }),
    ]);
    expect((err as { code: string }).code).toBe("conflict");
    expect((err as { errorCode: string }).errorCode).toBe("PTH-CONN-1004");
    vi.unstubAllGlobals();
  });

  it("keeps only the last 50", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 200 })));
    for (let i = 0; i < 55; i++) await api(`/api/v1/x${i}`);
    const log = recentRequests();
    expect(log).toHaveLength(50);
    expect(log[0]!.path).toBe("/api/v1/x5");
    vi.unstubAllGlobals();
  });
});

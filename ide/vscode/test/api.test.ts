import { describe, expect, it, vi } from "vitest";
import { describeError, findingWebUrl, PathosApiError, PathosClient, PathosConfigError, validateBaseUrl, type FetchFn } from "../src/api";

const TOKEN = "pathos_pat_secret123";

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function client(fetchFn: FetchFn, timeoutMs?: number) {
  return new PathosClient({ baseUrl: "https://pathos.example.com/", token: TOKEN, fetch: fetchFn, timeoutMs });
}

describe("validateBaseUrl", () => {
  it("accepts https and strips the trailing slash", () => {
    expect(validateBaseUrl("https://pathos.example.com/")).toBe("https://pathos.example.com");
    expect(validateBaseUrl(" https://example.com/pathos/ ")).toBe("https://example.com/pathos");
  });
  it("allows plain http only for localhost", () => {
    expect(validateBaseUrl("http://localhost:8080")).toBe("http://localhost:8080");
    expect(validateBaseUrl("http://127.0.0.1")).toBe("http://127.0.0.1");
    expect(() => validateBaseUrl("http://pathos.example.com")).toThrow(/http/);
  });
  it("refuses empty, invalid, other schemes, credentials and queries", () => {
    for (const bad of ["", "pathos.example.com", "ftp://pathos.example.com", "javascript:alert(1)", "https://u:p@pathos.example.com", "https://pathos.example.com/?a=1", "https://pathos.example.com/#x"]) {
      expect(() => validateBaseUrl(bad), bad).toThrow(PathosConfigError);
    }
  });
  it("is enforced by the client", () => {
    expect(() => new PathosClient({ baseUrl: "http://evil.example.com", token: TOKEN, fetch: vi.fn() })).toThrow(PathosConfigError);
    expect(() => new PathosClient({ baseUrl: "https://ok.example.com", token: "", fetch: vi.fn() })).toThrow(PathosConfigError);
  });
});

describe("findingWebUrl", () => {
  it("uses the notification link format", () => {
    expect(findingWebUrl("https://p.example.com", "abc")).toBe("https://p.example.com/findings?status=all&finding=abc");
  });
});

describe("PathosClient requests", () => {
  it("sends the bearer token and no cookies, and never follows redirects", async () => {
    const f = vi.fn<FetchFn>(async () => json(200, { items: [], next_cursor: null }));
    await client(f).listRepositories();
    const [url, init] = f.mock.calls[0];
    expect(url).toBe("https://pathos.example.com/api/v1/repositories?limit=200&sort=name");
    expect((init?.headers as Record<string, string>).Authorization).toBe(`Bearer ${TOKEN}`);
    expect(init?.redirect).toBe("error");
    expect(init?.credentials).toBe("omit");
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("follows repository cursors", async () => {
    const f = vi.fn<FetchFn>(async (url) =>
      url.includes("cursor=c1")
        ? json(200, { items: [{ id: "2", full_name: "o/b" }], next_cursor: null })
        : json(200, { items: [{ id: "1", full_name: "o/a" }], next_cursor: "c1" }),
    );
    const repos = await client(f).listRepositories();
    expect(repos.map((r) => r.id)).toEqual(["1", "2"]);
    expect(f).toHaveBeenCalledTimes(2);
    expect(f.mock.calls[1][0]).toContain("cursor=c1");
  });

  it("lists open findings of a repository with cursor pagination and a cap", async () => {
    const pages: Record<string, unknown> = {
      "": { items: [{ id: "a" }, { id: "b" }], next_cursor: "p2" },
      p2: { items: [{ id: "c" }, { id: "d" }], next_cursor: "p3" },
      p3: { items: [{ id: "e" }], next_cursor: null },
    };
    const f = vi.fn<FetchFn>(async (url) => {
      const u = new URL(url);
      expect(u.pathname).toBe("/api/v1/findings");
      expect(u.searchParams.get("repository_id")).toBe("repo-1");
      expect(u.searchParams.get("status")).toBe("open");
      return json(200, pages[u.searchParams.get("cursor") ?? ""]);
    });
    const all = await client(f).listOpenFindings("repo-1");
    expect(all.items.map((x) => x.id)).toEqual(["a", "b", "c", "d", "e"]);
    expect(all.truncated).toBe(false);

    f.mockClear();
    const capped = await client(f).listOpenFindings("repo-1", 3);
    expect(capped.items.map((x) => x.id)).toEqual(["a", "b", "c"]);
    expect(capped.truncated).toBe(true);
    expect(f).toHaveBeenCalledTimes(2);

    const exact = await client(f).listOpenFindings("repo-1", 5);
    expect(exact.truncated).toBe(false);
  });

  it("stops on a repeated cursor", async () => {
    const f = vi.fn<FetchFn>(async () => json(200, { items: [{ id: "x" }], next_cursor: "same" }));
    await expect(client(f).listOpenFindings("r")).rejects.toMatchObject({ kind: "bad_response" });
  });

  it("posts status changes and review requests as JSON", async () => {
    const f = vi.fn<FetchFn>(async (url) =>
      url.endsWith("/human-reviews") ? json(201, { created: ["r1"], existing: [] }) : new Response(null, { status: 204 }),
    );
    const c = client(f);
    await c.changeStatus("f/1", "false_positive", "  test fixture ");
    let [url, init] = f.mock.calls[0];
    expect(url).toBe("https://pathos.example.com/api/v1/findings/f%2F1/status");
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect(JSON.parse(String(init?.body))).toEqual({ status: "false_positive", reason: "test fixture" });

    await c.changeStatus("f1", "in_progress", "");
    expect(JSON.parse(String(f.mock.calls[1][1]?.body))).toEqual({ status: "in_progress" });

    const res = await c.requestHumanReview("f1", "please check");
    [url, init] = f.mock.calls[2];
    expect(url).toBe("https://pathos.example.com/api/v1/human-reviews");
    expect(JSON.parse(String(init?.body))).toEqual({ finding_ids: ["f1"], reason: "please check" });
    expect(res).toEqual({ created: ["r1"], existing: [] });
  });
});

describe("PathosClient errors", () => {
  const cases: [number, string | undefined, string][] = [
    [401, "invalid_token", "unauthorized"],
    [403, "token_read_only", "read_only"],
    [403, "token_not_allowed", "token_not_allowed"],
    [403, "forbidden", "forbidden"],
    [404, "not_found", "not_found"],
    [409, "conflict", "conflict"],
    [400, "invalid_request", "invalid"],
    [429, "rate_limited", "rate_limited"],
    [500, "internal", "server"],
  ];
  for (const [status, code, kind] of cases) {
    it(`maps ${status} ${code} to ${kind}`, async () => {
      const f = vi.fn<FetchFn>(async () => json(status, { error: { code, message: "msg" }, request_id: "rid" }));
      const err = await client(f).getFinding("x").catch((e) => e);
      expect(err).toBeInstanceOf(PathosApiError);
      expect(err).toMatchObject({ kind, status, code, requestId: "rid" });
    });
  }

  it("handles non-JSON error bodies", async () => {
    const f = vi.fn<FetchFn>(async () => new Response("<html>bad gateway</html>", { status: 502 }));
    await expect(client(f).getFinding("x")).rejects.toMatchObject({ kind: "server", status: 502 });
  });

  it("reports invalid JSON on success as bad_response", async () => {
    const f = vi.fn<FetchFn>(async () => new Response("<html>login</html>", { status: 200 }));
    await expect(client(f).getFinding("x")).rejects.toMatchObject({ kind: "bad_response" });
  });

  it("maps network failures and timeouts", async () => {
    const net = vi.fn<FetchFn>(async () => {
      throw new TypeError("fetch failed");
    });
    await expect(client(net).getFinding("x")).rejects.toMatchObject({ kind: "network" });

    const slow = vi.fn<FetchFn>(
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        }),
    );
    await expect(client(slow, 20).getFinding("x")).rejects.toMatchObject({ kind: "timeout" });
  });

  it("never puts the token into error messages", async () => {
    const f = vi.fn<FetchFn>(async () => json(401, { error: { code: "invalid_token", message: "invalid token" } }));
    const err = await client(f).getFinding("x").catch((e) => e);
    expect(String(err.message)).not.toContain(TOKEN);
    expect(describeError(err)).not.toContain(TOKEN);
  });

  it("explains auth problems to the user", () => {
    expect(describeError(new PathosApiError("unauthorized", "x", 401))).toMatch(/Set API token/);
    expect(describeError(new PathosApiError("read_only", "x", 403), "Changing the status")).toMatch(/api:write/);
    expect(describeError(new PathosApiError("forbidden", "x", 403))).toMatch(/your PATHOS role does not permit this/);
    expect(describeError(new PathosConfigError("bad url"))).toBe("bad url");
  });
});

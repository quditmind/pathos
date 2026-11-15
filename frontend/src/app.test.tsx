import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { api, ApiError, setCsrfToken } from "@/api/client";
import { LoginPage } from "@/features/auth/LoginPage";
import { initials } from "@/lib/utils";
import { grantIsComplete } from "@/features/users/RoleScopePicker";

describe("api client", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("sends the CSRF token on unsafe requests only", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    setCsrfToken("tok123");

    await api("/api/v1/me");
    await api("/api/v1/users", { method: "POST", body: { email: "a@b.c" } });

    const getHeaders = fetchMock.mock.calls[0]![1].headers as Record<string, string>;
    const postHeaders = fetchMock.mock.calls[1]![1].headers as Record<string, string>;
    expect(getHeaders["X-CSRF-Token"]).toBeUndefined();
    expect(postHeaders["X-CSRF-Token"]).toBe("tok123");
    expect(postHeaders["Content-Type"]).toBe("application/json");
    expect(fetchMock.mock.calls[1]![1].credentials).toBe("same-origin");
  });

  it("maps error responses to ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ error: { code: "forbidden", message: "nope" }, request_id: "r1" }), { status: 403 }),
      ),
    );
    const err = (await api("/api/v1/users").catch((e: unknown) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(403);
    expect(err.code).toBe("forbidden");
    expect(err.requestId).toBe("r1");
  });
});

describe("LoginPage", () => {
  it("links to the BFF login endpoint with return_to", () => {
    window.history.pushState({}, "", "/login?return_to=/admin/users");
    render(<LoginPage />);
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute(
      "href",
      "/api/auth/login?return_to=%2Fadmin%2Fusers",
    );
  });

  it("explains a deactivated account", () => {
    window.history.pushState({}, "", "/login?error=deactivated");
    render(<LoginPage />);
    expect(screen.getByRole("alert")).toHaveTextContent(/deactivated/i);
  });
});

describe("helpers", () => {
  it("computes initials", () => {
    expect(initials("Ada Lovelace")).toBe("AL");
    expect(initials("grace.hopper@example.com")).toBe("GH");
  });

  it("requires a scope id for narrow scopes", () => {
    expect(grantIsComplete({ role_key: "viewer", scope_type: "organization" })).toBe(true);
    expect(grantIsComplete({ role_key: "viewer", scope_type: "region" })).toBe(false);
    expect(grantIsComplete({ role_key: "viewer", scope_type: "region", scope_id: "x" })).toBe(true);
  });
});

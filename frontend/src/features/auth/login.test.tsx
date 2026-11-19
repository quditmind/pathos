import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { jsonResponse } from "@/test/harness";
import { LoginPage } from "./LoginPage";

afterEach(() => vi.unstubAllGlobals());

describe("sign-in page brand", () => {
  it("shows Quditmind | PATHOS and the server version from unauthenticated /api/v1/meta", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ product: "PATHOS", vendor: "Quditmind", version: "3.0.0-rc.1" })));
    window.history.pushState({}, "", "/login");
    render(<LoginPage />);
    expect(screen.getByText("Quditmind")).toBeInTheDocument();
    expect(await screen.findByTestId("login-version")).toHaveTextContent("v3.0.0-rc.1");
    expect(screen.getByText("Pre-release")).toBeInTheDocument();
  });

  it("works without the version when meta fails", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({}, 500)));
    window.history.pushState({}, "", "/login");
    render(<LoginPage />);
    expect(screen.getByRole("link", { name: "Sign in" })).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 10));
    expect(screen.queryByTestId("login-version")).toBeNull();
  });

  it("shows the catalogue code of a sign-in error", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({}, 500)));
    window.history.pushState({}, "", "/login?error=deactivated&code=PTH-AUTH-2001");
    render(<LoginPage />);
    expect(screen.getByTestId("login-error-code")).toHaveTextContent("PTH-AUTH-2001");
  });

  it("ignores a malformed code", () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({}, 500)));
    window.history.pushState({}, "", "/login?error=deactivated&code=<script>");
    render(<LoginPage />);
    expect(screen.queryByTestId("login-error-code")).toBeNull();
  });
});

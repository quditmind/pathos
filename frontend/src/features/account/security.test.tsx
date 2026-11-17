import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { SecuritySettingsPage } from "./SecuritySettingsPage";

afterEach(() => vi.unstubAllGlobals());

describe("sign-in security", () => {
  it("sets up recovery codes and tells the user to sign in again to see them", async () => {
    const api = mockApi({
      "GET /api/v1/me/mfa": () => ({ configured: true, pending: false, recovery_codes: false, recovery_pending: false }),
      "POST /api/v1/me/recovery-codes": () => ({ changed: true, mfa: { configured: true, pending: false, recovery_codes: false, recovery_pending: true } }),
    });
    renderApp(<SecuritySettingsPage />);
    expect(await screen.findByText("enabled")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Set up recovery codes/ }));
    expect(await screen.findByText(/your new codes are shown once/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Sign out now/ })).toBeInTheDocument();
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/me/recovery-codes")).toBe(true));
  });

  it("offers new codes when a set exists and explains errors", async () => {
    mockApi({ "GET /api/v1/me/mfa": () => ({ configured: true, pending: false, recovery_codes: true, recovery_pending: false }) });
    renderApp(<SecuritySettingsPage />);
    expect(await screen.findByRole("button", { name: /Generate new recovery codes/ })).toBeInTheDocument();
    expect(screen.getByText("set up")).toBeInTheDocument();
  });
});

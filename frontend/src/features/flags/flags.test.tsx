import { afterEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi, renderApp } from "@/test/harness";
import { Toaster } from "@/components/ui/toast";
import { FeatureFlagsPage, type FeatureFlagView } from "./FeatureFlagsPage";

afterEach(() => vi.unstubAllGlobals());

const flag = (over: Partial<FeatureFlagView> = {}): FeatureFlagView => ({
  name: "codegraph",
  description: "CodeGraph: discovery worker, graph store and views",
  milestone: "M4",
  enabled: false,
  updated_at: null,
  updated_by: null,
  ...over,
});

describe("feature flags page", () => {
  it("lists flags and toggles one with PUT {flags}", async () => {
    let on = false;
    const api = mockApi({
      "GET /api/v1/admin/feature-flags": () => ({ items: [flag({ enabled: on }), flag({ name: "connectors", milestone: "M2" })] }),
      "PUT /api/v1/admin/feature-flags": (_u, init) => {
        on = (init.json as { flags: Record<string, boolean> }).flags.codegraph!;
        return { items: [] };
      },
      "GET /api/v1/meta": () => ({ product: "PATHOS", vendor: "Quditmind", version: "1" }),
    });
    renderApp(
      <>
        <FeatureFlagsPage />
        <Toaster />
      </>,
      { permissions: ["settings.manage"] },
    );
    const sw = await screen.findByRole("switch", { name: "codegraph: off" });
    expect(screen.getByText("M4")).toBeInTheDocument();
    await userEvent.click(sw);
    expect(api.calls.find((c) => c.method === "PUT")!.body).toEqual({ flags: { codegraph: true } });
    expect(await screen.findByRole("switch", { name: "codegraph: on" })).toHaveAttribute("aria-checked", "true");
    expect(await screen.findByText("Feature flag codegraph turned on.")).toBeInTheDocument();
  });

  it("names the missing permission", async () => {
    mockApi({});
    renderApp(<FeatureFlagsPage />, { permissions: ["findings.read"] });
    expect(await screen.findByText("settings.manage")).toBeInTheDocument();
  });
});

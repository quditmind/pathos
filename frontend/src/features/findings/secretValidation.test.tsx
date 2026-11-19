import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import type { SecretValidation, SecretValidationSettings } from "@/api/types";
import { SecretValidationPanel } from "./SecretValidation";
import { SecretValidationPage } from "@/features/settings/SecretValidationPage";

afterEach(() => vi.unstubAllGlobals());

const active: SecretValidation = {
  status: "active", provider: "github", provider_name: "GitHub token", identity: "user octo", checked_at: "2026-11-19T10:00:00Z",
  evidence: { status: "active", endpoint: "GET https://api.github.com/user", http_status: 200, detail: "the provider accepted the credential (HTTP 200)", severity_raised_from: "high" },
};
const finding = (v: SecretValidation | undefined, category = "secrets") => ({ id: "f1", category, scan_target_id: null, secret_validation: v });

describe("secret validation panel", () => {
  it("explains an active key with its evidence and raised severity", async () => {
    renderApp(<SecretValidationPanel f={finding(active)} />, { permissions: ["findings.read"] });
    const panel = await screen.findByTestId("secret-validation");
    expect(panel).toHaveTextContent("Active key");
    expect(panel).toHaveTextContent("user octo");
    expect(panel).toHaveTextContent("GET https://api.github.com/user");
    expect(panel).toHaveTextContent("200");
    expect(panel).toHaveTextContent("raised from high to critical");
    expect(screen.queryByRole("button", { name: /Re-check/ })).not.toBeInTheDocument();
  });

  it("shows inactive and inconclusive results and the last attempt", async () => {
    const v: SecretValidation = { ...active, status: "inactive", identity: "",
      evidence: { endpoint: "GET https://api.github.com/user", http_status: 401, detail: "rejected (HTTP 401)",
        last_attempt: { status: "error", detail: "rate limited (HTTP 429)", checked_at: "2026-11-19T11:00:00Z" } } };
    renderApp(<SecretValidationPanel f={finding(v)} />, { permissions: ["findings.read"] });
    const panel = await screen.findByTestId("secret-validation");
    expect(panel).toHaveTextContent("Revoked or invalid");
    expect(panel).toHaveTextContent("Check failed — rate limited (HTTP 429)");
  });

  it("is hidden for other categories and re-checks with scans.run", async () => {
    const { unmount } = renderApp(<SecretValidationPanel f={finding(active, "sast")} />, { permissions: ["scans.run"] });
    await waitFor(() => expect(screen.queryByTestId("secret-validation")).not.toBeInTheDocument());
    unmount();
    const api = mockApi({ "POST /api/v1/findings/f1/secret-validation/recheck": () => jsonResponse({ job_id: "j9", coalesced: false }, 202) });
    renderApp(<SecretValidationPanel f={finding({ ...active, status: "not_checked", evidence: null })} />, { permissions: ["scans.run"] });
    expect(await screen.findByText(/Live validation is off unless/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Re-check/ }));
    expect(await screen.findByText(/Scan queued/)).toBeInTheDocument();
    expect(api.calls.some((c) => c.method === "POST" && c.path.endsWith("/recheck"))).toBe(true);
  });

  it("shows why a re-check is refused", async () => {
    mockApi({ "POST /api/v1/findings/f1/secret-validation/recheck": () => jsonResponse({ error: { code: "conflict", message: "live secret validation is off" } }, 409) });
    renderApp(<SecretValidationPanel f={finding(active)} />, { permissions: ["scans.run"] });
    fireEvent.click(await screen.findByRole("button", { name: /Re-check/ }));
    expect(await screen.findByText("live secret validation is off")).toBeInTheDocument();
  });
});

const settings = (enabled: string[]): SecretValidationSettings => ({
  providers: [
    { id: "aws", name: "AWS access key", hosts: ["sts.amazonaws.com"], endpoint: "POST https://sts.amazonaws.com/", checkable: true, enabled: enabled.includes("aws") },
    { id: "github", name: "GitHub token", hosts: ["api.github.com"], endpoint: "GET https://api.github.com/user", checkable: true, enabled: enabled.includes("github") },
    { id: "pypi", name: "PyPI API token", hosts: null, endpoint: "", checkable: false, note: "no read-only check", enabled: false },
  ],
  rate_per_second: 1, max_checks_per_scan: 50, updated_at: null, can_manage: true, offline: false,
});

describe("secret validation settings", () => {
  it("is off by default and saves the enabled providers with their allowlist hosts", async () => {
    let saved: unknown;
    const api = mockApi({
      "GET /api/v1/settings/secret-validation": () => settings([]),
      "PUT /api/v1/settings/secret-validation": (_u, init) => {
        saved = init.json;
        return settings((init.json as { providers: string[] }).providers);
      },
    });
    renderApp(<SecretValidationPage />, { permissions: ["settings.manage"] });
    expect(await screen.findByText("off")).toBeInTheDocument();
    expect(screen.getByLabelText("Validate PyPI API token")).toBeDisabled();
    fireEvent.click(screen.getByLabelText("Validate AWS access key"));
    expect(screen.getByText("sts.amazonaws.com", { selector: "pre" })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Checks per second/), { target: { value: "2" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByText(/Saved/)).toBeInTheDocument();
    expect(saved).toEqual({ providers: ["aws"], rate_per_second: 2, max_checks_per_scan: 50 });
    expect(api.calls.filter((c) => c.method === "PUT")).toHaveLength(1);
    expect(await screen.findByText("on")).toBeInTheDocument();
  });

  it("needs settings.manage", async () => {
    renderApp(<SecretValidationPage />, { permissions: ["findings.read"] });
    expect(await screen.findByText(/settings.manage permission/)).toBeInTheDocument();
  });
});

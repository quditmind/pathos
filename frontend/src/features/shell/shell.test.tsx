import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppShell } from "@/components/layout/AppShell";
import { toast } from "@/components/ui/toast";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import { changelogFor, parseChangelog, changelogText, noticeText } from "./bundled";
import { bundleVersion, displayVersion, isPreRelease, useFeatureFlag, versionMismatch, type Meta } from "./meta";

const meta = (over: Partial<Meta> = {}): Meta => ({
  product: "PATHOS",
  vendor: "Quditmind",
  version: bundleVersion,
  commit: "abc1234",
  build_date: "2026-11-20T10:00:00Z",
  api_version: "v1",
  feature_flags: { connectors: false, codegraph: true },
  workers: [{ name: "worker-core-1", family: "core", version: "3.0.0", scanners: { semgrep: "1.0" } }],
  scanner_packs: [{ family: "core", version: "3.0.0" }],
  ...over,
});

function shell(m: Meta | Response = meta(), path = "/", permissions: string[] = ["scans.read", "repos.read"]) {
  const api = mockApi({
    "GET /api/v1/meta": () => m,
    "GET /api/v1/workers": () => ({ items: [{ id: "w1", name: "worker-core-1", family: "core", version: "3.0.0", scanners: {}, last_seen_at: "2026-11-20T10:00:00Z", revoked_at: null, created_at: "", online: true, active_jobs: 0 }] }),
    "GET /api/v1/notifications": () => ({ items: [], unread: 0 }),
  });
  const r = renderApp(
    <AppShell>
      <input aria-label="Some field" />
    </AppShell>,
    { permissions, path },
  );
  return { ...r, api };
}

afterEach(() => {
  vi.unstubAllGlobals();
  toast.clear();
});

describe("version helpers", () => {
  it("detects pre-releases", () => {
    expect(isPreRelease("dev")).toBe(true);
    expect(isPreRelease("2.0.0-rc.1")).toBe(true);
    expect(isPreRelease("v3.0.0-beta.2")).toBe(true);
    expect(isPreRelease("2.2.0")).toBe(false);
    expect(isPreRelease("v2.2.0")).toBe(false);
    expect(isPreRelease(undefined)).toBe(false);
  });

  it("compares backend and bundle versions, ignoring dev and a leading v", () => {
    expect(versionMismatch("2.3.0", "2.2.0")).toBe(true);
    expect(versionMismatch("v2.2.0", "2.2.0")).toBe(false);
    expect(versionMismatch("dev", "2.2.0")).toBe(false);
    expect(versionMismatch(undefined, "2.2.0")).toBe(false);
    expect(displayVersion("2.2.0")).toBe("v2.2.0");
    expect(displayVersion("dev")).toBe("dev");
  });

  it("injects the bundle version from package.json", () => {
    expect(bundleVersion).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe("bundled files", () => {
  it("parses CHANGELOG sections and picks the running version", () => {
    const text = "# Changelog\n\n## [Unreleased]\n\n### Added\n- Shell\n\n## [2.2.0] — 2026-11-19\n\nProof.\n\n## [2.1.0] — 2026-11-18\n\nOld.";
    const s = parseChangelog(text);
    expect(s.map((x) => x.version)).toEqual(["Unreleased", "2.2.0", "2.1.0"]);
    expect(changelogFor("2.2.0", s)).toMatchObject({ version: "2.2.0", date: "2026-11-19", body: "Proof." });
    expect(changelogFor("v2.1.0", s)!.body).toBe("Old.");
    expect(changelogFor("3.0.0-rc.1", s)!.version).toBe("Unreleased");
    expect(changelogFor("dev", parseChangelog("## [Unreleased]\n\n## [1.0.0] — x\n\nOne"))!.version).toBe("1.0.0");
  });

  it("bundles CHANGELOG.md and NOTICE (offline)", () => {
    expect(changelogText).toContain("## [Unreleased]");
    expect(changelogFor(bundleVersion)).toBeDefined();
    expect(noticeText).toContain("Apache License");
  });
});

describe("brand header", () => {
  it("shows Quditmind | PATHOS and the backend version, which opens About", async () => {
    shell(meta({ version: "9.9.9" }));
    const chip = await screen.findByRole("button", { name: /PATHOS version v9\.9\.9/ });
    expect(chip).toHaveTextContent("v9.9.9");
    expect(screen.getByText("Quditmind")).toBeInTheDocument();
    await userEvent.click(chip);
    const about = await screen.findByRole("dialog", { name: "About PATHOS" });
    for (const t of ["v9.9.9", "abc1234", "2026-11-20T10:00:00Z", "v1", "Apache License 2.0", "Quditmind"]) {
      expect(within(about).getAllByText(new RegExp(t.replace(/[.]/g, "\\."))).length).toBeGreaterThan(0);
    }
    expect(within(about).getByText("core")).toBeInTheDocument();
    expect(within(about).getByText(/worker-core-1 v3\.0\.0/)).toBeInTheDocument();
    // Scanner tool names stay on Configurations › Scanners & workers.
    expect(within(about).queryByText(/semgrep/i)).toBeNull();
    expect(within(about).getByText(/Copyright 2026 The PATHOS Authors/)).toBeInTheDocument();
  });

  it("shows a Pre-release tag for dev and rc builds", async () => {
    shell(meta({ version: "3.0.0-rc.1" }));
    expect(await screen.findByText("Pre-release")).toBeInTheDocument();
  });

  it("offers a reload when the server runs another version, and not otherwise", async () => {
    shell(meta({ version: "99.0.0" }));
    expect(await screen.findByText(/A newer PATHOS version is available/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reload" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Dismiss version notice" }));
    expect(screen.queryByText(/A newer PATHOS version is available/)).toBeNull();
  });

  it("shows no banner when versions match", async () => {
    shell(meta());
    await screen.findByRole("button", { name: new RegExp(`PATHOS version v${bundleVersion.replace(/\./g, "\\.")}`) });
    expect(screen.queryByText(/A newer PATHOS version/)).toBeNull();
  });

  it("collapsed sidebar shows the logo with the version in its tooltip", async () => {
    shell(meta({ version: "9.9.9" }));
    await screen.findByRole("button", { name: /PATHOS version v9\.9\.9/ });
    await userEvent.click(screen.getByRole("button", { name: "Collapse navigation" }));
    expect(screen.getByRole("button", { name: /Quditmind PATHOS v9\.9\.9/ })).toHaveAttribute("title", "Quditmind PATHOS v9.9.9");
  });

  it("degrades when /api/v1/meta fails", async () => {
    shell(jsonResponse({ error: { code: "not_found", message: "nope" } }, 404));
    await waitFor(() => expect(screen.getByRole("button", { name: "About PATHOS" })).toHaveTextContent("v?"), { timeout: 4000 });
  });
});

describe("help menu and drawer", () => {
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn();
  });

  it("lists every §2.3 item", async () => {
    shell();
    const trigger = await screen.findByRole("button", { name: "Help" });
    trigger.focus();
    await userEvent.keyboard("{Enter}");
    const menu = await screen.findByRole("menu");
    const items = within(menu).getAllByRole("menuitem").map((i) => i.textContent?.replace(/F1$/, "").trim());
    expect(items).toEqual([
      "Help for this page",
      "Help centre",
      "Troubleshooting centre",
      "Keyboard shortcuts",
      `What's new in v${bundleVersion}`,
      "API reference",
      "System status",
      "Report a problem",
      "About PATHOS",
    ]);
    expect(within(menu).getByRole("menuitem", { name: "Troubleshooting centre" })).toHaveAttribute("href", "/help/troubleshooting");
    expect(within(menu).getByRole("menuitem", { name: "API reference" })).toHaveAttribute("href", "/help/api-reference/index");
  });

  it("F1 opens the article mapped to the current route", async () => {
    shell(meta(), "/scans/overview");
    await screen.findByRole("button", { name: "Help" });
    fireEvent.keyDown(window, { key: "F1" });
    const drawer = await screen.findByRole("dialog", { name: /Help: Running scans/ });
    expect(within(drawer).getByRole("link", { name: /Open in the Help Center/ })).toHaveAttribute("href", "/help/user-guide/scanning");
  });

  it("? opens help, but not while typing in a field", async () => {
    shell(meta(), "/");
    const field = await screen.findByRole("textbox", { name: "Some field" });
    field.focus();
    fireEvent.keyDown(field, { key: "?" });
    expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.keyDown(document.body, { key: "?" });
    expect(await screen.findByRole("dialog", { name: /Help: Dashboards/ })).toBeInTheDocument();
  });

  it("keyboard shortcuts and what's new open from the menu", async () => {
    shell();
    await screen.findByRole("button", { name: "Help" });
    const open = async (name: RegExp) => {
      screen.getByRole("button", { name: "Help" }).focus();
      await userEvent.keyboard("{Enter}");
      await userEvent.click(await screen.findByRole("menuitem", { name }));
    };
    await open(/Keyboard shortcuts/);
    const sc = await screen.findByRole("dialog", { name: "Keyboard shortcuts" });
    expect(within(sc).getByText("Help for this page")).toBeInTheDocument();
    expect(within(sc).getByText("F1")).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await open(/What's new/);
    expect(await screen.findByRole("dialog", { name: new RegExp(`What's new in v${bundleVersion.replace(/\./g, "\\.")}`) })).toBeInTheDocument();
  });

  it("system status shows real data and says Not available for the rest", async () => {
    shell();
    (await screen.findByRole("button", { name: "Help" })).focus();
    await userEvent.keyboard("{Enter}");
    await userEvent.click(await screen.findByRole("menuitem", { name: "System status" }));
    const d = await screen.findByRole("dialog", { name: "System status" });
    expect(await within(d).findByText("Worker pack: core")).toBeInTheDocument();
    expect(within(d).getByText(/1 of 1 worker online/)).toBeInTheDocument();
    const rows = within(d).getAllByRole("row");
    const row = (name: string) => rows.find((r) => r.textContent?.startsWith(name))!;
    for (const n of ["Database", "Queue", "Object storage", "Connectors"]) expect(row(n)).toHaveTextContent("Not available");
    // No AI permission: says which one is needed instead of calling the API.
    expect(row("AI providers")).toHaveTextContent(/ai\.review or ai\.configure/);
  });

  it("report a problem downloads a bundle and confirms with a toast", async () => {
    const created: Blob[] = [];
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: (b: Blob) => (created.push(b), "blob:x"), revokeObjectURL: () => undefined }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    shell();
    await screen.findByRole("button", { name: /PATHOS version/ });
    screen.getByRole("button", { name: "Help" }).focus();
    await userEvent.keyboard("{Enter}");
    await userEvent.click(await screen.findByRole("menuitem", { name: "Report a problem" }));
    expect(click).toHaveBeenCalled();
    const bundle = JSON.parse(await created[0]!.text());
    expect(bundle.kind).toBe("pathos-diagnostic-bundle");
    expect(bundle.backend.commit).toBe("abc1234");
    expect(bundle.feature_flags).toEqual({ connectors: false, codegraph: true });
    expect(bundle.recent_requests.some((r: { path: string }) => r.path === "/api/v1/meta")).toBe(true);
    expect(await screen.findByText(/Diagnostic bundle downloaded/)).toBeInTheDocument();
    click.mockRestore();
  });
});

function Flag() {
  return <span>{useFeatureFlag("codegraph") ? "on" : "off"}-{useFeatureFlag("connectors") ? "on" : "off"}</span>;
}

describe("feature flags", () => {
  it("reads flags from /api/v1/meta; unknown and missing are off", async () => {
    mockApi({ "GET /api/v1/meta": () => meta() });
    renderApp(<Flag />);
    expect(await screen.findByText("on-off")).toBeInTheDocument();
  });

  it("is off when the server sends no flags (unauthenticated meta)", async () => {
    mockApi({ "GET /api/v1/meta": () => ({ product: "PATHOS", vendor: "Quditmind", version: "1" }) });
    renderApp(<Flag />);
    await act(async () => undefined);
    expect(await screen.findByText("off-off")).toBeInTheDocument();
  });
});

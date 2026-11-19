import { afterEach, describe, expect, it, vi } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi, renderApp } from "@/test/harness";
import { buildDoc, helpDocs, helpGroups, renderDoc, resolveAnchor } from "./content";
import { TroubleshootingPage } from "./TroubleshootingPage";
import { catalogueSection, codesFromDocs, normaliseCode, parseCodes, searchCodes } from "./troubleshooting";

afterEach(() => vi.unstubAllGlobals());

const codes = [
  {
    code: "PTH-CONN-1004",
    area: "CONN",
    category: "connectivity",
    severity: "error",
    title: "Connection uses an untrusted certificate",
    description: "TLS verification failed.",
    confirmed_cause: "The certificate chain is not trusted.",
    probable_causes: ["Private CA"],
    impact: "No sync.",
    actions: ["Add the CA"],
    verify: ["Test the connection"],
    docs_url: "/help/troubleshooting/conn#PTH-CONN-1004",
    ai_help: true,
  },
  { code: "PTH-SCAN-2001", title: "Scan timed out", actions: [{ text: "Raise the timeout" }] },
  { code: "not-a-code", title: "ignored" },
];

describe("catalogue parsing", () => {
  it("normalises entries and skips invalid ones", () => {
    const list = parseCodes({ items: codes });
    expect(list.map((c) => c.code)).toEqual(["PTH-CONN-1004", "PTH-SCAN-2001"]);
    expect(list[1]).toMatchObject({ area: "SCAN", actions: ["Raise the timeout"], docs_url: "/help/troubleshooting/scan#PTH-SCAN-2001" });
    expect(parseCodes(codes)).toHaveLength(2);
    expect(parseCodes({ codes })).toHaveLength(2);
    expect(parseCodes(null)).toEqual([]);
    expect(normaliseCode({ code: "PTH-AI-0001", docs_url: "https://evil" })!.docs_url).toBe("");
  });

  it("searches by code, words and symptom", () => {
    const list = parseCodes(codes);
    expect(searchCodes(list, "pth-conn").map((c) => c.code)).toEqual(["PTH-CONN-1004"]);
    expect(searchCodes(list, "certificate untrusted")).toHaveLength(1);
    expect(searchCodes(list, "timeout")).toHaveLength(1);
    expect(searchCodes(list, "")).toHaveLength(2);
  });

  it("reads codes from bundled troubleshooting docs (offline)", () => {
    const doc = buildDoc("x/docs/troubleshooting/conn.md", "---\ntitle: Connections\n---\n# Connections\n\n<a id=\"PTH-CONN-1004\"></a>\n\n## PTH-CONN-1004 Connection uses an untrusted certificate\n\nText. <a href=x>bad</a>\n\n## Other\n")!;
    const html = renderDoc(doc);
    expect(html).toContain('<span id="PTH-CONN-1004"></span>');
    expect(html).toContain("&lt;a href=x&gt;");
    expect(doc.section).toBe("troubleshooting");
    const list = codesFromDocs([doc]);
    expect(list).toEqual([expect.objectContaining({ code: "PTH-CONN-1004", title: "Connection uses an untrusted certificate", docs_url: "/help/troubleshooting/conn#pth-conn-1004-connection-uses-an-untrusted-certificate" })]);
    expect(resolveAnchor(doc.headings, "PTH-CONN-1004")).toBe("pth-conn-1004-connection-uses-an-untrusted-certificate");
  });
});

describe("catalogue section (sign-in page, offline)", () => {
  it("extracts one code's section from the bundled doc", () => {
    const doc = buildDoc(
      "x/docs/troubleshooting/auth.md",
      "---\ntitle: Auth\n---\n# Auth\n\n<a id=\"PTH-AUTH-2001\"></a>\n\n## PTH-AUTH-2001: Account deactivated\n\nAsk an admin.\n\n<a id=\"PTH-AUTH-2002\"></a>\n\n## PTH-AUTH-2002: Other\n\nNo.\n",
    )!;
    const s = catalogueSection("PTH-AUTH-2001", [doc])!;
    expect(s.title).toBe("Account deactivated");
    expect(s.body).toBe("Ask an admin.");
    expect(catalogueSection("PTH-AUTH-9999", [doc])).toBeUndefined();
    expect(catalogueSection("nope", [doc])).toBeUndefined();
  });
});

describe("Troubleshooting centre", () => {
  it("lists the live catalogue by area and searches it", async () => {
    mockApi({ "GET /api/v1/diagnostics/codes": () => ({ areas: [{ key: "CONN", slug: "conn", title: "Connections and webhooks" }], items: codes }) });
    renderApp(<TroubleshootingPage />, { path: "/help/troubleshooting" });
    expect(await screen.findByRole("heading", { level: 1, name: "Troubleshooting centre" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: /Connections and webhooks · PTH-CONN/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Scan execution · PTH-SCAN/ })).toBeInTheDocument();
    const entry = document.getElementById("PTH-CONN-1004")!;
    await userEvent.click(within(entry).getByText("Connection uses an untrusted certificate"));
    expect(within(entry).getByText("Add the CA")).toBeVisible();
    expect(within(entry).getByRole("link", { name: /Read the article/ })).toHaveAttribute("href", "/help/troubleshooting/conn#PTH-CONN-1004");
  });

  it("filters from ?q=", async () => {
    mockApi({ "GET /api/v1/diagnostics/codes": () => ({ items: codes }) });
    renderApp(<TroubleshootingPage />, { path: "/help/troubleshooting?q=timed" });
    expect(await screen.findByText(/1 of 2 codes match “timed”/)).toBeInTheDocument();
    expect(screen.queryByText("PTH-CONN-1004")).toBeNull();
  });

  it("says when the live catalogue is unreachable", async () => {
    mockApi({});
    renderApp(<TroubleshootingPage />, { path: "/help/troubleshooting" });
    expect(await screen.findByText(/live catalogue is not reachable/, {}, { timeout: 4000 })).toBeInTheDocument();
  });
});

describe("Help Center organisation", () => {
  it("every user-guide page belongs to a Help Center group", () => {
    const guide = helpDocs.filter((d) => d.section === "user-guide");
    expect(guide.filter((d) => !d.groups.length).map((d) => d.slug)).toEqual([]);
    expect(helpGroups).toHaveLength(12);
  });
});

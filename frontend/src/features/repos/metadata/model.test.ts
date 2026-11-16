import { describe, expect, it } from "vitest";
import { clientErrors, diffMetadata, domainProblem, draftToMetadata, emptyDraft, ipProblem, sectionForKey, urlProblem, type MetadataDraft } from "./model";

const draft = (p: Partial<MetadataDraft>): MetadataDraft => ({ ...emptyDraft(), ...p });

describe("exposure metadata", () => {
  it("maps the answer to the network exposure detail and drops endpoints unless Yes", () => {
    const yes = draft({ public_exposure: "yes", public_urls: [" https://a.example.com ", ""], public_ips: ["203.0.113.5"], internet_exposure: "public" });
    expect(draftToMetadata(yes)).toMatchObject({ public_exposure: "yes", public_urls: ["https://a.example.com"], public_domains: [], public_ips: ["203.0.113.5"], internet_exposure: "public" });
    const no = draft({ public_exposure: "no", public_urls: ["https://a.example.com"], internet_exposure: "internal" });
    expect(draftToMetadata(no)).toMatchObject({ public_exposure: "no", public_urls: [], internet_exposure: "internal" });
    expect(draftToMetadata(draft({ public_exposure: "unknown" }))).toMatchObject({ public_exposure: "unknown", internet_exposure: "unknown" });
    expect(draftToMetadata(draft({}))).not.toHaveProperty("public_exposure");
  });

  it("PATCH sends the exposure fields together when any of them changes", () => {
    const orig = draft({ public_exposure: "yes", public_urls: ["https://a.example.com"], internet_exposure: "public", production_url: "https://a.example.com" });
    expect(diffMetadata(orig, orig)).toEqual({});
    const now = { ...orig, public_exposure: "no" as const, internet_exposure: "" };
    expect(diffMetadata(orig, now)).toEqual({ public_exposure: "no", public_urls: [], public_domains: [], public_ips: [], exposure_notes: "", internet_exposure: "" });
    expect(diffMetadata(orig, { ...orig, production_url: "" })).toEqual({ production_url: "" });
  });

  it("requires an answer and an endpoint for Yes", () => {
    expect(clientErrors(draft({}), new Set(), { section: "classification" })).toHaveProperty("public_exposure");
    expect(clientErrors(draft({ public_exposure: "yes", public_urls: [""] }), new Set(), { section: "classification" })).toHaveProperty("public_urls");
    expect(clientErrors(draft({ public_exposure: "unknown" }), new Set(), { section: "classification" })).toEqual({});
  });

  it("maps endpoint error keys to the Classification step", () => {
    for (const k of ["public_urls", "public_domains", "public_ips", "exposure_notes", "public_exposure"]) expect(sectionForKey(k)).toBe("classification");
    for (const k of ["staging_url", "production_url"]) expect(sectionForKey(k)).toBe("general");
  });

  it("checks endpoint formats", () => {
    expect(urlProblem("https://x.example.com/path")).toBeNull();
    expect(urlProblem("x.example.com")).not.toBeNull();
    expect(urlProblem("https://u:p@x.example.com")).toMatch(/passwords/);
    expect(domainProblem("*.example.com")).toBeNull();
    expect(domainProblem("https://example.com")).not.toBeNull();
    expect(domainProblem("localhost")).not.toBeNull();
    expect(ipProblem("203.0.113.9")).toBeNull();
    expect(ipProblem("2001:db8::1")).toBeNull();
    expect(ipProblem("192.168.1.1")).toMatch(/not a public address/);
    expect(ipProblem("::1")).toMatch(/not a public address/);
    expect(ipProblem("300.1.1.1")).not.toBeNull();
  });
});

import { describe, expect, it } from "vitest";
import { router } from "@/app/router";
import { findDoc, resolveAnchor } from "./content";
import { articleForRoute, routeHelp } from "./routeHelp";

// Every route declared in app/router.tsx (pathless layout routes excluded).
const routePaths = [...new Set(Object.values(router.routesById).map((r) => r.fullPath as string))]
  .map((p) => (p.length > 1 ? p.replace(/\/$/, "") : p))
  .filter((p) => p !== "");

describe("route ↔ help mapping", () => {
  it("finds the routes of the router", () => {
    expect(routePaths.length).toBeGreaterThan(70);
    expect(routePaths).toContain("/help/troubleshooting");
  });

  it.each(routePaths)("route %s has a help article that exists", (path) => {
    const a = routeHelp[path];
    expect(a, `no help article mapped for ${path}`).toBeDefined();
    const doc = findDoc(a!.section, a!.slug);
    expect(doc, `${path} → missing article ${a!.section}/${a!.slug}`).toBeDefined();
    if (a!.anchor) expect(resolveAnchor(doc!.headings, a!.anchor), `${path} → missing heading #${a!.anchor} in ${a!.slug}`).toBeDefined();
  });

  it("has no stale entries for routes that no longer exist", () => {
    expect(Object.keys(routeHelp).filter((k) => !routePaths.includes(k))).toEqual([]);
  });

  it("falls back to the help guide for an unknown route", () => {
    expect(articleForRoute("/nope").slug).toBe("help-and-troubleshooting");
    expect(articleForRoute("/scans/$id/").slug).toBe("scanning");
  });
});

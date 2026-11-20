import { afterEach, describe, expect, it } from "vitest";
import { generatedByStamp, getBuildInfo, setBuildInfo, shortBuild, stampedFileName, versionTag, withGeneratedBy } from "./buildStamp";

// Example build data for tests only.
const info = { version: "3.0.0", commit: "0123456789abcdef0123" };
const now = new Date("2026-11-20T10:11:12.000Z");

afterEach(() => setBuildInfo(undefined));

describe("version stamps on client-side exports", () => {
  it("shortens the build commit to 12 characters", () => {
    expect(shortBuild(info.commit)).toBe("0123456789ab");
    expect(shortBuild(undefined)).toBe("");
    expect(shortBuild("abc/../def")).toBe("abcdef");
  });

  it("prefixes release versions with v and keeps dev builds", () => {
    expect(versionTag("3.0.0")).toBe("v3.0.0");
    expect(versionTag("v3.0.0-rc.1")).toBe("v3.0.0-rc.1");
    expect(versionTag("dev")).toBe("dev");
    expect(versionTag("")).toBe("");
  });

  it("builds the generated-by line", () => {
    expect(generatedByStamp(info, now)).toBe("Quditmind PATHOS v3.0.0 · build 0123456789ab · generated 2026-11-20T10:11:12.000Z");
    expect(generatedByStamp({}, now)).toBe("Quditmind PATHOS version unknown · build unknown · generated 2026-11-20T10:11:12.000Z");
  });

  it("stamps export file names with the version, short build and UTC date", () => {
    expect(stampedFileName("findings", "csv", info, now)).toBe("pathos-v3.0.0-b0123456789ab-findings-2026-11-20.csv");
    expect(stampedFileName("Monitoring feed!", ".csv", { version: "dev" }, now)).toBe("pathos-dev-monitoring-feed-2026-11-20.csv");
    expect(stampedFileName("", "json", {}, now)).toBe("pathos-export-2026-11-20.json");
  });

  it("adds generated_by to JSON objects only", () => {
    expect(withGeneratedBy({ nodes: [] }, info, now)).toEqual({ generated_by: generatedByStamp(info, now), nodes: [] });
    expect(withGeneratedBy([1, 2], info, now)).toEqual([1, 2]);
    expect(withGeneratedBy("x", info, now)).toBe("x");
    expect(withGeneratedBy(null, info, now)).toBeNull();
  });

  it("uses the recorded server build by default", () => {
    setBuildInfo({ version: "3.0.0", commit: "fedcba9876543210" });
    expect(getBuildInfo()).toEqual({ version: "3.0.0", commit: "fedcba9876543210" });
    expect(stampedFileName("x", "csv", undefined, now)).toBe("pathos-v3.0.0-bfedcba987654-x-2026-11-20.csv");
  });
});

import { describe, expect, it } from "vitest";
import { CHECK_KINDS, countsByKind, enginesCount, kindOfFinding, kindOfTool, redactToolNames } from "./checkKinds";

// The same cases as TestKindOfFinding and TestEngines in
// backend/internal/scanners/checkkinds_test.go: the UI computes what the API sends.
describe("kinds of check", () => {
  it("has the 20 kinds of the build prompt plus the outside groups", () => {
    expect(CHECK_KINDS.filter((k) => !k.outside)).toHaveLength(20);
  });

  it.each([
    ["sast", ["opengrep"], "sast-deep"],
    ["sast", ["bandit"], "sast-language"],
    ["sast", ["bandit", "opengrep"], "sast-deep"],
    ["sast", ["import-sast-gosec"], "sast-language"],
    ["sast", [], "sast-deep"],
    ["code-quality", ["pmd"], "sast-language"],
    ["misconfiguration", ["testssl"], "web-api"],
    ["misconfiguration", ["opengrep"], "sast-deep"],
    ["sca", ["trivy-fs", "grype"], "dependencies"],
    ["eol", ["endoflife"], "dependencies"],
    ["ai", ["modelscan"], "ai"],
    ["other", ["import-other-x"], "other"],
    ["runtime", [], "cloud-kubernetes"],
  ])("kindOfFinding(%s, %j) = %s", (cat, keys, want) => {
    expect(kindOfFinding(cat, keys)).toBe(want);
  });

  it.each([
    [[], 0],
    [["trivy-fs"], 1],
    [["trivy-fs", "import-sca-trivy", "sarif-trivy"], 1],
    [["trivy-fs", "grype", "osv-scanner"], 3],
    [["zap", "zap-baseline", "import-dast-zap"], 1],
    [["import-supply-chain-scorecard", "scorecard"], 1],
    [["gitleaks", "trufflehog", "import-secrets-trufflehog-v2"], 2],
  ])("enginesCount(%j) = %d", (keys, want) => {
    expect(enginesCount(keys)).toBe(want);
  });

  it("maps engines and counts to kinds", () => {
    expect(kindOfTool("checkov")).toBe("iac");
    expect(kindOfTool("bandit")).toBe("sast-language");
    expect(kindOfTool("import-secrets-ggshield")).toBe("secrets");
    expect(countsByKind([{ key: "gitleaks", count: 2 }, { key: "trufflehog", count: 1 }, { key: "none", count: 1 }])).toEqual([
      { key: "secrets", label: "Secrets", count: 3 },
      { key: "other", label: "Other", count: 1 },
    ]);
    expect(redactToolNames("Trivy (image) and trivy-fs failed; Infrastructure as code is fine")).toBe("engine and engine failed; Infrastructure as code is fine");
  });
});

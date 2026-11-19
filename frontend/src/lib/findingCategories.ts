/**
 * Finding categories (findings.category), in display order. Mirrors
 * scanners.FindingCategories in the backend.
 */
export const FINDING_CATEGORIES = [
  "secrets",
  "sast",
  "sca",
  "iac",
  "container",
  "license",
  "dast",
  "api",
  "iast",
  "mobile",
  "fuzz",
  "malware",
  "misconfiguration",
  "binary",
  "crypto",
  "cicd",
  "ai",
  "runtime",
  "compliance",
  "database",
  "code-quality",
  "eol",
  "supply-chain",
  "other",
] as const;

export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

/**
 * Categories an import or a declarative adapter may declare: every finding
 * category except eol (end-of-life findings come from the intelligence
 * feed). Mirrors scanners.ToolCategories.
 */
export const TOOL_CATEGORIES = FINDING_CATEGORIES.filter((c) => c !== "eol");

export const categoryLabel: Record<string, string> = {
  secrets: "Secrets",
  sast: "Code (SAST)",
  sca: "Dependencies (SCA)",
  iac: "Infrastructure as code",
  container: "Container",
  license: "License",
  dast: "Web and API (DAST)",
  api: "API security",
  iast: "Interactive testing (IAST)",
  mobile: "Mobile (MAST)",
  fuzz: "Fuzzing",
  malware: "Malware",
  misconfiguration: "Framework configuration",
  binary: "Binary hardening",
  crypto: "Cryptography",
  cicd: "CI/CD pipeline",
  ai: "AI / LLM",
  runtime: "Runtime",
  compliance: "Compliance",
  database: "Database security",
  "code-quality": "Code-quality security",
  eol: "End of life",
  "supply-chain": "Supply chain (signatures)",
  other: "Other",
};

/** Human label of a category (falls back to the raw value). */
export function categoryName(c: string): string {
  return categoryLabel[c] ?? c;
}

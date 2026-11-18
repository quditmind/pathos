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
  "malware",
  "misconfiguration",
  "binary",
  "other",
] as const;

export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

export const categoryLabel: Record<string, string> = {
  secrets: "Secrets",
  sast: "Code (SAST)",
  sca: "Dependencies (SCA)",
  iac: "Infrastructure as code",
  container: "Container",
  license: "License",
  dast: "Web and API (DAST)",
  malware: "Malware",
  misconfiguration: "Framework configuration",
  binary: "Binary hardening",
  other: "Other",
};

/** Human label of a category (falls back to the raw value). */
export function categoryName(c: string): string {
  return categoryLabel[c] ?? c;
}

// CVSS vector builder. CVSS 3.1 base scores are computed (the API computes
// them too and rejects a mismatching score); CVSS 4.0 vectors are built and
// validated here, and the score comes from the FIRST calculator.

export type CvssVersion = "3.1" | "4.0";

export interface Metric {
  key: string;
  label: string;
  values: { v: string; label: string }[];
}

export const cvss31: Metric[] = [
  { key: "AV", label: "Attack vector", values: [{ v: "N", label: "Network" }, { v: "A", label: "Adjacent" }, { v: "L", label: "Local" }, { v: "P", label: "Physical" }] },
  { key: "AC", label: "Attack complexity", values: [{ v: "L", label: "Low" }, { v: "H", label: "High" }] },
  { key: "PR", label: "Privileges required", values: [{ v: "N", label: "None" }, { v: "L", label: "Low" }, { v: "H", label: "High" }] },
  { key: "UI", label: "User interaction", values: [{ v: "N", label: "None" }, { v: "R", label: "Required" }] },
  { key: "S", label: "Scope", values: [{ v: "U", label: "Unchanged" }, { v: "C", label: "Changed" }] },
  { key: "C", label: "Confidentiality impact", values: [{ v: "H", label: "High" }, { v: "L", label: "Low" }, { v: "N", label: "None" }] },
  { key: "I", label: "Integrity impact", values: [{ v: "H", label: "High" }, { v: "L", label: "Low" }, { v: "N", label: "None" }] },
  { key: "A", label: "Availability impact", values: [{ v: "H", label: "High" }, { v: "L", label: "Low" }, { v: "N", label: "None" }] },
];

const hln = [{ v: "H", label: "High" }, { v: "L", label: "Low" }, { v: "N", label: "None" }];
export const cvss40: Metric[] = [
  { key: "AV", label: "Attack vector", values: [{ v: "N", label: "Network" }, { v: "A", label: "Adjacent" }, { v: "L", label: "Local" }, { v: "P", label: "Physical" }] },
  { key: "AC", label: "Attack complexity", values: [{ v: "L", label: "Low" }, { v: "H", label: "High" }] },
  { key: "AT", label: "Attack requirements", values: [{ v: "N", label: "None" }, { v: "P", label: "Present" }] },
  { key: "PR", label: "Privileges required", values: [{ v: "N", label: "None" }, { v: "L", label: "Low" }, { v: "H", label: "High" }] },
  { key: "UI", label: "User interaction", values: [{ v: "N", label: "None" }, { v: "P", label: "Passive" }, { v: "A", label: "Active" }] },
  { key: "VC", label: "Confidentiality (vulnerable system)", values: hln },
  { key: "VI", label: "Integrity (vulnerable system)", values: hln },
  { key: "VA", label: "Availability (vulnerable system)", values: hln },
  { key: "SC", label: "Confidentiality (subsequent systems)", values: hln },
  { key: "SI", label: "Integrity (subsequent systems)", values: hln },
  { key: "SA", label: "Availability (subsequent systems)", values: hln },
];

export const metricsFor = (v: CvssVersion) => (v === "4.0" ? cvss40 : cvss31);

export function buildVector(version: CvssVersion, m: Record<string, string>): string | null {
  const metrics = metricsFor(version);
  if (!metrics.every((x) => m[x.key])) return null;
  return `CVSS:${version}/` + metrics.map((x) => `${x.key}:${m[x.key]}`).join("/");
}

export function parseVector(vector: string): { version: CvssVersion; metrics: Record<string, string> } | null {
  const [prefix, ...parts] = vector.trim().split("/");
  const version = prefix === "CVSS:4.0" ? "4.0" : prefix === "CVSS:3.1" || prefix === "CVSS:3.0" ? "3.1" : null;
  if (!version) return null;
  const metrics: Record<string, string> = {};
  for (const p of parts) {
    const [k, v] = p.split(":");
    if (!k || !v) return null;
    metrics[k] = v;
  }
  return { version, metrics };
}

function roundUp1(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** CVSS v3.1 base score (null when a metric is missing). */
export function score31(m: Record<string, string>): number | null {
  if (!cvss31.every((x) => m[x.key])) return null;
  const av = ({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as Record<string, number>)[m.AV!]!;
  const ac = ({ L: 0.77, H: 0.44 } as Record<string, number>)[m.AC!]!;
  const ui = ({ N: 0.85, R: 0.62 } as Record<string, number>)[m.UI!]!;
  const changed = m.S === "C";
  const pr = (changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 } as Record<string, number>)[m.PR as "N"]!;
  const cia = { H: 0.56, L: 0.22, N: 0 } as Record<string, number>;
  const iss = 1 - (1 - cia[m.C!]!) * (1 - cia[m.I!]!) * (1 - cia[m.A!]!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  return roundUp1(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

export function severityForScore(s: number): "critical" | "high" | "medium" | "low" | "info" {
  if (s >= 9) return "critical";
  if (s >= 7) return "high";
  if (s >= 4) return "medium";
  if (s > 0) return "low";
  return "info";
}

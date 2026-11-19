import data from "./checkKinds.json";

/**
 * Kinds of check (PATHOS 3.0 M6, rule 3): outside Configurations › Scan
 * profiles, Configurations › Scanners & workers and Import results, the UI
 * names the kind of check and "confirmed by N engines", never a scanner
 * tool. checkKinds.json is generated from the backend registry
 * (backend/internal/scanners/scantypes.go; a Go test keeps it current), so
 * these helpers compute exactly what the API's kind_of_check and
 * engines_count fields carry.
 */

type Override = { kind: string; categories: string[]; tools: string[] };

const kindNames: Record<string, string> = Object.fromEntries(data.kinds.map((k) => [k.id, k.name]));
const categoryKinds = data.category_kinds as Record<string, string>;
const overrides = data.overrides as Override[];
const toolKinds = data.tool_kinds as Record<string, string>;
const importRe = new RegExp(`^import-(${data.import_categories.join("|")})-([a-z0-9][a-z0-9-]{0,22})$`);

/** The 20 kinds of check and the groups outside them, in display order. */
export const CHECK_KINDS: { id: string; name: string; outside: boolean }[] = data.kinds;

/** Catalogued scanner tools (key and name): the names rule 3 hides. */
export const CATALOG_TOOLS: { key: string; name: string; first_party?: boolean }[] = data.tools;

export function kindName(id: string | undefined | null): string {
  return (id && kindNames[id]) || "Other";
}

export function kindOfCategory(category: string): string {
  return categoryKinds[category] ?? "other";
}

/** KindOfFinding of the backend: the category's kind unless all engines belong to a more specific kind. */
export function kindOfFinding(category: string, scannerKeys: string[] = []): string {
  for (const o of overrides) {
    if (o.categories.includes(category) && scannerKeys.length > 0 && scannerKeys.every((k) => o.tools.includes(k))) return o.kind;
  }
  return kindOfCategory(category);
}

/** The kind of check of one engine's results (a catalog key or an import key). */
export function kindOfTool(key: string): string {
  if (toolKinds[key]) return toolKinds[key];
  const m = importRe.exec(key);
  if (m) return kindOfCategory(m[1]!);
  return "other";
}

/** Engine identity: imports, SARIF variants and tool modes count once. */
export function engineOf(key: string): string {
  const m = importRe.exec(key);
  let k = m ? m[2]! : key;
  k = k.replace(/^sarif-/, "");
  for (const fam of data.engine_families) {
    if (k === fam || k.startsWith(fam + "-")) return fam;
  }
  return k;
}

export function enginesCount(keys: string[] = []): number {
  return new Set(keys.filter(Boolean).map(engineOf)).size;
}

export function confirmedBy(n: number): string {
  if (n <= 0) return "no engine";
  return n === 1 ? "confirmed by 1 engine" : `confirmed by ${n} engines`;
}

type FindingLike = { category: string; scanner_keys?: string[] | null; kind_of_check?: string; kind_of_check_name?: string; engines_count?: number };

/** Kind of check of a finding (API field when present). */
export function findingKind(f: FindingLike): { id: string; name: string; engines: number } {
  const id = f.kind_of_check || kindOfFinding(f.category, f.scanner_keys ?? []);
  return { id, name: f.kind_of_check_name || kindName(id), engines: f.engines_count ?? enginesCount(f.scanner_keys ?? []) };
}

/** "Infrastructure as code · confirmed by 2 engines". */
export function findingCheckLabel(f: FindingLike): string {
  const k = findingKind(f);
  return `${k.name} · ${confirmedBy(k.engines)}`;
}

/** "Infrastructure as code" for one engine key. */
export function toolCheckLabel(key: string | null | undefined): string {
  return key ? kindName(kindOfTool(key)) : "—";
}

/** Kinds and engine count of a list of engine keys (when the category is unknown). */
export function keysCheckLabel(keys: string[] = []): string {
  const kinds = [...new Set(keys.map((k) => kindName(kindOfTool(k))))];
  return `${kinds.join(", ") || "Other"} · ${confirmedBy(enginesCount(keys))}`;
}

/** Catalogued engine keys whose results belong to a kind (for filters that take engine keys). */
export function toolKeysOfKind(kind: string): string[] {
  return Object.entries(toolKinds).filter(([, k]) => k === kind).map(([key]) => key);
}

/** Regroups counts keyed by engine into counts keyed by kind of check (key: kind id, label: kind name). */
export function countsByKind<T extends { key: string; count: number }>(rows: T[]): { key: string; label: string; count: number }[] {
  const by = new Map<string, number>();
  for (const r of rows) {
    const id = !r.key || r.key === "none" ? "other" : kindOfTool(r.key);
    by.set(id, (by.get(id) ?? 0) + r.count);
  }
  return [...by.entries()].map(([key, count]) => ({ key, label: kindName(key), count })).sort((a, b) => b.count - a.count);
}

/**
 * Every spelling of a catalogued third-party tool that rule 3 hides: keys,
 * names, lower-case names, a one-word name before a parenthesis ("Trivy" of
 * "Trivy (image)") or inside it ("licensecheck"), and engine families.
 * PATHOS's own checks (first_party) have descriptive names, not tool names.
 */
function toolTerms(t: { key: string; name: string; first_party?: boolean }): string[] {
  if (t.first_party) return [];
  const out = [t.key, t.name, t.name.toLowerCase()];
  const m = /^(.*?)\s*\((.*)\)$/.exec(t.name);
  if (m) {
    if (!/\s/.test(m[1]!)) out.push(m[1]!, m[1]!.toLowerCase());
    // "File licences (licensecheck)": the tool is in the parenthesis.
    if (/\s/.test(m[1]!) && !/\s/.test(m[2]!)) out.push(m[2]!);
  }
  return out;
}

export const TOOL_NAME_TERMS: string[] = [...new Set([...CATALOG_TOOLS.flatMap(toolTerms), ...data.engine_families])]
  .filter((t) => t.length >= 3)
  .sort((a, b) => b.length - a.length);

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const toolNameRe = new RegExp(`(?<![\\w-])(?:${TOOL_NAME_TERMS.map(escapeRe).join("|")})(?![\\w-])`, "g");

/** Replaces catalogued tool names in free text (errors, log lines, events) with "engine". */
export function redactToolNames(text: string | null | undefined): string {
  return (text ?? "").replace(toolNameRe, "engine");
}

// Pure helpers (no VS Code dependency): severity mapping, git remote
// normalization and repository matching, finding path mapping, grouping.

import type { Finding, FindingStatus, Repository, Severity } from "./types";

// ---------------------------------------------------------------------------
// Severity

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export type DiagnosticLevel = "error" | "warning" | "information" | "hint";

/** Rank for sorting: critical = 0 … info = 4, unknown values last. */
export function severityRank(severity: string): number {
  const i = SEVERITIES.indexOf(String(severity).toLowerCase() as Severity);
  return i === -1 ? SEVERITIES.length : i;
}

/** critical/high → error, medium → warning, low → information, info (and unknown) → hint. */
export function diagnosticLevel(severity: string): DiagnosticLevel {
  switch (String(severity).toLowerCase()) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "information";
    default:
      return "hint";
  }
}

export function severityLabel(severity: string): string {
  const s = String(severity || "unknown").toLowerCase();
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** CWE identifiers as "CWE-79", de-duplicated. Accepts "79", "CWE-79", "cwe-79: XSS". */
export function formatCwes(cwe: readonly string[] | null | undefined): string[] {
  const out: string[] = [];
  for (const raw of cwe ?? []) {
    const m = /^\s*(?:cwe-?)?(\d+)/i.exec(String(raw));
    const v = m ? `CWE-${m[1]}` : String(raw).trim();
    if (v && !out.includes(v)) out.push(v);
  }
  return out;
}

/** Message of the diagnostic in the Problems panel. */
export function diagnosticMessage(f: Finding): string {
  const parts = [`[${severityLabel(f.severity)}] ${oneLine(f.title) || "Untitled finding"}`];
  const cwes = formatCwes(f.cwe);
  if (cwes.length) parts.push(`(${cwes.join(", ")})`);
  if (typeof f.risk_score === "number") parts.push(`risk ${Math.round(f.risk_score)}`);
  return parts.join(" ");
}

function oneLine(s: string | undefined): string {
  return String(s ?? "").replace(/\s+/g, " ").trim();
}

// ---------------------------------------------------------------------------
// Status changes

const OPEN_STATUSES: readonly FindingStatus[] = ["open", "in_progress", "needs_review"];

/** Manual status changes allowed from a stored status (docs/api-reference/findings.md). */
export function allowedStatusTargets(from: string): FindingStatus[] {
  if ((OPEN_STATUSES as readonly string[]).includes(from)) {
    return [...OPEN_STATUSES.filter((s) => s !== from), "false_positive", "fixed"];
  }
  if (from === "false_positive" || from === "fixed") return ["open"];
  return [];
}

/** false_positive and fixed need a reason of at least 5 characters. */
export function statusNeedsReason(to: string): boolean {
  return to === "false_positive" || to === "fixed";
}

export const MIN_REASON_LENGTH = 5;

// ---------------------------------------------------------------------------
// Git remotes and repository matching

/**
 * Normalizes a git remote or repository web URL to "host/path" in lower
 * case, without credentials, port, trailing slash or ".git". Handles
 * https://, http://, ssh://, git://, scp-like "git@host:org/repo.git" and the
 * Azure DevOps URL variants. Returns null for anything unrecognized (local
 * paths, file:// URLs).
 */
export function normalizeRemoteUrl(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const s = raw.trim();
  if (!s) return null;
  let host: string;
  let path: string;
  const scheme = /^([a-z][a-z0-9+.-]*):\/\/(.*)$/i.exec(s);
  if (scheme) {
    const proto = scheme[1].toLowerCase();
    if (!["http", "https", "ssh", "git", "git+ssh", "ssh+git"].includes(proto)) return null;
    const rest = scheme[2];
    const slash = rest.indexOf("/");
    let authority = slash === -1 ? rest : rest.slice(0, slash);
    path = slash === -1 ? "" : rest.slice(slash + 1);
    const at = authority.lastIndexOf("@");
    if (at !== -1) authority = authority.slice(at + 1);
    host = authority.replace(/:\d*$/, "");
  } else {
    // scp-like: [user@]host:path (no scheme; a single colon not followed by "//")
    const scp = /^(?:[^@/\s]+@)?([^:/\s]+):(?!\/\/)(.+)$/.exec(s);
    if (!scp) return null;
    host = scp[1];
    path = scp[2];
    // "C:\\repo" style Windows paths are not remotes
    if (/^[a-z]$/i.test(host)) return null;
  }
  host = host.toLowerCase().replace(/^\[|\]$/g, "");
  path = path
    .split(/[?#]/)[0]
    .replace(/\\/g, "/")
    .replace(/^\/+|\/+$/g, "")
    .replace(/\.git$/i, "")
    .replace(/\/+$/g, "");
  try {
    path = decodeURIComponent(path);
  } catch {
    // keep as is
  }
  path = path.toLowerCase();
  if (!host || !path) return null;

  // GitHub over SSH on port 443.
  if (host === "ssh.github.com") host = "github.com";

  // Azure DevOps: https://dev.azure.com/org/project/_git/repo,
  // git@ssh.dev.azure.com:v3/org/project/repo,
  // https://org.visualstudio.com/[DefaultCollection/]project/_git/repo
  if (host === "ssh.dev.azure.com" || host === "vs-ssh.visualstudio.com") {
    const p = path.replace(/^v3\//, "").split("/");
    if (p.length >= 3) return `dev.azure.com/${p[0]}/${p[1]}/${p.slice(2).join("/")}`;
  }
  if (host === "dev.azure.com") {
    const p = path.split("/");
    const git = p.indexOf("_git");
    if (git === 2 && p.length > 3) return `dev.azure.com/${p[0]}/${p[1]}/${p.slice(3).join("/")}`;
  }
  const vs = /^([a-z0-9-]+)\.visualstudio\.com$/.exec(host);
  if (vs) {
    const p = path.split("/").filter((x) => x !== "defaultcollection");
    const git = p.indexOf("_git");
    if (git === 1 && p.length > 2) return `dev.azure.com/${vs[1]}/${p[0]}/${p.slice(2).join("/")}`;
  }
  return `${host}/${path}`;
}

/** The "org/repo" part of a normalized remote (everything after the host). */
function remotePath(normalized: string): string {
  const i = normalized.indexOf("/");
  return i === -1 ? "" : normalized.slice(i + 1);
}

export interface RepositoryMatch {
  repository: Repository;
  /** "url": the repository URL equals a remote; "name": only the full name matches. */
  by: "url" | "name";
}

/**
 * Repositories matching any of the remotes. Exact URL matches win; when no
 * repository URL matches, repositories whose full_name equals the remote's
 * path (case-insensitive) are returned instead.
 */
export function matchRepositories(remotes: readonly string[], repos: readonly Repository[]): RepositoryMatch[] {
  const norm = new Set(remotes.map(normalizeRemoteUrl).filter((x): x is string => !!x));
  if (norm.size === 0) return [];
  const byUrl = repos.filter((r) => {
    const n = normalizeRemoteUrl(r.url);
    return n !== null && norm.has(n);
  });
  if (byUrl.length) return byUrl.map((repository) => ({ repository, by: "url" as const }));
  const paths = new Set([...norm].map(remotePath));
  return repos
    .filter((r) => r.full_name && paths.has(r.full_name.toLowerCase().replace(/^\/+|\/+$/g, "")))
    .map((repository) => ({ repository, by: "name" as const }));
}

/** Remote URLs from the text of a .git/config file. */
export function parseGitConfigRemotes(text: string): string[] {
  const urls: string[] = [];
  let inRemote = false;
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#") || t.startsWith(";")) continue;
    const section = /^\[\s*([^\]\s"]+)(?:\s+"([^"]*)")?\s*\]/.exec(t);
    if (section) {
      inRemote = section[1].toLowerCase() === "remote";
      continue;
    }
    if (!inRemote) continue;
    const kv = /^(url|pushurl)\s*=\s*(.*)$/i.exec(t);
    if (kv) {
      let v = kv[2].trim();
      if (v.startsWith('"') && v.endsWith('"') && v.length >= 2) v = v.slice(1, -1);
      if (v && !urls.includes(v)) urls.push(v);
    }
  }
  return urls;
}

// ---------------------------------------------------------------------------
// Paths

/**
 * The finding's file path as safe, relative path segments, or null when it
 * has none or it cannot be mapped into a workspace folder (parent
 * references, drive letters, URLs).
 */
export function findingPathSegments(filePath: string | null | undefined): string[] | null {
  if (!filePath) return null;
  let p = String(filePath).trim().replace(/\\/g, "/");
  if (!p || /^[a-z][a-z0-9+.-]*:\/\//i.test(p) || /^[a-z]:\//i.test(p)) return null;
  p = p.replace(/^(\.\/)+/, "").replace(/^\/+/, "");
  const segs = p.split("/").filter((s) => s !== "" && s !== ".");
  if (segs.length === 0 || segs.some((s) => s === ".." || s.includes("\0"))) return null;
  return segs;
}

/** Normalized display path ("src/app.ts"), or "" without a mappable path. */
export function displayPath(filePath: string | null | undefined): string {
  return findingPathSegments(filePath)?.join("/") ?? "";
}

/** Zero-based line for a 1-based start_line (missing or invalid → 0). */
export function zeroBasedLine(startLine: number | null | undefined): number {
  return typeof startLine === "number" && Number.isFinite(startLine) && startLine >= 1 ? Math.floor(startLine) - 1 : 0;
}

// ---------------------------------------------------------------------------
// Grouping (tree view)

export type GroupingMode = "severity" | "file";

export interface FileGroup {
  /** Display path; "" for findings without a location. */
  path: string;
  findings: Finding[];
}

export interface SeverityGroup {
  severity: string;
  count: number;
  files: FileGroup[];
}

export function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(a.severity) - severityRank(b.severity) ||
    (b.risk_score ?? -1) - (a.risk_score ?? -1) ||
    (a.start_line ?? 0) - (b.start_line ?? 0) ||
    a.title.localeCompare(b.title)
  );
}

function compareLocation(a: Finding, b: Finding): number {
  return (a.start_line ?? 0) - (b.start_line ?? 0) || compareFindings(a, b);
}

/** Findings grouped by file, files sorted by path (findings without a path last), findings by line. */
export function groupByFile(findings: readonly Finding[]): FileGroup[] {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const p = displayPath(f.file_path);
    const list = map.get(p);
    if (list) list.push(f);
    else map.set(p, [f]);
  }
  return [...map.entries()]
    .sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b)))
    .map(([path, list]) => ({ path, findings: list.sort(compareLocation) }));
}

/** Findings grouped by severity (critical first, empty severities omitted), then by file. */
export function groupBySeverity(findings: readonly Finding[]): SeverityGroup[] {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const s = String(f.severity || "unknown").toLowerCase();
    const list = map.get(s);
    if (list) list.push(f);
    else map.set(s, [f]);
  }
  return [...map.entries()]
    .sort(([a], [b]) => severityRank(a) - severityRank(b) || a.localeCompare(b))
    .map(([severity, list]) => ({ severity, count: list.length, files: groupByFile(list) }));
}

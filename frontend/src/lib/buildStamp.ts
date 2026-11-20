/**
 * Version stamps on client-side exports (PATHOS 3.0 M9): CSV file names,
 * graph JSON downloads and printed pages say which PATHOS release and build
 * produced them. The server stamps its own downloads (X-PATHOS-Generated-By).
 *
 * The version and build come from GET /api/v1/meta (useMeta records them
 * here when it loads), never from the bundle alone: the backend is the
 * source of truth for what generated the data.
 */

export interface BuildInfo {
  version?: string;
  commit?: string;
}

let current: BuildInfo = {};

/** Records the server's version and build (called when /api/v1/meta loads). */
export function setBuildInfo(info: BuildInfo | undefined | null) {
  current = { version: info?.version || undefined, commit: info?.commit || undefined };
}

export function getBuildInfo(): BuildInfo {
  return current;
}

/** The first 12 characters of the build commit (hex/alphanumeric only), or "". */
export function shortBuild(commit: string | undefined): string {
  return (commit ?? "").replace(/[^0-9a-zA-Z]/g, "").slice(0, 12);
}

/** "v3.0.0" for a release, "dev" for a dev build, "" when unknown. */
export function versionTag(version: string | undefined): string {
  const v = (version ?? "").trim().replace(/[^\w.+-]/g, "");
  if (!v) return "";
  return v === "dev" || v.startsWith("v") ? v : `v${v}`;
}

/** "Quditmind PATHOS v3.0.0 · build 0123456789ab · generated 2026-11-20T10:00:00.000Z" */
export function generatedByStamp(info: BuildInfo = current, now: Date = new Date()): string {
  const v = versionTag(info.version) || "version unknown";
  const b = shortBuild(info.commit) || "unknown";
  return `Quditmind PATHOS ${v} · build ${b} · generated ${now.toISOString()}`;
}

/**
 * Version-stamped export file name:
 * pathos-v3.0.0-b0123456789ab-findings-2026-11-20.csv (UTC date). Parts that
 * are unknown are left out.
 */
export function stampedFileName(what: string, ext: string, info: BuildInfo = current, now: Date = new Date()): string {
  const safe = what.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "export";
  const parts = ["pathos"];
  const v = versionTag(info.version);
  if (v) parts.push(v);
  const b = shortBuild(info.commit);
  if (b) parts.push(`b${b}`);
  parts.push(safe, now.toISOString().slice(0, 10));
  return `${parts.join("-")}.${ext.replace(/^\./, "")}`;
}

/** Adds a top-level "generated_by" stamp to a plain JSON object; arrays and scalars are returned unchanged. */
export function withGeneratedBy<T>(data: T, info: BuildInfo = current, now: Date = new Date()): T | (T & { generated_by: string }) {
  if (data === null || typeof data !== "object" || Array.isArray(data)) return data;
  return { generated_by: generatedByStamp(info, now), ...(data as object) } as T & { generated_by: string };
}

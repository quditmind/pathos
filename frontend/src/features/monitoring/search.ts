import type { FeedFilters } from "./api";

/** URL state of /monitoring: the feed filters plus tab, time range, open drift and the unchanged toggle. */
export interface MonitoringSearch extends FeedFilters {
  tab?: "feed" | "drift";
  /** 24h, 7d, 30d or custom (custom uses since/until). */
  range?: string;
  /** Open drift (detail drawer). */
  drift?: string;
  /** "true": the drift timeline also lists snapshots without changes. */
  unchanged?: string;
}

const idLike = (v: unknown) => (typeof v === "string" && /^[0-9a-zA-Z-]{1,64}$/.test(v) ? v : undefined);
const listOf = (v: unknown) => (typeof v === "string" && /^[a-z0-9_.,]{1,400}$/.test(v) ? v : undefined);
const timeLike = (v: unknown) => (typeof v === "string" && !Number.isNaN(Date.parse(v)) ? v : undefined);

export function validateMonitoringSearch(s: Record<string, unknown>): MonitoringSearch {
  const out: MonitoringSearch = {
    tab: s.tab === "drift" ? "drift" : undefined,
    application_id: idLike(s.application_id),
    repository_id: idLike(s.repository_id),
    type: listOf(s.type),
    severity: listOf(s.severity),
    loop: typeof s.loop === "string" || typeof s.loop === "number" ? (/^[1-7]$/.test(String(s.loop)) ? String(s.loop) : undefined) : undefined,
    range: ["24h", "7d", "30d", "custom"].includes(s.range as string) ? (s.range as string) : undefined,
    since: timeLike(s.since),
    until: timeLike(s.until),
    drift: idLike(s.drift),
    unchanged: s.unchanged === "true" || s.unchanged === true ? "true" : undefined,
  };
  for (const k of Object.keys(out) as (keyof MonitoringSearch)[]) if (out[k] === undefined) delete out[k];
  return out;
}

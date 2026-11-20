// URL state of the reverse-engineering pages (kept out of the lazily loaded page modules).

export const reaTabs = ["functions", "call-graph", "strings", "runtime", "diff", "history"] as const;
export type ReaTab = (typeof reaTabs)[number];

export type ReaArtifactsSearch = { repository?: string; q?: string };
export type ReaAnalysisSearch = { tab?: ReaTab; fn?: string; node?: string };

const idLike = (v: unknown) => (typeof v === "string" && /^[\w:.\-/@]{1,300}$/.test(v) ? v : undefined);
const text = (v: unknown) => (typeof v === "string" && v.length <= 200 ? v : undefined);

export const validateReaArtifactsSearch = (s: Record<string, unknown>): ReaArtifactsSearch => ({
  repository: idLike(s.repository),
  q: text(s.q),
});

export const validateReaAnalysisSearch = (s: Record<string, unknown>): ReaAnalysisSearch => ({
  tab: (reaTabs as readonly string[]).includes(s.tab as string) ? (s.tab as ReaTab) : undefined,
  fn: idLike(s.fn),
  node: idLike(s.node),
});

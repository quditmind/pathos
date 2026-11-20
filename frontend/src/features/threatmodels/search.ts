// URL state of /threat-models and /threat-models/$modelId (kept out of the lazily loaded page modules).
export const modelTabs = ["threats", "diagram", "versions"] as const;
export type ModelTab = (typeof modelTabs)[number];

export type ThreatModelSearch = { tab?: ModelTab; threat?: string };
export type ThreatModelsSearch = { application?: string; status?: string };

const uuidLike = (v: unknown) => (typeof v === "string" && /^[0-9a-fA-F-]{8,64}$/.test(v) ? v : undefined);
const statuses = ["draft", "in_review", "approved", "superseded", "archived"];

export const validateThreatModelSearch = (s: Record<string, unknown>): ThreatModelSearch => ({
  tab: (modelTabs as readonly string[]).includes(s.tab as string) ? (s.tab as ModelTab) : undefined,
  threat: uuidLike(s.threat),
});

export const validateThreatModelsSearch = (s: Record<string, unknown>): ThreatModelsSearch => ({
  application: uuidLike(s.application),
  status: statuses.includes(s.status as string) ? (s.status as string) : undefined,
});

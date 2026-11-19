import { isCodeGraphView, type CodeGraphView } from "./views";

// URL state of /codegraph/$appId (kept out of the lazily loaded page module).
export type CodeGraphSearch = { view?: CodeGraphView; snapshot?: string; compare?: string; focus?: string; node?: string };

const idLike = (v: unknown) => (typeof v === "string" && /^[\w:.\-/@]{1,300}$/.test(v) ? v : undefined);

export const validateCodeGraphSearch = (s: Record<string, unknown>): CodeGraphSearch => ({
  view: isCodeGraphView(s.view) ? s.view : undefined,
  snapshot: idLike(s.snapshot),
  compare: idLike(s.compare),
  focus: idLike(s.focus),
  node: idLike(s.node),
});


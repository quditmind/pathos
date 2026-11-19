import { useQuery } from "@tanstack/react-query";
import { api, isCatalogueCode } from "@/api/client";
import { helpDocs, type HelpDoc } from "./content";

/** One entry of the error catalogue (GET /api/v1/diagnostics/codes). */
export interface DiagCode {
  code: string;
  area: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  confirmed_cause: string;
  probable_causes: string[];
  impact: string;
  actions: string[];
  verify: string[];
  docs_url: string;
  ai_help: boolean;
}

export const diagAreas: Record<string, string> = {
  PLAT: "Platform",
  AUTH: "Sign-in and authorization",
  CONN: "Connections",
  SYNC: "Source sync",
  ONB: "Onboarding",
  DISC: "Discovery",
  GRAPH: "CodeGraph",
  TM: "Threat modelling",
  REA: "Reverse engineering",
  SCAN: "Scan execution",
  WORK: "Workers",
  AI: "AI models",
  GATE: "Security gates",
  REM: "Remediation",
  REP: "Reports",
  MON: "Monitoring",
};

const s = (v: unknown) => (typeof v === "string" ? v : "");
const ss = (v: unknown) => (Array.isArray(v) ? v.map((x) => (typeof x === "string" ? x : x && typeof x === "object" && typeof (x as { text?: unknown }).text === "string" ? (x as { text: string }).text : "")).filter(Boolean) : []);

/** Normalises one catalogue entry; tolerant of optional or renamed fields. */
export function normaliseCode(raw: unknown): DiagCode | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const code = s(r.code) || s(r.error_code);
  if (!isCatalogueCode(code)) return null;
  const area = s(r.area) || code.split("-")[1]!;
  const docs = s(r.docs_url) || (s(r.docs_slug) ? `/help/troubleshooting/${s(r.docs_slug)}` : `/help/troubleshooting/${area.toLowerCase()}#${code}`);
  const confirmed = r.confirmed_cause ?? (r.cause && typeof r.cause === "object" ? (r.cause as { text?: unknown }).text : undefined);
  return {
    code,
    area,
    category: s(r.category),
    severity: s(r.severity),
    title: s(r.title),
    description: s(r.description) || s(r.technical_description) || s(r.message),
    confirmed_cause: s(confirmed),
    probable_causes: ss(r.probable_causes),
    impact: s(r.impact),
    actions: ss(r.actions),
    verify: ss(r.verify),
    docs_url: docs.startsWith("/") ? docs : "",
    ai_help: r.ai_help === true || r.ai_offered === true,
  };
}

/** Accepts {items: [...]}, {codes: [...]} or a bare array. */
export function parseCodes(resp: unknown): DiagCode[] {
  const list = Array.isArray(resp) ? resp : resp && typeof resp === "object" ? ((resp as { items?: unknown }).items ?? (resp as { codes?: unknown }).codes) : [];
  return (Array.isArray(list) ? list : []).map(normaliseCode).filter((c): c is DiagCode => c !== null).sort((a, b) => a.code.localeCompare(b.code));
}

/** Area titles sent with the catalogue ({areas: [{key, title}]}), over the built-in names. */
export function parseAreas(resp: unknown): Record<string, string> {
  const list = resp && typeof resp === "object" ? (resp as { areas?: unknown }).areas : undefined;
  const out: Record<string, string> = {};
  if (Array.isArray(list))
    for (const a of list) if (a && typeof a === "object" && typeof a.key === "string" && typeof a.title === "string" && a.title) out[a.key] = a.title;
  return out;
}

export function useDiagnosticCodes() {
  return useQuery({
    queryKey: ["diagnostics", "codes"],
    queryFn: () =>
      api<unknown>("/api/v1/diagnostics/codes").then((r) => ({ codes: parseCodes(r), areas: { ...diagAreas, ...parseAreas(r) } })),
    staleTime: 10 * 60_000,
    retry: 1,
  });
}

/** The bundled troubleshooting docs (docs/troubleshooting/<area>.md). */
export const troubleshootingDocs: HelpDoc[] = helpDocs.filter((d) => d.section === "troubleshooting");

/**
 * Codes listed in the bundled docs: every heading that starts with a code.
 * Used offline (or before the API answers) so the centre never shows nothing.
 */
export function codesFromDocs(docs: HelpDoc[] = troubleshootingDocs): DiagCode[] {
  const out: DiagCode[] = [];
  for (const d of docs) {
    for (const h of d.headings) {
      const m = /^(PTH-[A-Z]+-\d{4})\b[\s:—–-]*(.*)$/.exec(h.text);
      if (!m) continue;
      out.push({
        code: m[1]!,
        area: m[1]!.split("-")[1]!,
        category: "",
        severity: "",
        title: m[2]!.trim(),
        description: "",
        confirmed_cause: "",
        probable_causes: [],
        impact: "",
        actions: [],
        verify: [],
        docs_url: `/help/troubleshooting/${d.slug}#${h.id}`,
        ai_help: false,
      });
    }
  }
  return out.sort((a, b) => a.code.localeCompare(b.code));
}

export function searchCodes(codes: DiagCode[], q: string): DiagCode[] {
  const terms = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return codes;
  return codes.filter((c) => {
    const hay = [c.code, c.title, c.description, c.category, diagAreas[c.area] ?? "", c.confirmed_cause, ...c.probable_causes, ...c.actions].join(" ").toLowerCase();
    return terms.every((t) => hay.includes(t));
  });
}

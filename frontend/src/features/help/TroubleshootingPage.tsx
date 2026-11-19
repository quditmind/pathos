import { useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { BookOpen, ChevronRight, FileQuestion, Search, WifiOff } from "lucide-react";
import { Badge, Card, EmptyState, Input, PageHeader } from "@/components/ui/primitives";
import { LoadingSkeleton } from "@/components/ui/states";
import { codesFromDocs, diagAreas, searchCodes, troubleshootingDocs, useDiagnosticCodes, type DiagCode } from "./troubleshooting";

export type TroubleshootingSearch = { q?: string };

export function validateTroubleshootingSearch(s: Record<string, unknown>): TroubleshootingSearch {
  return typeof s.q === "string" && s.q.length <= 200 ? { q: s.q } : {};
}

function DocsLink({ url, children }: { url: string; children: ReactNode }) {
  const [to, hash] = url.split("#");
  return (
    <Link to={to as never} hash={hash} className="inline-flex items-center gap-1 text-primary hover:underline">
      {children}
    </Link>
  );
}

function CodeEntry({ c }: { c: DiagCode }) {
  const hasDetail = c.description || c.confirmed_cause || c.probable_causes.length || c.impact || c.actions.length || c.verify.length;
  return (
    <li id={c.code} className="px-4 py-2.5">
      <details className="group">
        <summary className="flex cursor-pointer list-none items-center gap-2 rounded text-[13px] focus-visible:outline-2 focus-visible:outline-ring">
          <ChevronRight className="size-3.5 shrink-0 text-muted-foreground transition-transform group-open:rotate-90 motion-reduce:transition-none" aria-hidden />
          <code className="font-mono text-[12px] font-semibold">{c.code}</code>
          <span className="flex-1">{c.title || "—"}</span>
          {c.severity && <Badge tone={c.severity === "critical" || c.severity === "error" ? "danger" : c.severity === "warning" ? "warning" : "neutral"}>{c.severity}</Badge>}
        </summary>
        <div className="mt-2 space-y-2 pl-6 text-[13px]">
          {c.description && <p>{c.description}</p>}
          {c.confirmed_cause && (
            <p>
              <span className="font-medium">When the cause is confirmed: </span>
              {c.confirmed_cause}
            </p>
          )}
          {c.probable_causes.length > 0 && (
            <div>
              <div className="font-medium">Probable causes</div>
              <ul className="list-disc pl-5">{c.probable_causes.map((x, i) => <li key={i}>{x}</li>)}</ul>
            </div>
          )}
          {c.impact && (
            <p>
              <span className="font-medium">Impact: </span>
              {c.impact}
            </p>
          )}
          {c.actions.length > 0 && (
            <div>
              <div className="font-medium">How to fix it</div>
              <ol className="list-decimal pl-5">{c.actions.map((x, i) => <li key={i}>{x}</li>)}</ol>
            </div>
          )}
          {c.verify.length > 0 && (
            <div>
              <div className="font-medium">How to verify</div>
              <ol className="list-decimal pl-5">{c.verify.map((x, i) => <li key={i}>{x}</li>)}</ol>
            </div>
          )}
          {!hasDetail && <p className="text-muted-foreground">Open the article for the causes and fixes.</p>}
          {c.docs_url && (
            <DocsLink url={c.docs_url}>
              <BookOpen className="size-3.5" /> Read the article
            </DocsLink>
          )}
        </div>
      </details>
    </li>
  );
}

/** /help/troubleshooting: every error code, searchable, grouped by area. */
export function TroubleshootingPage() {
  const { q = "" } = useSearch({ strict: false }) as TroubleshootingSearch;
  const navigate = useNavigate();
  const [text, setText] = useState(q);
  const api = useDiagnosticCodes();
  const offline = useMemo(() => codesFromDocs(), []);
  const all = api.data && api.data.codes.length ? api.data.codes : offline;
  const areaNames = api.data?.areas ?? diagAreas;
  const hits = useMemo(() => searchCodes(all, q), [all, q]);
  const byArea = useMemo(() => {
    const m = new Map<string, DiagCode[]>();
    for (const c of hits) m.set(c.area, [...(m.get(c.area) ?? []), c]);
    return [...m.entries()].sort(([a], [b]) => Object.keys(diagAreas).indexOf(a) - Object.keys(diagAreas).indexOf(b));
  }, [hits]);

  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 flex items-center gap-1 text-[12px] text-muted-foreground">
        <Link to="/help" className="hover:underline">
          Help Center
        </Link>
        <ChevronRight className="size-3" />
        <span>Troubleshooting centre</span>
      </nav>
      <PageHeader
        title="Troubleshooting centre"
        description="Every PATHOS error code with its causes, fixes and how to verify the fix. Search by code, message or symptom."
        actions={
          <form
            role="search"
            className="relative w-full max-w-md"
            onSubmit={(e) => {
              e.preventDefault();
              void navigate({ to: "/help/troubleshooting", search: text.trim() ? { q: text.trim() } : {} });
            }}
          >
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <Input aria-label="Search error codes" placeholder="PTH-CONN-1004, certificate, webhook…" className="pl-8" value={text} onChange={(e) => setText(e.target.value)} />
          </form>
        }
      />
      {api.isError && (
        <div className="mb-3 flex items-center gap-2 rounded-md bg-warning-soft px-3 py-2 text-[13px] text-warning" role="status">
          <WifiOff className="size-4" aria-hidden /> The live catalogue is not reachable ({api.error.message}); showing the codes bundled with this version.
        </div>
      )}
      {api.isPending && !offline.length ? (
        <LoadingSkeleton rows={6} label="Loading error codes" />
      ) : (
        <div className="space-y-4">
          <p className="text-[12px] text-muted-foreground" aria-live="polite">
            {hits.length} of {all.length} code{all.length === 1 ? "" : "s"}
            {q ? ` match “${q}”` : ""}
          </p>
          {byArea.length === 0 ? (
            <Card>
              <EmptyState icon={<FileQuestion />} title={all.length ? "No code matches" : "No error codes are available"}>
                {all.length
                  ? "Try a shorter search, the code itself (for example PTH-SCAN), or words from the message."
                  : "The error catalogue was not found in this build and the server did not return it."}
              </EmptyState>
            </Card>
          ) : (
            byArea.map(([area, codes]) => {
              const doc = troubleshootingDocs.find((d) => d.slug === area.toLowerCase());
              return (
                <Card key={area}>
                  <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
                    <h2 className="flex-1 text-[14px] font-semibold">
                      {areaNames[area] ?? area} <span className="font-normal text-muted-foreground">· PTH-{area}</span>
                    </h2>
                    {doc && (
                      <Link to="/help/$section/$slug" params={{ section: "troubleshooting", slug: doc.slug }} className="text-[12px] text-primary hover:underline">
                        Full article
                      </Link>
                    )}
                  </div>
                  <ul className="divide-y divide-border">
                    {codes.map((c) => (
                      <CodeEntry key={c.code} c={c} />
                    ))}
                  </ul>
                </Card>
              );
            })
          )}
        </div>
      )}
    </>
  );
}

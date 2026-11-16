import { useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { BookOpen, ChevronRight, Code2, FileQuestion, LifeBuoy, Search } from "lucide-react";
import { Card, EmptyState, Input, PageHeader } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import { findDoc, helpDocs, renderDoc, searchDocs, sectionLabels, type HelpDoc, type HelpSection } from "./content";

export type HelpSearch = { q?: string };

export function validateHelpSearch(s: Record<string, unknown>): HelpSearch {
  return typeof s.q === "string" && s.q.length <= 200 ? { q: s.q } : {};
}

const sections: HelpSection[] = ["user-guide", "api-reference"];

function latestUpdate(docs: HelpDoc[]): string {
  return docs.reduce((m, d) => (d.updated > m ? d.updated : m), "");
}

function DocLink({ doc, className, hash }: { doc: HelpDoc; className?: string; hash?: string }) {
  return (
    <Link to="/help/$section/$slug" params={{ section: doc.section, slug: doc.slug }} hash={hash} className={className}>
      {doc.title}
    </Link>
  );
}

/** Left navigation: every section and document. */
function HelpNav({ current }: { current?: HelpDoc }) {
  return (
    <nav aria-label="Help topics" className="space-y-4 text-[13px]">
      {sections.map((s) => (
        <div key={s}>
          <div className="mb-1.5 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">{sectionLabels[s]}</div>
          <ul className="space-y-0.5">
            {helpDocs
              .filter((d) => d.section === s)
              .map((d) => (
                <li key={d.slug}>
                  <DocLink
                    doc={d}
                    className={cn(
                      "block rounded px-2 py-1 hover:bg-surface-muted",
                      current?.section === d.section && current.slug === d.slug ? "bg-primary/10 font-medium text-primary" : "text-foreground",
                    )}
                  />
                </li>
              ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function SearchBox({ initial = "" }: { initial?: string }) {
  const navigate = useNavigate();
  const [q, setQ] = useState(initial);
  useEffect(() => setQ(initial), [initial]);
  return (
    <form
      role="search"
      onSubmit={(e) => {
        e.preventDefault();
        void navigate({ to: "/help", search: q.trim() ? { q: q.trim() } : {} });
      }}
      className="relative w-full max-w-md"
    >
      <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input aria-label="Search documentation" placeholder="Search documentation" className="pl-8" value={q} onChange={(e) => setQ(e.target.value)} />
    </form>
  );
}

export function HelpHomePage() {
  const { q = "" } = useSearch({ strict: false }) as HelpSearch;
  const hits = useMemo(() => searchDocs(q), [q]);
  const version = helpDocs.find((d) => d.version)?.version ?? "";
  return (
    <>
      <PageHeader
        title="Help Center"
        description="Step-by-step guides, configuration references and API documentation for PATHOS."
        actions={<SearchBox initial={q} />}
      />
      <div className="grid gap-6 lg:grid-cols-[220px_1fr]">
        <aside className="hidden lg:block">
          <HelpNav />
        </aside>
        <div className="min-w-0 space-y-6">
          {q ? (
            <Card>
              <div className="border-b border-border px-4 py-3 text-[13px] font-semibold" aria-live="polite">
                {hits.length} result{hits.length === 1 ? "" : "s"} for “{q}”
              </div>
              {hits.length === 0 ? (
                <EmptyState icon={<FileQuestion />} title="Nothing found">
                  Try other words, or browse the topics on the left.
                </EmptyState>
              ) : (
                <ul className="divide-y divide-border">
                  {hits.map((h) => (
                    <li key={`${h.doc.section}/${h.doc.slug}`} className="px-4 py-3">
                      <div className="flex flex-wrap items-center gap-1.5 text-[13px]">
                        <span className="text-[11px] text-muted-foreground">{sectionLabels[h.doc.section]}</span>
                        <ChevronRight className="size-3 text-muted-foreground" />
                        <DocLink doc={h.doc} hash={h.heading?.id} className="font-medium text-primary hover:underline" />
                        {h.heading && <span className="text-muted-foreground">› {h.heading.text}</span>}
                      </div>
                      <p className="mt-1 text-[12px] text-muted-foreground">{h.snippet}</p>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          ) : (
            <>
              <div className="grid gap-4 md:grid-cols-2">
                {sections.map((s) => {
                  const docs = helpDocs.filter((d) => d.section === s);
                  const Icon = s === "user-guide" ? BookOpen : Code2;
                  return (
                    <Card key={s} className="p-4">
                      <div className="mb-2 flex items-center gap-2">
                        <Icon className="size-5 text-primary" />
                        <h2 className="text-[15px] font-semibold">{sectionLabels[s]}</h2>
                      </div>
                      <ul className="space-y-2">
                        {docs.map((d) => (
                          <li key={d.slug}>
                            <DocLink doc={d} className="text-[13px] font-medium text-primary hover:underline" />
                            {d.summary && <p className="text-[12px] text-muted-foreground">{d.summary}</p>}
                          </li>
                        ))}
                      </ul>
                    </Card>
                  );
                })}
              </div>
              {findDoc("user-guide", "troubleshooting") && (
                <Card className="flex items-center gap-3 p-4">
                  <LifeBuoy className="size-5 text-primary" />
                  <div className="flex-1 text-[13px]">
                    <div className="font-medium">Something not working?</div>
                    <div className="text-muted-foreground">Answers to common questions about imports, connections, exposure and scanning.</div>
                  </div>
                  <Link to="/help/$section/$slug" params={{ section: "user-guide", slug: "troubleshooting" }} className="text-[13px] font-medium text-primary hover:underline">
                    Troubleshooting & FAQ
                  </Link>
                </Card>
              )}
              <p className="text-[12px] text-muted-foreground">
                Documentation version {version || "—"} · last updated {latestUpdate(helpDocs) || "—"} · {helpDocs.length} topics
              </p>
            </>
          )}
        </div>
      </div>
    </>
  );
}

export function HelpDocPage() {
  const { section, slug } = useParams({ strict: false }) as { section: string; slug: string };
  const doc = findDoc(section, slug);
  const navigate = useNavigate();
  const html = useMemo(() => (doc ? renderDoc(doc) : ""), [doc]);
  const ref = useRef<HTMLDivElement>(null);

  // Scroll to the hash target after rendering (and on hash changes).
  useEffect(() => {
    const scroll = () => {
      const id = decodeURIComponent(window.location.hash.slice(1));
      const el = id ? document.getElementById(id) : null;
      if (el) el.scrollIntoView({ block: "start" });
      else ref.current?.scrollIntoView({ block: "start" });
    };
    scroll();
    window.addEventListener("hashchange", scroll);
    return () => window.removeEventListener("hashchange", scroll);
  }, [html]);

  if (!doc) {
    return (
      <Card className="mt-4">
        <EmptyState icon={<FileQuestion />} title="Page not found">
          <Link to="/help" className="text-primary underline">
            Back to the Help Center
          </Link>
        </EmptyState>
      </Card>
    );
  }

  // Internal links: client-side navigation instead of a full reload.
  const onClick = (e: MouseEvent<HTMLDivElement>) => {
    const a = (e.target as HTMLElement).closest("a");
    if (!a || a.target === "_blank" || e.metaKey || e.ctrlKey || e.shiftKey) return;
    const href = a.getAttribute("href") ?? "";
    if (a.dataset.helpLink) {
      e.preventDefault();
      const [path, hash] = href.split("#");
      const [, , sec, sl] = path!.split("/");
      void navigate({ to: "/help/$section/$slug", params: { section: sec!, slug: sl! }, hash });
    }
  };

  const toc = doc.headings.filter((h) => h.depth === 2 || h.depth === 3);
  return (
    <div ref={ref}>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-[12px] text-muted-foreground">
          <Link to="/help" className="hover:underline">
            Help Center
          </Link>
          <ChevronRight className="size-3" />
          <span>{sectionLabels[doc.section]}</span>
        </nav>
        <div className="flex-1" />
        <SearchBox />
      </div>
      <div className="grid gap-6 lg:grid-cols-[220px_minmax(0,1fr)] xl:grid-cols-[220px_minmax(0,1fr)_220px]">
        <aside className="hidden lg:block">
          <div className="sticky top-4">
            <HelpNav current={doc} />
          </div>
        </aside>
        <Card className="min-w-0 px-5 py-6 sm:px-8">
          <article className="help-prose" onClick={onClick} dangerouslySetInnerHTML={{ __html: html }} />
          <footer className="mt-8 border-t border-border pt-3 text-[12px] text-muted-foreground">
            Documentation version {doc.version || "—"} · last updated {doc.updated || "—"} · source: <code>docs/{doc.section}/{doc.slug}.md</code>
          </footer>
        </Card>
        {toc.length > 2 && (
          <aside className="hidden xl:block">
            <nav aria-label="On this page" className="sticky top-4 text-[12px]">
              <div className="mb-1.5 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">On this page</div>
              <ul className="max-h-[80vh] space-y-1 overflow-y-auto">
                {toc.map((h) => (
                  <li key={h.id} className={h.depth === 3 ? "pl-3" : ""}>
                    <a href={`#${h.id}`} className="text-muted-foreground hover:text-foreground">
                      {h.text}
                    </a>
                  </li>
                ))}
              </ul>
            </nav>
          </aside>
        )}
      </div>
    </div>
  );
}

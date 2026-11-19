import { useEffect, useMemo, useRef, type MouseEvent } from "react";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { ExternalLink } from "lucide-react";
import { Dialog } from "@/components/ui/dialog";
import { findDoc, renderDoc, resolveAnchor } from "@/features/help/content";
import { articleForRoute } from "@/features/help/routeHelp";

/** Right-hand drawer with the help article mapped to the current route (F1 or ?). */
export function HelpDrawer({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const fullPath = useRouterState({ select: (s) => s.matches[s.matches.length - 1]?.fullPath ?? s.location.pathname });
  const article = articleForRoute(fullPath);
  const doc = findDoc(article.section, article.slug);
  const html = useMemo(() => (doc ? renderDoc(doc) : ""), [doc]);
  const anchor = doc && article.anchor ? resolveAnchor(doc.headings, article.anchor) : undefined;
  const ref = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!open || !anchor) return;
    const t = setTimeout(() => ref.current?.querySelector(`[id="${anchor}"]`)?.scrollIntoView({ block: "start" }), 0);
    return () => clearTimeout(t);
  }, [open, anchor, html]);

  const onClick = (e: MouseEvent<HTMLDivElement>) => {
    const a = (e.target as HTMLElement).closest("a");
    if (!a || a.target === "_blank" || e.metaKey || e.ctrlKey || e.shiftKey) return;
    const href = a.getAttribute("href") ?? "";
    if (a.dataset.helpLink) {
      e.preventDefault();
      const [path, hash] = href.split("#");
      const [, , sec, sl] = path!.split("/");
      onOpenChange(false);
      void navigate({ to: "/help/$section/$slug", params: { section: sec!, slug: sl! }, hash });
    } else if (href.startsWith("#")) {
      e.preventDefault();
      ref.current?.querySelector(`[id="${href.slice(1)}"]`)?.scrollIntoView({ block: "start" });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange} side size="lg" title={doc ? `Help: ${doc.title}` : "Help for this page"} description="Help for this page. Press F1 or ? to open it from anywhere.">
      {doc ? (
        <div ref={ref}>
          <div className="mb-3 flex justify-end">
            <Link
              to="/help/$section/$slug"
              params={{ section: doc.section, slug: doc.slug }}
              hash={anchor}
              onClick={() => onOpenChange(false)}
              className="inline-flex items-center gap-1 text-[12px] text-primary hover:underline"
            >
              Open in the Help Center <ExternalLink className="size-3" aria-hidden />
            </Link>
          </div>
          <article className="help-prose" onClick={onClick} dangerouslySetInnerHTML={{ __html: html }} />
        </div>
      ) : (
        <p className="text-[13px] text-muted-foreground">
          No article is bundled for this page.{" "}
          <Link to="/help" className="text-primary underline" onClick={() => onOpenChange(false)}>
            Browse the Help Center
          </Link>
          .
        </p>
      )}
    </Dialog>
  );
}

import { Marked, type Tokens } from "marked";

/**
 * Help Center content: Markdown files under docs/user-guide and
 * docs/api-reference, bundled at build time. Each file starts with front
 * matter (title, section, order, version, updated, summary).
 */
export type HelpSection = "user-guide" | "api-reference";

export interface HelpHeading {
  depth: number;
  text: string;
  id: string;
}

export interface HelpDoc {
  section: HelpSection;
  slug: string;
  title: string;
  order: number;
  version: string;
  updated: string;
  summary: string;
  body: string;
  headings: HelpHeading[];
  /** Plain text for search. */
  text: string;
}

export const sectionLabels: Record<HelpSection, string> = {
  "user-guide": "User guide",
  "api-reference": "API reference",
};

const sectionRank: Record<HelpSection, number> = { "user-guide": 0, "api-reference": 1 };

const rawDocs = import.meta.glob<string>(["../../../../docs/user-guide/*.md", "../../../../docs/api-reference/*.md"], {
  query: "?raw",
  import: "default",
  eager: true,
});

const images = import.meta.glob<string>("../../../../docs/user-guide/images/*.{png,svg,jpg,webp}", {
  query: "?url",
  import: "default",
  eager: true,
});

/** Parses "key: value" front matter between --- lines. */
export function parseFrontMatter(raw: string): { meta: Record<string, string>; body: string } {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(raw);
  if (!m) return { meta: {}, body: raw };
  const meta: Record<string, string> = {};
  for (const line of m[1]!.split(/\r?\n/)) {
    const i = line.indexOf(":");
    if (i > 0) meta[line.slice(0, i).trim()] = line.slice(i + 1).trim().replace(/^["']|["']$/g, "");
  }
  return { meta, body: raw.slice(m[0].length) };
}

/** GitHub-style heading anchors. */
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/<[^>]*>/g, "")
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .trim()
    .replace(/\s+/g, "-");
}

function plain(md: string): string {
  return md
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, " ")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[#>*_`|-]+/g, " ")
    .replace(/\s+/g, " ");
}

export function buildDoc(path: string, raw: string): HelpDoc | null {
  const m = /docs\/(user-guide|api-reference)\/([\w-]+)\.md$/.exec(path);
  if (!m) return null;
  const { meta, body } = parseFrontMatter(raw);
  const headings: HelpHeading[] = [];
  const seen = new Map<string, number>();
  for (const line of body.split(/\r?\n/)) {
    const h = /^(#{1,4})\s+(.+?)\s*#*\s*$/.exec(line);
    if (!h) continue;
    let id = slugify(h[2]!);
    const n = seen.get(id) ?? 0;
    seen.set(id, n + 1);
    if (n > 0) id = `${id}-${n}`;
    headings.push({ depth: h[1]!.length, text: h[2]!.replace(/`/g, ""), id });
  }
  return {
    section: m[1] as HelpSection,
    slug: m[2]!,
    title: meta.title ?? headings[0]?.text ?? m[2]!,
    order: Number(meta.order ?? 99),
    version: meta.version ?? "",
    updated: meta.updated ?? "",
    summary: meta.summary ?? "",
    body,
    headings,
    text: plain(body),
  };
}

export const helpDocs: HelpDoc[] = Object.entries(rawDocs)
  .map(([path, raw]) => buildDoc(path, raw))
  .filter((d): d is HelpDoc => d !== null)
  .sort((a, b) => sectionRank[a.section] - sectionRank[b.section] || a.order - b.order || a.title.localeCompare(b.title));

export function findDoc(section: string, slug: string): HelpDoc | undefined {
  return helpDocs.find((d) => d.section === section && d.slug === slug);
}

export function imageURL(src: string): string | undefined {
  const name = src.replace(/^\.?\/?images\//, "").replace(/^\.\.\/user-guide\/images\//, "");
  const hit = Object.entries(images).find(([p]) => p.endsWith("/images/" + name));
  return hit?.[1];
}

const escapeHtml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/**
 * Renders a document to HTML. Raw HTML in Markdown is escaped (content is
 * trusted, but the renderer never emits author-supplied markup), links to
 * other .md files become Help Center routes, images resolve to bundled
 * assets, and external links open in a new tab.
 */
export function renderDoc(doc: Pick<HelpDoc, "section" | "body" | "headings">): string {
  const ids = [...doc.headings];
  const md = new Marked({ gfm: true, breaks: false });
  md.use({
    renderer: {
      html(t: Tokens.HTML | Tokens.Tag) {
        return escapeHtml(t.text);
      },
      heading(t: Tokens.Heading) {
        const text = this.parser.parseInline(t.tokens);
        const h = ids.shift();
        const id = h?.id ?? slugify(t.text);
        return `<h${t.depth} id="${escapeHtml(id)}"><a class="help-anchor" href="#${escapeHtml(id)}" aria-hidden="true" tabindex="-1">#</a>${text}</h${t.depth}>\n`;
      },
      link(t: Tokens.Link) {
        const text = this.parser.parseInline(t.tokens);
        let href = t.href ?? "";
        const title = t.title ? ` title="${escapeHtml(t.title)}"` : "";
        const rel = /^(\.\.\/)?(user-guide|api-reference)?\/?([\w-]+)\.md(#[\w-]+)?$/.exec(href);
        if (rel) {
          const section = rel[2] ?? doc.section;
          href = `/help/${section}/${rel[3]}${rel[4] ?? ""}`;
          return `<a href="${escapeHtml(href)}" data-help-link="true"${title}>${text}</a>`;
        }
        if (/^https?:\/\//.test(href)) {
          return `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer"${title}>${text}</a>`;
        }
        if (href.startsWith("#") || href.startsWith("/")) return `<a href="${escapeHtml(href)}"${title}>${text}</a>`;
        return text; // unsupported scheme (javascript:, data:, …)
      },
      image(t: Tokens.Image) {
        const url = imageURL(t.href ?? "");
        if (!url) return `<span class="help-missing-image">[missing image: ${escapeHtml(t.href ?? "")}]</span>`;
        const cap = t.title || t.text;
        return `<figure><img src="${escapeHtml(url)}" alt="${escapeHtml(t.text)}" loading="lazy" />${cap ? `<figcaption>${escapeHtml(cap)}</figcaption>` : ""}</figure>`;
      },
      table(t: Tokens.Table) {
        const head = t.header.map((c) => `<th${c.align ? ` style="text-align:${c.align}"` : ""}>${this.parser.parseInline(c.tokens)}</th>`).join("");
        const rows = t.rows
          .map((r) => `<tr>${r.map((c) => `<td${c.align ? ` style="text-align:${c.align}"` : ""}>${this.parser.parseInline(c.tokens)}</td>`).join("")}</tr>`)
          .join("");
        return `<div class="help-table"><table><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table></div>`;
      },
    },
  });
  return md.parse(doc.body, { async: false }) as string;
}

export interface SearchHit {
  doc: HelpDoc;
  heading?: HelpHeading;
  snippet: string;
  score: number;
}

/** Simple full-text search over titles, headings and text. */
export function searchDocs(query: string, docs: HelpDoc[] = helpDocs, limit = 30): SearchHit[] {
  const terms = query.toLowerCase().split(/\s+/).filter((t) => t.length > 1);
  if (!terms.length) return [];
  const hits: SearchHit[] = [];
  for (const doc of docs) {
    const text = doc.text.toLowerCase();
    if (!terms.every((t) => text.includes(t) || doc.title.toLowerCase().includes(t))) continue;
    let score = 0;
    for (const t of terms) {
      if (doc.title.toLowerCase().includes(t)) score += 10;
      score += Math.min(text.split(t).length - 1, 20);
    }
    const heading = doc.headings.find((h) => terms.some((t) => h.text.toLowerCase().includes(t)));
    if (heading) score += 5;
    const i = text.indexOf(terms[0]!);
    const start = Math.max(0, i - 60);
    const snippet = (start > 0 ? "…" : "") + doc.text.slice(start, start + 180).trim() + "…";
    hits.push({ doc, heading, snippet, score });
  }
  return hits.sort((a, b) => b.score - a.score).slice(0, limit);
}

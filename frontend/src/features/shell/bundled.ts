/**
 * Files bundled at build time so the shell works offline: CHANGELOG.md for
 * "What's new", NOTICE for About. A missing file
 * yields an empty string (the glob simply matches nothing). The patterns
 * carry a character class because a glob without wildcards outside the
 * project root does not resolve.
 */
const changelogFiles = import.meta.glob<string>("../../../../CHANGELO[G].md", { query: "?raw", import: "default", eager: true });
const noticeFiles = import.meta.glob<string>("../../../../NOTIC[E]", { query: "?raw", import: "default", eager: true });

const first = (m: Record<string, string>) => Object.values(m)[0] ?? "";

export const changelogText = first(changelogFiles);
export const noticeText = first(noticeFiles);

export interface ChangelogSection {
  /** "2.2.0" or "Unreleased". */
  version: string;
  date: string;
  body: string;
}

/** Splits a Keep-a-Changelog file into its "## [x.y.z] — date" sections. */
export function parseChangelog(text: string): ChangelogSection[] {
  const out: ChangelogSection[] = [];
  const re = /^## \[([^\]]+)\](?:\s*[—–-]\s*(\S+))?.*$/gm;
  const heads = [...text.matchAll(re)];
  heads.forEach((m, i) => {
    const start = m.index! + m[0].length;
    const end = i + 1 < heads.length ? heads[i + 1]!.index! : text.length;
    out.push({ version: m[1]!, date: m[2] ?? "", body: text.slice(start, end).trim() });
  });
  return out;
}

/**
 * The section for a version. A pre-release (2.3.0-rc.1) or dev build shows
 * "Unreleased" when it has content, else the newest release.
 */
export function changelogFor(version: string, sections: ChangelogSection[] = parseChangelog(changelogText)): ChangelogSection | undefined {
  const v = version.replace(/^v/, "");
  const exact = sections.find((s) => s.version === v);
  if (exact) return exact;
  const unreleased = sections.find((s) => s.version.toLowerCase() === "unreleased");
  if (unreleased?.body) return unreleased;
  return sections.find((s) => s.version.toLowerCase() !== "unreleased");
}

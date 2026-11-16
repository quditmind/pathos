import { describe, expect, it } from "vitest";
import { buildDoc, parseFrontMatter, renderDoc, searchDocs, slugify } from "./content";

const sample = `---
title: Importing repositories
section: user-guide
order: 3
version: "1.0"
updated: 2026-11-17
summary: How to import.
---
# Importing repositories

## Local PC import

Upload a **ZIP** file. See [Imports API](../api-reference/imports.md#start-an-import) and [history](import-history.md).

<script>alert(1)</script>

[bad](javascript:alert(1)) and [site](https://example.com)

| Field | Meaning |
|---|---|
| Repository ID | QD-REPO-000042 |

## Local PC import
`;

describe("help content", () => {
  it("parses front matter", () => {
    const { meta, body } = parseFrontMatter(sample);
    expect(meta.title).toBe("Importing repositories");
    expect(meta.version).toBe("1.0");
    expect(body.startsWith("# Importing")).toBe(true);
  });

  it("builds headings with unique anchors", () => {
    const doc = buildDoc("../../../../docs/user-guide/repository-import.md", sample)!;
    expect(doc.section).toBe("user-guide");
    expect(doc.slug).toBe("repository-import");
    expect(doc.headings.map((h) => h.id)).toEqual(["importing-repositories", "local-pc-import", "local-pc-import-1"]);
    expect(slugify("Start an import (Git)")).toBe("start-an-import-git");
  });

  it("renders safely and rewrites links", () => {
    const doc = buildDoc("x/docs/user-guide/repository-import.md", sample)!;
    const html = renderDoc(doc);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("javascript:");
    expect(html).toContain('href="/help/api-reference/imports#start-an-import"');
    expect(html).toContain('href="/help/user-guide/import-history"');
    expect(html).toContain('target="_blank" rel="noopener noreferrer"');
    expect(html).toContain("<table>");
    expect(html).toContain('id="local-pc-import-1"');
  });

  it("searches titles and text", () => {
    const doc = buildDoc("x/docs/user-guide/repository-import.md", sample)!;
    const hits = searchDocs("zip import", [doc]);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.heading?.text).toBe("Importing repositories");
    expect(searchDocs("kubernetes", [doc])).toHaveLength(0);
  });
});

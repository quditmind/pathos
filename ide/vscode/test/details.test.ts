import { describe, expect, it } from "vitest";
import { buildDetailsHtml, escapeHtml, safeHttpUrl } from "../src/details";
import type { Finding } from "../src/types";

const evil = `<script>alert("x")</script><img src=x onerror='y'>\`&`;

function finding(p: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    repository_id: "r1",
    title: evil,
    description: evil,
    severity: "high",
    status: "open",
    rule_id: evil,
    cwe: [evil],
    scanner_keys: [evil],
    file_path: `src/${evil}.ts`,
    start_line: 3,
    package_name: evil,
    fixed_version: evil,
    snippet: evil,
    risk_score: 77,
    ...p,
  };
}

describe("escapeHtml", () => {
  it("escapes all HTML-significant characters", () => {
    expect(escapeHtml(`<a href="x" onclick='y'>&\`</a>`)).toBe("&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&#96;&lt;/a&gt;");
    expect(escapeHtml(null)).toBe("");
    expect(escapeHtml(5)).toBe("5");
  });
});

describe("safeHttpUrl", () => {
  it("allows only http(s)", () => {
    expect(safeHttpUrl("https://p.example.com/findings?status=all&finding=1")).toBe("https://p.example.com/findings?status=all&finding=1");
    expect(safeHttpUrl("javascript:alert(1)")).toBeNull();
    expect(safeHttpUrl("command:pathos.refresh")).toBeNull();
    expect(safeHttpUrl("not a url")).toBeNull();
  });
});

describe("buildDetailsHtml", () => {
  const html = buildDetailsHtml(finding(), { webUrl: "https://p.example.com/findings?status=all&finding=f1", nonce: "abc123" });

  it("contains no unescaped scanner markup", () => {
    expect(html).not.toContain("<script");
    expect(html).not.toContain("<img");
    expect(html).not.toMatch(/onerror=['"]/);
    expect(html).toContain("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;");
  });

  it("has a strict CSP with a nonce for the only style", () => {
    expect(html).toContain(`content="default-src 'none'; style-src 'nonce-abc123'; img-src 'none'; script-src 'none'`);
    expect(html.match(/<style/g)).toHaveLength(1);
    expect(html).toContain('<style nonce="abc123">');
    expect(html).not.toMatch(/<link|<iframe|src="http/);
  });

  it("shows the main fields and the PATHOS link", () => {
    expect(html).toContain("77 / 100");
    expect(html).toContain('href="https://p.example.com/findings?status=all&amp;finding=f1"');
    expect(html).toContain("Remediation");
    expect(html).toContain("Scanner");
  });

  it("omits the link for non-http URLs and handles missing fields", () => {
    const h = buildDetailsHtml(
      { id: "x", repository_id: "r", title: "", severity: "info", status: "open" },
      { webUrl: "javascript:alert(1)", nonce: "n" },
    );
    expect(h).not.toContain("javascript:");
    expect(h).toContain("Untitled finding");
    expect(h).toContain("not scored");
  });

  it("escapes the nonce", () => {
    const h = buildDetailsHtml(finding(), { webUrl: "https://p", nonce: `"><script>` });
    expect(h).not.toContain(`"><script>`);
  });
});

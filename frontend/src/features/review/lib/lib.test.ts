import { describe, expect, it } from "vitest";
import { findReferences, findSymbols, highlightLine, highlightLines } from "./highlight";
import { diffLines, hunks } from "./diff";
import { buildVector, parseVector, score31, severityForScore } from "./cvss";

describe("highlight", () => {
  it("tokenizes keywords, strings, comments and calls", () => {
    const { tokens } = highlightLine(`  return db.query("SELECT 1") // run`, "javascript");
    expect(tokens.find((t) => t.kind === "kw")?.text).toBe("return");
    expect(tokens.find((t) => t.kind === "str")?.text).toBe(`"SELECT 1"`);
    expect(tokens.find((t) => t.kind === "fn")?.text).toBe("query");
    expect(tokens.at(-1)).toEqual({ kind: "com", text: "// run" });
    expect(tokens.map((t) => t.text).join("")).toBe(`  return db.query("SELECT 1") // run`);
  });
  it("carries block comments and triple-quoted strings across lines", () => {
    const js = highlightLines(["a /* start", "middle", "end */ b"], "javascript");
    expect(js[1]).toEqual([{ kind: "com", text: "middle" }]);
    expect(js[2]![0]).toEqual({ kind: "com", text: "end */" });
    const py = highlightLines(['x = """doc', "still doc", 'end""" + y'], "python");
    expect(py[1]).toEqual([{ kind: "str", text: "still doc" }]);
  });
  it("keeps identifiers as separate tokens", () => {
    const { tokens } = highlightLine("  sql = a + b", "python");
    expect(tokens.filter((t) => t.kind === "plain" && /^\w+$/.test(t.text)).map((t) => t.text)).toEqual(["sql", "a", "b"]);
  });
  it("never turns code into markup", () => {
    const line = `<img src=x onerror=alert(1)>`;
    expect(highlightLine(line, "html").tokens.map((t) => t.text).join("")).toBe(line);
  });
  it("finds symbols and references", () => {
    const lines = ["func (s *Service) Load(ctx context.Context) error {", "def handler(request):", "  x = handler(1)", "function search(q) {", "const run = async (x) => x"];
    expect(findSymbols(lines).map((s) => s.name)).toEqual(["Load", "handler", "search", "run"]);
    expect(findReferences(lines, "handler")).toEqual([2, 3]);
    expect(findReferences(lines, "a.b")).toEqual([]);
  });
});

describe("diffLines", () => {
  it("produces an edit script", () => {
    const d = diffLines(["a", "b", "c", "d"], ["a", "x", "c", "d", "e"])!;
    expect(d.filter((l) => l.op !== "equal")).toEqual([
      { op: "delete", a: 2, text: "b" },
      { op: "insert", b: 2, text: "x" },
      { op: "insert", b: 5, text: "e" },
    ]);
    expect(d.filter((l) => l.op === "equal").map((l) => l.text)).toEqual(["a", "c", "d"]);
  });
  it("handles empty inputs and gives up past the limit", () => {
    expect(diffLines([], ["a"])).toEqual([{ op: "insert", b: 1, text: "a" }]);
    expect(diffLines(["a"], [])).toEqual([{ op: "delete", a: 1, text: "a" }]);
    expect(diffLines(["a", "b"], ["c", "d"], 1)).toBeNull();
  });
  it("collapses unchanged regions", () => {
    const a = Array.from({ length: 30 }, (_, i) => `l${i}`);
    const b = [...a];
    b[15] = "changed";
    const h = hunks(diffLines(a, b)!, 2);
    expect(h[0]).toBeNull();
    expect(h.filter(Boolean)).toHaveLength(6);
  });
});

describe("cvss", () => {
  it("scores CVSS 3.1 like the API", () => {
    expect(score31(parseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")!.metrics)).toBe(9.8);
    expect(score31(parseVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N")!.metrics)).toBe(8.1);
    expect(score31(parseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")!.metrics)).toBe(6.1);
    expect(score31({ AV: "N" })).toBeNull();
  });
  it("builds vectors only when complete", () => {
    expect(buildVector("4.0", { AV: "N" })).toBeNull();
    const m = { AV: "N", AC: "L", AT: "N", PR: "N", UI: "N", VC: "H", VI: "H", VA: "H", SC: "N", SI: "N", SA: "N" };
    expect(buildVector("4.0", m)).toBe("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    expect(parseVector("bogus")).toBeNull();
    expect(severityForScore(7)).toBe("high");
  });
});

import { describe, expect, it } from "vitest";
import { createTar, normalizeTarPath, paxRecord, tarSize } from "./tar";
import { readBlob } from "./sha256";

const dec = new TextDecoder();

function str(b: Uint8Array, off: number, len: number) {
  const s = b.subarray(off, off + len);
  const end = s.indexOf(0);
  return dec.decode(end >= 0 ? s.subarray(0, end) : s);
}

/** Small reader for the tests: ustar headers + PAX path/size records, checksums verified. */
function parseTar(b: Uint8Array) {
  const out: { path: string; content: string; mode: number; mtime: number }[] = [];
  let off = 0;
  let pax: Record<string, string> = {};
  while (off + 512 <= b.length) {
    const h = b.subarray(off, off + 512);
    if (h.every((x) => x === 0)) break;
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : h[i]!;
    expect(parseInt(str(h, 148, 8).trim(), 8)).toBe(sum);
    expect(str(h, 257, 6)).toBe("ustar");
    const type = String.fromCharCode(h[156]!);
    let size = parseInt(str(h, 124, 12), 8);
    const body = b.subarray(off + 512, off + 512 + size);
    off += 512 + Math.ceil(size / 512) * 512;
    if (type === "x") {
      let rest = body;
      pax = {};
      while (rest.length) {
        const sp = rest.indexOf(0x20);
        const len = parseInt(dec.decode(rest.subarray(0, sp)), 10);
        const rec = dec.decode(rest.subarray(sp + 1, len - 1));
        expect(rest[len - 1]).toBe(0x0a);
        const eq = rec.indexOf("=");
        pax[rec.slice(0, eq)] = rec.slice(eq + 1);
        rest = rest.subarray(len);
      }
      continue;
    }
    const prefix = str(h, 345, 155);
    let path = prefix ? `${prefix}/${str(h, 0, 100)}` : str(h, 0, 100);
    if (pax.path) path = pax.path;
    if (pax.size) size = Number(pax.size);
    out.push({ path, content: dec.decode(body), mode: parseInt(str(h, 100, 8), 8), mtime: parseInt(str(h, 136, 12), 8) });
    pax = {};
  }
  return out;
}

describe("tar writer", () => {
  it("round-trips files with ustar headers", async () => {
    const tar = createTar([
      { path: "repo/README.md", data: new Blob(["hello\n"]), mtime: 1_700_000_000_000 },
      { path: "repo/src/main.go", data: new Blob(["package main\n".repeat(100)]) },
      { path: "repo/empty", data: new Blob([]) },
    ]);
    expect(tar.size % 512).toBe(0);
    const entries = parseTar(await readBlob(tar));
    expect(entries.map((e) => e.path)).toEqual(["repo/README.md", "repo/src/main.go", "repo/empty"]);
    expect(entries[0]!.content).toBe("hello\n");
    expect(entries[0]!.mtime).toBe(1_700_000_000);
    expect(entries[0]!.mode).toBe(0o644);
    expect(entries[1]!.content).toBe("package main\n".repeat(100));
    expect(entries[2]!.content).toBe("");
    expect(
      tarSize([
        { path: "repo/README.md", size: 6 },
        { path: "repo/src/main.go", size: 1300 },
        { path: "repo/empty", size: 0 },
      ]),
    ).toBe(tar.size);
  });

  it("uses the ustar prefix or a PAX header for long and non-ASCII names", async () => {
    const splittable = `${"d".repeat(120)}/${"f".repeat(90)}.txt`;
    const tooLong = `${"x".repeat(60)}/${"y".repeat(150)}.go`;
    const unicode = "repo/dokumentation/überblick-日本.md";
    const tar = createTar([
      { path: splittable, data: new Blob(["a"]) },
      { path: tooLong, data: new Blob(["b"]) },
      { path: unicode, data: new Blob(["c"]) },
    ]);
    const entries = parseTar(await readBlob(tar));
    expect(entries.map((e) => e.path)).toEqual([splittable, tooLong, unicode]);
    expect(entries.map((e) => e.content)).toEqual(["a", "b", "c"]);
  });

  it("normalises paths", () => {
    expect(normalizeTarPath("./a\\b//c/./d")).toBe("a/b/c/d");
    expect(normalizeTarPath("/abs/x")).toBe("abs/x");
  });

  it("computes self-describing PAX record lengths", () => {
    const bytes = paxRecord("path", "a".repeat(95));
    expect(dec.decode(bytes).startsWith(`${bytes.length} path=`)).toBe(true);
    expect(bytes.length).toBe(105);
  });
});

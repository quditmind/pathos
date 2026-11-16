import { describe, expect, it } from "vitest";
import { hashBlob, Sha256, sha256Hex, toHex } from "./sha256";

const enc = new TextEncoder();
const vectors: [string, string][] = [
  ["", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
  ["abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
  ["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"],
  [
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
  ],
];

describe("Sha256 (incremental)", () => {
  it.each(vectors)("hashes %j", (input, want) => {
    expect(toHex(new Sha256().update(enc.encode(input)).digest())).toBe(want);
  });

  it("gives the same result for any chunking", () => {
    const data = enc.encode(vectors[3]![0].repeat(37));
    const whole = toHex(new Sha256().update(data).digest());
    for (const step of [1, 3, 63, 64, 65, 200]) {
      const h = new Sha256();
      for (let i = 0; i < data.length; i += step) h.update(data.subarray(i, i + step));
      expect(toHex(h.digest())).toBe(whole);
    }
  });

  it("hashes one million 'a' in pieces", () => {
    const h = new Sha256();
    const piece = new Uint8Array(1000).fill(0x61);
    for (let i = 0; i < 1000; i++) h.update(piece);
    expect(toHex(h.digest())).toBe("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  });

  it("refuses reuse after digest", () => {
    const h = new Sha256();
    h.digest();
    expect(() => h.update(new Uint8Array(1))).toThrow();
  });
});

describe("hash helpers", () => {
  it("sha256Hex matches the vectors", async () => {
    expect(await sha256Hex(enc.encode("abc"))).toBe(vectors[1]![1]);
  });

  it("hashBlob streams large blobs incrementally with progress", async () => {
    const data = enc.encode(vectors[2]![0]);
    const progress: number[] = [];
    const hex = await hashBlob(new Blob([data]), { threshold: 0, onProgress: (n) => progress.push(n) });
    expect(hex).toBe(vectors[2]![1]);
    expect(progress.at(-1)).toBe(data.length);
  });
});

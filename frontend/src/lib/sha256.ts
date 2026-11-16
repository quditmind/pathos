// SHA-256 helpers. WebCrypto cannot hash incrementally, so files larger than
// STREAM_THRESHOLD are hashed with a small incremental implementation
// (FIPS 180-4) reading the file in slices; smaller inputs use crypto.subtle.

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** Incremental SHA-256: update() any number of times, then digest() once. */
export class Sha256 {
  private h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  private w = new Uint32Array(64);
  private buf = new Uint8Array(64);
  private bufLen = 0;
  private bytes = 0;
  private done = false;

  update(data: Uint8Array): this {
    if (this.done) throw new Error("sha256: update after digest");
    this.bytes += data.length;
    let i = 0;
    if (this.bufLen > 0) {
      const take = Math.min(64 - this.bufLen, data.length);
      this.buf.set(data.subarray(0, take), this.bufLen);
      this.bufLen += take;
      i = take;
      if (this.bufLen < 64) return this;
      this.block(this.buf, 0);
      this.bufLen = 0;
    }
    for (; i + 64 <= data.length; i += 64) this.block(data, i);
    if (i < data.length) {
      this.buf.set(data.subarray(i), 0);
      this.bufLen = data.length - i;
    }
    return this;
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("sha256: digest called twice");
    this.done = true;
    const bitLen = this.bytes * 8;
    const pad = new Uint8Array(this.bufLen < 56 ? 64 : 128);
    pad.set(this.buf.subarray(0, this.bufLen));
    pad[this.bufLen] = 0x80;
    const dv = new DataView(pad.buffer);
    // 64-bit big-endian length; JS numbers are exact up to 2^53.
    dv.setUint32(pad.length - 8, Math.floor(bitLen / 0x100000000));
    dv.setUint32(pad.length - 4, bitLen >>> 0);
    for (let off = 0; off < pad.length; off += 64) this.block(pad, off);
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let j = 0; j < 8; j++) odv.setUint32(j * 4, this.h[j]!);
    return out;
  }

  private block(p: Uint8Array, off: number) {
    const w = this.w;
    for (let t = 0; t < 16; t++) {
      const j = off + t * 4;
      w[t] = ((p[j]! << 24) | (p[j + 1]! << 16) | (p[j + 2]! << 8) | p[j + 3]!) >>> 0;
    }
    for (let t = 16; t < 64; t++) {
      const a = w[t - 15]!;
      const b = w[t - 2]!;
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
      const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
      w[t] = (w[t - 16]! + s0 + w[t - 7]! + s1) >>> 0;
    }
    const h = this.h;
    let a = h[0]!, b = h[1]!, c = h[2]!, d = h[3]!, e = h[4]!, f = h[5]!, g = h[6]!, hh = h[7]!;
    for (let t = 0; t < 64; t++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[t]! + w[t]!) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0]! + a) >>> 0;
    h[1] = (h[1]! + b) >>> 0;
    h[2] = (h[2]! + c) >>> 0;
    h[3] = (h[3]! + d) >>> 0;
    h[4] = (h[4]! + e) >>> 0;
    h[5] = (h[5]! + f) >>> 0;
    h[6] = (h[6]! + g) >>> 0;
    h[7] = (h[7]! + hh) >>> 0;
  }
}

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function subtle(): SubtleCrypto | undefined {
  return globalThis.crypto?.subtle;
}

/** Hex SHA-256 of an in-memory buffer (WebCrypto when available). */
export async function sha256Hex(data: Uint8Array | ArrayBuffer): Promise<string> {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const s = subtle();
  if (s) {
    try {
      return toHex(new Uint8Array(await s.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>)));
    } catch {
      /* fall through (e.g. insecure context) */
    }
  }
  return toHex(new Sha256().update(bytes).digest());
}

/** Files above this size are hashed incrementally instead of loading them whole. */
export const STREAM_THRESHOLD = 512 * 1024 * 1024;
const SLICE = 8 * 1024 * 1024;

export async function readBlob(blob: Blob): Promise<Uint8Array> {
  if (typeof blob.arrayBuffer === "function") return new Uint8Array(await blob.arrayBuffer());
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(new Uint8Array(r.result as ArrayBuffer));
    r.onerror = () => reject(r.error ?? new Error("read failed"));
    r.readAsArrayBuffer(blob);
  });
}

/**
 * Hex SHA-256 of a Blob/File. Large files are read in 8 MiB slices so memory
 * stays bounded; onProgress receives the number of bytes hashed.
 */
export async function hashBlob(
  blob: Blob,
  opts: { onProgress?: (done: number) => void; signal?: AbortSignal; threshold?: number } = {},
): Promise<string> {
  const threshold = opts.threshold ?? STREAM_THRESHOLD;
  if (blob.size <= threshold && subtle()) {
    const hex = await sha256Hex(await readBlob(blob));
    opts.onProgress?.(blob.size);
    return hex;
  }
  const h = new Sha256();
  for (let off = 0; off < blob.size; off += SLICE) {
    if (opts.signal?.aborted) throw new DOMException("Aborted", "AbortError");
    h.update(await readBlob(blob.slice(off, off + SLICE)));
    opts.onProgress?.(Math.min(blob.size, off + SLICE));
  }
  return toHex(h.digest());
}

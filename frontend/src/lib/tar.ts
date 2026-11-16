// Minimal POSIX tar (ustar + PAX extended headers) writer used to pack
// folder uploads in the browser. File contents are never copied: the result
// is a Blob composed of header blocks and the original File slices.

export interface TarEntry {
  /** Relative path with "/" separators, e.g. "my-repo/src/main.go". */
  path: string;
  data: Blob;
  /** Modification time in milliseconds since the epoch. */
  mtime?: number;
  mode?: number;
}

const BLOCK = 512;
const enc = new TextEncoder();

function utf8(s: string) {
  return enc.encode(s);
}

function writeString(buf: Uint8Array, off: number, len: number, s: string | Uint8Array) {
  const b = typeof s === "string" ? utf8(s) : s;
  buf.set(b.subarray(0, len), off);
}

function writeOctal(buf: Uint8Array, off: number, len: number, value: number) {
  // len-1 octal digits followed by NUL.
  const s = Math.floor(value).toString(8).padStart(len - 1, "0");
  writeString(buf, off, len - 1, s);
  buf[off + len - 1] = 0;
}

/** Normalises a browser-provided relative path. */
export function normalizeTarPath(p: string): string {
  return p
    .replace(/\\/g, "/")
    .split("/")
    .filter((seg) => seg !== "" && seg !== ".")
    .join("/");
}

function isAscii(s: string) {
  return /^[\x20-\x7e]*$/.test(s);
}

/** Splits a long ASCII path into ustar prefix (≤155) and name (≤100), or null. */
function splitUstar(path: string): { prefix: string; name: string } | null {
  for (let i = path.length - 1; i > 0; i--) {
    if (path[i] !== "/") continue;
    const prefix = path.slice(0, i);
    const name = path.slice(i + 1);
    if (prefix.length <= 155 && name.length <= 100 && name.length > 0) return { prefix, name };
  }
  return null;
}

/** One PAX record: "<len> <key>=<value>\n" where len counts the whole record. */
export function paxRecord(key: string, value: string): Uint8Array {
  const body = utf8(` ${key}=${value}\n`);
  let len = body.length + 1;
  while (String(len).length + body.length !== len) len = String(len).length + body.length;
  return utf8(`${len} ${key}=${value}\n`);
}

const MAX_OCTAL_SIZE = 0o77777777777; // 8 GiB - 1

function header(opts: { name: string; prefix?: string; size: number; mtime: number; mode: number; type: "0" | "x" }): Uint8Array {
  const h = new Uint8Array(BLOCK);
  writeString(h, 0, 100, opts.name);
  writeOctal(h, 100, 8, opts.mode);
  writeOctal(h, 108, 8, 0); // uid
  writeOctal(h, 116, 8, 0); // gid
  writeOctal(h, 124, 12, Math.min(opts.size, MAX_OCTAL_SIZE));
  writeOctal(h, 136, 12, opts.mtime);
  h.fill(0x20, 148, 156); // checksum placeholder (spaces)
  h[156] = opts.type.charCodeAt(0);
  writeString(h, 257, 6, "ustar\0");
  writeString(h, 263, 2, "00");
  if (opts.prefix) writeString(h, 345, 155, opts.prefix);
  let sum = 0;
  for (const b of h) sum += b;
  // Six octal digits, NUL, space.
  writeString(h, 148, 6, sum.toString(8).padStart(6, "0"));
  h[154] = 0;
  h[155] = 0x20;
  return h;
}

function padding(size: number): Uint8Array<ArrayBuffer> | null {
  const rem = size % BLOCK;
  return rem === 0 ? null : new Uint8Array(BLOCK - rem);
}

/** Header blocks (PAX extended header when needed, then ustar) for one entry. */
export function entryHeaders(entry: { path: string; size: number; mtime?: number; mode?: number }): Uint8Array[] {
  const path = normalizeTarPath(entry.path);
  if (!path) throw new Error("tar: empty path");
  const mtime = Math.floor((entry.mtime ?? Date.now()) / 1000);
  const mode = entry.mode ?? 0o644;
  const out: Uint8Array[] = [];
  let name = path;
  let prefix: string | undefined;
  const pax: Uint8Array[] = [];

  if (!isAscii(path) || path.length > 100) {
    const split = isAscii(path) ? splitUstar(path) : null;
    if (split) {
      name = split.name;
      prefix = split.prefix;
    } else {
      pax.push(paxRecord("path", path));
      // Fallback name for readers without PAX support.
      const base = path.split("/").pop()!.replace(/[^\x20-\x7e]/g, "_");
      name = base.slice(-100) || "file";
    }
  }
  if (entry.size > MAX_OCTAL_SIZE) pax.push(paxRecord("size", String(entry.size)));

  if (pax.length) {
    const len = pax.reduce((n, r) => n + r.length, 0);
    const body = new Uint8Array(len);
    let o = 0;
    for (const r of pax) {
      body.set(r, o);
      o += r.length;
    }
    out.push(header({ name: `PaxHeader/${name}`.slice(0, 100), size: len, mtime, mode: 0o644, type: "x" }), body);
    const pad = padding(len);
    if (pad) out.push(pad);
  }
  out.push(header({ name, prefix, size: entry.size, mtime, mode, type: "0" }));
  return out;
}

/** Packs entries into a tar archive Blob (two zero blocks terminate it). */
export function createTar(entries: TarEntry[]): Blob {
  const parts: BlobPart[] = [];
  for (const e of entries) {
    for (const h of entryHeaders({ path: e.path, size: e.data.size, mtime: e.mtime, mode: e.mode })) parts.push(h as Uint8Array<ArrayBuffer>);
    parts.push(e.data);
    const pad = padding(e.data.size);
    if (pad) parts.push(pad as Uint8Array<ArrayBuffer>);
  }
  parts.push(new Uint8Array(BLOCK * 2));
  return new Blob(parts, { type: "application/x-tar" });
}

/** Archive size without building it (for limit checks). */
export function tarSize(entries: { path: string; size: number }[]): number {
  let n = BLOCK * 2;
  for (const e of entries) {
    n += entryHeaders({ path: e.path, size: e.size, mtime: 0 }).reduce((s, b) => s + b.length, 0);
    n += Math.ceil(e.size / BLOCK) * BLOCK;
  }
  return n;
}

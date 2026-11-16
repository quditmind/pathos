// Minimal ZIP (stored, no compression) writer for e2e fixtures.
export const strToU8 = (s: string) => new TextEncoder().encode(s);

function crc32(b: Uint8Array): number {
  let c, crc = 0xffffffff;
  for (let n = 0; n < b.length; n++) {
    c = (crc ^ b[n]) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function zipSync(files: Record<string, Uint8Array>): Uint8Array {
  const parts: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  for (const [name, data] of Object.entries(files)) {
    const nb = strToU8(name);
    const crc = crc32(data);
    const h = new DataView(new ArrayBuffer(30));
    h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint32(14, crc, true);
    h.setUint32(18, data.length, true); h.setUint32(22, data.length, true); h.setUint16(26, nb.length, true);
    const local = new Uint8Array([...new Uint8Array(h.buffer), ...nb, ...data]);
    const c = new DataView(new ArrayBuffer(46));
    c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true); c.setUint32(16, crc, true);
    c.setUint32(20, data.length, true); c.setUint32(24, data.length, true); c.setUint16(28, nb.length, true); c.setUint32(42, offset, true);
    central.push(new Uint8Array([...new Uint8Array(c.buffer), ...nb]));
    parts.push(local);
    offset += local.length;
  }
  const cd = central.reduce((a, b) => new Uint8Array([...a, ...b]), new Uint8Array());
  const e = new DataView(new ArrayBuffer(22));
  e.setUint32(0, 0x06054b50, true); e.setUint16(8, central.length, true); e.setUint16(10, central.length, true);
  e.setUint32(12, cd.length, true); e.setUint32(16, offset, true);
  return new Uint8Array([...parts.reduce((a, b) => new Uint8Array([...a, ...b]), new Uint8Array()), ...cd, ...new Uint8Array(e.buffer)]);
}

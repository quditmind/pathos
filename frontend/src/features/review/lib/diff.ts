// Line diff (Myers' O((N+M)D) algorithm) for comparing the scanned code
// with a later version.

export type DiffLine =
  | { op: "equal"; a: number; b: number; text: string }
  | { op: "delete"; a: number; text: string }
  | { op: "insert"; b: number; text: string };

/** Diffs two line arrays. Returns null when the edit distance exceeds maxD. */
export function diffLines(a: string[], b: string[], maxD = 4000): DiffLine[] | null {
  const n = a.length;
  const m = b.length;
  const max = Math.min(n + m, maxD);
  const off = max + 1;
  const v = new Int32Array(2 * max + 3);
  const trace: Int32Array[] = [];
  let found = -1;
  for (let d = 0; d <= max; d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[off + k - 1]! < v[off + k + 1]!) ? v[off + k + 1]! : v[off + k - 1]! + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x++;
        y++;
      }
      v[off + k] = x;
      if (x >= n && y >= m) {
        found = d;
        break;
      }
    }
    if (found >= 0) break;
  }
  if (found < 0) return null;
  // Backtrack.
  const out: DiffLine[] = [];
  let x = n;
  let y = m;
  for (let d = found; d > 0; d--) {
    const vd = trace[d]!;
    const k = x - y;
    const prevK = k === -d || (k !== d && vd[off + k - 1]! < vd[off + k + 1]!) ? k + 1 : k - 1;
    const prevX = vd[off + prevK]!;
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      x--;
      y--;
      out.push({ op: "equal", a: x + 1, b: y + 1, text: a[x]! });
    }
    if (x === prevX) {
      y--;
      out.push({ op: "insert", b: y + 1, text: b[y]! });
    } else {
      x--;
      out.push({ op: "delete", a: x + 1, text: a[x]! });
    }
  }
  while (x > 0 && y > 0) {
    x--;
    y--;
    out.push({ op: "equal", a: x + 1, b: y + 1, text: a[x]! });
  }
  return out.reverse();
}

/** Keeps changes with `context` unchanged lines around them; gaps become null. */
export function hunks(lines: DiffLine[], context = 3): (DiffLine | null)[] {
  const keep = new Array<boolean>(lines.length).fill(false);
  lines.forEach((l, i) => {
    if (l.op !== "equal") for (let j = Math.max(0, i - context); j <= Math.min(lines.length - 1, i + context); j++) keep[j] = true;
  });
  const out: (DiffLine | null)[] = [];
  let gap = false;
  lines.forEach((l, i) => {
    if (keep[i]) {
      out.push(l);
      gap = false;
    } else if (!gap) {
      out.push(null);
      gap = true;
    }
  });
  return out;
}

import type { LayoutEdge, LayoutNode, Placed } from "./layoutTypes";

/**
 * A fast layered layout for large graphs (ADR-005 measurement: ELK layered
 * needs seconds above a few hundred nodes, see docs/PERFORMANCE.md).
 *
 * Longest-path layering over the acyclic part, cycle members after it; nodes
 * ordered inside each layer by the barycentre of their predecessors (a few
 * sweeps); every container (trust boundary) gets its own horizontal band so
 * its box holds only its children. Roughly O((V + E) · sweeps).
 */
export const PAD = { top: 34, side: 16, bottom: 16 };
const COL_GAP = 64;
const ROW_GAP = 22;
const BAND_GAP = 40;

export function fastLayered(nodes: LayoutNode[], edges: LayoutEdge[], sweeps = 4): Map<string, Placed> {
  const leaves = nodes.filter((n) => !n.container);
  const ids = new Set(leaves.map((n) => n.id));
  const indeg = new Map<string, number>();
  for (const n of leaves) indeg.set(n.id, 0);
  const out = new Map<string, string[]>();
  const inc = new Map<string, string[]>();
  for (const e of edges) {
    if (!ids.has(e.source) || !ids.has(e.target) || e.source === e.target) continue;
    indeg.set(e.target, (indeg.get(e.target) ?? 0) + 1);
    let o = out.get(e.source);
    if (!o) out.set(e.source, (o = []));
    o.push(e.target);
    let i = inc.get(e.target);
    if (!i) inc.set(e.target, (i = []));
    i.push(e.source);
  }
  // Longest-path layering (Kahn's order).
  const layer = new Map<string, number>();
  const queue: string[] = [];
  for (const n of leaves) if (indeg.get(n.id) === 0) {
    queue.push(n.id);
    layer.set(n.id, 0);
  }
  const deg = new Map(indeg);
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i]!;
    const l = layer.get(id)!;
    for (const t of out.get(id) ?? []) {
      if ((layer.get(t) ?? -1) < l + 1) layer.set(t, l + 1);
      const d = deg.get(t)! - 1;
      deg.set(t, d);
      if (d === 0) queue.push(t);
    }
  }
  // Nodes in cycles: one layer after their furthest placed predecessor.
  let changed = true;
  while (changed) {
    changed = false;
    for (const n of leaves) {
      if (layer.has(n.id)) continue;
      const preds = (inc.get(n.id) ?? []).map((p) => layer.get(p)).filter((x): x is number => x !== undefined);
      layer.set(n.id, preds.length ? Math.max(...preds) + 1 : 0);
      changed = true;
    }
  }
  const nLayers = Math.max(0, ...layer.values()) + 1;

  // Bands: top-level nodes first, then one band per container (input order).
  const bandOf = (n: LayoutNode) => n.parent ?? "";
  const bands = ["", ...nodes.filter((n) => n.container).map((n) => n.id)];
  const cells = new Map<string, string[][]>(bands.map((b) => [b, Array.from({ length: nLayers }, () => [])]));
  const byId = new Map(leaves.map((n) => [n.id, n]));
  for (const n of leaves) {
    const b = cells.get(bandOf(n)) ?? cells.get("")!;
    b[layer.get(n.id)!]!.push(n.id);
  }

  // Barycentre ordering, sweeping left to right (predecessors) and back (successors).
  const order = new Map<string, number>();
  const setOrder = () => {
    for (const rows of cells.values()) for (const col of rows) col.forEach((id, i) => order.set(id, i));
  };
  setOrder();
  const bary = (id: string, nbrs: Map<string, string[]>) => {
    const ns = nbrs.get(id);
    if (!ns?.length) return order.get(id)!;
    let s = 0;
    for (const x of ns) s += order.get(x) ?? 0;
    return s / ns.length;
  };
  for (let s = 0; s < sweeps; s++) {
    const nbrs = s % 2 === 0 ? inc : out;
    for (const rows of cells.values()) {
      const cols = s % 2 === 0 ? rows : [...rows].reverse();
      for (const col of cols) {
        const keyed = col.map((id) => [id, bary(id, nbrs)] as const);
        keyed.sort((a, b) => a[1] - b[1]);
        keyed.forEach(([id], i) => {
          col[i] = id;
          order.set(id, i);
        });
      }
    }
  }

  // Coordinates: each band as tall as its fullest column.
  const result = new Map<string, Placed>();
  const colW = Math.max(200, ...leaves.map((n) => n.width)) + COL_GAP;
  let y0 = 0;
  for (const b of bands) {
    const rows = cells.get(b)!;
    const used = rows.some((c) => c.length);
    if (!used) {
      if (b) result.set(b, { x: 0, y: y0, width: 160, height: 60 });
      continue;
    }
    const inset = b ? PAD.top : 0;
    let bandH = 0;
    rows.forEach((col, l) => {
      let y = inset;
      for (const id of col) {
        const n = byId.get(id)!;
        result.set(id, { x: (b ? PAD.side : 0) + l * colW, y: b ? y : y0 + y, width: n.width, height: n.height });
        y += n.height + ROW_GAP;
      }
      bandH = Math.max(bandH, y - ROW_GAP);
    });
    if (b) {
      // Container: spans the columns it uses; children are relative to it.
      const first = rows.findIndex((c) => c.length);
      const last = rows.length - 1 - [...rows].reverse().findIndex((c) => c.length);
      const x = first * colW - PAD.side;
      for (const col of rows) for (const id of col) {
        const p = result.get(id)!;
        result.set(id, { ...p, x: p.x - first * colW });
      }
      const w = (last - first) * colW + (colW - COL_GAP) + 2 * PAD.side;
      const h = bandH + PAD.bottom;
      result.set(b, { x, y: y0, width: w, height: h });
      y0 += h + BAND_GAP;
    } else {
      y0 += bandH + BAND_GAP;
    }
  }
  return result;
}

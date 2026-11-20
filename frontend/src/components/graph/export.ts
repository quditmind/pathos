import { withGeneratedBy } from "@/lib/buildStamp";
import { getNodesBounds, getViewportForBounds, type Node } from "@xyflow/react";

/** File name stamp: pathos-<what>-<YYYYMMDD-HHMM>.<ext>, with the PATHOS version when known. */
export function exportFileName(what: string, ext: string, version?: string, now = new Date()): string {
  const p = (n: number) => String(n).padStart(2, "0");
  const ts = `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}`;
  const safe = what.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "graph";
  return `pathos${version ? `-${version.replace(/[^\w.-]/g, "")}` : ""}-${safe}-${ts}.${ext}`;
}

export function downloadUrl(url: string, name: string) {
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

/**
 * Renders the whole graph (not just the visible part) to PNG or SVG in the
 * browser, using the React Flow viewport element and html-to-image.
 */
export async function exportImage(root: HTMLElement, nodes: Node[], format: "png" | "svg", name: string) {
  const viewport = root.querySelector<HTMLElement>(".react-flow__viewport");
  if (!viewport || !nodes.length) throw new Error("Nothing to export");
  const { toPng, toSvg } = await import("html-to-image");
  const bounds = getNodesBounds(nodes);
  const width = Math.min(8000, Math.max(800, Math.ceil(bounds.width + 80)));
  const height = Math.min(8000, Math.max(500, Math.ceil(bounds.height + 80)));
  const vp = getViewportForBounds(bounds, width, height, 0.1, 2, 0.05);
  const bg = getComputedStyle(document.body).getPropertyValue("--surface").trim() || "#ffffff";
  const opts = {
    backgroundColor: bg,
    width,
    height,
    style: { width: `${width}px`, height: `${height}px`, transform: `translate(${vp.x}px, ${vp.y}px) scale(${vp.zoom})` },
    // Skip the controls and minimap (they are siblings, but be safe).
    filter: (el: HTMLElement) => !el.classList?.contains("react-flow__minimap") && !el.classList?.contains("react-flow__controls"),
  };
  const url = format === "png" ? await toPng(viewport, opts) : await toSvg(viewport, opts);
  downloadUrl(url, name);
}

/** Downloads JSON; an object gets a top-level "generated_by" version stamp. */
export function downloadJson(data: unknown, name: string) {
  const blob = new Blob([JSON.stringify(withGeneratedBy(data), null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  downloadUrl(url, name);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

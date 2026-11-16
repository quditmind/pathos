import type { CSSProperties } from "react";
import type { TagColor, TagPaletteColor } from "@/api/types";
import { chipColors, isHexColor } from "@/lib/color";
import { cn } from "@/lib/utils";

const colors: Record<TagPaletteColor, string> = {
  slate: "bg-slate-500/12 text-slate-700 dark:text-slate-300 ring-slate-500/25",
  blue: "bg-blue-500/12 text-blue-700 dark:text-blue-300 ring-blue-500/25",
  green: "bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 ring-emerald-500/25",
  amber: "bg-amber-500/15 text-amber-800 dark:text-amber-300 ring-amber-500/30",
  red: "bg-red-500/12 text-red-700 dark:text-red-300 ring-red-500/25",
  purple: "bg-violet-500/12 text-violet-700 dark:text-violet-300 ring-violet-500/25",
  teal: "bg-teal-500/12 text-teal-700 dark:text-teal-300 ring-teal-500/25",
  pink: "bg-pink-500/12 text-pink-700 dark:text-pink-300 ring-pink-500/25",
};

/** Representative swatch per palette name (for pickers). */
export const paletteSwatch: Record<TagPaletteColor, string> = {
  slate: "#64748b",
  blue: "#3b82f6",
  green: "#10b981",
  amber: "#f59e0b",
  red: "#ef4444",
  purple: "#8b5cf6",
  teal: "#14b8a6",
  pink: "#ec4899",
};

export const tagColorNames = Object.keys(colors) as TagPaletteColor[];

/**
 * Class name and inline style for a palette or hex colour. Hex colours get
 * a tinted background and a text colour with ≥ 4.5:1 contrast in each theme
 * (via --chip-fg / --chip-fg-dark).
 */
export function colorChipProps(color: TagColor | string): { className: string; style?: CSSProperties } {
  if (isHexColor(color)) {
    const c = chipColors(color.toLowerCase());
    return {
      className: "text-[var(--chip-fg)] dark:text-[var(--chip-fg-dark)] ring-[var(--chip-ring)]",
      style: { backgroundColor: c.background, "--chip-fg": c.fgLight, "--chip-fg-dark": c.fgDark, "--chip-ring": c.ring } as CSSProperties,
    };
  }
  return { className: colors[color as TagPaletteColor] ?? colors.slate };
}

export function TagChip({ name, category, color, className }: { name: string; category?: string; color: TagColor; className?: string }) {
  const c = colorChipProps(color);
  return (
    <span
      className={cn("inline-flex items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset", c.className, className)}
      style={c.style}
      title={category ? `${category}: ${name}` : name}
      data-color={color}
    >
      {category && <span className="opacity-70">{category}:</span>}
      {name}
    </span>
  );
}

const critTone: Record<string, string> = {
  critical: "bg-[var(--sev-critical)]/12 text-[var(--sev-critical)]",
  high: "bg-[var(--sev-high)]/12 text-[var(--sev-high)]",
  medium: "bg-[var(--sev-medium)]/15 text-[var(--sev-medium)]",
  low: "bg-[var(--sev-low)]/12 text-[var(--sev-low)]",
};

/** Criticality badge; a configured label/colour from the catalog overrides the defaults. */
export function CriticalityBadge({ value, label, color }: { value: string; label?: string; color?: string }) {
  if (color && isHexColor(color)) {
    const c = colorChipProps(color);
    return (
      <span className={cn("inline-flex rounded px-1.5 py-0.5 text-[11px] font-medium", c.className)} style={c.style}>
        {label || value}
      </span>
    );
  }
  return <span className={cn("inline-flex rounded px-1.5 py-0.5 text-[11px] font-medium capitalize", critTone[value])}>{label || value}</span>;
}

/** A small round swatch for asset / classification colours. Decorative unless labelled. */
export function ColorDot({ color, label, className }: { color: string; label?: string; className?: string }) {
  if (!color) return <span className={cn("inline-block size-2.5 shrink-0 rounded-full border border-dashed border-border", className)} aria-hidden={!label} aria-label={label} />;
  const bg = isHexColor(color) ? color : paletteSwatch[color as TagPaletteColor] ?? "var(--muted-foreground)";
  return (
    <span
      className={cn("inline-block size-2.5 shrink-0 rounded-full ring-1 ring-black/10 dark:ring-white/20", className)}
      style={{ backgroundColor: bg }}
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={!label}
    />
  );
}

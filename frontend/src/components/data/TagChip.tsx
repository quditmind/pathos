import type { TagColor } from "@/api/types";
import { cn } from "@/lib/utils";

const colors: Record<TagColor, string> = {
  slate: "bg-slate-500/12 text-slate-700 dark:text-slate-300 ring-slate-500/25",
  blue: "bg-blue-500/12 text-blue-700 dark:text-blue-300 ring-blue-500/25",
  green: "bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 ring-emerald-500/25",
  amber: "bg-amber-500/15 text-amber-800 dark:text-amber-300 ring-amber-500/30",
  red: "bg-red-500/12 text-red-700 dark:text-red-300 ring-red-500/25",
  purple: "bg-violet-500/12 text-violet-700 dark:text-violet-300 ring-violet-500/25",
  teal: "bg-teal-500/12 text-teal-700 dark:text-teal-300 ring-teal-500/25",
  pink: "bg-pink-500/12 text-pink-700 dark:text-pink-300 ring-pink-500/25",
};

export const tagColorNames = Object.keys(colors) as TagColor[];

export function TagChip({ name, category, color, className }: { name: string; category?: string; color: TagColor; className?: string }) {
  return (
    <span
      className={cn("inline-flex items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset", colors[color] ?? colors.slate, className)}
      title={category ? `${category}: ${name}` : name}
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

export function CriticalityBadge({ value }: { value: string }) {
  return <span className={cn("inline-flex rounded px-1.5 py-0.5 text-[11px] font-medium capitalize", critTone[value])}>{value}</span>;
}

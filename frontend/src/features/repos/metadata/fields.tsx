import { cloneElement, isValidElement, useId, type ReactElement, type ReactNode } from "react";
import type { BusinessUnit, Region } from "@/api/types";
import { cn } from "@/lib/utils";

/** Label + control + hint + error, wiring ids and aria attributes. */
export function FormField({
  label,
  required,
  error,
  hint,
  children,
  className,
}: {
  label: string;
  required?: boolean;
  error?: string;
  hint?: ReactNode;
  children: ReactElement<{ id?: string; "aria-invalid"?: boolean; "aria-describedby"?: string; "aria-required"?: boolean }>;
  className?: string;
}) {
  const auto = useId();
  const id = children.props.id ?? `f-${auto}`;
  const hintId = hint ? `${id}-hint` : undefined;
  const errId = error ? `${id}-err` : undefined;
  const describedBy = [hintId, errId].filter(Boolean).join(" ") || undefined;
  const control = isValidElement(children)
    ? cloneElement(children, { id, "aria-invalid": error ? true : undefined, "aria-describedby": describedBy, "aria-required": required || undefined })
    : children;
  return (
    <div className={className}>
      <label htmlFor={id} className="mb-1 block text-[12px] font-medium text-foreground">
        {label}
        {required && (
          <span className="ml-0.5 text-danger" aria-hidden>
            *
          </span>
        )}
      </label>
      {control}
      {hint && (
        <p id={hintId} className="mt-1 text-[11.5px] text-muted-foreground">
          {hint}
        </p>
      )}
      {error && (
        <p id={errId} className="mt-1 text-[12px] text-danger" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement> & { invalid?: boolean }) {
  const { className, invalid, ...rest } = props;
  return (
    <textarea
      rows={3}
      {...rest}
      className={cn(
        "w-full rounded-md border bg-surface px-2.5 py-1.5 text-[13px] text-foreground placeholder:text-muted-foreground focus-visible:outline-2 focus-visible:outline-ring disabled:opacity-60",
        invalid || props["aria-invalid"] ? "border-danger" : "border-border",
        className,
      )}
    />
  );
}

/** Business units in tree order with depth, for indented selects. */
export function buTree(units: BusinessUnit[]): { unit: BusinessUnit; depth: number }[] {
  const children = new Map<string | null, BusinessUnit[]>();
  const ids = new Set(units.map((u) => u.id));
  for (const u of units) {
    const parent = u.parent_id && ids.has(u.parent_id) ? u.parent_id : null;
    children.set(parent, [...(children.get(parent) ?? []), u]);
  }
  const out: { unit: BusinessUnit; depth: number }[] = [];
  const walk = (parent: string | null, depth: number) => {
    for (const u of (children.get(parent) ?? []).sort((a, b) => a.name.localeCompare(b.name))) {
      out.push({ unit: u, depth });
      walk(u.id, depth + 1);
    }
  };
  walk(null, 0);
  return out;
}

/** All descendants (not the unit itself) of a business unit. */
export function descendants(units: BusinessUnit[], rootId: string): { unit: BusinessUnit; depth: number }[] {
  const tree = buTree(units);
  const start = tree.findIndex((t) => t.unit.id === rootId);
  if (start < 0) return [];
  const base = tree[start]!.depth;
  const out: { unit: BusinessUnit; depth: number }[] = [];
  for (let i = start + 1; i < tree.length && tree[i]!.depth > base; i++) out.push({ unit: tree[i]!.unit, depth: tree[i]!.depth - base - 1 });
  return out;
}

export function countryName(regions: Region[] | undefined, id: string) {
  for (const r of regions ?? []) for (const c of r.countries) if (c.id === id) return { country: c, region: r };
  return null;
}

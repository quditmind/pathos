import type { ReactNode } from "react";
import { X } from "lucide-react";
import { Select } from "@/components/ui/primitives";
import { Button } from "@/components/ui/button";

export interface FilterOption {
  value: string;
  label: string;
}

export interface FilterDef {
  key: string;
  label: string;
  options: FilterOption[];
  /** Label of the empty option. Omit for filters that always have a value. */
  allLabel?: string;
  disabled?: boolean;
  disabledReason?: string;
}

/** A row of select filters bound to a values object. */
export function FilterBar({
  filters,
  values,
  onChange,
  onReset,
  trailing,
}: {
  filters: FilterDef[];
  values: Record<string, string | undefined>;
  onChange: (key: string, value: string | undefined) => void;
  onReset?: () => void;
  trailing?: ReactNode;
}) {
  const active = filters.some((f) => f.allLabel && values[f.key]);
  return (
    <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filters">
      {filters.map((f) => (
        <Select
          key={f.key}
          aria-label={f.label}
          title={f.disabled ? f.disabledReason : f.label}
          disabled={f.disabled}
          value={values[f.key] ?? ""}
          onChange={(e) => onChange(f.key, e.target.value || undefined)}
          className="max-w-48"
        >
          {f.allLabel && <option value="">{f.allLabel}</option>}
          {f.options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </Select>
      ))}
      {active && onReset && (
        <Button variant="ghost" size="sm" onClick={onReset}>
          <X /> Clear filters
        </Button>
      )}
      {trailing && <div className="ml-auto flex items-center gap-2">{trailing}</div>}
    </div>
  );
}

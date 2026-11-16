import { useEffect, useId, useState } from "react";
import { Check, X } from "lucide-react";
import { Input } from "@/components/ui/primitives";
import { isHexColor } from "@/lib/color";
import { cn } from "@/lib/utils";

export interface Swatch {
  value: string;
  label: string;
  /** CSS colour used to paint the swatch (defaults to value). */
  paint?: string;
}

/**
 * Swatch list plus a custom #rrggbb input. `value` is "" (none), a swatch
 * value (palette name or hex) or a custom hex colour.
 */
export function ColorPicker({
  value,
  onChange,
  swatches,
  allowNone,
  disabled,
  label,
  invalid,
}: {
  value: string;
  onChange: (v: string) => void;
  swatches: Swatch[];
  allowNone?: boolean;
  disabled?: boolean;
  label: string;
  invalid?: boolean;
}) {
  const id = useId();
  const [custom, setCustom] = useState(isHexColor(value) ? value : "");
  useEffect(() => {
    if (isHexColor(value)) setCustom(value);
  }, [value]);
  const customValid = custom === "" || isHexColor(custom);

  return (
    <div role="group" aria-label={label} className="space-y-2">
      <div className="flex flex-wrap items-center gap-1.5">
        {allowNone && (
          <button
            type="button"
            disabled={disabled}
            aria-pressed={value === ""}
            aria-label="No colour"
            title="No colour"
            onClick={() => onChange("")}
            className={cn(
              "flex size-7 items-center justify-center rounded-full border border-dashed border-border text-muted-foreground",
              value === "" && "ring-2 ring-primary ring-offset-1 ring-offset-surface",
            )}
          >
            <X className="size-3.5" />
          </button>
        )}
        {swatches.map((s) => {
          const selected = value.toLowerCase() === s.value.toLowerCase();
          return (
            <button
              key={s.value + s.label}
              type="button"
              disabled={disabled}
              aria-pressed={selected}
              aria-label={`${s.label} (${s.value})`}
              title={s.label}
              onClick={() => onChange(s.value)}
              className={cn(
                "flex size-7 items-center justify-center rounded-full ring-1 ring-black/10 dark:ring-white/20",
                selected && "ring-2 ring-primary ring-offset-1 ring-offset-surface",
              )}
              style={{ backgroundColor: s.paint ?? s.value }}
            >
              {selected && <Check className="size-3.5 text-white mix-blend-difference" aria-hidden />}
            </button>
          );
        })}
      </div>
      <div className="flex items-center gap-2">
        <input
          type="color"
          aria-label={`${label}: custom colour`}
          disabled={disabled}
          value={isHexColor(custom) ? custom : "#1f5fd6"}
          onChange={(e) => {
            setCustom(e.target.value);
            onChange(e.target.value);
          }}
          className="h-8 w-10 cursor-pointer rounded border border-border bg-surface p-0.5"
        />
        <Input
          id={`${id}-hex`}
          aria-label={`${label}: hex value`}
          aria-invalid={!customValid || invalid || undefined}
          placeholder="#rrggbb"
          maxLength={7}
          disabled={disabled}
          value={custom}
          onChange={(e) => {
            const v = e.target.value.trim().toLowerCase();
            setCustom(v);
            if (isHexColor(v)) onChange(v);
          }}
          className={cn("w-28 font-mono", !customValid && "border-danger")}
        />
        {!customValid && <span className="text-[12px] text-danger">Use the form #rrggbb</span>}
      </div>
    </div>
  );
}

import { useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, X } from "lucide-react";
import { Spinner } from "@/components/ui/primitives";
import { useDebounced } from "@/lib/useDebounced";
import { cn } from "@/lib/utils";

export interface ComboOption {
  value: string;
  label: string;
  description?: string;
  group?: string;
  disabled?: boolean;
  icon?: ReactNode;
}

/**
 * Accessible single-select combobox (WAI-ARIA combobox + listbox). Options
 * come from `options` (filtered locally) or from `load` (server search,
 * debounced, only while open).
 */
export function Combobox({
  id,
  value,
  onChange,
  options,
  load,
  queryKey,
  placeholder = "Search…",
  disabled,
  clearable = true,
  invalid,
  describedBy,
  emptyText = "No matches",
  className,
  ariaLabel,
  ...aria
}: {
  id?: string;
  value: ComboOption | null;
  onChange: (v: ComboOption | null) => void;
  options?: ComboOption[];
  load?: (q: string, signal?: AbortSignal) => Promise<ComboOption[]>;
  /** Cache key prefix for `load`. */
  queryKey?: string;
  placeholder?: string;
  disabled?: boolean;
  clearable?: boolean;
  invalid?: boolean;
  describedBy?: string;
  emptyText?: string;
  className?: string;
  ariaLabel?: string;
  "aria-invalid"?: boolean;
  "aria-describedby"?: string;
  "aria-required"?: boolean;
}) {
  const autoId = useId();
  const inputId = id ?? `cb-${autoId}`;
  const listId = `${inputId}-list`;
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const dq = useDebounced(q.trim(), 250);
  const inputRef = useRef<HTMLInputElement>(null);

  const remote = useQuery({
    queryKey: ["combobox", queryKey ?? inputId, dq],
    queryFn: ({ signal }) => load!(dq, signal),
    enabled: !!load && open,
    staleTime: 30_000,
    retry: false,
  });

  const shown = useMemo(() => {
    if (load) return remote.data ?? [];
    const needle = q.trim().toLowerCase();
    const all = options ?? [];
    return needle ? all.filter((o) => `${o.label} ${o.description ?? ""} ${o.group ?? ""}`.toLowerCase().includes(needle)) : all;
  }, [load, remote.data, options, q]);

  const choose = (o: ComboOption) => {
    if (o.disabled) return;
    onChange(o);
    setOpen(false);
    setQ("");
  };

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (!open) setOpen(true);
      else setActive((a) => Math.min(shown.length - 1, a + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(0, a - 1));
    } else if (e.key === "Enter") {
      if (open && shown[active]) {
        e.preventDefault();
        choose(shown[active]);
      }
    } else if (e.key === "Escape") {
      if (open) {
        e.preventDefault();
        e.stopPropagation();
        setOpen(false);
        setQ("");
      }
    }
  };

  let lastGroup: string | undefined;
  return (
    <div className={cn("relative", className)}>
      <div className="relative">
        <input
          ref={inputRef}
          id={inputId}
          role="combobox"
          aria-label={ariaLabel}
          aria-expanded={open}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={open && shown[active] ? `${listId}-${active}` : undefined}
          aria-invalid={invalid || aria["aria-invalid"] || undefined}
          aria-describedby={describedBy ?? aria["aria-describedby"]}
          aria-required={aria["aria-required"]}
          autoComplete="off"
          disabled={disabled}
          placeholder={value ? value.label : placeholder}
          value={open ? q : value?.label ?? ""}
          onChange={(e) => {
            setQ(e.target.value);
            setActive(0);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onClick={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onKeyDown={onKey}
          className={cn(
            "h-8 w-full rounded-md border bg-surface pl-2.5 pr-14 text-[13px] text-foreground placeholder:text-muted-foreground focus-visible:outline-2 focus-visible:outline-ring disabled:opacity-60",
            invalid || aria["aria-invalid"] ? "border-danger" : "border-border",
          )}
        />
        <div className="absolute inset-y-0 right-1 flex items-center gap-0.5">
          {remote.isFetching && <Spinner className="size-3.5" />}
          {clearable && value && !disabled && (
            <button
              type="button"
              aria-label="Clear selection"
              className="rounded p-1 text-muted-foreground hover:bg-surface-muted"
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => {
                onChange(null);
                inputRef.current?.focus();
              }}
            >
              <X className="size-3.5" />
            </button>
          )}
          <ChevronDown className="size-3.5 text-muted-foreground" aria-hidden />
        </div>
      </div>
      {open && !disabled && (
        <ul
          id={listId}
          role="listbox"
          className="absolute z-50 mt-1 max-h-64 w-full overflow-y-auto rounded-md border border-border bg-surface p-1 shadow-lg"
        >
          {remote.isError && <li className="px-2 py-1.5 text-[12px] text-danger">{(remote.error as Error).message}</li>}
          {!remote.isError && !shown.length && (
            <li className="px-2 py-1.5 text-[12px] text-muted-foreground">{load && remote.isPending ? "Loading…" : emptyText}</li>
          )}
          {shown.map((o, i) => {
            const header = o.group && o.group !== lastGroup ? o.group : null;
            lastGroup = o.group;
            return (
              <li key={`${o.group ?? ""}-${o.value}`} role="presentation">
                {header && <div className="px-2 pb-0.5 pt-1.5 text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">{header}</div>}
                <div
                  id={`${listId}-${i}`}
                  role="option"
                  aria-selected={value?.value === o.value}
                  aria-disabled={o.disabled || undefined}
                  onMouseDown={(e) => e.preventDefault()}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => choose(o)}
                  className={cn(
                    "flex cursor-pointer items-start gap-2 rounded px-2 py-1.5 text-[13px]",
                    i === active && "bg-surface-muted",
                    value?.value === o.value && "font-medium text-primary",
                    o.disabled && "cursor-not-allowed opacity-50",
                  )}
                >
                  {o.icon}
                  <span className="min-w-0">
                    <span className="block truncate">{o.label}</span>
                    {o.description && <span className="block truncate text-[11.5px] text-muted-foreground">{o.description}</span>}
                  </span>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

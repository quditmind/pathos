import { useState, type ReactNode } from "react";
import * as DM from "@radix-ui/react-dropdown-menu";
import { Check, Columns3, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Alert, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";

export interface Column<T> {
  id: string;
  header: string;
  cell: (row: T) => ReactNode;
  /** Plain value for CSV export; omit to exclude the column from export. */
  csv?: (row: T) => string | number | null | undefined;
  className?: string;
  /** Hidden unless the user enables it in the column chooser. */
  defaultHidden?: boolean;
  /** Cannot be hidden. */
  required?: boolean;
  /** Included in the CSV export even while hidden in the table. */
  exportAlways?: boolean;
}

function loadHidden<T>(tableId: string, columns: Column<T>[]): Set<string> {
  try {
    const raw = localStorage.getItem(`pathos-columns:${tableId}`);
    if (raw) {
      const saved = JSON.parse(raw) as string[] | { hidden: string[]; known: string[] };
      if (Array.isArray(saved)) return new Set(saved);
      // Columns added after the choice was saved keep their default visibility.
      const known = new Set(saved.known);
      return new Set([...saved.hidden, ...columns.filter((c) => c.defaultHidden && !known.has(c.id)).map((c) => c.id)]);
    }
  } catch {
    /* storage unavailable or corrupt */
  }
  return new Set(columns.filter((c) => c.defaultHidden).map((c) => c.id));
}

export function csvEscape(v: unknown): string {
  if (v == null) return "";
  let s = String(v);
  // Neutralise spreadsheet formula injection.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv<T>(columns: Column<T>[], rows: T[]): string {
  const cols = columns.filter((c) => c.csv);
  const lines = [cols.map((c) => csvEscape(c.header)).join(",")];
  for (const r of rows) lines.push(cols.map((c) => csvEscape(c.csv!(r))).join(","));
  return lines.join("\r\n") + "\r\n";
}

function download(name: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: "text/csv;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * Data table with column chooser, CSV export of loaded rows, loading /
 * empty / error states and cursor-based "load more". Filtering and paging
 * happen on the server; the table renders what it is given.
 */
export function DataTable<T>({
  tableId,
  columns,
  rows,
  rowKey,
  isPending,
  error,
  empty,
  onRowClick,
  hasMore,
  loadingMore,
  onLoadMore,
  toolbar,
  exportName,
  selection,
  onSelectionChange,
}: {
  tableId: string;
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  isPending?: boolean;
  error?: Error | null;
  empty: ReactNode;
  onRowClick?: (row: T) => void;
  hasMore?: boolean;
  loadingMore?: boolean;
  onLoadMore?: () => void;
  toolbar?: ReactNode;
  exportName?: string;
  /** Enables row checkboxes when provided. */
  selection?: Set<string>;
  onSelectionChange?: (next: Set<string>) => void;
}) {
  const selectable = !!selection && !!onSelectionChange;
  const allSelected = selectable && rows.length > 0 && rows.every((r) => selection!.has(rowKey(r)));
  const toggleRow = (key: string) => {
    const next = new Set(selection);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    onSelectionChange!(next);
  };
  const toggleAll = () => onSelectionChange!(allSelected ? new Set() : new Set(rows.map(rowKey)));
  const [hidden, setHidden] = useState(() => loadHidden(tableId, columns));
  const visible = columns.filter((c) => !hidden.has(c.id));

  const toggle = (id: string) => {
    const next = new Set(hidden);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setHidden(next);
    try {
      localStorage.setItem(`pathos-columns:${tableId}`, JSON.stringify({ hidden: [...next], known: columns.map((c) => c.id) }));
    } catch {
      /* storage unavailable */
    }
  };

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
        <div className="flex flex-1 flex-wrap items-center gap-2">{toolbar}</div>
        <div className="flex items-center gap-1">
          {exportName && (
            <Button
              variant="ghost"
              size="sm"
              disabled={!rows.length}
              onClick={() => download(`${exportName}-${new Date().toISOString().slice(0, 10)}.csv`, toCsv(columns.filter((c) => !hidden.has(c.id) || c.exportAlways), rows))}
              title="Export loaded rows as CSV"
            >
              <Download /> Export
            </Button>
          )}
          <DM.Root>
            <DM.Trigger asChild>
              <Button variant="ghost" size="sm" aria-label="Choose columns">
                <Columns3 /> Columns
              </Button>
            </DM.Trigger>
            <DM.Portal>
              <DM.Content align="end" sideOffset={4} className="z-50 min-w-44 rounded-md border border-border bg-surface p-1 shadow-lg">
                {columns.map((c) => (
                  <DM.CheckboxItem
                    key={c.id}
                    checked={!hidden.has(c.id)}
                    disabled={c.required}
                    onSelect={(e) => {
                      e.preventDefault();
                      toggle(c.id);
                    }}
                    className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-[13px] outline-none data-disabled:opacity-50 data-highlighted:bg-surface-muted"
                  >
                    <span className="flex size-4 items-center justify-center">
                      <DM.ItemIndicator>
                        <Check className="size-3.5" />
                      </DM.ItemIndicator>
                    </span>
                    {c.header}
                  </DM.CheckboxItem>
                ))}
              </DM.Content>
            </DM.Portal>
          </DM.Root>
        </div>
      </div>

      {error ? (
        <div className="p-4">
          <Alert>Could not load data: {error.message}</Alert>
        </div>
      ) : isPending ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-9" />
          ))}
        </div>
      ) : rows.length === 0 ? (
        empty
      ) : (
        <Table>
          <thead>
            <tr>
              {selectable && (
                <Th className="w-8">
                  <input type="checkbox" aria-label="Select all loaded rows" checked={allSelected} onChange={toggleAll} className="size-3.5 accent-[var(--primary)]" />
                </Th>
              )}
              {visible.map((c) => (
                <Th key={c.id} className={c.className}>
                  {c.header}
                </Th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr
                key={rowKey(r)}
                className={cn(onRowClick && "cursor-pointer hover:bg-surface-muted/60")}
                onClick={onRowClick ? () => onRowClick(r) : undefined}
                onKeyDown={onRowClick ? (e) => e.key === "Enter" && onRowClick(r) : undefined}
                tabIndex={onRowClick ? 0 : undefined}
              >
                {selectable && (
                  <Td className="w-8" >
                    <input
                      type="checkbox"
                      aria-label="Select row"
                      checked={selection!.has(rowKey(r))}
                      onClick={(e) => e.stopPropagation()}
                      onChange={() => toggleRow(rowKey(r))}
                      className="size-3.5 accent-[var(--primary)]"
                    />
                  </Td>
                )}
                {visible.map((c) => (
                  <Td key={c.id} className={c.className}>
                    {c.cell(r)}
                  </Td>
                ))}
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {hasMore && onLoadMore && (
        <div className="flex justify-center p-3">
          <Button variant="secondary" onClick={onLoadMore} disabled={loadingMore}>
            {loadingMore ? "Loading…" : "Load more"}
          </Button>
        </div>
      )}
      {!isPending && !error && rows.length > 0 && (
        <div className="tabular border-t border-border px-3 py-2 text-[11.5px] text-muted-foreground">
          {rows.length} {rows.length === 1 ? "row" : "rows"} loaded{hasMore ? " · more available" : ""}
        </div>
      )}
    </div>
  );
}

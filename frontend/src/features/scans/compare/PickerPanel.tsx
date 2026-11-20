import { useEffect, useState } from "react";
import { CHECK_KINDS } from "@/lib/checkKinds";
import { GitCompareArrows, Search, X } from "lucide-react";
import type { ScanJob } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Card, Input, Label, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { JobStatusPill } from "@/components/data/Severity";
import { useDebounced } from "@/lib/useDebounced";
import { formatDateTime } from "@/lib/utils";
import { useProfiles, useScans } from "../api";
import { statusOptions } from "../shared";
import { dateRange, MAX_COMPARE, MIN_COMPARE, type CompareSearch } from "./model";
import { ErrorPanel } from "@/components/ui/error-panel";

type Filters = Omit<CompareSearch, "ids">;

/** Left panel: filter executions and select 2–10 of them. */
export function PickerPanel({
  search,
  onFilter,
  selected,
  onSelectedChange,
  onCompare,
}: {
  search: CompareSearch;
  onFilter: (f: Partial<Filters>) => void;
  selected: string[];
  onSelectedChange: (ids: string[]) => void;
  onCompare: () => void;
}) {
  const profiles = useProfiles();
  const range = dateRange(search.from, search.to);
  const [q, setQ] = useState(search.q ?? "");
  const [scanKey, setScanKey] = useState(search.scan_key ?? "");
  const dq = useDebounced(q.trim(), 300);
  const dk = useDebounced(scanKey.trim(), 300);
  useEffect(() => {
    if ((search.q ?? "") !== dq) onFilter({ q: dq || undefined });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dq]);
  useEffect(() => {
    if ((search.scan_key ?? "") !== dk) onFilter({ scan_key: dk || undefined });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dk]);

  const scans = useScans(
    {
      q: search.q,
      scan_key: search.scan_key,
      from: range.from,
      to: range.to,
      profile_id: search.profile_id,
      status: search.status,
      scanner: search.scanner,
      kind: search.kind,
      asset_type: "repository",
    },
    false,
  );
  const rows = scans.data?.pages.flatMap((p) => p.items) ?? [];
  const full = selected.length >= MAX_COMPARE;
  const toggle = (j: ScanJob) => {
    if (selected.includes(j.id)) onSelectedChange(selected.filter((x) => x !== j.id));
    else if (!full) onSelectedChange([...selected, j.id]);
  };
  const ok = selected.length >= MIN_COMPARE && selected.length <= MAX_COMPARE;

  return (
    <Card className="flex min-w-0 flex-col">
      <div className="space-y-2.5 border-b border-border p-3">
        <h2 className="text-[13px] font-semibold">Select executions</h2>
        <div className="relative">
          <Search className="pointer-events-none absolute left-2 top-2 size-4 text-muted-foreground" aria-hidden />
          <Input aria-label="Search asset name or Repository ID" placeholder="Asset name or Repository ID" className="pl-8" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <Label htmlFor="cmp-type">Asset type</Label>
            <Select id="cmp-type" className="w-full" value="repository" onChange={() => undefined}>
              <option value="repository">Repository</option>
            </Select>
          </div>
          <div>
            <Label htmlFor="cmp-key">Scan ID</Label>
            <Input id="cmp-key" className="font-mono" placeholder="QD-SCAN-…" value={scanKey} onChange={(e) => setScanKey(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="cmp-from">From</Label>
            <Input id="cmp-from" type="date" value={range.from} max={range.to} onChange={(e) => onFilter({ from: e.target.value || undefined })} />
          </div>
          <div>
            <Label htmlFor="cmp-to">To</Label>
            <Input id="cmp-to" type="date" value={range.to} min={range.from} onChange={(e) => onFilter({ to: e.target.value || undefined })} />
          </div>
          <div>
            <Label htmlFor="cmp-profile">Scan profile</Label>
            <Select id="cmp-profile" className="w-full" value={search.profile_id ?? ""} onChange={(e) => onFilter({ profile_id: e.target.value || undefined })}>
              <option value="">All profiles</option>
              {(profiles.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </Select>
          </div>
          <div>
            <Label htmlFor="cmp-status">Status</Label>
            <Select id="cmp-status" className="w-full" value={search.status ?? ""} onChange={(e) => onFilter({ status: e.target.value || undefined })}>
              <option value="">All statuses</option>
              {statusOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </Select>
          </div>
          <div className="col-span-2">
            <Label htmlFor="cmp-scanner">Kind of check</Label>
            <Select id="cmp-scanner" className="w-full" value={search.kind ?? ""} onChange={(e) => onFilter({ kind: e.target.value || undefined, scanner: undefined })}>
              <option value="">All kinds of check</option>
              {CHECK_KINDS.map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
            </Select>
          </div>
        </div>
        {range.clamped && <p className="text-[11.5px] text-warning">The date range is limited to 360 days; “From” was adjusted.</p>}
      </div>

      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2 text-[12px]">
        <span className="tabular font-medium" aria-live="polite">
          {selected.length} of {MAX_COMPARE} selected
        </span>
        {selected.length < MIN_COMPARE && <span className="text-muted-foreground">Select at least 2 executions</span>}
        {full && <span className="text-muted-foreground">Maximum reached</span>}
        <div className="ml-auto flex gap-1">
          {selected.length > 0 && (
            <Button size="sm" variant="ghost" onClick={() => onSelectedChange([])}>
              <X /> Clear
            </Button>
          )}
          <Button size="sm" disabled={!ok} onClick={onCompare}>
            <GitCompareArrows /> Compare selected
          </Button>
        </div>
      </div>

      <div className="max-h-[60vh] min-h-40 overflow-y-auto">
        {scans.error ? (
          <div className="p-3"><ErrorPanel error={scans.error} title="Could not load executions" /></div>
        ) : scans.isPending ? (
          <div className="space-y-2 p-3">{Array.from({ length: 5 }, (_, i) => <Skeleton key={i} className="h-8" />)}</div>
        ) : rows.length === 0 ? (
          <p className="px-3 py-10 text-center text-[13px] text-muted-foreground">No executions match these filters.</p>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th className="w-8"><span className="sr-only">Select</span></Th>
                <Th>Scan</Th>
                <Th>Status</Th>
                <Th className="text-right">Findings</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((j) => {
                const checked = selected.includes(j.id);
                return (
                  <tr key={j.id} className={checked ? "bg-primary/5" : undefined}>
                    <Td className="w-8">
                      <input
                        type="checkbox"
                        aria-label={`Select ${j.scan_key || j.id}`}
                        checked={checked}
                        disabled={!checked && full}
                        onChange={() => toggle(j)}
                        className="size-3.5 accent-[var(--primary)]"
                      />
                    </Td>
                    <Td>
                      <div className="font-mono text-[12px]">{j.scan_key || j.id.slice(0, 8)}</div>
                      <div className="truncate text-[12px]">
                        {j.repository_name}
                        {j.repository_key && <span className="ml-1 font-mono text-[11px] text-muted-foreground">{j.repository_key}</span>}
                      </div>
                      <div className="text-[11.5px] text-muted-foreground">
                        {formatDateTime(j.started_at ?? j.queued_at)} · {j.profile_name} v{j.profile_version}
                      </div>
                    </Td>
                    <Td><JobStatusPill status={j.status} /></Td>
                    <Td className="tabular text-right">{j.findings_total ?? 0}</Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
        {scans.hasNextPage && (
          <div className="flex justify-center p-3">
            <Button variant="secondary" size="sm" disabled={scans.isFetchingNextPage} onClick={() => void scans.fetchNextPage()}>
              {scans.isFetchingNextPage ? "Loading…" : "Load more"}
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}

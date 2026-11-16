import { useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Search, X } from "lucide-react";
import { api } from "@/api/client";
import type { Page, Repository, StartScanItem } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Input, Label, Select, Spinner } from "@/components/ui/primitives";
import { useDebounced } from "@/lib/useDebounced";
import { cn } from "@/lib/utils";
import { startScans, useProfiles, useScanMutation } from "./api";

type Picked = { id: string; name: string; key: string };

/** Searchable multi-select over /api/v1/repositories (name + Repository ID). */
export function RepositoryMultiSelect({ value, onChange }: { value: Picked[]; onChange: (v: Picked[]) => void }) {
  const [q, setQ] = useState("");
  const dq = useDebounced(q.trim(), 250);
  const repos = useQuery({
    queryKey: ["repo-picker", dq],
    queryFn: ({ signal }) => {
      const p = new URLSearchParams({ limit: "25" });
      if (dq) p.set("q", dq);
      return api<Page<Repository>>(`/api/v1/repositories?${p}`, { signal }).then((r) => r.items);
    },
    staleTime: 30_000,
  });
  const chosen = new Set(value.map((v) => v.id));
  const toggle = (r: Repository) =>
    onChange(chosen.has(r.id) ? value.filter((v) => v.id !== r.id) : [...value, { id: r.id, name: r.full_name, key: r.repository_key }]);
  return (
    <div>
      {value.length > 0 && (
        <ul className="mb-2 flex flex-wrap gap-1.5" aria-label="Selected repositories">
          {value.map((v) => (
            <li key={v.id} className="inline-flex items-center gap-1 rounded bg-primary/10 px-1.5 py-0.5 text-[12px] text-primary">
              {v.name}
              {v.key && <span className="font-mono text-[11px] opacity-80">{v.key}</span>}
              <button type="button" aria-label={`Remove ${v.name}`} className="rounded p-0.5 hover:bg-primary/15" onClick={() => onChange(value.filter((x) => x.id !== v.id))}>
                <X className="size-3" />
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="relative">
        <Search className="pointer-events-none absolute left-2 top-2 size-4 text-muted-foreground" aria-hidden />
        <Input id="start-repo-q" className="pl-8" placeholder="Search by name or Repository ID…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search repositories" />
      </div>
      <ul role="listbox" aria-multiselectable="true" aria-label="Repositories" className="mt-1.5 max-h-56 overflow-y-auto rounded-md border border-border">
        {repos.isPending && <li className="flex items-center gap-2 px-3 py-2 text-[12px] text-muted-foreground"><Spinner className="size-3.5" /> Loading…</li>}
        {repos.isError && <li className="px-3 py-2 text-[12px] text-danger">{repos.error.message}</li>}
        {repos.data?.length === 0 && <li className="px-3 py-2 text-[12px] text-muted-foreground">No repositories match.</li>}
        {repos.data?.map((r) => {
          const disabled = !r.scan_enabled || !!r.archived_at;
          return (
            <li key={r.id} role="option" aria-selected={chosen.has(r.id)} aria-disabled={disabled || undefined}>
              <label className={cn("flex cursor-pointer items-center gap-2 border-b border-border px-3 py-1.5 text-[13px] last:border-0 hover:bg-surface-muted/60", disabled && "cursor-not-allowed opacity-50")}>
                <input type="checkbox" className="size-3.5 accent-[var(--primary)]" checked={chosen.has(r.id)} disabled={disabled} onChange={() => toggle(r)} aria-label={`Select ${r.full_name}`} />
                <span className="min-w-0 flex-1 truncate">{r.full_name}</span>
                <span className="font-mono text-[11px] text-muted-foreground">{r.repository_key}</span>
                {disabled && <Badge>scanning off</Badge>}
              </label>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function StartScanDialog({ open, onOpenChange, initial }: { open: boolean; onOpenChange: (o: boolean) => void; initial?: Picked[] }) {
  const [assets, setAssets] = useState<Picked[]>([]);
  const [profileId, setProfileId] = useState("");
  const [name, setName] = useState("");
  const [result, setResult] = useState<StartScanItem[] | null>(null);
  const profiles = useProfiles();
  const start = useScanMutation(startScans);
  useEffect(() => {
    if (open) {
      setAssets(initial ?? []);
      setProfileId("");
      setName("");
      setResult(null);
      start.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  const names = new Map(assets.map((a) => [a.id, a]));

  const submit = () =>
    start.mutate(
      { repository_ids: assets.map((a) => a.id), profile_id: profileId || undefined, name: name.trim() || undefined },
      { onSuccess: (r) => setResult(r.items) },
    );

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="lg"
      title="Start scan"
      description="Queue one execution per selected asset. Each execution gets a permanent Scan ID."
      footer={
        result ? (
          <Button onClick={() => onOpenChange(false)}>Done</Button>
        ) : (
          <>
            <Button variant="secondary" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button disabled={!assets.length || start.isPending} onClick={submit}>
              {start.isPending ? "Starting…" : `Start ${assets.length > 1 ? `${assets.length} scans` : "scan"}`}
            </Button>
          </>
        )
      }
    >
      {result ? (
        <div className="space-y-2 text-[13px]">
          <p>
            {result.filter((r) => r.job_id && !r.coalesced).length} queued · {result.filter((r) => r.coalesced).length} already queued · {result.filter((r) => r.error).length} errors
          </p>
          <ul className="divide-y divide-border rounded-md border border-border" aria-label="Start results">
            {result.map((r) => {
              const a = names.get(r.repository_id);
              return (
                <li key={r.repository_id} className="flex flex-wrap items-center gap-2 px-3 py-2">
                  <span className="min-w-0 flex-1 truncate">
                    {a?.name ?? r.repository_id}
                    {a?.key && <span className="ml-1.5 font-mono text-[11px] text-muted-foreground">{a.key}</span>}
                  </span>
                  {r.error ? (
                    <Badge tone="danger">error: {r.error}</Badge>
                  ) : r.coalesced ? (
                    <Badge tone="warning">already queued</Badge>
                  ) : (
                    <Badge tone="success">queued</Badge>
                  )}
                  {r.job_id && (
                    <Link to="/scans/$id" params={{ id: r.job_id }} className="text-[12px] text-primary hover:underline" onClick={() => onOpenChange(false)}>
                      Open execution →
                    </Link>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      ) : (
        <div className="space-y-4">
          {start.isError && <Alert>{start.error.message}</Alert>}
          <div>
            <Label htmlFor="start-repo-q" hint="asset type: repository">Assets</Label>
            <RepositoryMultiSelect value={assets} onChange={setAssets} />
          </div>
          <div>
            <Label htmlFor="start-profile" hint="Compatible with repositories">Scan profile</Label>
            <Select id="start-profile" className="w-full" value={profileId} onChange={(e) => setProfileId(e.target.value)} disabled={profiles.isPending}>
              <option value="">Repository's own profile</option>
              {(profiles.data ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} v{p.current.version}
                  {p.is_default ? " (default)" : ""}
                </option>
              ))}
            </Select>
            <p className="mt-1 text-[11.5px] text-muted-foreground">
              Profiles are managed in{" "}
              <Link to="/configurations/scan-profiles" className="text-primary hover:underline">Configurations → Scan profiles</Link>.
            </p>
          </div>
          <div>
            <Label htmlFor="start-name" hint="optional">Scan name</Label>
            <Input id="start-name" value={name} maxLength={200} placeholder="e.g. Pre-release audit" onChange={(e) => setName(e.target.value)} />
          </div>
        </div>
      )}
    </Dialog>
  );
}

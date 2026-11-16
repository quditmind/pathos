import { Plus, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import type { Page, Repository } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Combobox, type ComboOption } from "@/components/ui/combobox";
import { Select } from "@/components/ui/primitives";
import { useProfiles } from "@/features/scans/api";
import { useBusinessUnits, useRegions } from "@/features/users/api";
import { newPlanRow, targetLabels, type PlanRow, type PlanTarget } from "./form";

const loadRepos = async (q: string, signal?: AbortSignal): Promise<ComboOption[]> => {
  const p = new URLSearchParams({ limit: "20" });
  if (q) p.set("q", q);
  const r = await api<Page<Repository>>(`/api/v1/repositories?${p}`, { signal });
  return r.items.map((x) => ({ value: x.id, label: x.full_name, description: x.repository_key }));
};

/** Execution plan: asset scope × scan profile rows. */
export function PlanEditor({ rows, onChange }: { rows: PlanRow[]; onChange: (rows: PlanRow[]) => void }) {
  const regions = useRegions();
  const bus = useBusinessUnits();
  const profiles = useProfiles();
  const set = (i: number, patch: Partial<PlanRow>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  return (
    <div className="space-y-2">
      {rows.map((r, i) => {
        const n = i + 1;
        const options =
          r.target_type === "region" ? (regions.data ?? []).map((x) => ({ id: x.id, name: x.name }))
            : r.target_type === "business_unit" ? (bus.data ?? []).map((x) => ({ id: x.id, name: x.name })) : [];
        return (
          <div key={r.key} className="grid grid-cols-1 gap-2 rounded-md border border-border p-2 sm:grid-cols-[10rem_1fr_1fr_auto]" data-testid="plan-row">
            <Select aria-label={`Plan row ${n} asset scope`} value={r.target_type}
              onChange={(e) => set(i, { target_type: e.target.value as PlanTarget, target_id: "", target_name: "" })}>
              {(Object.keys(targetLabels) as PlanTarget[]).map((k) => <option key={k} value={k}>{targetLabels[k]}</option>)}
            </Select>
            {r.target_type === "organization" ? (
              <div className="flex items-center text-[12.5px] text-muted-foreground">Every scan-enabled repository</div>
            ) : r.target_type === "repository" ? (
              <Combobox ariaLabel={`Plan row ${n} repository`} queryKey="schedule-plan-repos" load={loadRepos} placeholder="Search repositories…"
                value={r.target_id ? { value: r.target_id, label: r.target_name || r.target_id } : null}
                onChange={(o) => set(i, { target_id: o?.value ?? "", target_name: o?.label ?? "" })} />
            ) : (
              <Select aria-label={`Plan row ${n} ${targetLabels[r.target_type].toLowerCase()}`} value={r.target_id}
                onChange={(e) => set(i, { target_id: e.target.value, target_name: options.find((o) => o.id === e.target.value)?.name ?? "" })}>
                <option value="">Choose…</option>
                {r.target_id && !options.some((o) => o.id === r.target_id) && <option value={r.target_id}>{r.target_name || r.target_id}</option>}
                {options.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
              </Select>
            )}
            <Select aria-label={`Plan row ${n} scan profile`} value={r.profile_id} onChange={(e) => set(i, { profile_id: e.target.value })}>
              <option value="">Repository's own profile</option>
              {r.profile_id && !(profiles.data ?? []).some((p) => p.id === r.profile_id) && <option value={r.profile_id}>{r.profile_id}</option>}
              {(profiles.data ?? []).map((p) => (
                <option key={p.id} value={p.id}>{p.name} v{p.current.version}{p.is_default ? " (default)" : ""}</option>
              ))}
            </Select>
            <Button type="button" variant="ghost" size="icon" className="text-danger" aria-label={`Remove plan row ${n}`} disabled={rows.length <= 1}
              onClick={() => onChange(rows.filter((_, j) => j !== i))}>
              <Trash2 />
            </Button>
          </div>
        );
      })}
      <Button type="button" variant="secondary" size="sm" disabled={rows.length >= 50} onClick={() => onChange([...rows, newPlanRow()])}>
        <Plus /> Add plan row
      </Button>
    </div>
  );
}

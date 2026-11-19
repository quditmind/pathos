import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Building2, Plus } from "lucide-react";
import { api } from "@/api/client";
import type { BusinessUnit } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Card, EmptyState, Input, Label, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { useBusinessUnits, useOrganization, useRegions } from "./api";
import { ErrorPanel } from "@/components/ui/error-panel";

export function OrganizationPage() {
  const { canOrgWide } = useSession();
  const org = useOrganization();
  const regions = useRegions();
  const bus = useBusinessUnits();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [parent, setParent] = useState("");
  const create = useMutation({
    mutationFn: (body: { name: string; parent_id: string | null }) => api<BusinessUnit>("/api/v1/business-units", { method: "POST", body }),
    onSuccess: () => {
      setName("");
      setParent("");
      void qc.invalidateQueries({ queryKey: ["business-units"] });
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate({ name: name.trim(), parent_id: parent || null });
  };
  const byId = new Map((bus.data ?? []).map((b) => [b.id, b]));

  return (
    <>
      <PageHeader title={org.data?.name ?? "Organization"} description="Regions, countries and business units used to scope access and reporting." />
      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <div className="border-b border-border px-4 py-3 text-[13px] font-semibold">Regions & countries</div>
          {regions.isPending ? (
            <Skeleton className="m-4 h-32" />
          ) : (
            <ul className="divide-y divide-border">
              {(regions.data ?? []).map((r) => (
                <li key={r.id} className="px-4 py-3">
                  <div className="flex items-baseline justify-between">
                    <span className="text-[13px] font-medium">{r.name}</span>
                    <span className="tabular text-[12px] text-muted-foreground">{r.countries.length} countries</span>
                  </div>
                  <div className="mt-1 text-[12px] leading-relaxed text-muted-foreground">{r.countries.map((c) => c.name).join(", ")}</div>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card>
          <div className="border-b border-border px-4 py-3 text-[13px] font-semibold">Business units</div>
          {canOrgWide("org.manage") && (
            <form onSubmit={submit} className="border-b border-border p-4">
              {create.isError && (
                <div className="mb-3">
                  <ErrorPanel error={create.error} />
                </div>
              )}
              <div className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
                <div>
                  <Label htmlFor="bu-name">Name</Label>
                  <Input id="bu-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={200} />
                </div>
                <div>
                  <Label htmlFor="bu-parent" hint="(optional)">
                    Parent
                  </Label>
                  <Select id="bu-parent" className="w-full" value={parent} onChange={(e) => setParent(e.target.value)}>
                    <option value="">None (top level)</option>
                    {(bus.data ?? []).map((b) => (
                      <option key={b.id} value={b.id}>
                        {b.name}
                      </option>
                    ))}
                  </Select>
                </div>
                <Button type="submit" disabled={!name.trim() || create.isPending}>
                  <Plus /> Add
                </Button>
              </div>
            </form>
          )}
          {bus.isPending ? (
            <Skeleton className="m-4 h-20" />
          ) : bus.data?.length ? (
            <ul className="divide-y divide-border">
              {bus.data.map((b) => (
                <li key={b.id} className="px-4 py-2.5 text-[13px]">
                  <span className="font-medium">{b.name}</span>
                  {b.parent_id && <span className="ml-2 text-[12px] text-muted-foreground">in {byId.get(b.parent_id)?.name ?? "…"}</span>}
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState icon={<Building2 />} title="No business units yet">
              Business units let you scope roles and reports to parts of the organization.
            </EmptyState>
          )}
        </Card>
      </div>
    </>
  );
}

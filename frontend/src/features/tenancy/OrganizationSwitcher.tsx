import { useState } from "react";
import * as DM from "@radix-ui/react-dropdown-menu";
import { Building2, Check, ChevronsUpDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { switchOrganization, useMyOrganizations } from "./api";

/**
 * Header switcher between the organizations the signed-in person belongs
 * to. Hidden on single-organization installs and for people who belong to
 * one organization only.
 */
export function OrganizationSwitcher() {
  const orgs = useMyOrganizations();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const data = orgs.data;
  if (!data?.multi_tenant) return null;
  const active = data.items.find((m) => m.organization_id === data.active_organization_id);
  if (data.items.length < 2) {
    return active ? (
      <span className="hidden items-center gap-1.5 px-2 text-[13px] text-muted-foreground md:flex" title="Active organization">
        <Building2 className="size-4" /> {active.name}
      </span>
    ) : null;
  }
  const choose = async (id: string) => {
    if (id === data.active_organization_id) return;
    setPending(true);
    setError(null);
    try {
      await switchOrganization(id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "switch failed");
      setPending(false);
    }
  };
  return (
    <DM.Root>
      <DM.Trigger
        className="flex h-8 items-center gap-1.5 rounded-md border border-border px-2 text-[13px] hover:bg-surface-muted disabled:opacity-60"
        aria-label="Switch organization"
        disabled={pending}
      >
        <Building2 className="size-4 text-muted-foreground" />
        <span className="max-w-40 truncate">{active?.name ?? "Organization"}</span>
        <ChevronsUpDown className="size-3.5 text-muted-foreground" />
      </DM.Trigger>
      <DM.Portal>
        <DM.Content align="end" sideOffset={6} className="z-50 min-w-56 rounded-md border border-border bg-surface p-1 shadow-lg">
          <div className="px-2 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Organizations</div>
          {data.items.map((m) => (
            <DM.Item
              key={m.organization_id}
              disabled={m.status !== "active"}
              onSelect={() => void choose(m.organization_id)}
              className={cn(
                "flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-[13px] outline-none data-highlighted:bg-surface-muted",
                m.status !== "active" && "cursor-default opacity-60",
              )}
            >
              <Check className={cn("size-4", m.organization_id === data.active_organization_id ? "opacity-100" : "opacity-0")} />
              <span className="flex-1 truncate">{m.name}</span>
              {m.status !== "active" && <span className="text-[11px] text-muted-foreground">suspended</span>}
            </DM.Item>
          ))}
          {error && <div className="px-2 py-1.5 text-[12px] text-danger">{error}</div>}
        </DM.Content>
      </DM.Portal>
    </DM.Root>
  );
}

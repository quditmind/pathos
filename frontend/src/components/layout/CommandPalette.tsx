import { useEffect, useState, type ReactNode } from "react";
import { Command } from "cmdk";
import * as D from "@radix-ui/react-dialog";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { Boxes, Building2, Radar, ShieldAlert, FileClock, GitBranch, Globe2, LayoutDashboard, LogOut, MapPin, Moon, Plug, Search, Tags, UserRound, Users } from "lucide-react";
import { api } from "@/api/client";
import { splitHref } from "@/lib/utils";
import type { SearchResult } from "@/api/types";
import { useSession } from "@/features/auth/session";
import { Spinner } from "@/components/ui/primitives";

const typeIcon: Record<SearchResult["type"], ReactNode> = {
  repository: <GitBranch />,
  application: <Boxes />,
  user: <UserRound />,
  business_unit: <Building2 />,
  region: <Globe2 />,
  country: <MapPin />,
};

const typeLabel: Record<SearchResult["type"], string> = {
  repository: "Repositories",
  application: "Applications",
  user: "Users",
  business_unit: "Business units",
  region: "Regions",
  country: "Countries",
};

function useDebounced<T>(value: T, ms: number) {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function useCommandPaletteHotkey(setOpen: (fn: (o: boolean) => boolean) => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setOpen]);
}

export function CommandPalette({ open, onOpenChange, onToggleTheme }: { open: boolean; onOpenChange: (o: boolean) => void; onToggleTheme: () => void }) {
  const navigate = useNavigate();
  const { can, canOrgWide, logout } = useSession();
  const [q, setQ] = useState("");
  const dq = useDebounced(q.trim(), 200);

  const results = useQuery({
    queryKey: ["search", dq],
    queryFn: ({ signal }) => api<{ items: SearchResult[] }>(`/api/v1/search?q=${encodeURIComponent(dq)}`, { signal }).then((r) => r.items),
    enabled: open && dq.length >= 2,
    staleTime: 30_000,
  });

  const go = (to: string) => {
    onOpenChange(false);
    setQ("");
    void navigate(splitHref(to) as { to: string });
  };

  const pages = [
    { label: "Dashboard", to: "/", icon: <LayoutDashboard />, show: true },
    { label: "Repositories", to: "/repositories", icon: <GitBranch />, show: can("repos.read") },
    { label: "Import repositories", to: "/repositories/import", icon: <GitBranch />, show: can("repos.manage") },
    { label: "Applications", to: "/applications", icon: <Boxes />, show: can("repos.read") },
    { label: "Findings", to: "/findings", icon: <ShieldAlert />, show: can("findings.read") },
    { label: "Risk acceptances", to: "/risk", icon: <ShieldAlert />, show: can("findings.read") },
    { label: "SBOM inventory", to: "/sbom", icon: <ShieldAlert />, show: can("sbom.read") },
    { label: "Scan schedules", to: "/scans/schedules", icon: <Radar />, show: can("scans.read") },
    { label: "Notifications (rules, SMTP, history)", to: "/admin/notifications", icon: <Radar />, show: canOrgWide("notifications.manage") },
    { label: "Policies (SLA, licenses)", to: "/admin/policies", icon: <ShieldAlert />, show: canOrgWide("settings.manage") },
    { label: "Scans", to: "/scans", icon: <Radar />, show: can("scans.read") },
    { label: "Scan profiles", to: "/scans/profiles", icon: <Radar />, show: can("scans.read") },
    { label: "Scanners & workers", to: "/admin/scanners", icon: <Radar />, show: can("scanners.read") },
    { label: "AI reviews", to: "/ai", icon: <Radar />, show: can("findings.read") },
    { label: "AI settings", to: "/admin/ai", icon: <Radar />, show: canOrgWide("ai.configure") },
    { label: "MCP registry", to: "/admin/mcp", icon: <Radar />, show: can("ai.review") },
    { label: "API tokens", to: "/settings/tokens", icon: <Radar />, show: true },
    { label: "Users", to: "/admin/users", icon: <Users />, show: canOrgWide("users.read") },
    { label: "SCM connections", to: "/admin/scm", icon: <Plug />, show: canOrgWide("scm.manage") },
    { label: "Tags", to: "/admin/tags", icon: <Tags />, show: can("repos.read") },
    { label: "Organization", to: "/admin/organization", icon: <Building2 />, show: can("org.read") },
    { label: "Audit log", to: "/admin/audit", icon: <FileClock />, show: canOrgWide("audit.read") },
  ].filter((p) => p.show);

  const groups = new Map<SearchResult["type"], SearchResult[]>();
  for (const r of results.data ?? []) groups.set(r.type, [...(groups.get(r.type) ?? []), r]);

  // Results load asynchronously (shouldFilter=false), so cmdk does not
  // select anything by itself: select the first visible item.
  const [selected, setSelected] = useState("");
  const firstResult = [...groups.values()][0]?.[0];
  const firstPage = pages.find((p) => !dq || p.label.toLowerCase().includes(dq.toLowerCase()));
  const firstValue = firstResult ? `${firstResult.type}-${firstResult.id}` : firstPage ? `page-${firstPage.to}` : "";
  useEffect(() => setSelected(firstValue), [firstValue]);

  const item = "flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] data-[selected=true]:bg-surface-muted [&_svg]:size-4 [&_svg]:text-muted-foreground";
  const heading = "[&_[cmdk-group-heading]]:px-2.5 [&_[cmdk-group-heading]]:pb-1 [&_[cmdk-group-heading]]:pt-2 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-muted-foreground";

  return (
    <D.Root open={open} onOpenChange={(o) => { onOpenChange(o); if (!o) setQ(""); }}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-black/30" />
        <D.Content className="fixed left-1/2 top-[12vh] z-50 w-[calc(100vw-32px)] max-w-xl -translate-x-1/2 overflow-hidden rounded-lg border border-border bg-surface shadow-2xl">
          <D.Title className="sr-only">Search and commands</D.Title>
          <D.Description className="sr-only">Search PATHOS or run a command</D.Description>
          <Command shouldFilter={false} label="Search and commands" value={selected} onValueChange={setSelected}>
            <div className="flex items-center gap-2 border-b border-border px-3">
              <Search className="size-4 text-muted-foreground" />
              <Command.Input
                value={q}
                onValueChange={setQ}
                placeholder="Search users, business units, countries… or type a command"
                className="h-12 flex-1 bg-transparent text-[14px] outline-none placeholder:text-muted-foreground"
              />
              {results.isFetching && <Spinner />}
            </div>
            <Command.List className={`max-h-[60vh] overflow-y-auto p-1.5 ${heading}`}>
              <Command.Empty className="px-3 py-6 text-center text-[13px] text-muted-foreground">
                {dq.length >= 2 && !results.isFetching ? "No results" : "Type at least 2 characters to search"}
              </Command.Empty>
              {[...groups.entries()].map(([type, items]) => (
                <Command.Group key={type} heading={typeLabel[type]}>
                  {items.map((r) => (
                    <Command.Item key={`${r.type}-${r.id}`} value={`${r.type}-${r.id}`} onSelect={() => go(r.href)} className={item}>
                      {typeIcon[r.type]}
                      <span className="flex-1 truncate">{r.title}</span>
                      <span className="truncate text-[12px] text-muted-foreground">{r.subtitle}</span>
                    </Command.Item>
                  ))}
                </Command.Group>
              ))}
              {(!dq || pages.some((p) => p.label.toLowerCase().includes(dq.toLowerCase()))) && (
                <Command.Group heading="Go to">
                  {pages
                    .filter((p) => !dq || p.label.toLowerCase().includes(dq.toLowerCase()))
                    .map((p) => (
                      <Command.Item key={p.to} value={`page-${p.to}`} onSelect={() => go(p.to)} className={item}>
                        {p.icon}
                        {p.label}
                      </Command.Item>
                    ))}
                </Command.Group>
              )}
              {!dq && (
                <Command.Group heading="Actions">
                  <Command.Item value="action-theme" onSelect={() => { onToggleTheme(); onOpenChange(false); }} className={item}>
                    <Moon /> Toggle light / dark theme
                  </Command.Item>
                  <Command.Item value="action-logout" onSelect={() => void logout()} className={item}>
                    <LogOut /> Sign out
                  </Command.Item>
                </Command.Group>
              )}
            </Command.List>
          </Command>
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}

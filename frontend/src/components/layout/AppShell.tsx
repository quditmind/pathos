import { useEffect, useState, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import * as DM from "@radix-ui/react-dropdown-menu";
import {
  Bot,
  Boxes,
  Building2,
  ChevronsLeft,
  ChevronsRight,
  FileClock,
  GitBranch,
  LayoutDashboard,
  LogOut,
  Moon,
  Radar,
  Search,
  ShieldAlert,
  SlidersHorizontal,
  Sun,
  Users,
} from "lucide-react";
import { Wordmark, LogoMark } from "./Logo";
import { CommandPalette, useCommandPaletteHotkey } from "./CommandPalette";
import { NotificationCentre } from "./NotificationCentre";
import { useSession } from "@/features/auth/session";
import { cn, initials } from "@/lib/utils";

type NavItem = { label: string; to?: string; icon: ReactNode; perm?: string; phase?: number };
type NavGroup = { label: string; items: NavItem[] };

const groups: NavGroup[] = [
  { label: "Overview", items: [{ label: "Dashboard", to: "/", icon: <LayoutDashboard /> }] },
  {
    label: "Assets",
    items: [
      { label: "Repositories", icon: <GitBranch />, phase: 3 },
      { label: "Applications", icon: <Boxes />, phase: 3 },
    ],
  },
  {
    label: "Scanning",
    items: [
      { label: "Scans", icon: <Radar />, phase: 4 },
      { label: "Scan profiles", icon: <SlidersHorizontal />, phase: 4 },
    ],
  },
  { label: "Findings", items: [{ label: "Findings", icon: <ShieldAlert />, phase: 6 }] },
  { label: "AI & MCP", items: [{ label: "AI reviews", icon: <Bot />, phase: 5 }] },
  {
    label: "Administration",
    items: [
      { label: "Users", to: "/admin/users", icon: <Users />, perm: "users.read" },
      { label: "Organization", to: "/admin/organization", icon: <Building2 />, perm: "org.read" },
      { label: "Audit log", to: "/admin/audit", icon: <FileClock />, perm: "audit.read" },
    ],
  },
];

function useTheme() {
  const [dark, setDark] = useState(() => {
    try {
      const saved = localStorage.getItem("pathos-theme");
      if (saved) return saved === "dark";
    } catch {
      /* storage unavailable */
    }
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
  });
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    try {
      localStorage.setItem("pathos-theme", dark ? "dark" : "light");
    } catch {
      /* storage unavailable */
    }
  }, [dark]);
  return [dark, setDark] as const;
}

export function AppShell({ children }: { children: ReactNode }) {
  const { me, canOrgWide, can, logout } = useSession();
  const [collapsed, setCollapsed] = useState(false);
  const [dark, setDark] = useTheme();
  const [paletteOpen, setPaletteOpen] = useState(false);
  useCommandPaletteHotkey(setPaletteOpen);
  const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);
  const path = useRouterState({ select: (s) => s.location.pathname });

  const visible = (it: NavItem) => !it.perm || (it.perm === "org.read" ? can(it.perm) : canOrgWide(it.perm));

  return (
    <div className="flex h-full">
      <aside
        className={cn(
          "flex shrink-0 flex-col border-r border-border bg-surface transition-[width] duration-150",
          collapsed ? "w-14" : "w-56",
        )}
      >
        <div className="flex h-14 items-center border-b border-border px-3">{collapsed ? <LogoMark /> : <Wordmark />}</div>
        <nav className="flex-1 overflow-y-auto px-2 py-3" aria-label="Main">
          {groups.map((g) => {
            const items = g.items.filter(visible);
            if (!items.length) return null;
            return (
              <div key={g.label} className="mb-4">
                {!collapsed && (
                  <div className="px-2 pb-1 text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">{g.label}</div>
                )}
                {items.map((it) => {
                  const active = it.to && (it.to === "/" ? path === "/" : path.startsWith(it.to));
                  const cls = cn(
                    "flex h-8 items-center gap-2.5 rounded-md px-2 text-[13px] [&_svg]:size-4 [&_svg]:shrink-0",
                    active ? "bg-primary/10 font-medium text-primary" : "text-muted-foreground",
                    it.to ? "hover:bg-surface-muted hover:text-foreground" : "cursor-default opacity-60",
                  );
                  const content = (
                    <>
                      {it.icon}
                      {!collapsed && <span className="flex-1 truncate">{it.label}</span>}
                      {!collapsed && it.phase && (
                        <span className="rounded bg-surface-muted px-1 text-[10px] text-muted-foreground">Soon</span>
                      )}
                    </>
                  );
                  return it.to ? (
                    <Link key={it.label} to={it.to} className={cls} title={collapsed ? it.label : undefined}>
                      {content}
                    </Link>
                  ) : (
                    <div key={it.label} className={cls} title={`${it.label}: arrives in roadmap phase ${it.phase}`} aria-disabled>
                      {content}
                    </div>
                  );
                })}
              </div>
            );
          })}
        </nav>
        <button
          onClick={() => setCollapsed((c) => !c)}
          className="flex h-10 items-center gap-2 border-t border-border px-4 text-[12px] text-muted-foreground hover:text-foreground"
          aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
        >
          {collapsed ? <ChevronsRight className="size-4" /> : <ChevronsLeft className="size-4" />}
          {!collapsed && "Collapse"}
        </button>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-2 border-b border-border bg-surface px-5">
          <button
            onClick={() => setPaletteOpen(true)}
            className="flex h-8 w-full max-w-sm items-center gap-2 rounded-md border border-border bg-surface-muted/50 px-2.5 text-[13px] text-muted-foreground hover:bg-surface-muted"
            aria-label="Search (Ctrl+K)"
          >
            <Search className="size-4" />
            <span className="flex-1 text-left">Search…</span>
            <kbd className="rounded border border-border bg-surface px-1.5 text-[11px] font-medium">{isMac ? "⌘" : "Ctrl"} K</kbd>
          </button>
          <div className="flex-1" />
          <NotificationCentre />
          <button
            onClick={() => setDark(!dark)}
            className="rounded-md p-2 text-muted-foreground hover:bg-surface-muted hover:text-foreground"
            aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
          >
            {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
          </button>
          <DM.Root>
            <DM.Trigger className="flex items-center gap-2 rounded-md px-2 py-1 hover:bg-surface-muted" aria-label="User menu">
              <span className="flex size-7 items-center justify-center rounded-full bg-primary/15 text-[11px] font-semibold text-primary">
                {initials(me.user.display_name || me.user.email)}
              </span>
              <span className="hidden text-left sm:block">
                <span className="block text-[13px] font-medium leading-tight">{me.user.display_name || me.user.email}</span>
                <span className="block text-[11px] leading-tight text-muted-foreground">{me.role_assignments[0]?.role_name ?? "No role"}</span>
              </span>
            </DM.Trigger>
            <DM.Portal>
              <DM.Content align="end" sideOffset={6} className="z-50 min-w-52 rounded-md border border-border bg-surface p-1 shadow-lg">
                <div className="px-2 py-1.5 text-[12px] text-muted-foreground">{me.user.email}</div>
                <DM.Separator className="my-1 h-px bg-border" />
                <DM.Item
                  onSelect={() => void logout()}
                  className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-[13px] outline-none data-highlighted:bg-surface-muted"
                >
                  <LogOut className="size-4" /> Sign out
                </DM.Item>
              </DM.Content>
            </DM.Portal>
          </DM.Root>
        </header>
        <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} onToggleTheme={() => setDark(!dark)} />
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto max-w-7xl px-6 py-6">{children}</div>
        </main>
      </div>
    </div>
  );
}

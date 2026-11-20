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
  Gauge,
  GitCompareArrows,
  GitBranch,
  History,
  Settings2,
  LayoutDashboard,
  LogOut,
  Moon,
  Radar,
  Search,
  Server,
  ShieldAlert,
  SlidersHorizontal,
  Plug,
  Cpu,
  KeyRound,
  Network,
  Sun,
  Tags,
  Users,
  Package,
  CalendarClock,
  BellRing,
  Scale,
  ShieldOff,
  UserCheck,
  ListChecks,
  ClipboardCheck,
  UsersRound,
  FileBarChart,
  FileUp,
  Container,
  Ship,
  Grid3x3,
  ShieldQuestion,
  BarChart3,
  Crosshair,
  Activity,
  FileText,
  MessagesSquare,
  Route,
  FilterX,
  FileCode2,
  GitPullRequest,
  FileSpreadsheet,
  Presentation,
  ShieldCheck,
  PackageSearch,
  FileCheck2,
  UserRoundSearch,
  Fingerprint,
  Workflow,
  Cable,
  FolderPlus,
  Waypoints,
  Webhook,
  ShieldHalf,
  Binary,
  Wrench,
  RadioTower,
  Microscope,
  ToggleRight,
  Rocket,
} from "lucide-react";
import { useFeatureFlags, type FeatureFlag } from "@/features/shell/meta";
import { BrandBlock, PreReleaseIndicator, VersionBanner } from "@/features/shell/Brand";
import { HelpMenu } from "@/features/shell/HelpMenu";
import { ShellProvider } from "@/features/shell/ShellProvider";
import { PrintStamp } from "@/features/shell/PrintStamp";
import { Toaster } from "@/components/ui/toast";
import { CommandPalette, useCommandPaletteHotkey } from "./CommandPalette";
import { NotificationCentre } from "./NotificationCentre";
import { useSession } from "@/features/auth/session";
import { OrganizationSwitcher } from "@/features/tenancy/OrganizationSwitcher";
import { useMyOrganizations } from "@/features/tenancy/api";
import { cn, initials } from "@/lib/utils";

export type NavItem = {
  label: string;
  to?: string;
  icon: ReactNode;
  perm?: string;
  /** Roadmap milestone of a not-yet-built item: shown disabled with "arrives in roadmap phase N". */
  phase?: number;
  /**
   * Feature flag of the module (server-side, default off). An item with a
   * route and a flag is a link only while the flag is on; otherwise it shows
   * disabled with its phase.
   */
  flag?: FeatureFlag;
  /** Sub-heading shown above the item when it changes within a group. */
  section?: string;
};
export type NavGroup = { label: string; items: NavItem[] };

/**
 * Sidebar (prompt §5): Home, the nine lifecycle phases, Configurations and
 * Administration. Existing URLs are unchanged; new modules carry `phase` until
 * they are built.
 */
export const groups: NavGroup[] = [
  {
    label: "Home",
    items: [
      { label: "Dashboard", to: "/", icon: <LayoutDashboard /> },
      { label: "Lifecycle overview", to: "/lifecycle", icon: <Workflow />, perm: "repos.read", phase: 3, flag: "lifecycle_overview" },
    ],
  },
  {
    label: "1 · Connect",
    items: [
      { label: "Connectors", to: "/connectors", icon: <Cable />, phase: 2, flag: "connectors" },
      { label: "Onboard an application", to: "/onboarding", icon: <Rocket />, perm: "repos.manage", phase: 3, flag: "onboarding" },
      { label: "Add repositories", to: "/repositories/import", icon: <FolderPlus />, perm: "repos.manage" },
      { label: "Import history", to: "/repositories/imports", icon: <History />, perm: "repos.read" },
      { label: "SCM connections", to: "/admin/scm", icon: <Plug />, perm: "scm.manage" },
      { label: "Integrations", to: "/admin/integrations", icon: <Plug />, perm: "settings.manage" },
    ],
  },
  {
    label: "2 · Inventory",
    items: [
      { label: "Applications", to: "/applications", icon: <Boxes />, perm: "repos.read" },
      { label: "Repositories", to: "/repositories", icon: <GitBranch />, perm: "repos.read" },
      { label: "Scan targets", to: "/scans/targets", icon: <Container />, perm: "scans.read" },
      { label: "Unmanaged assets", to: "/posture/unmanaged", icon: <ShieldQuestion />, perm: "repos.read" },
      { label: "Coverage", to: "/posture/coverage", icon: <Grid3x3 />, perm: "repos.read" },
      { label: "Tags", to: "/admin/tags", icon: <Tags />, perm: "repos.read" },
    ],
  },
  {
    label: "3 · Discover",
    items: [
      { label: "CodeGraph", to: "/codegraph", icon: <Waypoints />, perm: "findings.read", phase: 4, flag: "codegraph" },
      { label: "Context graph", to: "/posture/graph", icon: <Network />, perm: "findings.read" },
      { label: "Runtime", to: "/runtime", icon: <Ship />, perm: "findings.read" },
      { label: "API & endpoints", to: "/api-endpoints", icon: <Webhook />, perm: "findings.read", phase: 4, flag: "codegraph" },
      { label: "SBOM inventory", to: "/sbom", icon: <Package />, perm: "sbom.read" },
      { label: "Component portfolio", to: "/portfolio", icon: <PackageSearch />, perm: "sbom.read" },
    ],
  },
  {
    label: "4 · Threat model",
    items: [
      { label: "Threat models", to: "/threat-models", icon: <ShieldHalf />, perm: "threats.read", phase: 5, flag: "threat_models" },
      { label: "Attack paths", to: "/posture/attack-paths", icon: <Route />, perm: "findings.read" },
      { label: "Blast radius", to: "/posture/blast-radius", icon: <Crosshair />, perm: "findings.read" },
    ],
  },
  {
    label: "5 · Reverse engineering",
    items: [{ label: "Binary analysis", icon: <Binary />, phase: 10, flag: "reverse_engineering" }],
  },
  {
    label: "6 · Assess",
    items: [
      { label: "Scan overview", to: "/scans/overview", icon: <Gauge />, perm: "scans.read" },
      { label: "Scans", to: "/scans", icon: <Radar />, perm: "scans.read" },
      { label: "Scan schedules", to: "/scans/schedules", icon: <CalendarClock />, perm: "scans.read" },
      { label: "Scan comparison", to: "/scans/compare", icon: <GitCompareArrows />, perm: "scans.compare" },
      { label: "Import results", to: "/scans/imports", icon: <FileUp />, perm: "scans.read" },
      { label: "Findings", to: "/findings", icon: <ShieldAlert />, perm: "findings.read" },
    ],
  },
  {
    label: "7 · Validate & intelligence",
    items: [
      { label: "AI Security Analyst", to: "/ai/analyst", icon: <MessagesSquare />, perm: "ai.review" },
      { label: "AI reviews", to: "/ai", icon: <Bot />, perm: "findings.read" },
      { label: "AI reports", to: "/ai/reports", icon: <FileText />, perm: "findings.read" },
      { label: "Human Eye overview", to: "/human-review", icon: <UserCheck />, perm: "reviews.read", section: "Human Eye" },
      { label: "Review queue", to: "/human-review/queue", icon: <ListChecks />, perm: "reviews.read", section: "Human Eye" },
      { label: "Assessments", to: "/human-review/assessments", icon: <ClipboardCheck />, perm: "reviews.read", section: "Human Eye" },
      { label: "Assignments", to: "/human-review/assignments", icon: <UsersRound />, perm: "reviews.read", section: "Human Eye" },
      { label: "Review reports", to: "/human-review/reports", icon: <FileBarChart />, perm: "reviews.read", section: "Human Eye" },
    ],
  },
  {
    label: "8 · Remediate & gate",
    items: [
      { label: "Remediation workspace", to: "/remediation", icon: <Wrench />, phase: 8, flag: "remediation_workspace" },
      { label: "Policies", to: "/admin/policies", icon: <Scale />, perm: "settings.manage" },
      { label: "Component policies", to: "/sbom/policies", icon: <Scale />, perm: "sbom.read" },
      { label: "Pull request checks", to: "/pull-requests", icon: <GitPullRequest />, perm: "scans.read" },
      { label: "Risk acceptances", to: "/risk", icon: <ShieldOff />, perm: "findings.read" },
      { label: "Suppression rules", to: "/suppression-rules", icon: <FilterX />, perm: "findings.read" },
      { label: "VEX statements", to: "/vex", icon: <FileCheck2 />, perm: "findings.read" },
    ],
  },
  {
    label: "9 · Report & monitor",
    items: [
      { label: "Executive overview", to: "/executive", icon: <Presentation />, perm: "findings.read" },
      { label: "Reports", to: "/reports", icon: <FileSpreadsheet />, perm: "findings.read" },
      { label: "Application posture", to: "/posture", icon: <Gauge />, perm: "findings.read" },
      { label: "Benchmarking", to: "/posture/benchmark", icon: <BarChart3 />, perm: "findings.read" },
      { label: "Compliance", to: "/compliance", icon: <ClipboardCheck />, perm: "findings.read" },
      { label: "Developer insights", to: "/insights/developers", icon: <UserRoundSearch />, perm: "insights.people" },
      { label: "Continuous monitoring", to: "/monitoring", icon: <RadioTower />, perm: "findings.read", phase: 9, flag: "continuous_monitoring" },
    ],
  },
  {
    label: "Configurations",
    items: [
      { label: "Scan profiles", to: "/configurations/scan-profiles", icon: <SlidersHorizontal />, perm: "scans.read" },
      { label: "Scanners & workers", to: "/configurations/scanners", icon: <Server />, perm: "scanners.read" },
      { label: "Scan coverage", to: "/configurations/scan-coverage", icon: <Grid3x3 />, perm: "scanners.read" },
      { label: "Custom rules", to: "/configurations/custom-rules", icon: <FileCode2 />, perm: "scanners.read" },
      { label: "Asset settings", to: "/admin/assets", icon: <Settings2 />, perm: "assets.configure" },
      { label: "Risk & intelligence", to: "/admin/risk-intelligence", icon: <Gauge />, perm: "settings.manage" },
      { label: "Secret validation", to: "/admin/secret-validation", icon: <KeyRound />, perm: "settings.manage" },
      { label: "Review configurations", to: "/human-review/configurations", icon: <Settings2 />, perm: "reviews.read" },
      { label: "AI settings", to: "/admin/ai", icon: <Cpu />, perm: "ai.configure" },
      { label: "Reverse engineering tools", icon: <Microscope />, phase: 10, flag: "reverse_engineering" },
    ],
  },
  {
    label: "Administration",
    items: [
      { label: "Users", to: "/admin/users", icon: <Users />, perm: "users.read" },
      { label: "Organization", to: "/admin/organization", icon: <Building2 />, perm: "org.read" },
      { label: "Developer attribution", to: "/admin/developer-attribution", icon: <Fingerprint />, perm: "settings.manage" },
      { label: "Notifications", to: "/admin/notifications", icon: <BellRing />, perm: "notifications.manage" },
      { label: "AI usage", to: "/admin/ai-usage", icon: <Activity />, perm: "ai.configure" },
      { label: "MCP registry", to: "/admin/mcp", icon: <Network />, perm: "ai.review" },
      { label: "Audit log", to: "/admin/audit", icon: <FileClock />, perm: "audit.read" },
      { label: "Feature flags", to: "/admin/feature-flags", icon: <ToggleRight />, perm: "settings.manage" },
    ],
  },
];

/** Multi-tenant installs: Installation › Organizations, first in Administration, for installation administrators. */
export const installationItem: NavItem = { label: "Organizations", to: "/installation/organizations", icon: <Building2 /> };

/**
 * The item as rendered: a flagged item keeps its route only while its flag
 * is on (otherwise it is a roadmap item, disabled with its phase); an
 * enabled flagged item drops its phase badge.
 */
export function navTarget(it: NavItem, flags: Record<string, boolean>): NavItem {
  if (!it.flag) return it;
  if (it.to && flags[it.flag] === true) return { ...it, phase: undefined };
  return { ...it, to: undefined };
}

export function navGroupsFor(installationAdmin: boolean): NavGroup[] {
  if (!installationAdmin) return groups;
  return groups.map((g) => (g.label === "Administration" ? { ...g, items: [installationItem, ...g.items] } : g));
}

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

  // Scoped permissions show the entry if held anywhere; org-only ones need an org-wide grant.
  const scopedPerms = new Set(["org.read", "repos.read", "repos.manage", "scans.read", "scans.compare", "findings.read", "scanners.read", "ai.review", "sbom.read", "reviews.read"]);
  const visible = (it: NavItem) => !it.perm || (scopedPerms.has(it.perm) ? can(it.perm) : canOrgWide(it.perm));
  // Installation administration (multi-tenant installs): a person attribute,
  // not an organization permission.
  const tenancy = useMyOrganizations();
  const navGroups = navGroupsFor(!!(tenancy.data?.multi_tenant && tenancy.data.installation_admin));
  const { flags } = useFeatureFlags();

  return (
    <ShellProvider>
    <div className="flex h-full">
      <aside
        className={cn(
          "flex shrink-0 flex-col border-r border-border bg-surface transition-[width] duration-150 motion-reduce:transition-none",
          collapsed ? "w-14" : "w-64",
        )}
      >
        <div className={cn("flex h-14 items-center border-b border-border", collapsed ? "justify-center px-1" : "px-3")}>
          <BrandBlock collapsed={collapsed} />
        </div>
        <nav className="flex-1 overflow-y-auto px-2 py-3" aria-label="Main">
          {navGroups.map((g) => {
            const items = g.items.filter(visible);
            if (!items.length) return null;
            return (
              <div key={g.label} className="mb-4" role="group" aria-label={g.label}>
                {!collapsed && (
                  <div className="px-2 pb-1 text-[10.5px] font-semibold uppercase tracking-wider text-muted-foreground">{g.label}</div>
                )}
                {items.map((item, idx) => {
                  // A flagged module is a link only while its flag is on for this organization.
                  const it = navTarget(item, flags);
                  const isLive = !!it.to;
                  const active =
                    isLive &&
                    it.to &&
                    (it.to === "/" ? path === "/" : path === it.to || (path.startsWith(it.to + "/") && !items.some((o) => o.to && o.to !== it.to && path.startsWith(o.to))));
                  const cls = cn(
                    "flex h-8 items-center gap-2.5 rounded-md px-2 text-[13px] [&_svg]:size-4 [&_svg]:shrink-0",
                    active ? "bg-primary/10 font-medium text-primary" : "text-muted-foreground",
                    isLive ? "hover:bg-surface-muted hover:text-foreground" : "cursor-default opacity-60",
                  );
                  const sectionHead =
                    !collapsed && it.section && it.section !== items[idx - 1]?.section ? (
                      <div className="px-2 pt-1.5 pb-0.5 text-[11px] font-medium text-muted-foreground">{it.section}</div>
                    ) : null;
                  const content = (
                    <>
                      {it.icon}
                      {!collapsed && <span className="flex-1 truncate">{it.label}</span>}
                      {!collapsed && it.phase && !isLive && (
                        <span className="rounded bg-surface-muted px-1 text-[10px] text-muted-foreground" aria-hidden>
                          Phase {it.phase}
                        </span>
                      )}
                    </>
                  );
                  return (
                    <div key={it.label}>
                      {sectionHead}
                      {isLive ? (
                        <Link to={it.to!} className={cls} title={collapsed ? it.label : undefined} aria-current={active ? "page" : undefined}>
                          {content}
                        </Link>
                      ) : (
                        <div className={cls} title={`${it.label}: arrives in roadmap phase ${it.phase}`} aria-disabled="true" role="link">
                          {content}
                          <span className="sr-only">{`${collapsed ? it.label + ", " : ""}arrives in roadmap phase ${it.phase}`}</span>
                        </div>
                      )}
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
        <VersionBanner />
        <header className="flex h-14 shrink-0 items-center gap-2 border-b border-border bg-surface px-5">
          <PreReleaseIndicator />
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
          <OrganizationSwitcher />
          <NotificationCentre />
          <HelpMenu />
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
                <DM.Item asChild className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-[13px] outline-none data-highlighted:bg-surface-muted">
                  <Link to="/settings/tokens"><KeyRound className="size-4" /> API tokens (MCP)</Link>
                </DM.Item>
                <DM.Item asChild className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-[13px] outline-none data-highlighted:bg-surface-muted">
                  <Link to="/settings/security"><ShieldCheck className="size-4" /> Sign-in security</Link>
                </DM.Item>
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
          <PrintStamp />
        </main>
      </div>
      <Toaster />
    </div>
    </ShellProvider>
  );
}

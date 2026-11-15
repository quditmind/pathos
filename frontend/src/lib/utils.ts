import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : dtf.format(d);
}

export function initials(nameOrEmail: string): string {
  const base = nameOrEmail.includes("@") ? nameOrEmail.split("@")[0]! : nameOrEmail;
  const parts = base.split(/[\s._-]+/).filter(Boolean);
  const letters = parts.length >= 2 ? parts[0]![0]! + parts[1]![0]! : base.slice(0, 2);
  return letters.toUpperCase();
}

/** Splits an app route like "/admin/audit?outcome=denied" for router links. */
export function splitHref(href: string): { to: string; search: Record<string, string> } {
  const [to, qs] = href.split("?", 2) as [string, string | undefined];
  return { to, search: Object.fromEntries(new URLSearchParams(qs ?? "")) };
}

/** Routes that exist today; drill-down links to later-phase pages are suppressed. */
const appRoutes = ["/admin/", "/repositories", "/applications", "/findings", "/scans"];
export function isAppRoute(href: string) {
  return appRoutes.some((r) => href.startsWith(r));
}

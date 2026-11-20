import { useState, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { api } from "@/api/client";
import type { Page, User } from "@/api/types";
import { Combobox, type ComboOption } from "@/components/ui/combobox";
import { Badge, PageHeader } from "@/components/ui/primitives";
import { FeatureDisabled, LoadingSkeleton, PermissionDenied } from "@/components/ui/states";
import { useSession } from "@/features/auth/session";
import { useFeatureFlags } from "@/features/shell/meta";
import { cn } from "@/lib/utils";
import type { GuidanceEvidence } from "./api";

export const FLAG = "remediation_workspace";

const tabs = [
  { to: "/remediation", label: "Workspace" },
  { to: "/remediation/gates", label: "Gates & decisions" },
  { to: "/remediation/exceptions", label: "Exceptions & approvals" },
] as const;

/**
 * Frame of every remediation page: breadcrumb, header, the three tabs, and
 * the feature-disabled and permission-denied states (the API answers 404
 * PTH-PLAT-1007 while the flag is off; the page shows the same).
 */
export function RemediationFrame({
  title,
  description,
  actions,
  permission = "remediation.read",
  disabled,
  children,
}: {
  title: string;
  description: string;
  actions?: ReactNode;
  permission?: string;
  /** The API reported the module as disabled. */
  disabled?: boolean;
  children: ReactNode;
}) {
  const { flags, isPending } = useFeatureFlags();
  const { can } = useSession();
  const path = useRouterState({ select: (s) => s.location.pathname });
  const header = (
    <>
      <nav aria-label="Breadcrumb" className="mb-1 text-[12px] text-muted-foreground">
        8 · Remediate &amp; gate / <span className="text-foreground">{title}</span>
      </nav>
      <PageHeader title={title} description={description} actions={actions} />
    </>
  );
  if (isPending) return <LoadingSkeleton rows={4} label={`Loading ${title.toLowerCase()}`} />;
  if (flags[FLAG] !== true || disabled) {
    return (
      <>
        {header}
        <FeatureDisabled flag={FLAG} feature="The remediation workspace and security gates" />
      </>
    );
  }
  if (!can(permission)) {
    return (
      <>
        {header}
        <PermissionDenied permission={permission} what={title} />
      </>
    );
  }
  return (
    <>
      {header}
      <div className="mb-3 flex gap-1 border-b border-border" role="tablist" aria-label="Remediation views">
        {tabs.map((t) => {
          const active = t.to === "/remediation" ? path === "/remediation" || path.startsWith("/remediation/items") : path.startsWith(t.to);
          return (
            <Link
              key={t.to}
              to={t.to}
              role="tab"
              aria-selected={active}
              className={cn(
                "-mb-px border-b-2 px-3 py-2 text-[13px] font-medium",
                active ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              {t.label}
            </Link>
          );
        })}
      </div>
      {children}
    </>
  );
}

const evidenceLabel: Record<GuidanceEvidence, { label: string; tone: "success" | "warning" | "neutral" }> = {
  verified: { label: "Verified", tone: "success" },
  ai_inferred: { label: "AI-inferred", tone: "warning" },
  scanner: { label: "Scanner", tone: "neutral" },
  human: { label: "Human reviewer", tone: "neutral" },
};

/** Evidence label of a piece of guidance (prompt rule 5). */
export function EvidenceBadge({ evidence }: { evidence: GuidanceEvidence }) {
  const e = evidenceLabel[evidence] ?? { label: evidence, tone: "neutral" as const };
  return <Badge tone={e.tone}>{e.label}</Badge>;
}

/** User search (needs users.read; without it, only "assign to me" is offered by the callers). */
export function UserPicker({ value, onChange, id, label = "Owner" }: { value: ComboOption | null; onChange: (v: ComboOption | null) => void; id?: string; label?: string }) {
  return (
    <Combobox
      id={id}
      ariaLabel={label}
      className="w-64"
      placeholder="Search users…"
      queryKey="rem-user-picker"
      value={value}
      load={(q, signal) => {
        const p = new URLSearchParams({ limit: "20", status: "active" });
        if (q) p.set("q", q);
        return api<Page<User>>(`/api/v1/users?${p}`, { signal }).then((r) => r.items.map((u) => ({ value: u.id, label: u.email, description: u.display_name })));
      }}
      onChange={onChange}
    />
  );
}

/** Local state helper for a picked combobox option. */
export function useOption() {
  return useState<ComboOption | null>(null);
}

export const shortSha = (s: string | null | undefined) => (s ? s.slice(0, 12) : "—");

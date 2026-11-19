import type { ReactNode } from "react";
import { Ban, Inbox, Lock, ToggleLeft, TriangleAlert } from "lucide-react";
import { Card, EmptyState, Skeleton } from "./primitives";
import { cn } from "@/lib/utils";

/**
 * Shared page states (prompt §3.3). Loading uses skeletons, not spinners;
 * empty says what will appear and how to add the first item; partial,
 * permission denied and feature disabled name what is missing. Errors use
 * <ErrorPanel>, success uses toast.success().
 */

/** Skeleton rows for a list or table while content loads. */
export function LoadingSkeleton({ rows = 3, className, label = "Loading" }: { rows?: number; className?: string; label?: string }) {
  return (
    <div className={cn("space-y-2", className)} role="status" aria-busy="true" aria-label={label}>
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className={cn("h-9", i === 0 && "h-10")} />
      ))}
      <span className="sr-only">{label}…</span>
    </div>
  );
}

/** Nothing yet: what will appear here and how to add the first item. */
export function EmptyStateCard({ title, children, action, icon = <Inbox /> }: { title: string; children?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <Card>
      <EmptyState icon={icon} title={title}>
        {children}
        {action && <div className="mt-3 flex justify-center">{action}</div>}
      </EmptyState>
    </Card>
  );
}

/** Some data loaded, some did not: says which part is missing. */
export function PartialData({ missing, children }: { missing: string[]; children?: ReactNode }) {
  return (
    <div role="status" className="flex items-start gap-2 rounded-md bg-warning-soft px-3 py-2 text-[13px] text-warning">
      <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div>
        <span className="font-medium">Partial data.</span> Not loaded: {missing.join(", ")}.{children && <> {children}</>}
      </div>
    </div>
  );
}

/** The caller lacks a permission; names it. */
export function PermissionDenied({ permission, what }: { permission: string; what?: string }) {
  return (
    <Card>
      <EmptyState icon={<Lock />} title="You do not have access to this">
        {what ? `${what} needs` : "This needs"} the <code className="rounded bg-surface-muted px-1">{permission}</code> permission. Ask an
        administrator to grant a role that includes it.
      </EmptyState>
    </Card>
  );
}

/** A module behind a feature flag that is off for this organization. */
export function FeatureDisabled({ flag, feature, enabledBy = "An administrator with the settings.manage permission" }: { flag: string; feature: string; enabledBy?: string }) {
  return (
    <Card>
      <EmptyState icon={<ToggleLeft />} title={`${feature} is not enabled`}>
        It is behind the feature flag <code className="rounded bg-surface-muted px-1">{flag}</code>, which is off for this organization.{" "}
        {enabledBy} can turn it on under Administration.
      </EmptyState>
    </Card>
  );
}

/** A roadmap item that is not built yet. */
export function NotAvailable({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1 text-[12px] text-muted-foreground">
      <Ban className="size-3.5" aria-hidden /> {children}
    </span>
  );
}

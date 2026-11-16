import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import type { UseQueryResult } from "@tanstack/react-query";
import type { RepositoryInsights } from "@/api/types";
import { Alert, Skeleton } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";

function Stat({ label, value, to, search, tone, sub }: { label: string; value: ReactNode; to: string; search?: Record<string, string | boolean>; tone?: "danger" | "warning"; sub?: ReactNode }) {
  return (
    <Link
      to={to as never}
      search={search as never}
      className="flex flex-col rounded-lg border border-border bg-surface px-3 py-2.5 transition-colors hover:border-primary/40 focus-visible:outline-2 focus-visible:outline-ring"
      aria-label={`${label}: ${typeof value === "string" || typeof value === "number" ? value : ""}. View details`}
    >
      <span className="text-[11.5px] font-medium text-muted-foreground">{label}</span>
      <span className={`tabular mt-0.5 text-xl font-semibold tracking-tight ${tone === "danger" ? "text-danger" : tone === "warning" ? "text-warning" : ""}`}>{value}</span>
      {sub && <span className="text-[11px] text-muted-foreground">{sub}</span>}
    </Link>
  );
}

const grid = "mb-3 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5 xl:grid-cols-7";

/** KPI strip for the repository list; each card links to the matching filtered list or import history. */
export function RepoKpis({ insights }: { insights: UseQueryResult<RepositoryInsights> }) {
  if (insights.isError) {
    return (
      <div className="mb-3">
        <Alert tone="warning">
          Repository insights are unavailable: {insights.error.message}{" "}
          <button className="underline" onClick={() => void insights.refetch()}>
            Retry
          </button>
        </Alert>
      </div>
    );
  }
  if (!insights.data) {
    return (
      <div className={grid}>
        {Array.from({ length: 14 }, (_, i) => (
          <Skeleton key={i} className="h-[68px]" />
        ))}
      </div>
    );
  }
  const t = insights.data.totals;
  const r = "/repositories";
  return (
    <div className={grid} aria-label="Repository indicators">
      <Stat label="Total" value={t.total} to={r} search={{ status: "all" }} />
      <Stat label="Active" value={t.active} to={r} />
      <Stat label="Archived" value={t.archived} to={r} search={{ status: "archived" }} />
      <Stat label="Pending imports" value={t.pending_imports} to="/repositories/imports" search={{ status: "active" }} />
      <Stat label="Failed imports" value={t.failed_imports} to="/repositories/imports" search={{ status: "finished" }} tone={t.failed_imports ? "danger" : undefined} />
      <Stat label="Critical" value={t.critical} to={r} search={{ criticality: "critical" }} />
      <Stat label="No business owner" value={t.without_business_owner} to={r} search={{ missing_owner: "business" }} tone={t.without_business_owner ? "warning" : undefined} />
      <Stat label="No technical owner" value={t.without_technical_owner} to={r} search={{ missing_owner: "technical" }} tone={t.without_technical_owner ? "warning" : undefined} />
      <Stat label="Missing ownership" value={t.missing_ownership} to={r} search={{ missing_owner: "any" }} tone={t.missing_ownership ? "warning" : undefined} />
      <Stat label="Publicly exposed" value={t.publicly_exposed} to={r} search={{ public_exposure: "yes" }} tone={t.publicly_exposed ? "danger" : undefined} />
      <Stat label="Not public" value={t.not_public} to={r} search={{ public_exposure: "no" }} />
      <Stat label="Unknown exposure" value={t.exposure_unknown} to={r} search={{ public_exposure: "unknown" }} tone={t.exposure_unknown ? "warning" : undefined} />
      <Stat label="Missing production URL" value={t.missing_production_url} to={r} search={{ missing_production_url: true }} />
      <Stat
        label="Last successful sync"
        value={<span className="text-[13px]">{formatDateTime(t.last_successful_sync_at)}</span>}
        to={r}
        search={t.sync_failures ? { sync_status: "failed" } : { sort: "-last_sync_at" }}
        sub={t.sync_failures ? <span className="text-danger">{t.sync_failures} sync failures</span> : undefined}
      />
    </div>
  );
}

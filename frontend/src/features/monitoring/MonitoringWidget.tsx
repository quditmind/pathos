import { Link } from "@tanstack/react-router";
import { ExternalLink } from "lucide-react";
import { SeverityBadge } from "@/components/data/Severity";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Badge, Card, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { useFeatureFlag } from "@/features/shell/meta";
import { formatDateTime } from "@/lib/utils";
import { driftCategories, isFeatureDisabled, shortSha, useDrifts, useEvents } from "./api";
import { EventCard } from "./shared";

/**
 * The application profile's Monitoring card (Overview tab, PATHOS 3.0 M9):
 * the application's latest five feed events and latest architecture drift,
 * with a link to Continuous monitoring filtered to the application. Hidden
 * while the `continuous_monitoring` flag is off.
 */
export function MonitoringWidget({ applicationId }: { applicationId: string }) {
  const on = useFeatureFlag("continuous_monitoring");
  const { can } = useSession();
  const allowed = can("findings.read");
  const events = useEvents({ application_id: applicationId }, undefined, 5, on && allowed);
  const drift = useDrifts(applicationId, true, undefined, 1, on && allowed);
  if (!on || isFeatureDisabled(events.error)) return null;
  const latest = drift.data?.items[0];
  return (
    <Card className="p-4" data-testid="monitoring-widget">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[14px] font-semibold">Monitoring</h2>
        {allowed && (
          <Link to="/monitoring" search={{ application_id: applicationId } as never} className="inline-flex items-center gap-1 text-[12.5px] text-primary hover:underline">
            Open in Continuous monitoring <ExternalLink className="size-3" aria-hidden />
          </Link>
        )}
      </div>
      {!allowed ? (
        <p className="text-[13px] text-muted-foreground">
          Viewing monitoring events requires the <code>findings.read</code> permission.
        </p>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
          <section aria-label="Latest events">
            <h3 className="mb-1.5 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">Latest events</h3>
            {events.isPending ? (
              <Skeleton className="h-24" />
            ) : events.isError ? (
              <ErrorPanel error={events.error} title="Monitoring events could not be loaded" onVerify={() => events.refetch()} />
            ) : !events.data.items.length ? (
              <p className="text-[13px] text-muted-foreground">
                No monitoring events for this application yet. They appear as commits, dependency and architecture changes, new intelligence, fixes, gate
                results and new findings are processed.
              </p>
            ) : (
              <ol className="space-y-1.5">
                {events.data.items.map((e) => (
                  <li key={e.id}>
                    <EventCard e={e} compact />
                  </li>
                ))}
              </ol>
            )}
          </section>
          <section aria-label="Latest architecture drift">
            <h3 className="mb-1.5 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">Latest architecture drift</h3>
            {drift.isPending ? (
              <Skeleton className="h-16" />
            ) : drift.isError ? (
              isFeatureDisabled(drift.error) ? null : <ErrorPanel error={drift.error} title="Architecture drift could not be loaded" onVerify={() => drift.refetch()} />
            ) : !latest ? (
              <p className="text-[13px] text-muted-foreground">No architecture drift yet. It appears when a new CodeGraph snapshot differs from the previous one.</p>
            ) : (
              <Link
                to="/monitoring"
                search={{ application_id: applicationId, tab: "drift", drift: latest.id } as never}
                className="block rounded-md border border-border p-3 text-[12.5px] hover:bg-surface-muted/60"
              >
                <div className="mb-1 flex flex-wrap items-center gap-1.5">
                  <SeverityBadge value={latest.severity} />
                  {latest.repository_name && <span className="text-muted-foreground">{latest.repository_name}</span>}
                  <time dateTime={latest.created_at} className="ml-auto text-[11.5px] text-muted-foreground">
                    {formatDateTime(latest.created_at)}
                  </time>
                </div>
                <div className="font-mono text-[11.5px]">
                  {shortSha(latest.from_commit) || "baseline"} → {shortSha(latest.to_commit)}
                </div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {driftCategories.map((c) => {
                    const n = (latest.counts?.[c.added] ?? 0) + (latest.counts?.[c.removed] ?? 0) + (c.changed ? (latest.counts?.[c.changed] ?? 0) : 0);
                    return n ? (
                      <Badge key={c.label}>
                        {c.label}: {n}
                      </Badge>
                    ) : null;
                  })}
                </div>
              </Link>
            )}
          </section>
        </div>
      )}
    </Card>
  );
}

import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { Workflow } from "lucide-react";
import { CriticalityBadge } from "@/components/data/TagChip";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Badge, Card, EmptyState, PageHeader, Table, Td, Th } from "@/components/ui/primitives";
import { FeatureDisabled, LoadingSkeleton } from "@/components/ui/states";
import { useFeatureFlag, useFeatureFlags } from "@/features/shell/meta";
import { formatDateTime } from "@/lib/utils";
import { useLifecycleOverview, type AppLifecycle, type Phase } from "./api";
import { PhaseCell, phaseShort } from "./LifecycleStrip";

const phaseTitles = ["Connect", "Inventory", "Discover", "Threat model", "Reverse engineering", "Assess", "Validate & intelligence", "Remediate & gate", "Report & monitor"];

/** Where each phase's data lives (only linked when the phase has data). */
function phaseLink(a: AppLifecycle, p: Phase, hub: boolean, children: ReactNode): ReactNode {
  if (!p.has_data) return children;
  const cls = "inline-flex rounded focus-visible:outline-2 focus-visible:outline-ring";
  const label = `${a.name}: ${p.title}`;
  switch (p.key) {
    case "connect":
      return <Link to="/repositories" search={{ application_id: a.id } as never} className={cls} aria-label={label}>{children}</Link>;
    case "inventory":
      return hub ? (
        <Link to="/applications/$id" params={{ id: a.id }} search={{ tab: "classification" } as never} className={cls} aria-label={label}>{children}</Link>
      ) : (
        <Link to="/applications" search={{ app: a.id } as never} className={cls} aria-label={label}>{children}</Link>
      );
    case "discover":
      return hub ? (
        <Link to="/applications/$id" params={{ id: a.id }} search={{ tab: (p.metrics?.codegraph_snapshots ?? 0) > 0 ? "codegraph" : "sbom" } as never} className={cls} aria-label={label}>{children}</Link>
      ) : (
        <Link to="/sbom" className={cls} aria-label={label}>{children}</Link>
      );
    case "threat_model":
      return hub ? (
        <Link to="/applications/$id" params={{ id: a.id }} search={{ tab: "threat-model" } as never} className={cls} aria-label={label}>{children}</Link>
      ) : (
        <Link to="/threat-models" search={{ application: a.id } as never} className={cls} aria-label={label}>{children}</Link>
      );
    case "assess":
      return <Link to="/findings" search={{ application_id: a.id } as never} className={cls} aria-label={label}>{children}</Link>;
    case "validate":
      return <Link to="/ai" className={cls} aria-label={label}>{children}</Link>;
    case "remediate":
      return (p.metrics?.remediation_items ?? 0) > 0 ? (
        <Link to="/remediation" search={{ application_id: a.id } as never} className={cls} aria-label={label}>{children}</Link>
      ) : (
        <Link to="/risk" className={cls} aria-label={label}>{children}</Link>
      );
    case "report":
      return (p.metrics?.monitoring_events ?? 0) > 0 || (p.metrics?.drift_changes ?? 0) > 0 ? (
        <Link to="/monitoring" search={{ application_id: a.id } as never} className={cls} aria-label={label}>{children}</Link>
      ) : (
        <Link to="/applications/$id/versions" params={{ id: a.id }} className={cls} aria-label={label}>{children}</Link>
      );
  }
  return children;
}

/** /lifecycle (flag "lifecycle_overview"): every application and which of the nine phases hold real data. */
export function LifecyclePage() {
  const { isPending: flagsPending } = useFeatureFlags();
  const enabled = useFeatureFlag("lifecycle_overview");
  const hub = useFeatureFlag("onboarding");
  const data = useLifecycleOverview(enabled);
  if (flagsPending) return <LoadingSkeleton rows={4} />;
  if (!enabled) {
    return (
      <>
        <PageHeader title="Lifecycle overview" />
        <FeatureDisabled flag="lifecycle_overview" feature="The lifecycle overview" />
      </>
    );
  }
  const items = data.data?.items ?? [];
  return (
    <>
      <PageHeader
        title="Lifecycle overview"
        description="Every application and which of the nine lifecycle phases already hold real data. Phases without data say so; hover a cell for its counts."
      />
      {data.isError && <ErrorPanel error={data.error} onVerify={() => data.refetch()} />}
      <Card>
        {data.isPending ? (
          <LoadingSkeleton rows={6} label="Loading the lifecycle overview" />
        ) : !items.length ? (
          <EmptyState icon={<Workflow />} title="No applications yet">
            Onboard an application to follow it through the lifecycle.
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <thead className="sticky top-0 bg-surface">
                <tr>
                  <Th>Application</Th>
                  {phaseTitles.map((t, i) => (
                    <Th key={t} className="text-center">
                      <span title={t}>
                        {i + 1}
                        <span className="block text-[10px] font-normal normal-case">{phaseShort[Object.keys(phaseShort)[i]!]}</span>
                      </span>
                    </Th>
                  ))}
                  <Th>Phases with data</Th>
                  <Th>Last scan</Th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.id}>
                    <Td>
                      {hub ? (
                        <Link to="/applications/$id" params={{ id: a.id }} className="font-medium text-primary hover:underline">
                          {a.name}
                        </Link>
                      ) : (
                        <Link to="/applications" search={{ app: a.id } as never} className="font-medium text-primary hover:underline">
                          {a.name}
                        </Link>
                      )}
                      <div className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
                        <span className="font-mono">{a.application_key}</span>
                        <CriticalityBadge value={a.criticality} />
                        {a.onboarding_status === "draft" && <Badge tone="warning">Onboarding</Badge>}
                      </div>
                    </Td>
                    {a.phases.map((p) => (
                      <Td key={p.key} className="text-center">
                        {phaseLink(a, p, hub, <PhaseCell p={p} compact />)}
                      </Td>
                    ))}
                    <Td className="tabular text-center">{a.phases_with_data} / 9</Td>
                    <Td className="whitespace-nowrap text-[12px] text-muted-foreground">{a.last_scan_at ? formatDateTime(a.last_scan_at) : "Never"}</Td>
                  </tr>
                ))}
              </tbody>
              <tfoot>
                <tr>
                  <Td className="text-[12px] font-medium">Applications with data</Td>
                  {(data.data?.phase_totals ?? []).map((n, i) => (
                    <Td key={i} className="tabular text-center text-[12px]">
                      {n}
                    </Td>
                  ))}
                  <Td />
                  <Td />
                </tr>
              </tfoot>
            </Table>
          </div>
        )}
      </Card>
      {data.data?.truncated && <p className="mt-2 text-[12px] text-muted-foreground">Showing the first 500 applications by name.</p>}
      <p className="mt-3 flex flex-wrap gap-3 text-[12px] text-muted-foreground">
        <span className="inline-flex items-center gap-1"><span className="inline-block size-3 rounded bg-success-soft" aria-hidden /> Has data</span>
        <span className="inline-flex items-center gap-1"><span className="inline-block size-3 rounded border border-dashed border-border" aria-hidden /> No data yet</span>
        <span className="inline-flex items-center gap-1"><span className="inline-block size-3 rounded bg-surface-muted" aria-hidden /> Not available (module not enabled)</span>
      </p>
    </>
  );
}

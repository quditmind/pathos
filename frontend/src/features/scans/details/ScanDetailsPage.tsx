import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { ArrowLeft, RotateCcw, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Alert, PageHeader, Skeleton } from "@/components/ui/primitives";
import { JobStatusPill } from "@/components/data/Severity";
import { useSession } from "@/features/auth/session";
import { cancelScan, isActive, retryScan, useScan, useScanMutation } from "../api";
import { Tabs } from "../shared";
import { OverviewTab } from "./OverviewTab";
import { FindingsTab } from "./FindingsTab";
import { LogsTab } from "./LogsTab";
import { StagesTab } from "./StagesTab";
import { ConfigurationTab } from "./ConfigurationTab";
import { HistoryTab } from "./HistoryTab";
import { ScanMaterialChanges } from "@/features/insights/MaterialChanges";

export const detailTabs = [
  ["overview", "Overview"],
  ["findings", "Findings"],
  ["material", "Material changes"],
  ["logs", "Execution Logs"],
  ["stages", "Stages"],
  ["configuration", "Configuration"],
  ["history", "History"],
] as const;
export type DetailTab = (typeof detailTabs)[number][0];

export type DetailsSearch = { tab?: DetailTab };
export const validateDetailsSearch = (s: Record<string, unknown>): DetailsSearch =>
  detailTabs.some(([k]) => k === s.tab) ? { tab: s.tab as DetailTab } : {};

export function ScanDetailsPage() {
  const { id } = useParams({ strict: false }) as { id: string };
  return <ScanDetails id={id} />;
}

/** Execution details with seven tabs; the active tab lives in the URL (?tab=). */
export function ScanDetails({ id }: { id: string }) {
  const search = useSearch({ strict: false }) as DetailsSearch;
  const tab: DetailTab = validateDetailsSearch(search).tab ?? "overview";
  const navigate = useNavigate();
  const { can } = useSession();
  const scan = useScan(id);
  const cancel = useScanMutation(cancelScan);
  const retry = useScanMutation(retryScan);
  const j = scan.data;
  const setTab = (t: DetailTab) => void navigate({ to: ".", search: (t === "overview" ? {} : { tab: t }) as never, replace: true });
  const canRetry = j && (j.status === "failed" || j.status === "partial" || j.status === "cancelled");

  return (
    <>
      <Link to="/scans" className="mb-3 inline-flex items-center gap-1 text-[12px] text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-3.5" /> Scans
      </Link>
      {scan.isError ? (
        <Alert>Could not load the execution: {scan.error.message}</Alert>
      ) : !j ? (
        <Skeleton className="h-40" />
      ) : (
        <>
          <PageHeader
            title={j.name || `${j.repository_name} scan`}
            description={`${j.scan_key} · ${j.repository_name}${j.repository_key ? ` (${j.repository_key})` : ""} · ${j.profile_name} v${j.profile_version}`}
            actions={
              <>
                <JobStatusPill status={j.status} />
                {can("scans.run") && isActive(j) && (
                  <Button variant="danger-outline" disabled={cancel.isPending} onClick={() => cancel.mutate(j.id)}>
                    <Square /> Cancel
                  </Button>
                )}
                {can("scans.run") && canRetry && (
                  <Button
                    variant="secondary"
                    disabled={retry.isPending}
                    onClick={() => retry.mutate(j.id, { onSuccess: (nj) => void navigate({ to: "/scans/$id", params: { id: nj.id } }) })}
                  >
                    <RotateCcw /> Retry
                  </Button>
                )}
              </>
            }
          />
          {(cancel.error ?? retry.error) && (
            <div className="mb-3">
              <Alert>{(cancel.error ?? retry.error)!.message}</Alert>
            </div>
          )}
          <Tabs tabs={detailTabs} value={tab} onChange={setTab} label="Execution sections" idPrefix="scan" />
          <div role="tabpanel" id={`scan-panel-${tab}`} aria-labelledby={`scan-tab-${tab}`} className="pt-4">
            {tab === "overview" && <OverviewTab job={j} />}
            {tab === "findings" && <FindingsTab job={j} />}
            {tab === "material" && <ScanMaterialChanges jobId={j.id} />}
            {tab === "logs" && <LogsTab job={j} />}
            {tab === "stages" && <StagesTab job={j} />}
            {tab === "configuration" && <ConfigurationTab job={j} />}
            {tab === "history" && <HistoryTab job={j} />}
          </div>
        </>
      )}
    </>
  );
}

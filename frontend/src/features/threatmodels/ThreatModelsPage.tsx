import { useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { FileUp, Plus, ShieldHalf } from "lucide-react";
import { ApiError } from "@/api/client";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Card, PageHeader, Select, Table, Td, Th } from "@/components/ui/primitives";
import { EmptyStateCard, FeatureDisabled, LoadingSkeleton, PermissionDenied } from "@/components/ui/states";
import { useSession } from "@/features/auth/session";
import { useApplications } from "@/features/repos/api";
import { useFeatureFlags } from "@/features/shell/meta";
import { formatDateTime } from "@/lib/utils";
import { modelStatuses, statusLabel, threatSeverities, useThreatModels, type ThreatModel } from "./api";
import { ModelStatusBadge } from "./badges";
import { CreateModelDialog, ImportModelDialog } from "./dialogs";
import type { ThreatModelsSearch } from "./search";

export function SeverityCounts({ m }: { m: ThreatModel }) {
  const by = m.counts?.by_severity ?? {};
  const present = threatSeverities.filter((s) => (by[s] ?? 0) > 0);
  if (!present.length) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {present.map((s) => (
        <span key={s} className="inline-flex items-center gap-0.5 text-[12px]">
          <SeverityBadge value={s} /> {by[s]}
        </span>
      ))}
    </span>
  );
}

/** The list of threat models (latest version of each), with filters, create and import. */
export function ThreatModelList({ applicationId, status, onFilter }: { applicationId?: string; status?: string; onFilter?: (s: ThreatModelsSearch) => void }) {
  const { can } = useSession();
  const apps = useApplications();
  const q = useThreatModels({ application_id: applicationId, status });
  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState(false);
  const manage = can("threats.manage");
  const actions = manage && (
    <div className="flex gap-2">
      <Button size="sm" onClick={() => setCreating(true)}>
        <Plus /> New threat model
      </Button>
      <Button size="sm" variant="secondary" onClick={() => setImporting(true)}>
        <FileUp /> Import
      </Button>
    </div>
  );
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        {onFilter && (
          <>
            <label className="flex items-center gap-1.5 text-[13px]">
              Application
              <Select aria-label="Application" value={applicationId ?? ""} onChange={(e) => onFilter({ application: e.target.value || undefined, status })} className="h-8 w-auto">
                <option value="">All applications</option>
                {(apps.data ?? []).map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </Select>
            </label>
            <label className="flex items-center gap-1.5 text-[13px]">
              Status
              <Select aria-label="Status" value={status ?? ""} onChange={(e) => onFilter({ application: applicationId, status: e.target.value || undefined })} className="h-8 w-auto">
                <option value="">Any</option>
                {modelStatuses.map((s) => (
                  <option key={s} value={s}>
                    {statusLabel[s]}
                  </option>
                ))}
              </Select>
            </label>
          </>
        )}
        <span className="ml-auto">{actions}</span>
      </div>
      {q.isPending ? (
        <LoadingSkeleton rows={5} label="Loading threat models" />
      ) : q.isError ? (
        q.error instanceof ApiError && q.error.status === 403 ? (
          <PermissionDenied permission="threats.read" what="Viewing threat models" />
        ) : (
          <ErrorPanel error={q.error} title="Could not load the threat models" onVerify={() => q.refetch()} />
        )
      ) : q.data.length === 0 ? (
        <EmptyStateCard icon={<ShieldHalf />} title={applicationId || status ? "No threat model matches" : "No threat models yet"} action={actions || undefined}>
          A threat model is generated from an application's CodeGraph (STRIDE rules on its routes, data stores, data flows and trust boundaries) and its attack paths. You can also
          import an OWASP Threat Dragon or PATHOS JSON model.
        </EmptyStateCard>
      ) : (
        <Card className="overflow-x-auto">
          <Table>
            <thead>
              <tr>
                <Th>Threat model</Th>
                <Th>Application</Th>
                <Th>Status</Th>
                <Th>Version</Th>
                <Th>Open threats</Th>
                <Th>Unverified</Th>
                <Th>Updated</Th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((m) => (
                <tr key={m.id} data-testid="model-row">
                  <Td>
                    <Link to="/threat-models/$modelId" params={{ modelId: m.id }} className="text-primary underline">
                      {m.title}
                    </Link>
                  </Td>
                  <Td>
                    {m.application_name ?? "—"}
                    {m.repository_name ? <span className="text-muted-foreground"> / {m.repository_name}</span> : null}
                  </Td>
                  <Td>
                    <ModelStatusBadge status={m.status} />
                  </Td>
                  <Td>v{m.version}</Td>
                  <Td>
                    <span className="mr-2">{m.counts?.open ?? 0}</span>
                    <SeverityCounts m={m} />
                  </Td>
                  <Td>{m.counts?.unverified ?? 0}</Td>
                  <Td>{formatDateTime(m.updated_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      )}
      {manage && <CreateModelDialog open={creating} onOpenChange={setCreating} applicationId={onFilter ? undefined : applicationId} />}
      {manage && <ImportModelDialog open={importing} onOpenChange={setImporting} applicationId={onFilter ? undefined : applicationId} />}
    </div>
  );
}

/** /threat-models */
export function ThreatModelsPage() {
  const search = useSearch({ strict: false }) as ThreatModelsSearch;
  const navigate = useNavigate();
  const { flags, isPending } = useFeatureFlags();
  const header = (
    <PageHeader
      title="Threat models"
      description="STRIDE threat models of your applications, generated from the CodeGraph and the attack paths, edited and approved by people. Each threat shows its evidence: verified from code, observed at runtime, or imported and not yet verified."
    />
  );
  if (isPending) return <>{header}<LoadingSkeleton rows={4} /></>;
  if (!flags.threat_models) return <>{header}<FeatureDisabled flag="threat_models" feature="Threat models" /></>;
  return (
    <>
      {header}
      <ThreatModelList
        applicationId={search.application}
        status={search.status}
        onFilter={(s) => void navigate({ to: "/threat-models", search: s as never, replace: true })}
      />
    </>
  );
}

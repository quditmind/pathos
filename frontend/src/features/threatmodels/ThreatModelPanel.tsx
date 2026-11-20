import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { Plus, ShieldHalf } from "lucide-react";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Card } from "@/components/ui/primitives";
import { EmptyStateCard, FeatureDisabled, LoadingSkeleton } from "@/components/ui/states";
import { useSession } from "@/features/auth/session";
import { useFeatureFlags } from "@/features/shell/meta";
import { categoryLabel, useThreatModels, useThreats, type ThreatModel } from "./api";
import { EvidenceLabel, ModelStatusBadge } from "./badges";
import { CreateModelDialog } from "./dialogs";
import { filterThreats, emptyThreatFilters } from "./threats";
import { SeverityCounts } from "./ThreatModelsPage";

function TopThreats({ model }: { model: ThreatModel }) {
  const t = useThreats(model.id);
  if (t.isPending) return <LoadingSkeleton rows={3} label="Loading threats" />;
  if (t.isError) return <ErrorPanel error={t.error} title="Could not load the threats" onVerify={() => t.refetch()} />;
  const top = filterThreats(t.data, { ...emptyThreatFilters, status: "open" }).slice(0, 5);
  if (!top.length) return <p className="text-[13px] text-muted-foreground">No open threats.</p>;
  return (
    <ul className="space-y-1" aria-label="Top open threats">
      {top.map((x) => (
        <li key={x.id} className="flex flex-wrap items-center gap-2 text-[13px]">
          <SeverityBadge value={x.severity} />
          <Link to="/threat-models/$modelId" params={{ modelId: model.id }} search={{ threat: x.id } as never} className="text-primary underline">
            {x.title}
          </Link>
          <span className="text-[12px] text-muted-foreground">{categoryLabel[x.category]}</span>
          <EvidenceLabel threat={x} />
        </li>
      ))}
    </ul>
  );
}

/** Application hub tab: the application's threat models, their status and top open threats. */
export function ThreatModelPanel({ applicationId }: { applicationId: string }) {
  const { flags, isPending } = useFeatureFlags();
  const enabled = flags.threat_models === true;
  const { can } = useSession();
  const q = useThreatModels({ application_id: applicationId }, enabled);
  const [creating, setCreating] = useState(false);
  if (isPending) return <LoadingSkeleton rows={3} label="Loading threat models" />;
  if (!enabled) return <FeatureDisabled flag="threat_models" feature="Threat models" />;
  if (q.isPending) return <LoadingSkeleton rows={4} label="Loading threat models" />;
  if (q.isError) return <ErrorPanel error={q.error} title="Could not load the threat models" onVerify={() => q.refetch()} />;
  const manage = can("threats.manage");
  const create = manage && (
    <Button size="sm" onClick={() => setCreating(true)}>
      <Plus /> Create threat model
    </Button>
  );
  return (
    <div className="space-y-3">
      {q.data.length === 0 ? (
        <EmptyStateCard icon={<ShieldHalf />} title="No threat model yet" action={create || undefined}>
          Generate one from the application's CodeGraph: STRIDE threats for its routes, data stores, data flows and trust boundaries, plus its attack paths.
        </EmptyStateCard>
      ) : (
        q.data.map((m) => (
          <Card key={m.id} className="space-y-2 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <Link to="/threat-models/$modelId" params={{ modelId: m.id }} className="font-medium text-primary underline">
                {m.title}
              </Link>
              <ModelStatusBadge status={m.status} />
              <span className="text-[12px] text-muted-foreground">v{m.version}</span>
              {m.repository_name && <span className="text-[12px] text-muted-foreground">{m.repository_name}</span>}
            </div>
            <div className="flex flex-wrap items-center gap-4 text-[12px]">
              <span>
                <strong>{m.counts?.open ?? 0}</strong> open of {m.counts?.total ?? 0}
              </span>
              <SeverityCounts m={m} />
              {(m.counts?.unverified ?? 0) > 0 && <span className="text-warning">{m.counts?.unverified} unverified</span>}
            </div>
            <TopThreats model={m} />
          </Card>
        ))
      )}
      {manage && <CreateModelDialog open={creating} onOpenChange={setCreating} applicationId={applicationId} />}
    </div>
  );
}

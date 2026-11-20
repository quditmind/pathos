import { useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { ScrollText } from "lucide-react";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Card, PageHeader, Select, Table, Td, Th } from "@/components/ui/primitives";
import { EmptyStateCard, FeatureDisabled, LoadingSkeleton, PermissionDenied } from "@/components/ui/states";
import { useSession } from "@/features/auth/session";
import { useFeatureFlags } from "@/features/shell/meta";
import { formatDateTime } from "@/lib/utils";
import { AIInferredLabel, EvidenceRecordCard, LocationBadge } from "./AIEvidencePanel";
import { decisionLabel, evidenceKeys, fetchEvidence, useEvidenceDetail, type EvidenceFilters } from "./evidence";

const tasks: [string, string][] = [
  ["finding_validation", "Triage and review"],
  ["fix_proposal", "Fix proposals"],
  ["troubleshooting", "Troubleshooting"],
  ["threat_suggestion", "Threat suggestions"],
  ["correlation", "Correlation"],
  ["analyst", "Analyst chat"],
  ["report", "Report narratives"],
];

function Filter({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: [string, string][] }) {
  return (
    <Select aria-label={label} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{label}: all</option>
      {options.map(([v, l]) => (
        <option key={v} value={v}>
          {l}
        </option>
      ))}
    </Select>
  );
}

function RecordDrawer({ id, onClose }: { id?: string; onClose: () => void }) {
  const q = useEvidenceDetail(id);
  return (
    <Dialog side size="lg" open={!!id} onOpenChange={(o) => !o && onClose()} title="AI evidence record" description={q.data?.record.task_label}>
      {q.isPending ? (
        <LoadingSkeleton rows={4} label="Loading the record" />
      ) : q.isError ? (
        <ErrorPanel error={q.error} title="Could not load the record" onVerify={() => q.refetch()} />
      ) : (
        <div className="space-y-3 text-[13px]">
          <EvidenceRecordCard record={q.data.record} />
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[12px]">
            <dt className="text-muted-foreground">Subject</dt>
            <dd>
              {q.data.record.subject_kind.replaceAll("_", " ")} <span className="font-mono">{q.data.record.subject_id ?? "—"}</span>
            </dd>
            <dt className="text-muted-foreground">Operation</dt>
            <dd>{q.data.record.operation}</dd>
            <dt className="text-muted-foreground">Parameters</dt>
            <dd className="font-mono text-[11px]">{JSON.stringify(q.data.record.parameters)}</dd>
            <dt className="text-muted-foreground">Response SHA-256</dt>
            <dd className="break-all font-mono text-[11px]">{q.data.record.response_sha256 || "—"}</dd>
            <dt className="text-muted-foreground">Related</dt>
            <dd className="break-all font-mono text-[11px]">{JSON.stringify(q.data.record.related)}</dd>
            <dt className="text-muted-foreground">Prompt kept until</dt>
            <dd>{q.data.record.payload_expires_at ? formatDateTime(q.data.record.payload_expires_at) : "not stored"}</dd>
          </dl>
          {q.data.related_records.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-[13px] font-semibold">Items and replays</h3>
              {q.data.related_records.map((r) => (
                <EvidenceRecordCard key={r.id} record={r} />
              ))}
            </div>
          )}
        </div>
      )}
    </Dialog>
  );
}

/** 7 · Validate & intelligence → AI evidence log (M7, flag ai_intelligence). */
export function AIEvidencePage() {
  const { flags, isPending } = useFeatureFlags();
  const { can } = useSession();
  const [f, setF] = useState<EvidenceFilters>({});
  const [open, setOpen] = useState<string>();
  const on = flags.ai_intelligence === true;
  const q = useInfiniteQuery({
    queryKey: [...evidenceKeys.list(f), "pages"],
    queryFn: ({ pageParam }) => fetchEvidence({ ...f, limit: 50, cursor: pageParam || undefined }),
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
    enabled: on && can("ai.evidence_read"),
  });
  const header = (
    <PageHeader
      title="AI evidence log"
      description="Every AI decision or conclusion PATHOS stored, with its model, prompt, reasoning, confidence and the person who decided it. AI conclusions are labelled AI-inferred until a person confirms them; none closes or suppresses anything by itself."
    />
  );
  if (isPending) return <LoadingSkeleton rows={4} />;
  if (!on)
    return (
      <>
        {header}
        <FeatureDisabled flag="ai_intelligence" feature="AI security intelligence" />
      </>
    );
  if (!can("ai.evidence_read"))
    return (
      <>
        {header}
        <PermissionDenied permission="ai.evidence_read" what="The AI evidence log" />
      </>
    );
  const set = (k: keyof EvidenceFilters) => (v: string) => setF({ ...f, [k]: v || undefined });
  const items = q.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <>
      {header}
      <Card className="mb-3 flex flex-wrap items-center gap-2 p-3">
        <Filter label="Task" value={f.task ?? ""} onChange={set("task")} options={tasks} />
        <Filter label="Decision" value={f.review_decision ?? ""} onChange={set("review_decision")} options={Object.entries(decisionLabel)} />
        <Filter label="Model location" value={f.provider_location ?? ""} onChange={set("provider_location")} options={[["local", "Local"], ["cloud", "Cloud"], ["user", "Person's own assistant"]]} />
        <Filter label="Status" value={f.status ?? ""} onChange={set("status")} options={[["succeeded", "Succeeded"], ["invalid_output", "Invalid output"], ["failed", "Failed"], ["disabled", "Refused"]]} />
      </Card>
      {q.isPending ? (
        <LoadingSkeleton rows={6} label="Loading AI evidence" />
      ) : q.isError ? (
        q.error instanceof ApiError && q.error.status === 403 ? (
          <PermissionDenied permission="ai.evidence_read" what="The AI evidence log" />
        ) : (
          <ErrorPanel error={q.error} title="Could not load the AI evidence log" onVerify={() => q.refetch()} />
        )
      ) : items.length === 0 ? (
        <EmptyStateCard icon={<ScrollText />} title="No AI evidence yet">
          Records appear here when PATHOS asks a model for a review, a suggestion, a fix, a troubleshooting answer, a threat or a correlation. Change the
          filters if you set any.
        </EmptyStateCard>
      ) : (
        <>
          <Table>
            <thead>
              <tr>
                <Th>When</Th>
                <Th>Task</Th>
                <Th>Conclusion</Th>
                <Th>Model</Th>
                <Th>Confidence</Th>
                <Th>Label</Th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id} className="cursor-pointer hover:bg-surface-muted" onClick={() => setOpen(r.id)}>
                  <Td className="tabular whitespace-nowrap">{formatDateTime(r.created_at)}</Td>
                  <Td>{r.task_label || r.task}</Td>
                  <Td>
                    <button type="button" className="line-clamp-2 text-left text-primary hover:underline" onClick={() => setOpen(r.id)}>
                      {r.conclusion || r.error || r.status}
                    </button>
                  </Td>
                  <Td>
                    <div className="flex flex-wrap items-center gap-1">
                      <LocationBadge location={r.provider_location} />
                      <span className="font-mono text-[11px] text-muted-foreground">{r.model_reported || r.model}</span>
                    </div>
                  </Td>
                  <Td className="tabular">{r.confidence == null ? "—" : `${Math.round(r.confidence * 100)}%`}</Td>
                  <Td>
                    <AIInferredLabel record={r} />
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
          {q.hasNextPage && (
            <div className="mt-3 flex justify-center">
              <Button variant="secondary" disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
                {q.isFetchingNextPage ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </>
      )}
      <RecordDrawer id={open} onClose={() => setOpen(undefined)} />
    </>
  );
}

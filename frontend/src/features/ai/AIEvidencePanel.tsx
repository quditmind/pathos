import { useState } from "react";
import { Check, ChevronDown, ChevronRight, RotateCcw, ShieldAlert, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge, Input } from "@/components/ui/primitives";
import { ErrorPanel } from "@/components/ui/error-panel";
import { LoadingSkeleton } from "@/components/ui/states";
import { useSession } from "@/features/auth/session";
import { useFeatureFlag } from "@/features/shell/meta";
import { formatDateTime } from "@/lib/utils";
import {
  decisionLabel,
  locationLabel,
  useEvidenceDetail,
  useEvidenceList,
  useReplayEvidence,
  useReviewEvidence,
  type EvidenceRecord,
  type ReplayComparison,
} from "./evidence";

/**
 * AI evidence (PATHOS 3.0 M7): every AI conclusion PATHOS stored about a
 * finding or a threat, with its model, reasoning steps, conclusion,
 * confidence and reviewer. Every conclusion is labelled AI-inferred; a
 * person's acceptance is shown next to the label.
 */

/** The rule 5 label of an AI conclusion and its human decision. */
export function AIInferredLabel({ record }: { record: Pick<EvidenceRecord, "review_decision" | "reviewer_name"> }) {
  const who = record.reviewer_name ?? "a person";
  if (record.review_decision === "accepted")
    return (
      <Badge tone="success" className="font-semibold">
        AI-inferred · confirmed by {who}
      </Badge>
    );
  if (record.review_decision === "rejected")
    return (
      <Badge tone="danger" className="font-semibold">
        AI-inferred · rejected by {who}
      </Badge>
    );
  return (
    <Badge tone="warning" className="font-semibold">
      AI-inferred{record.review_decision === "pending" ? " · awaiting a decision" : ""}
    </Badge>
  );
}

export function LocationBadge({ location }: { location: EvidenceRecord["provider_location"] | string }) {
  const tone = location === "local" ? "success" : location === "cloud" ? "primary" : "neutral";
  return <Badge tone={tone}>{locationLabel[location as EvidenceRecord["provider_location"]] ?? location}</Badge>;
}

const pct = (c: number | null | undefined) => (c == null ? "—" : `${Math.round(c * 100)}%`);

function Comparison({ c }: { c: ReplayComparison }) {
  const yes = (b: boolean) => (b ? "yes" : "no");
  return (
    <div className="space-y-1 rounded-md border border-border p-2 text-[12px]" data-testid="replay-comparison">
      <div className="font-semibold">Replay compared with the original</div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
        <dt className="text-muted-foreground">Same conclusion</dt>
        <dd className={c.same_conclusion ? "text-success" : "text-warning"}>{yes(c.same_conclusion)}</dd>
        <dt className="text-muted-foreground">Identical response</dt>
        <dd>{yes(c.identical_response)}</dd>
        <dt className="text-muted-foreground">Model changed</dt>
        <dd>
          {yes(c.model_changed)}
          {c.model_changed && ` (${c.original_model} → ${c.replay_model})`}
        </dd>
        <dt className="text-muted-foreground">Confidence</dt>
        <dd>
          {pct(c.original_confidence)} → {pct(c.replay_confidence)}
        </dd>
      </dl>
      {!c.same_conclusion && <p>Replay: {c.replay_conclusion || c.replay_verdict}</p>}
      {c.steps_added.length > 0 && (
        <div>
          <span className="text-muted-foreground">Steps added:</span>
          <ul className="list-disc pl-5">{c.steps_added.map((s) => <li key={s}>{s}</li>)}</ul>
        </div>
      )}
      {c.steps_removed.length > 0 && (
        <div>
          <span className="text-muted-foreground">Steps removed:</span>
          <ul className="list-disc pl-5">{c.steps_removed.map((s) => <li key={s}>{s}</li>)}</ul>
        </div>
      )}
      <p className="text-muted-foreground">{c.determinism_note}</p>
    </div>
  );
}

function PromptDisclosure({ id }: { id: string }) {
  const [open, setOpen] = useState(false);
  const q = useEvidenceDetail(open ? id : undefined, true);
  return (
    <div>
      <button type="button" className="inline-flex items-center gap-1 text-[12px] text-primary hover:underline" aria-expanded={open} onClick={() => setOpen(!open)}>
        {open ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />} Show prompt and response
      </button>
      {open &&
        (q.isPending ? (
          <LoadingSkeleton rows={2} label="Loading the prompt" />
        ) : q.isError ? (
          <ErrorPanel error={q.error} />
        ) : q.data?.prompt ? (
          <div className="mt-1 space-y-1">
            <p className="text-[11px] text-muted-foreground">Redacted as sent: secrets are never sent or stored.</p>
            <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded border border-border bg-muted/40 p-2 font-mono text-[11px]" aria-label="Prompt">
              {q.data.prompt.system}
              {"\n\n"}
              {q.data.prompt.user}
            </pre>
            <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded border border-border bg-muted/40 p-2 font-mono text-[11px]" aria-label="Response">
              {q.data.response}
            </pre>
          </div>
        ) : (
          <p className="text-[12px] text-muted-foreground">{q.data?.payload_unavailable ?? "The prompt is not available."}</p>
        ))}
    </div>
  );
}

function ReviewControls({ record }: { record: EvidenceRecord }) {
  const review = useReviewEvidence();
  const [note, setNote] = useState("");
  return (
    <div className="space-y-1">
      {review.isError && <ErrorPanel error={review.error} title="The decision was not recorded" />}
      <div className="flex flex-wrap items-center gap-2">
        <Input aria-label="Decision note" placeholder="Note (optional)" value={note} onChange={(e) => setNote(e.target.value)} className="h-7 max-w-64" />
        <Button size="sm" disabled={review.isPending} onClick={() => review.mutate({ id: record.id, decision: "accepted", note })}>
          <Check /> Accept
        </Button>
        <Button size="sm" variant="danger-outline" disabled={review.isPending} onClick={() => review.mutate({ id: record.id, decision: "rejected", note })}>
          <X /> Reject
        </Button>
      </div>
    </div>
  );
}

function Replay({ record }: { record: EvidenceRecord }) {
  const replay = useReplayEvidence();
  if (!record.replayable) return <p className="text-[12px] text-muted-foreground">Reproduce unavailable: {record.replay_unavailable}</p>;
  return (
    <div className="space-y-1">
      <Button size="sm" variant="secondary" disabled={replay.isPending} onClick={() => replay.mutate(record.id)}>
        <RotateCcw /> {replay.isPending ? "Reproducing…" : "Reproduce"}
      </Button>
      {replay.isError && <ErrorPanel error={replay.error} title="The replay did not run" />}
      {replay.data?.comparison && <Comparison c={replay.data.comparison} />}
    </div>
  );
}

/** One record: model, steps, conclusion, confidence, reviewer, actions. */
export function EvidenceRecordCard({ record }: { record: EvidenceRecord }) {
  const r = record;
  return (
    <article className="space-y-2 rounded-md border border-border p-3 text-[12.5px]" data-testid="ai-evidence-record">
      <div className="flex flex-wrap items-center gap-2">
        <AIInferredLabel record={r} />
        <span className="font-medium">{r.task_label || r.task}</span>
        <LocationBadge location={r.provider_location} />
        <span className="font-mono text-[11px] text-muted-foreground">{r.model_reported || r.model}</span>
        {r.status !== "succeeded" && <Badge tone="danger">{r.status.replaceAll("_", " ")}{r.error_code && ` · ${r.error_code}`}</Badge>}
        <span className="ml-auto tabular text-[11px] text-muted-foreground">{formatDateTime(r.created_at)}</span>
      </div>
      {r.conclusion && <p className="whitespace-pre-wrap">{r.conclusion}</p>}
      {r.error && <p className="text-danger">{r.error}</p>}
      <div className="flex flex-wrap gap-x-4 text-[12px] text-muted-foreground">
        <span>Confidence {pct(r.confidence)}</span>
        {r.verdict && <span>Conclusion {r.verdict.replaceAll("_", " ")}</span>}
        <span>{r.sent_code ? "Source code was sent" : "No source code sent"}</span>
        <span>{decisionLabel[r.review_decision]}</span>
      </div>
      {r.proposes_suppression && r.review_decision !== "rejected" && (
        <div role="note" className="flex items-start gap-1.5 rounded bg-danger-soft px-2 py-1 text-danger">
          <ShieldAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          Proposal only: a person decides in triage or Human Eye. The AI never closes or suppresses a finding.
        </div>
      )}
      {r.steps.length > 0 && (
        <div>
          <div className="text-[12px] text-muted-foreground">Reasoning steps</div>
          <ol className="list-decimal pl-5">{r.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
        </div>
      )}
      {r.reviewed_at && (
        <p className="text-[12px] text-muted-foreground">
          {decisionLabel[r.review_decision]} by {r.reviewer_name ?? "a person"} on {formatDateTime(r.reviewed_at)}
          {r.review_note && `: ${r.review_note}`}
        </p>
      )}
      {r.can_review && <ReviewControls record={r} />}
      <PromptDisclosure id={r.id} />
      <Replay record={r} />
      <p className="text-[11px] text-muted-foreground" title={r.determinism_note}>
        Template {r.prompt_template} · input {r.input_sha256.slice(0, 12)}
        {r.payload_purged_at && ` · prompt deleted ${formatDateTime(r.payload_purged_at)} (retention)`}
      </p>
    </article>
  );
}

/** The AI evidence of a finding or a threat; nothing when the module is off or the caller cannot read evidence. */
export function AIEvidencePanel({ findingId, threatId }: { findingId?: string; threatId?: string }) {
  const on = useFeatureFlag("ai_intelligence");
  const { can } = useSession();
  const visible = on && can("ai.evidence_read") && !!(findingId || threatId);
  const q = useEvidenceList({ finding_id: findingId, threat_id: threatId }, visible);
  if (!visible) return null;
  return (
    <section aria-label="AI evidence" className="space-y-2">
      <h3 className="text-[13px] font-semibold">AI evidence</h3>
      {q.isPending ? (
        <LoadingSkeleton rows={2} label="Loading AI evidence" />
      ) : q.isError ? (
        <ErrorPanel error={q.error} title="Could not load the AI evidence" onVerify={() => q.refetch()} />
      ) : q.data.items.length === 0 ? (
        <p className="text-[12px] text-muted-foreground">No AI conclusion has been recorded for this {findingId ? "finding" : "threat"}.</p>
      ) : (
        <div className="space-y-2">{q.data.items.map((r) => <EvidenceRecordCard key={r.id} record={r} />)}</div>
      )}
    </section>
  );
}

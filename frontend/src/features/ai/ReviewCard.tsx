import { useState } from "react";
import { Bot, Check, UserRound, X } from "lucide-react";
import { api } from "@/api/client";
import type { AIReview } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Input } from "@/components/ui/primitives";
import { SeverityBadge } from "@/components/data/Severity";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { useAIMutation } from "./api";

const verdictTone = { true_positive: "danger", false_positive: "success", needs_review: "warning" } as const;
const verdictLabel = { true_positive: "True positive", false_positive: "False positive", needs_review: "Needs human review" };

export function ReviewCard({ review, showFinding = false }: { review: AIReview; showFinding?: boolean }) {
  const { can, me } = useSession();
  const [note, setNote] = useState("");
  const decide = useAIMutation(({ action }: { action: "approve" | "reject" }) =>
    api(`/api/v1/ai/reviews/${review.id}/${action}`, { method: "POST", body: { note } }));
  const pending = review.status === "pending_approval";
  const own = review.reviewed_by && review.reviewed_by === (me.user.display_name || me.user.email);
  const needsNote = review.verdict === "false_positive" && review.finding_severity === "critical";

  return (
    <div className="rounded-md border border-border p-3 text-[13px]">
      {showFinding && (
        <div className="mb-2 flex items-center gap-2">
          <SeverityBadge value={review.finding_severity} />
          <span className="truncate font-medium">{review.finding_title}</span>
          <span className="truncate text-[12px] text-muted-foreground">· {review.repository_name}</span>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={verdictTone[review.verdict]}>{verdictLabel[review.verdict]}</Badge>
        <span className="tabular text-[12px] text-muted-foreground">{Math.round(review.confidence * 100)}% confidence</span>
        <span className="text-[12px] text-muted-foreground">· suggests <span className="capitalize">{review.suggested_severity}</span></span>
        <span className="ml-auto flex items-center gap-1 text-[11.5px] text-muted-foreground">
          {review.source === "interactive_mcp" ? <UserRound className="size-3.5" /> : <Bot className="size-3.5" />}
          {review.source === "interactive_mcp" ? `${review.reviewed_by} via MCP` : review.model} · {formatDateTime(review.created_at)}
        </span>
      </div>
      <p className="mt-2 whitespace-pre-wrap">{review.rationale}</p>
      {review.remediation && (
        <p className="mt-2 whitespace-pre-wrap text-muted-foreground"><span className="font-medium text-foreground">Remediation: </span>{review.remediation}</p>
      )}
      {review.evidence_cited.length > 0 && (
        <ul className="mt-2 list-disc pl-5 text-[12px] text-muted-foreground">{review.evidence_cited.map((e, i) => <li key={i} className="break-words">{e}</li>)}</ul>
      )}
      <div className="mt-2 text-[11.5px] text-muted-foreground">
        Status: <span className="font-medium">{review.status.replace("_", " ")}</span>
        {review.decided_by && ` by ${review.decided_by} ${formatDateTime(review.decided_at)}`}
        {review.decision_note && ` — “${review.decision_note}”`}
        {review.transmitted_sha256 && <span className="ml-1 font-mono" title="SHA-256 of exactly what was sent to the provider">· sent {review.transmitted_sha256.slice(0, 12)}</span>}
      </div>
      {pending && can("ai.review") && can("findings.triage") && (
        <div className="mt-3 space-y-2 border-t border-border pt-3">
          {decide.isError && <Alert>{decide.error.message}</Alert>}
          {needsNote && <p className="text-[12px] text-warning">Closing a Critical finding as a false positive requires a justification.</p>}
          <div className="flex flex-wrap items-center gap-2">
            <Input aria-label="Decision note" placeholder={needsNote ? "Justification (required)" : "Note (optional)"} value={note} onChange={(e) => setNote(e.target.value)} className="max-w-sm" />
            <Button size="sm" disabled={decide.isPending || !!own || (needsNote && !note.trim())} onClick={() => decide.mutate({ action: "approve" })}
              title={own ? "Another reviewer must approve your own review" : "Apply this verdict to the finding"}>
              <Check /> Approve
            </Button>
            <Button size="sm" variant="secondary" disabled={decide.isPending} onClick={() => decide.mutate({ action: "reject" })}><X /> Reject</Button>
          </div>
        </div>
      )}
    </div>
  );
}

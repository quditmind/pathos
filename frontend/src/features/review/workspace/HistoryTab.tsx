import { useState } from "react";
import { History, MessageSquare } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge, EmptyState, Skeleton } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { reviewApi, useComments, useHistory, useReviewMutation } from "../api";
import { dispositionLabel, humanize } from "../shared";
import type { Disposition, HistoryEntry, ReviewDetail } from "../types";
import { textareaCls } from "./actions";
import { Panel } from "./section";
import { ErrorPanel } from "@/components/ui/error-panel";

const actionLabel: Record<string, string> = {
  "review.created": "Review created",
  "review.assigned": "Reviewer assigned",
  "review.reassigned": "Reviewer changed",
  "review.independent_assigned": "Independent reviewer assigned",
  "review.status": "Status changed",
  "review.priority": "Priority changed",
  "review.due_date": "Due date changed",
  "review.completed": "Review completed",
  "review.reopened": "Review reopened",
  "assessment.update": "Assessment updated",
  "severity.assessed": "Severity assessed",
  "decision.submitted": "Decision submitted",
  "independent_review.approved": "Independent review: approved",
  "independent_review.rejected": "Independent review: rejected",
  "independent_review.information_requested": "Independent review: information requested",
  "evidence.upload": "Evidence uploaded",
  "evidence.delete": "Evidence deleted",
  "comment.add": "Comment",
  "remediation.status": "Remediation status changed",
  "remediation.update": "Remediation updated",
  "risk_acceptance.requested": "Risk acceptance requested",
  "ai.suggestion": "AI suggestion requested",
  "ai.suggestion_used": "AI suggestion used in the assessment",
};

function show(v: unknown): string {
  if (v == null) return "—";
  if (typeof v === "string") return dispositionLabel[v as Disposition] ?? (v.length > 160 ? `${v.slice(0, 160)}…` : v);
  if (typeof v === "object") {
    return Object.entries(v as Record<string, unknown>)
      .filter(([, x]) => x != null && x !== "")
      .map(([k, x]) => `${humanize(k)}: ${typeof x === "string" ? (dispositionLabel[x as Disposition] ?? x) : JSON.stringify(x)}`)
      .join(", ");
  }
  return String(v);
}

function Entry({ e }: { e: HistoryEntry }) {
  const changed = e.old_value != null || e.new_value != null;
  return (
    <li className="py-2 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{actionLabel[e.action] ?? e.action}</span>
        {e.field && e.action === "assessment.update" && <span className="font-mono text-[11.5px] text-muted-foreground">{e.field}</span>}
        <Badge>round {e.round}</Badge>
        <span className="ml-auto tabular text-[11.5px] text-muted-foreground">{formatDateTime(e.created_at)}</span>
      </div>
      <div className="text-[11.5px] text-muted-foreground">
        {e.actor ?? "PATHOS"} {e.actor_id && <span className="font-mono">({e.actor_id.slice(0, 8)})</span>}
      </div>
      {changed && e.action !== "comment.add" && (
        <div className="mt-0.5 text-[12px]">
          <span className="text-muted-foreground line-through decoration-muted-foreground/50">{show(e.old_value)}</span> → <span>{show(e.new_value)}</span>
        </div>
      )}
      {e.note && <p className="mt-0.5 whitespace-pre-wrap text-[12px]">{e.note}</p>}
    </li>
  );
}

export function HistoryTab({ d }: { d: ReviewDetail }) {
  const h = useHistory(d.id);
  const c = useComments(d.id);
  const [body, setBody] = useState("");
  const add = useReviewMutation(() => reviewApi.comment(d.id, body));
  const [filter, setFilter] = useState<"all" | "decisions">("all");
  const items = (h.data ?? []).filter((e) => filter === "all" || /^(decision|independent_review|review\.(completed|reopened)|severity)/.test(e.action)).reverse();
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_360px]">
      <Panel
        title="Activity and audit history"
        actions={
          <div className="flex gap-1 text-[12px]">
            {(["all", "decisions"] as const).map((f) => (
              <button key={f} type="button" className={f === filter ? "font-medium text-primary" : "text-muted-foreground hover:text-foreground"} onClick={() => setFilter(f)}>
                {f === "all" ? "Everything" : "Decisions"}
              </button>
            ))}
          </div>
        }
      >
        <p className="mb-2 text-[11.5px] text-muted-foreground">Append-only: entries cannot be edited or deleted. Each entry records the user, action, previous and new value, and time.</p>
        {h.isError ? (
          <ErrorPanel error={h.error} />
        ) : h.isPending ? (
          <Skeleton className="h-40" />
        ) : items.length === 0 ? (
          <EmptyState icon={<History />} title="No history" />
        ) : (
          <ol className="divide-y divide-border">{items.map((e) => <Entry key={e.id} e={e} />)}</ol>
        )}
      </Panel>
      <Panel title="Comments">
        {c.isPending ? (
          <Skeleton className="h-24" />
        ) : (c.data ?? []).length === 0 ? (
          <EmptyState icon={<MessageSquare />} title="No comments yet" />
        ) : (
          <ul className="max-h-[50vh] space-y-2 overflow-auto">
            {(c.data ?? []).map((m) => (
              <li key={m.id} className="rounded-md border border-border p-2 text-[12.5px]">
                <div className="mb-0.5 flex items-center gap-2 text-[11.5px] text-muted-foreground">
                  <span className="font-medium text-foreground">{m.author_name}</span>
                  {m.kind !== "comment" && <Badge tone={m.kind === "independent" ? "primary" : "warning"}>{humanize(m.kind)}</Badge>}
                  <span className="ml-auto">{formatDateTime(m.created_at)}</span>
                </div>
                <p className="whitespace-pre-wrap">{m.body}</p>
              </li>
            ))}
          </ul>
        )}
        {d.can.comment && (
          <form
            className="mt-3 space-y-2"
            onSubmit={(e) => {
              e.preventDefault();
              add.mutate(undefined, { onSuccess: () => setBody("") });
            }}
          >
            {add.error && <ErrorPanel error={add.error} />}
            <textarea aria-label="New comment" rows={3} className={textareaCls} value={body} onChange={(e) => setBody(e.target.value)} placeholder="Add a comment for the team…" />
            <Button type="submit" size="sm" disabled={!body.trim() || add.isPending}>Comment</Button>
          </form>
        )}
      </Panel>
    </div>
  );
}

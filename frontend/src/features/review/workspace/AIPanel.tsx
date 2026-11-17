import { useState } from "react";
import { Bot, Check, ClipboardCopy, Download, Sparkles, X } from "lucide-react";
import { Input } from "@/components/ui/primitives";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, Select, Skeleton } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { reviewApi, useRecommendations, useReviewMutation } from "../api";
import { aiKindLabel } from "../shared";
import type { Recommendation, ReviewDetail } from "../types";

/** Where a suggestion of each kind can be copied into the assessment. */
const target: Record<string, { section: string; key: string; label: string }> = {
  explanation: { section: "remediation", key: "explanation", label: "Vulnerability explanation" },
  code_summary: { section: "fields", key: "investigation_notes", label: "Investigation notes" },
  code_paths: { section: "fields", key: "investigation_notes", label: "Investigation notes" },
  investigation_questions: { section: "fields", key: "investigation_notes", label: "Investigation notes" },
  false_positive_indicators: { section: "fields", key: "investigation_notes", label: "Investigation notes" },
  evidence_suggestions: { section: "fields", key: "investigation_notes", label: "Investigation notes" },
  remediation: { section: "remediation", key: "recommendation", label: "Recommended remediation" },
  secure_code: { section: "remediation", key: "secure_example", label: "Secure code example" },
  references: { section: "remediation", key: "references", label: "Security references" },
  assessment_summary: { section: "fields", key: "exploitability_justification", label: "Exploitability justification" },
  risk_explanation: { section: "fields", key: "investigation_notes", label: "Investigation notes" },
  duplicate_candidates: { section: "fields", key: "investigation_notes", label: "Investigation notes" },
};

/** A unified diff, coloured by line. */
function Diff({ text }: { text: string }) {
  return (
    <pre className="mt-2 max-h-72 overflow-auto rounded bg-surface-muted p-2 font-mono text-[11.5px] leading-5" aria-label="Proposed patch">
      {text.split("\n").map((l, i) => (
        <div key={i} className={l.startsWith("+") && !l.startsWith("+++") ? "bg-success/15" : l.startsWith("-") && !l.startsWith("---") ? "bg-danger/15" : l.startsWith("@@") ? "text-muted-foreground" : undefined}>
          {l || " "}
        </div>
      ))}
    </pre>
  );
}

/** A patch proposal's human decision: approve (download) or reject; never applied by PATHOS. */
function PatchDecision({ d, r }: { d: ReviewDetail; r: Recommendation }) {
  const [note, setNote] = useState("");
  const decide = useReviewMutation((decision: "approved" | "rejected") => reviewApi.patchDecision(d.id, r.id, decision, note));
  if (r.patch_status === "approved") {
    return (
      <div className="mt-2 flex flex-wrap items-center gap-2 text-[12px]">
        <Badge tone="success">Approved by {r.patch_decided_by}</Badge>
        <a href={`/api/v1/human-reviews/${d.id}/ai/${r.id}/patch`} className="inline-flex items-center gap-1 text-primary hover:underline" download>
          <Download className="size-3.5" /> Download .patch
        </a>
        <span className="text-muted-foreground">Apply it through your normal code review; PATHOS never changes repositories.</span>
      </div>
    );
  }
  if (r.patch_status === "rejected") {
    return <div className="mt-2 text-[12px]"><Badge>Rejected by {r.patch_decided_by}</Badge> <span className="text-muted-foreground">{r.patch_note}</span></div>;
  }
  if (!d.can.assess || r.patch_status !== "proposed") return null;
  return (
    <div className="mt-2 space-y-1.5">
      <Input aria-label="Patch decision note" placeholder="Note (required to reject)" value={note} onChange={(e) => setNote(e.target.value)} />
      <div className="flex gap-1">
        <Button size="sm" onClick={() => decide.mutate("approved")} disabled={decide.isPending}><Check /> Approve patch</Button>
        <Button size="sm" variant="secondary" onClick={() => decide.mutate("rejected")} disabled={decide.isPending || note.trim().length < 5}><X /> Reject</Button>
      </div>
      {decide.error && <Alert>{decide.error.message}</Alert>}
    </div>
  );
}

const asText = (r: Recommendation) =>
  [r.content.summary, ...r.content.points.map((p) => `- ${p}`), ...(r.content.references.length ? ["", "References:", ...r.content.references.map((x) => `- ${x}`)] : []), r.content.code ? `\n${r.content.code}` : ""]
    .filter((x) => x !== undefined)
    .join("\n")
    .trim();

function Suggestion({ d, r }: { d: ReviewDetail; r: Recommendation }) {
  const t = target[r.kind];
  const apply = useReviewMutation(() => {
    const sec = (d.assessment as unknown as Record<string, Record<string, string>>)[t!.section] ?? {};
    const prev = sec[t!.key] ?? "";
    const text = `${prev ? `${prev}\n\n` : ""}[AI suggestion ${r.id.slice(0, 8)}, reviewed by the analyst]\n${t!.key === "secure_example" && r.content.code ? r.content.code : asText(r)}`;
    return reviewApi.assessment(d.id, { [t!.section]: { [t!.key]: text }, ai_recommendation_id: r.id });
  });
  return (
    <Card className="p-3 text-[12.5px]">
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        <Badge tone="primary"><Bot className="size-3" /> AI suggestion</Badge>
        <span className="font-medium">{aiKindLabel[r.kind] ?? r.kind}</span>
      </div>
      {r.content.summary && <p className="whitespace-pre-wrap">{r.content.summary}</p>}
      {r.content.points.length > 0 && (
        <ul className="mt-1 list-disc space-y-0.5 pl-4">
          {r.content.points.map((p, i) => <li key={i}>{p}</li>)}
        </ul>
      )}
      {r.content.code && (r.kind === "patch" ? <Diff text={r.content.code} /> : <pre className="mt-2 max-h-60 overflow-auto rounded bg-surface-muted p-2 font-mono text-[11.5px]">{r.content.code}</pre>)}
      {r.kind === "patch" && <PatchDecision d={d} r={r} />}
      {r.content.references.length > 0 && (
        <ul className="mt-1 space-y-0.5 text-[11.5px] text-muted-foreground">
          {r.content.references.map((x, i) => <li key={i}>{x}</li>)}
        </ul>
      )}
      <div className="mt-2 text-[11px] text-muted-foreground" title={`Transmitted SHA-256 ${r.transmitted_sha256}`}>
        {r.model || r.provider} · requested by {r.requested_by_name} · {formatDateTime(r.created_at)}
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        <Button size="sm" variant="ghost" onClick={() => void navigator.clipboard?.writeText(asText(r))}><ClipboardCopy /> Copy</Button>
        {d.can.assess && t && (
          <Button size="sm" variant="secondary" disabled={apply.isPending || apply.isSuccess} onClick={() => apply.mutate(undefined)} title="Appends the text; you remain responsible for the assessment">
            {apply.isSuccess ? "Added" : `Add to ${t.label}`}
          </Button>
        )}
      </div>
      {apply.error && <div className="mt-2"><Alert>{apply.error.message}</Alert></div>}
    </Card>
  );
}

export function AIPanel({ d }: { d: ReviewDetail }) {
  const recs = useRecommendations(d.id);
  const [kind, setKind] = useState("explanation");
  const ask = useReviewMutation(() => reviewApi.ai(d.id, kind));
  return (
    <div className="space-y-3">
      <p className="text-[11.5px] text-muted-foreground">
        Suggestions are advisory. AI never completes a review, approves an accepted risk or marks a false positive. Every request is recorded.
      </p>
      {d.can.ai ? (
        <div className="flex gap-2">
          <Select aria-label="Kind of suggestion" className="min-w-0 flex-1" value={kind} onChange={(e) => setKind(e.target.value)}>
            {Object.entries(aiKindLabel).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </Select>
          <Button disabled={ask.isPending} onClick={() => ask.mutate(undefined)}>
            <Sparkles /> {ask.isPending ? "Asking…" : "Ask"}
          </Button>
        </div>
      ) : (
        <Alert tone="warning">{d.can.ai_unavailable_reason || "AI assistance requires reviews.assess or reviews.approve."}</Alert>
      )}
      {ask.error && <Alert>{ask.error.message}</Alert>}
      {recs.isPending ? (
        <Skeleton className="h-24" />
      ) : (
        <div className="max-h-[70vh] space-y-2 overflow-auto">
          {(recs.data ?? []).map((r) => <Suggestion key={r.id} d={d} r={r} />)}
          {recs.data?.length === 0 && <p className="text-[12px] text-muted-foreground">No suggestions requested yet.</p>}
        </div>
      )}
    </div>
  );
}

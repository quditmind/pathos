import { useState } from "react";
import { Bot, ClipboardCopy, Sparkles } from "lucide-react";
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
};

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
      {r.content.code && <pre className="mt-2 max-h-60 overflow-auto rounded bg-surface-muted p-2 font-mono text-[11.5px]">{r.content.code}</pre>}
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

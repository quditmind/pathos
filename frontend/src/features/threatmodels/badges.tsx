import { Badge } from "@/components/ui/primitives";
import { evidenceLabel, statusLabel, type ChangeState, type ModelStatus, type Threat } from "./api";

/** Rule 5 label of a threat: verified, observed, AI-inferred, or "imported/manual, unverified". */
export function EvidenceLabel({ threat }: { threat: Pick<Threat, "evidence_type" | "method" | "label"> & Partial<Pick<Threat, "ai_review">> }) {
  let text = evidenceLabel(threat);
  // M7: an AI-suggested threat stays a proposal until a person accepts it.
  if (threat.method === "ai") text = threat.ai_review === "accepted" ? "AI-inferred · accepted" : "AI-inferred (awaiting decision)";
  const tone = threat.evidence_type === "verified" ? "success" : threat.evidence_type === "observed" ? "primary" : "warning";
  return (
    <Badge tone={tone} className="font-semibold">
      <span className="sr-only">Evidence: </span>
      {text}
    </Badge>
  );
}

export function ModelStatusBadge({ status }: { status: ModelStatus }) {
  const tone = status === "approved" ? "success" : status === "in_review" ? "primary" : status === "draft" ? "warning" : "neutral";
  return <Badge tone={tone}>{statusLabel[status] ?? status}</Badge>;
}

const changeTone = { new: "primary", changed: "warning", resolved: "success", unchanged: "neutral" } as const;

export function ChangeBadge({ state }: { state?: ChangeState }) {
  if (!state) return null;
  return <Badge tone={changeTone[state]}>{state}</Badge>;
}

export const confidenceText = (c: number) => `${Math.round(c * 100)}%`;

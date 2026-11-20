import { Badge } from "@/components/ui/primitives";
import type { AnalysisStatus, ArtifactTrust, MatchState } from "./api";

/** Trust of an artifact: from our own builds (signature or provenance), authorised, or untrusted (refused by default). */
export function TrustBadge({ trust }: { trust: ArtifactTrust }) {
  if (trust.status === "trusted") {
    const basis = trust.basis === "provenance" ? "verified provenance" : "verified signature";
    return (
      <Badge tone="success">
        <span data-testid="trust-badge" title={`From our own builds: ${basis}`}>
          Trusted · {basis}
        </span>
      </Badge>
    );
  }
  if (trust.status === "authorized") {
    return (
      <Badge tone="warning">
        <span data-testid="trust-badge" title={trust.authorization?.reason ? `Authorised: ${trust.authorization.reason}` : "Authorised as an untrusted artifact"}>
          Authorised untrusted artifact
        </span>
      </Badge>
    );
  }
  return (
    <Badge tone="danger">
      <span data-testid="trust-badge" title={trust.reason || "Not tied to our own builds: refused by default"}>
        Untrusted · refused by default
      </span>
    </Badge>
  );
}

export const statusLabel: Record<AnalysisStatus, string> = {
  queued: "Queued",
  running: "Running",
  ready: "Ready",
  partial: "Partial",
  failed: "Failed",
};

export function AnalysisStatusBadge({ status }: { status: AnalysisStatus }) {
  const tone = status === "ready" ? "success" : status === "failed" ? "danger" : status === "partial" ? "warning" : "neutral";
  return <Badge tone={tone}>{statusLabel[status] ?? status}</Badge>;
}

export const matchLabel: Record<MatchState, string> = {
  matched: "Matched",
  binary_only: "Only in binary",
  library: "Library",
  unmatched: "Not compared",
};

export function MatchBadge({ match, sensitive }: { match: MatchState; sensitive?: boolean }) {
  const tone = match === "matched" ? "success" : match === "binary_only" ? "danger" : "neutral";
  return (
    <span className="inline-flex gap-1">
      <Badge tone={tone}>{matchLabel[match] ?? match}</Badge>
      {sensitive && <Badge tone="warning">Sensitive</Badge>}
    </span>
  );
}

/** Rule 5 label of a reference: binary facts are verified (static). */
export function EvidenceLabel({ evidence }: { evidence: string }) {
  const label = evidence === "verified" ? "verified" : evidence === "observed" ? "observed" : "AI-inferred";
  const tone = evidence === "verified" ? "success" : evidence === "observed" ? "primary" : "neutral";
  return <Badge tone={tone}>{label}</Badge>;
}

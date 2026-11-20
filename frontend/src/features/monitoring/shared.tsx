import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { SeverityBadge } from "@/components/data/Severity";
import { Badge } from "@/components/ui/primitives";
import { redactToolNames } from "@/lib/checkKinds";
import { formatDateTime, splitHref } from "@/lib/utils";
import { shortSha, type EvidenceLabel, type MonitoringEvent } from "./api";

const evidenceText: Record<EvidenceLabel, { label: string; tone: "success" | "primary" | "warning" }> = {
  verified: { label: "verified", tone: "success" },
  observed: { label: "observed", tone: "primary" },
  ai_inferred: { label: "AI-inferred", tone: "warning" },
};

/** Rule 5 label: verified (static analysis), observed (runtime) or AI-inferred. */
export function EvidenceBadge({ label }: { label: EvidenceLabel | string | undefined }) {
  const e = evidenceText[label as EvidenceLabel] ?? { label: label || "unlabelled", tone: "neutral" as const };
  return (
    <Badge tone={e.tone as "success" | "primary" | "warning" | "neutral"} className="font-semibold">
      <span className="sr-only">Evidence: </span>
      {e.label}
    </Badge>
  );
}

/** An in-app path as a router link, an http(s) URL as an external link, anything else as text. */
export function AppLink({ href, children, className = "text-primary hover:underline" }: { href: string; children: ReactNode; className?: string }) {
  if (href.startsWith("/") && !href.startsWith("//")) {
    const { to, search } = splitHref(href);
    return (
      <Link to={to as never} search={search as never} className={className}>
        {children}
      </Link>
    );
  }
  if (/^https?:\/\//.test(href)) {
    return (
      <a href={href} target="_blank" rel="noreferrer noopener" className={className}>
        {children}
      </a>
    );
  }
  return <span>{children}</span>;
}

/** CodeGraph change-impact view comparing two snapshots of an application (M4 route). */
export function codegraphCompareHref(appId: string | null | undefined, from: string | null | undefined, to: string | null | undefined): string | undefined {
  if (!appId || !to) return undefined;
  const p = new URLSearchParams({ view: "change_impact", snapshot: to });
  if (from) p.set("compare", from);
  return `/codegraph/${appId}?${p}`;
}

/** Evidence references of an event: snapshots, commit, scan, gate decision, threat model, feed. */
export function EventEvidence({ e }: { e: MonitoringEvent }) {
  const ev = e.evidence ?? {};
  const refs: ReactNode[] = [];
  if (ev.to_snapshot_id) {
    const href = codegraphCompareHref(e.application_id, ev.from_snapshot_id, ev.to_snapshot_id);
    const text = ev.from_snapshot_id ? `Snapshot ${ev.from_snapshot_id.slice(0, 8)} → ${ev.to_snapshot_id.slice(0, 8)}` : `Snapshot ${ev.to_snapshot_id.slice(0, 8)}`;
    refs.push(href ? <AppLink key="snap" href={href}>{text}</AppLink> : <span key="snap">{text}</span>);
  }
  if (ev.commit) refs.push(<span key="commit">Commit <code className="font-mono">{shortSha(ev.commit)}</code></span>);
  if (ev.scan_job_id) refs.push(<AppLink key="scan" href={`/scans/${ev.scan_job_id}`}>Scan {ev.scan_job_id.slice(0, 8)}</AppLink>);
  if (ev.gate_decision_id) refs.push(<AppLink key="gate" href={`/remediation/gates?decision=${ev.gate_decision_id}`}>Gate decision {ev.gate_decision_id.slice(0, 8)}</AppLink>);
  if (ev.verification_id) refs.push(<span key="ver">Verification {ev.verification_id.slice(0, 8)}</span>);
  if (ev.threat_model_id) refs.push(<AppLink key="tm" href={`/threat-models/${ev.threat_model_id}`}>Threat model {ev.threat_model_id.slice(0, 8)}</AppLink>);
  if (typeof ev.feed === "string" && ev.feed) refs.push(<span key="feed">Intelligence feed: {redactToolNames(ev.feed).toUpperCase()}</span>);
  if (!refs.length) return null;
  return (
    <ul className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11.5px] text-muted-foreground" aria-label="Evidence references">
      {refs.map((r, i) => (
        <li key={i}>{r}</li>
      ))}
    </ul>
  );
}

/** One feed event: type, loop, severity, evidence label, title, summary, scope, evidence and link. */
export function EventCard({ e, compact = false }: { e: MonitoringEvent; compact?: boolean }) {
  const titleId = `mon-ev-${e.id}`;
  return (
    <article aria-labelledby={titleId} className="rounded-md border border-border p-3 text-[12.5px]" data-testid="monitoring-event">
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        <Badge tone="neutral">{e.type_label || e.type}</Badge>
        {e.loop != null && <Badge tone="primary">Loop {e.loop}</Badge>}
        <SeverityBadge value={e.severity} />
        <EvidenceBadge label={e.evidence_label} />
        <time dateTime={e.created_at} className="ml-auto text-[11.5px] text-muted-foreground">
          {formatDateTime(e.created_at)}
        </time>
      </div>
      <h3 id={titleId} className="text-[13px] font-medium">
        {e.link ? <AppLink href={e.link}>{e.title}</AppLink> : e.title}
      </h3>
      {e.summary && !compact && <p className="mt-0.5 text-muted-foreground">{e.summary}</p>}
      {(e.application_name || e.repository_name) && (
        <p className="mt-1 text-[11.5px] text-muted-foreground">
          {e.application_id && e.application_name ? (
            <AppLink href={`/applications/${e.application_id}`}>{e.application_name}</AppLink>
          ) : (
            e.application_name
          )}
          {e.application_name && e.repository_name && " · "}
          {e.repository_name}
        </p>
      )}
      {!compact && (
        <div className="mt-1">
          <EventEvidence e={e} />
        </div>
      )}
    </article>
  );
}

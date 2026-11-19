import { Link } from "@tanstack/react-router";
import { RefreshCw } from "lucide-react";
import { api } from "@/api/client";
import type { Finding, SecretValidationStatus } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Badge } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { useVulnMutation } from "@/features/vuln/api";
import { formatDateTime } from "@/lib/utils";

export const secretStatusLabel: Record<SecretValidationStatus, string> = {
  active: "Active",
  inactive: "Revoked or invalid",
  error: "Check failed",
  not_checked: "Not checked",
};

const tone: Record<SecretValidationStatus, "danger" | "success" | "warning" | "neutral"> = {
  active: "danger",
  inactive: "success",
  error: "warning",
  not_checked: "neutral",
};

/** Compact verdict badge for lists. */
export function SecretStatusBadge({ status }: { status: SecretValidationStatus }) {
  return <Badge tone={tone[status]}>{status === "active" ? "Active key" : secretStatusLabel[status]}</Badge>;
}

/**
 * Live validation of a secret finding: the verdict, the request the worker
 * made and the provider's HTTP status, the non-secret identity of an active
 * key, and a re-check (which queues a scan; the secret is never stored).
 */
export function SecretValidationPanel({ f }: { f: Pick<Finding, "id" | "category" | "scan_target_id" | "secret_validation"> }) {
  const { can } = useSession();
  const recheck = useVulnMutation(() => api<{ job_id: string; coalesced: boolean }>(`/api/v1/findings/${f.id}/secret-validation/recheck`, { method: "POST" }));
  const v = f.secret_validation;
  if (f.category !== "secrets" || !v) return null;
  const ev = v.evidence ?? {};
  return (
    <div className="space-y-2 rounded-md border border-border p-3 text-[12.5px]" data-testid="secret-validation">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-[13px] font-semibold">Live secret validation</h3>
        {can("scans.run") && !f.scan_target_id && (
          <Button size="sm" variant="secondary" disabled={recheck.isPending} onClick={() => recheck.mutate(undefined)}>
            <RefreshCw /> Re-check
          </Button>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <SecretStatusBadge status={v.status} />
        {v.provider_name && <span>{v.provider_name}</span>}
        {v.checked_at && <span className="tabular text-muted-foreground">checked {formatDateTime(v.checked_at)}</span>}
      </div>
      {v.status === "active" && (
        <Alert>
          This credential was accepted by its provider{v.identity && <> (<strong>{v.identity}</strong>)</>}. Rotate or revoke it now, then remove
          it from the code and its Git history.
          {ev.severity_raised_from && <> Severity was raised from {ev.severity_raised_from} to critical because of this verdict.</>}
        </Alert>
      )}
      {v.status === "inactive" && (
        <p className="text-muted-foreground">
          The provider rejected the credential: it is revoked, expired or invalid. Remove it from the code and Git history anyway.
          {ev.severity_restored_to && <> The severity was set back to {ev.severity_restored_to}.</>}
        </p>
      )}
      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-[12px]">
        {ev.endpoint && (
          <>
            <dt className="text-muted-foreground">Request</dt>
            <dd className="break-all font-mono text-[11.5px]">{ev.endpoint}</dd>
          </>
        )}
        {ev.http_status != null && (
          <>
            <dt className="text-muted-foreground">HTTP status</dt>
            <dd className="tabular">{ev.http_status}</dd>
          </>
        )}
        {ev.detail && (
          <>
            <dt className="text-muted-foreground">Evidence</dt>
            <dd>{ev.detail}</dd>
          </>
        )}
        {ev.last_attempt && (
          <>
            <dt className="text-muted-foreground">Last attempt</dt>
            <dd>
              {secretStatusLabel[ev.last_attempt.status]}
              {ev.last_attempt.detail && <> — {ev.last_attempt.detail}</>}
              {ev.last_attempt.checked_at && <span className="tabular text-muted-foreground"> · {formatDateTime(ev.last_attempt.checked_at)}</span>}
            </dd>
          </>
        )}
        {ev.recheck_job_id && (
          <>
            <dt className="text-muted-foreground">Re-check</dt>
            <dd>
              <Link to="/scans" search={{ job: ev.recheck_job_id } as never} className="text-primary hover:underline">scan queued</Link>
              {ev.recheck_requested_at && <span className="tabular text-muted-foreground"> · {formatDateTime(ev.recheck_requested_at)}</span>}
            </dd>
          </>
        )}
      </dl>
      {v.status === "not_checked" && !ev.detail && (
        <p className="text-[12px] text-muted-foreground">
          Live validation is off unless an administrator enables providers in Administration → Secret validation.
        </p>
      )}
      {recheck.isError && <Alert>{recheck.error.message}</Alert>}
      {recheck.isSuccess && <p className="text-[12px] text-muted-foreground">Scan queued: the verdict is updated when the scan finishes.</p>}
    </div>
  );
}

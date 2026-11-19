import { useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, Radar, Settings2 } from "lucide-react";
import { api } from "@/api/client";
import type { Repository } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Input, Label, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { ErrorPanel } from "@/components/ui/error-panel";

export type EndpointStatus = "verified" | "unreachable" | "dns_failed" | "blocked" | "skipped" | "error" | "not_checked";

export interface EndpointState {
  kind: "url" | "domain" | "ip";
  value: string;
  authorized: boolean;
  status: EndpointStatus;
  detail: string;
  checks: {
    dns?: { addresses?: string[]; resolver?: string; error?: string };
    tls?: {
      protocol?: string;
      cipher_suite?: string;
      error?: string;
      legacy_protocols?: string[];
      weak_cipher_suites?: string[];
      certificate?: { subject?: string; issuer?: string; not_after?: string; days_remaining?: number; trusted?: boolean; hostname_match?: boolean };
    };
    https?: { url?: string; status?: number; error?: string };
    http?: { url?: string; status?: number; location?: string; error?: string };
  };
  checked_at: string | null;
  scan_job_id: string | null;
}

export interface EndpointVerificationState {
  configured: boolean;
  enabled: boolean;
  scan_target_id: string | null;
  authorized_by: string | null;
  authorized_at: string | null;
  authorization_note: string;
  rate_limit: number;
  nuclei: boolean;
  offline: boolean;
  open_findings: number;
  last_scan: { id: string; scan_key: string; status: string; queued_at: string; finished_at: string | null; error: string } | null;
  endpoints: EndpointState[];
  unauthorized: number;
}

const statusLabel: Record<EndpointStatus, string> = {
  verified: "Verified",
  unreachable: "Unreachable",
  dns_failed: "DNS failure",
  blocked: "Blocked by egress proxy",
  skipped: "Skipped",
  error: "Error",
  not_checked: "Not checked",
};
const statusTone: Record<EndpointStatus, "success" | "warning" | "danger" | "neutral"> = {
  verified: "success",
  unreachable: "danger",
  dns_failed: "danger",
  blocked: "warning",
  skipped: "neutral",
  error: "warning",
  not_checked: "neutral",
};

function tlsSummary(e: EndpointState): string {
  const t = e.checks?.tls;
  if (!t || t.error) return t?.error ? "no TLS" : "—";
  const parts = [t.protocol];
  const c = t.certificate;
  if (c?.days_remaining != null) parts.push(c.days_remaining < 0 ? "certificate expired" : `certificate ${c.days_remaining} days left`);
  if (c && c.trusted === false) parts.push("untrusted");
  if (c && c.hostname_match === false) parts.push("name mismatch");
  if (t.legacy_protocols?.length) parts.push(`accepts ${t.legacy_protocols.join(", ")}`);
  if (t.weak_cipher_suites?.length) parts.push("weak cipher");
  return parts.filter(Boolean).join(" · ");
}

export function useEndpointVerification(repoId: string) {
  return useQuery({
    queryKey: ["endpoint-verification", repoId],
    queryFn: () => api<EndpointVerificationState>(`/api/v1/repositories/${repoId}/endpoint-verification`),
    refetchInterval: (q) => (q.state.data?.last_scan && ["queued", "running"].includes(q.state.data.last_scan.status) ? 5000 : false),
  });
}

/** Repository Details: opt-in verification of the declared public endpoints. */
export function EndpointVerificationSection({ r }: { r: Repository }) {
  const { can } = useSession();
  const q = useEndpointVerification(r.id);
  const qc = useQueryClient();
  const [dialog, setDialog] = useState(false);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["endpoint-verification", r.id] });
  const run = useMutation({
    mutationFn: () => api<{ job_id: string; coalesced: boolean }>(`/api/v1/repositories/${r.id}/endpoint-verification/run`, { method: "POST" }),
    onSuccess: refresh,
  });
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => api<EndpointVerificationState>(`/api/v1/repositories/${r.id}/endpoint-verification`, { method: "PUT", body: { enabled } }),
    onSuccess: refresh,
  });
  const canManage = (r.can_manage ?? can("repos.manage")) && !r.archived_at;
  const canRun = can("scans.run") && !r.archived_at;
  if (q.isPending) return <Skeleton className="h-16" />;
  if (q.isError) return <ErrorPanel error={q.error} />;
  const v = q.data;
  const declared = v.endpoints.length > 0;
  return (
    <section aria-labelledby="ep-heading" className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <h3 id="ep-heading" className="flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
          <Radar className="size-3.5" /> Endpoint verification
        </h3>
        {v.configured ? <Badge tone={v.enabled ? "success" : "neutral"}>{v.enabled ? "enabled" : "disabled"}</Badge> : <Badge>off</Badge>}
        <div className="ml-auto flex flex-wrap gap-2">
          {canRun && v.configured && v.enabled && !v.offline && (
            <Button size="sm" variant="secondary" disabled={run.isPending} onClick={() => run.mutate()}>
              <Play /> Verify now
            </Button>
          )}
          {canManage && declared && !v.offline && (
            <Button size="sm" variant="secondary" onClick={() => setDialog(true)}>
              <Settings2 /> {v.configured ? "Settings" : "Enable"}
            </Button>
          )}
          {canManage && v.configured && v.enabled && (
            <Button size="sm" variant="ghost" disabled={toggle.isPending} onClick={() => toggle.mutate(false)}>
              Disable
            </Button>
          )}
        </div>
      </div>
      {v.offline && <Alert tone="warning">PATHOS runs offline (PATHOS_OFFLINE=true): declared endpoints are not contacted, so verification is disabled.</Alert>}
      {run.error && <ErrorPanel error={run.error} />}
      {toggle.error && <ErrorPanel error={toggle.error} />}
      {run.data && (
        <Alert tone="success">
          Verification {run.data.coalesced ? "already queued" : "queued"}.{" "}
          <Link to="/scans/$id" params={{ id: run.data.job_id }} className="underline">Follow the execution</Link>
        </Alert>
      )}
      {!declared ? (
        <p className="text-[12.5px] text-muted-foreground">
          Declare public URLs, domain names or IP addresses in the exposure section (Edit metadata) to verify them: DNS, reachability, TLS certificate and protocols, HSTS and security headers.
        </p>
      ) : (
        <>
          {!v.configured && (
            <p className="text-[12.5px] text-muted-foreground">
              Opt-in: a worker checks only these declared endpoints, at a limited rate, through the egress proxy, after someone authorized to test them confirms it.
            </p>
          )}
          {v.configured && v.unauthorized > 0 && (
            <Alert tone="warning">
              {v.unauthorized} declared endpoint{v.unauthorized === 1 ? " is" : "s are"} not covered by the authorization statement and {v.unauthorized === 1 ? "is" : "are"} skipped.
              {canManage && " Open Settings and confirm the endpoint list again to include them."}
            </Alert>
          )}
          <Table>
            <thead>
              <tr>
                <Th>Endpoint</Th>
                <Th>Status</Th>
                <Th>TLS</Th>
                <Th>Checked</Th>
              </tr>
            </thead>
            <tbody>
              {v.endpoints.map((e) => (
                <tr key={e.kind + e.value}>
                  <Td className="max-w-56 break-all font-mono text-[12px]">
                    {e.value}
                    {v.configured && !e.authorized && <div className="font-sans text-[11px] text-warning">not authorized</div>}
                  </Td>
                  <Td>
                    <span title={e.detail || undefined}>
                      <Badge tone={statusTone[e.status] ?? "neutral"}>{statusLabel[e.status] ?? e.status}</Badge>
                    </span>
                    {e.detail && e.status !== "verified" && <div className="max-w-56 text-[11px] text-muted-foreground">{e.detail}</div>}
                    {e.checks?.dns?.addresses?.length ? <div className="text-[11px] text-muted-foreground">{e.checks.dns.addresses.slice(0, 3).join(", ")}</div> : null}
                  </Td>
                  <Td className="text-[12px]">{tlsSummary(e)}</Td>
                  <Td className="tabular text-[12px] text-muted-foreground">{e.checked_at ? formatDateTime(e.checked_at) : "—"}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          {v.configured && (
            <p className="text-[11.5px] text-muted-foreground">
              {v.authorized_by && <>Authorized by {v.authorized_by}, {formatDateTime(v.authorized_at!)}{v.authorization_note && ` (${v.authorization_note})`}. </>}
              {v.rate_limit} requests per second{v.nuclei && ", plus Nuclei exposure templates"}.{" "}
              {v.open_findings > 0 && v.scan_target_id && (
                <Link to="/findings" search={{ scan_target_id: v.scan_target_id } as never} className="text-primary hover:underline">
                  {v.open_findings} open finding{v.open_findings === 1 ? "" : "s"}
                </Link>
              )}
              {v.last_scan && (
                <>
                  {" "}· Last run{" "}
                  <Link to="/scans/$id" params={{ id: v.last_scan.id }} className="font-mono text-primary hover:underline">{v.last_scan.scan_key}</Link> ({v.last_scan.status})
                </>
              )}
            </p>
          )}
        </>
      )}
      <EndpointVerificationDialog open={dialog} onClose={() => setDialog(false)} repoId={r.id} v={v} />
    </section>
  );
}

function EndpointVerificationDialog({ open, onClose, repoId, v }: { open: boolean; onClose: () => void; repoId: string; v: EndpointVerificationState }) {
  const qc = useQueryClient();
  const [authorized, setAuthorized] = useState(false);
  const [note, setNote] = useState("");
  const [rate, setRate] = useState("2");
  const [nuclei, setNuclei] = useState(false);
  useEffect(() => {
    if (!open) return;
    setAuthorized(false);
    setNote(v.authorization_note);
    setRate(String(v.rate_limit || 2));
    setNuclei(v.nuclei);
  }, [open, v]);
  const save = useMutation({
    mutationFn: () =>
      api<EndpointVerificationState>(`/api/v1/repositories/${repoId}/endpoint-verification`, {
        method: "PUT",
        body: { enabled: true, authorized, authorization_note: note, rate_limit: Number(rate), nuclei },
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["endpoint-verification", repoId] });
      onClose();
    },
  });
  const needsAuth = !v.configured || !v.enabled || (nuclei && !v.nuclei);
  const rateOk = Number(rate) >= 1 && Number(rate) <= 10;
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title="Endpoint verification"
      description="A worker checks the declared endpoints: DNS resolution, reachability, TLS certificate validity, expiry and host name, legacy protocols (TLS 1.0/1.1), weak cipher suites, HSTS and security headers. Nothing intrusive is sent."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button disabled={save.isPending || !rateOk || (needsAuth && !authorized)} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : v.configured && v.enabled ? "Save" : "Enable verification"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {save.error && <ErrorPanel error={save.error} />}
        <div>
          <span className="mb-1 block text-[12px] font-medium">Endpoints covered</span>
          <ul className="max-h-32 overflow-auto rounded-md border border-border p-2 font-mono text-[12px]">
            {v.endpoints.map((e) => <li key={e.kind + e.value}>{e.value}</li>)}
          </ul>
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <Label htmlFor="ep-rate" hint="(1-10)">Requests per second</Label>
            <Input id="ep-rate" type="number" min={1} max={10} value={rate} onChange={(e) => setRate(e.target.value)} />
          </div>
        </div>
        <label className="flex items-start gap-2 text-[12.5px]">
          <input type="checkbox" className="mt-0.5 accent-[var(--primary)]" checked={nuclei} onChange={(e) => setNuclei(e.target.checked)} />
          <span>
            Also run the Nuclei exposure templates (exposed files and panels, subdomain takeovers)
            <span className="block text-[11.5px] text-muted-foreground">Non-intrusive subset; fuzzing, brute-force and denial-of-service templates never run.</span>
          </span>
        </label>
        <div className="rounded-md border border-warning/40 bg-warning/5 p-3">
          <label className="flex items-start gap-2 text-[12.5px]">
            <input type="checkbox" className="mt-0.5 accent-[var(--primary)]" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
            <span>
              <span className="font-medium">I am authorized to test these endpoints.</span>
              <span className="block text-[11.5px] text-muted-foreground">
                The statement covers the endpoints listed above; endpoints declared later are skipped until someone confirms again. Your name and the time are recorded
                {needsAuth ? "" : " (optional now: confirm to cover the current list)"}.
              </span>
            </span>
          </label>
          <div className="mt-2">
            <Label htmlFor="ep-note" hint="(optional)">Authorization reference</Label>
            <Input id="ep-note" value={note} maxLength={2000} onChange={(e) => setNote(e.target.value)} placeholder="e.g. change ticket, owner's approval" />
          </div>
        </div>
        <p className="text-[11.5px] text-muted-foreground">
          Workers reach the endpoints only through the egress proxy: add their hosts to <code>deploy/egress/allowlist.txt</code>. Endpoints the proxy refuses are reported as blocked.
        </p>
      </div>
    </Dialog>
  );
}

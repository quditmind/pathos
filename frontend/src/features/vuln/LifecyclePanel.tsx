import { useState } from "react";
import { Clock, History, RotateCcw, ShieldOff, UserRound } from "lucide-react";
import { api } from "@/api/client";
import type { Finding } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Input, Label, Select } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { useUsers } from "@/features/users/api";
import { cn, formatDateTime } from "@/lib/utils";
import { needsReason, statusLabel, transitions, useAcceptances, useHistory, useVulnMutation } from "./api";

export function slaState(f: Pick<Finding, "sla_due_at" | "status">): { label: string; tone: "danger" | "warning" | "neutral" } | null {
  if (!f.sla_due_at || !["open", "in_progress", "needs_review"].includes(f.status)) return null;
  const days = Math.ceil((new Date(f.sla_due_at).getTime() - Date.now()) / 86400000);
  if (days < 0) return { label: `SLA breached ${-days}d ago`, tone: "danger" };
  if (days <= 7) return { label: `SLA due in ${days}d`, tone: "warning" };
  return { label: `SLA due in ${days}d`, tone: "neutral" };
}

export function LifecyclePanel({ f }: { f: Finding }) {
  const { can, canOrgWide, me } = useSession();
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");
  const [riskOpen, setRiskOpen] = useState(false);
  const [just, setJust] = useState("");
  const [days, setDays] = useState("90");
  const users = useUsers("", "active");
  const history = useHistory(f.id);
  const acceptances = useAcceptances({ finding_id: f.id });
  const setStatus = useVulnMutation((body: unknown) => api(`/api/v1/findings/${f.id}/status`, { method: "POST", body }));
  const assign = useVulnMutation((assignee_id: string | null) => api(`/api/v1/findings/${f.id}/assign`, { method: "POST", body: { assignee_id } }));
  const requestRisk = useVulnMutation((body: unknown) => api(`/api/v1/findings/${f.id}/risk-acceptance`, { method: "POST", body }));
  const decide = useVulnMutation(({ id, action }: { id: string; action: string }) => api(`/api/v1/risk-acceptances/${id}/${action}`, { method: "POST", body: { note: "" } }));
  const triage = can("findings.triage");
  const error = setStatus.error ?? assign.error ?? requestRisk.error ?? decide.error;
  const sla = slaState(f);
  const active = acceptances.data?.find((a) => a.status === "pending" || a.status === "approved");
  const userList = canOrgWide("users.read") ? users.data?.pages.flatMap((p) => p.items) ?? [] : [];

  return (
    <div className="space-y-4">
      {error && <Alert>{error.message}</Alert>}
      <div className="flex flex-wrap items-center gap-2 text-[12px]">
        {sla && <Badge tone={sla.tone}><Clock className="size-3" /> {sla.label}</Badge>}
        {f.recurrence_count > 0 && <Badge tone="warning"><RotateCcw className="size-3" /> reappeared {f.recurrence_count}×</Badge>}
        {f.accepted_until && <Badge tone="primary"><ShieldOff className="size-3" /> risk accepted until {formatDateTime(f.accepted_until)}</Badge>}
      </div>

      {triage && (
        <div className="grid gap-3 rounded-md border border-border p-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="lc-status">Status</Label>
            <div className="flex gap-2">
              <Select id="lc-status" className="w-full" value={target} onChange={(e) => setTarget(e.target.value)} disabled={!transitions[f.status]?.length}>
                <option value="">{statusLabel[f.status]} (current)</option>
                {(transitions[f.status] ?? []).map((s) => <option key={s} value={s}>{statusLabel[s]}</option>)}
              </Select>
              <Button size="sm" className="h-8" disabled={!target || setStatus.isPending || (needsReason(target) && reason.trim().length < 5)}
                onClick={() => setStatus.mutate({ status: target, reason }, { onSuccess: () => { setTarget(""); setReason(""); } })}>Apply</Button>
            </div>
            {target && <Input aria-label="Reason" className="mt-2" placeholder={needsReason(target) ? "Reason (required)" : "Reason (optional)"} value={reason} onChange={(e) => setReason(e.target.value)} />}
          </div>
          <div>
            <Label htmlFor="lc-assign">Assignee</Label>
            {userList.length ? (
              <Select id="lc-assign" className="w-full" value={f.assignee_id ?? ""} onChange={(e) => assign.mutate(e.target.value || null)}>
                <option value="">Unassigned</option>
                {userList.map((u) => <option key={u.id} value={u.id}>{u.display_name || u.email}</option>)}
              </Select>
            ) : (
              <div className="flex items-center gap-2">
                <span className="text-[13px]">{f.assignee_name ?? "Unassigned"}</span>
                {f.assignee_id !== me.user.id
                  ? <Button size="sm" variant="secondary" onClick={() => assign.mutate(me.user.id)}><UserRound /> Assign to me</Button>
                  : <Button size="sm" variant="ghost" onClick={() => assign.mutate(null)}>Unassign</Button>}
              </div>
            )}
          </div>
        </div>
      )}

      <div>
        <div className="mb-1.5 flex items-center justify-between">
          <h3 className="text-[13px] font-semibold">Risk acceptance</h3>
          {triage && !active && ["open", "in_progress", "needs_review"].includes(f.status) && !riskOpen && (
            <Button size="sm" variant="secondary" onClick={() => setRiskOpen(true)}>Request acceptance</Button>
          )}
        </div>
        {riskOpen && (
          <div className="space-y-2 rounded-md border border-border p-3">
            <textarea aria-label="Justification" rows={3} placeholder="Why the risk is acceptable (compensating controls, exposure, plan)" value={just} onChange={(e) => setJust(e.target.value)}
              className="w-full rounded-md border border-border bg-surface p-2 text-[13px] focus-visible:outline-2 focus-visible:outline-ring" />
            <div className="flex items-center gap-2">
              <Select aria-label="Duration" value={days} onChange={(e) => setDays(e.target.value)}>{["30", "90", "180", "365"].map((d) => <option key={d} value={d}>{d} days</option>)}</Select>
              <Button size="sm" disabled={just.trim().length < 10 || requestRisk.isPending}
                onClick={() => requestRisk.mutate({ justification: just, expires_at: new Date(Date.now() + Number(days) * 86400000).toISOString() },
                  { onSuccess: () => { setRiskOpen(false); setJust(""); } })}>Submit for approval</Button>
              <Button size="sm" variant="ghost" onClick={() => setRiskOpen(false)}>Cancel</Button>
            </div>
          </div>
        )}
        {acceptances.data?.length ? (
          <ul className="space-y-2">
            {acceptances.data.slice(0, 3).map((a) => (
              <li key={a.id} className="rounded-md border border-border p-2.5 text-[12.5px]">
                <div className="flex items-center gap-2"><Badge tone={a.status === "approved" ? "primary" : a.status === "pending" ? "warning" : "neutral"}>{a.status}</Badge>
                  <span className="text-muted-foreground">by {a.requested_by} · until {formatDateTime(a.expires_at)}</span></div>
                <p className="mt-1">{a.justification}</p>
                {a.decided_by && <p className="mt-1 text-[11.5px] text-muted-foreground">{a.status} by {a.decided_by}{a.decision_note && ` — “${a.decision_note}”`}</p>}
                {can("findings.accept_risk") && a.status === "pending" && (
                  <div className="mt-2 flex gap-2">
                    <Button size="sm" onClick={() => decide.mutate({ id: a.id, action: "approve" })}>Approve</Button>
                    <Button size="sm" variant="secondary" onClick={() => decide.mutate({ id: a.id, action: "reject" })}>Reject</Button>
                  </div>
                )}
                {can("findings.accept_risk") && a.status === "approved" && (
                  <Button size="sm" variant="danger-outline" className="mt-2" onClick={() => decide.mutate({ id: a.id, action: "revoke" })}>Revoke</Button>
                )}
              </li>
            ))}
          </ul>
        ) : !riskOpen && <p className="text-[12px] text-muted-foreground">None.</p>}
      </div>

      <div>
        <h3 className="mb-1.5 flex items-center gap-1.5 text-[13px] font-semibold"><History className="size-4" /> History</h3>
        <ol className="relative ml-1.5 border-l border-border">
          {(history.data ?? []).map((h, i) => (
            <li key={i} className="mb-2.5 ml-3 text-[12px]">
              <span className={cn("absolute -left-[4.5px] mt-1.5 size-2 rounded-full", h.source === "user" ? "bg-primary" : "bg-muted-foreground/50")} />
              <div><span className="font-medium">{h.from_status ? `${statusLabel[h.from_status]} → ` : ""}{statusLabel[h.to_status]}</span>
                <span className="text-muted-foreground"> · {h.actor ?? (h.source === "ai" ? "AI policy" : h.source === "scanner" ? "Scanner" : h.source === "expiry" ? "Expiry" : "PATHOS")} · {formatDateTime(h.created_at)}</span></div>
              {h.reason && <div className="text-muted-foreground">{h.reason}</div>}
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}

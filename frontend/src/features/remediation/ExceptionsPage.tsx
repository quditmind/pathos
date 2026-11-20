import { useState } from "react";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Badge, Card, Label, Select, Table, Td, Th } from "@/components/ui/primitives";
import { EmptyStateCard, LoadingSkeleton } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { exceptionStatuses, isFeatureDisabled, useDecideException, useExceptions, type ExceptionStatus, type GateException } from "./api";
import { RemediationFrame, shortSha } from "./shared";

export function validateExceptionsSearch(s: Record<string, unknown>): { status?: string } {
  return { status: typeof s.status === "string" && s.status ? s.status : undefined };
}

const tone: Record<ExceptionStatus, "neutral" | "success" | "danger" | "warning"> = {
  requested: "warning",
  approved: "success",
  rejected: "danger",
  expired: "neutral",
  revoked: "neutral",
};

type Action = "approve" | "reject" | "revoke";

/**
 * Gate exceptions and approvals (/remediation/exceptions): requests with
 * their reason, scope and expiry. The approver is never the requester (the
 * API refuses it, PTH-GATE-1103); every decision is audited.
 */
export function ExceptionsPage() {
  const search = useSearch({ strict: false }) as { status?: string };
  const navigate = useNavigate();
  const status = search.status ?? "requested";
  const list = useExceptions(status === "all" ? undefined : status);
  const [acting, setActing] = useState<{ x: GateException; action: Action } | null>(null);
  return (
    <RemediationFrame
      title="Gate exceptions and approvals"
      description="Time-limited exceptions to a blocking gate and approvals of gates that require one. Someone other than the requester decides; every decision is audited."
      disabled={isFeatureDisabled(list.error)}
    >
      <div className="mb-3 flex items-center gap-2">
        <Select
          aria-label="Exception status"
          value={status}
          onChange={(e) => void navigate({ to: "/remediation/exceptions", search: { status: e.target.value } as never, replace: true })}
        >
          <option value="all">All</option>
          {exceptionStatuses.map((s) => (
            <option key={s} value={s} className="capitalize">{s}</option>
          ))}
        </Select>
      </div>
      {list.isError ? (
        <ErrorPanel error={list.error} title="Exceptions could not be loaded" />
      ) : list.isPending ? (
        <LoadingSkeleton rows={4} label="Loading exceptions" />
      ) : !list.data.length ? (
        <EmptyStateCard icon={<ShieldAlert />} title={status === "requested" ? "Nothing waiting for a decision" : "No exceptions"}>
          Requests appear here when someone asks for an exception or an approval on a gate decision (Gates &amp; decisions → a decision → Request exception).
        </EmptyStateCard>
      ) : (
        <Card>
          <Table>
            <thead>
              <tr>
                <Th>Gate</Th>
                <Th>Kind</Th>
                <Th>Scope</Th>
                <Th>Reason</Th>
                <Th>Status</Th>
                <Th>Expires</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {list.data.map((x) => (
                <Row key={x.id} x={x} onAct={(action) => setActing({ x, action })} />
              ))}
            </tbody>
          </Table>
        </Card>
      )}
      {acting && <DecideDialog {...acting} onClose={() => setActing(null)} />}
    </RemediationFrame>
  );
}

function Row({ x, onAct }: { x: GateException; onAct: (a: Action) => void }) {
  const { can, me } = useSession();
  const mine = x.requested_by_email === me.user.email;
  const approver = can("gates.approve_exception");
  const pending = x.status === "requested";
  const why = !approver ? "Deciding needs the gates.approve_exception permission." : mine ? "You requested this; someone else must decide it." : "";
  return (
    <tr>
      <Td className="text-[12.5px]">{x.gate_name}</Td>
      <Td className="text-[12px]">{x.kind === "approval" ? "Approval" : "Exception"}</Td>
      <Td className="text-[12px]">
        {x.scope.pull_request ? `PR #${x.scope.pull_request}` : x.scope.commit_sha ? <span className="font-mono">{shortSha(x.scope.commit_sha)}</span> : x.scope.repository_id ? "Repository" : x.scope.application_id ? "Application" : "—"}
      </Td>
      <Td className="max-w-80 text-[12px]">
        <p className="line-clamp-3" title={x.reason}>{x.reason}</p>
        <p className="text-[11px] text-muted-foreground">
          by {x.requested_by_email} · {formatDateTime(x.created_at)}
          {x.decided_by_email && ` · decided by ${x.decided_by_email}`}
          {x.decision_note && ` — ${x.decision_note}`}
        </p>
      </Td>
      <Td><Badge tone={tone[x.status]}>{x.status}</Badge></Td>
      <Td className="whitespace-nowrap text-[11.5px]">{formatDateTime(x.expires_at)}</Td>
      <Td className="whitespace-nowrap text-right">
        {pending && (
          <>
            <Button size="sm" disabled={!!why || !x.can_decide} title={why || undefined} onClick={() => onAct("approve")}>Approve</Button>{" "}
            <Button size="sm" variant="secondary" disabled={!!why || !x.can_decide} title={why || undefined} onClick={() => onAct("reject")}>Reject</Button>
            {why && <p className="mt-1 max-w-52 whitespace-normal text-left text-[11px] text-muted-foreground">{why}</p>}
          </>
        )}
        {(x.status === "approved" || (pending && mine)) && (approver || mine) && (
          <Button size="sm" variant="danger-outline" className="ml-1" onClick={() => onAct("revoke")}>Revoke</Button>
        )}
      </Td>
    </tr>
  );
}

const actionText: Record<Action, { title: string; done: string }> = {
  approve: { title: "Approve", done: "Approved" },
  reject: { title: "Reject", done: "Rejected" },
  revoke: { title: "Revoke", done: "Revoked" },
};

function DecideDialog({ x, action, onClose }: { x: GateException; action: Action; onClose: () => void }) {
  const decide = useDecideException();
  const [note, setNote] = useState("");
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={`${actionText[action].title} ${x.kind === "approval" ? "approval" : "exception"}`}
      description={`Gate “${x.gate_name}”, requested by ${x.requested_by_email}. Expires ${formatDateTime(x.expires_at)}.`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button
            variant={action === "approve" ? "primary" : "danger"}
            disabled={decide.isPending || (action !== "approve" && note.trim().length < 3)}
            onClick={() =>
              decide.mutate(
                { id: x.id, action, note: note.trim() },
                {
                  onSuccess: () => {
                    toast.success(`${actionText[action].done}: ${x.gate_name}`);
                    onClose();
                  },
                },
              )
            }
          >
            {actionText[action].title}
          </Button>
        </>
      }
    >
      <div className="space-y-2 text-[13px]">
        <p className="whitespace-pre-wrap rounded-md bg-surface-muted p-2">{x.reason}</p>
        <Label htmlFor="exc-note">{action === "approve" ? "Note (optional)" : "Note (required)"}</Label>
        <textarea
          id="exc-note"
          className="min-h-20 w-full rounded-md border border-border bg-surface px-2 py-1.5 text-[13px] focus-visible:outline-2 focus-visible:outline-ring"
          value={note}
          maxLength={2000}
          onChange={(e) => setNote(e.target.value)}
        />
        {decide.error && <ErrorPanel error={decide.error} />}
      </div>
    </Dialog>
  );
}

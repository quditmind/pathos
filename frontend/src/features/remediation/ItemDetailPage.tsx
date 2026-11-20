import { useEffect, useState } from "react";
import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft, CheckCircle2, ExternalLink, RefreshCw } from "lucide-react";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Badge, Card, Input, Label, Select, Table, Td, Th } from "@/components/ui/primitives";
import { LoadingSkeleton } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useSession } from "@/features/auth/session";
import { redactToolNames } from "@/lib/checkKinds";
import { formatDateTime } from "@/lib/utils";
import {
  isFeatureDisabled,
  kindLabel,
  manualStatuses,
  priorities,
  statusLabel,
  useItem,
  useUpdateItem,
  useVerify,
  type ItemDetail,
  type ItemStatus,
  type Priority,
  type Verification,
} from "./api";
import { DueDate, StatusBadge, resultLabel } from "./RemediationPage";
import { EvidenceBadge, RemediationFrame, UserPicker, shortSha, useOption } from "./shared";

/**
 * One remediation item (/remediation/items/$id): findings, affected files,
 * owner, due date, status, root cause, secure fix guidance, fix pull
 * requests and the verification history with before-and-after evidence.
 */
export function RemediationItemPage({ id: idProp }: { id?: string } = {}) {
  const params = useParams({ strict: false }) as { id?: string };
  const id = idProp ?? params.id ?? "";
  const q = useItem(id);
  return (
    <RemediationFrame
      title="Remediation item"
      description="Everything needed to fix it, and the proof that it is fixed."
      disabled={isFeatureDisabled(q.error)}
      actions={
        <Button size="sm" variant="ghost" asChild>
          <Link to="/remediation">
            <ArrowLeft /> All items
          </Link>
        </Button>
      }
    >
      {q.isError ? (
        <ErrorPanel error={q.error} title="The remediation item could not be loaded" onVerify={() => q.refetch()} />
      ) : q.isPending ? (
        <LoadingSkeleton rows={6} label="Loading the remediation item" />
      ) : (
        <Detail item={q.data} />
      )}
    </RemediationFrame>
  );
}

function Detail({ item }: { item: ItemDetail }) {
  const { can } = useSession();
  const manage = can("remediation.manage");
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
      <div className="min-w-0 space-y-4">
        <Card className="p-4">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <h2 className="text-[15px] font-semibold">{item.title}</h2>
            <StatusBadge status={item.status} />
            <Badge>{kindLabel[item.kind] ?? item.kind}</Badge>
            {item.top_severity && <SeverityBadge value={item.top_severity} />}
          </div>
          <p className="text-[12px] text-muted-foreground">
            {item.repository_name || item.application_name} · created {formatDateTime(item.created_at)}
            {item.closed_at && <> · closed {formatDateTime(item.closed_at)}</>}
          </p>
        </Card>
        <Card className="p-4">
          <h3 className="mb-2 text-[13px] font-semibold">Findings ({item.findings.length})</h3>
          <Table>
            <thead>
              <tr>
                <Th>Severity</Th>
                <Th>Finding</Th>
                <Th>Location</Th>
                <Th>Status</Th>
              </tr>
            </thead>
            <tbody>
              {item.findings.map((f) => (
                <tr key={f.id}>
                  <Td><SeverityBadge value={f.severity} /></Td>
                  <Td className="text-[12.5px]">
                    <Link to="/findings" search={{ finding: f.id, status: "all" } as never} className="text-primary hover:underline">{f.title}</Link>
                  </Td>
                  <Td className="max-w-64 truncate font-mono text-[11.5px]">
                    <span title={f.file_path}>{f.file_path ? `${f.file_path}${f.start_line ? `:${f.start_line}` : ""}` : "—"}</span>
                  </Td>
                  <Td className="text-[12px]">{f.status.replace(/_/g, " ")}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <h4 className="mb-1 mt-3 text-[12px] font-semibold">Affected files</h4>
          {item.affected_files.length ? (
            <ul className="space-y-0.5 font-mono text-[11.5px]">
              {item.affected_files.map((f) => <li key={f}>{f}</li>)}
            </ul>
          ) : (
            <p className="text-[12px] text-muted-foreground">No file location (for example a finding on a component or an image).</p>
          )}
        </Card>
        <Guidance item={item} />
        <Verifications item={item} manage={manage} />
      </div>
      <div className="min-w-0 space-y-4">
        <Tracking item={item} manage={manage} />
        <Card className="p-4">
          <h3 className="mb-2 text-[13px] font-semibold">Fix pull requests</h3>
          {item.fix_prs.length ? (
            <ul className="space-y-1 text-[12.5px]">
              {item.fix_prs.map((p) => (
                <li key={p.id} className="flex items-center gap-2">
                  <Badge tone={p.status === "merged" ? "success" : p.status === "failed" || p.status === "closed" ? "danger" : "neutral"}>{p.status}</Badge>
                  <span>{p.kind === "ai_code" ? "Verified AI fix" : "Dependency upgrade"}</span>
                  {p.pr_url && (
                    <a href={p.pr_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
                      Open <ExternalLink className="size-3" />
                    </a>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[12px] text-muted-foreground">
              No fix pull request yet. Open one from a finding (dependency upgrade or verified AI fix); when it merges, PATHOS queues a targeted rescan automatically.
            </p>
          )}
        </Card>
      </div>
    </div>
  );
}

function Tracking({ item, manage }: { item: ItemDetail; manage: boolean }) {
  const { me, can } = useSession();
  const update = useUpdateItem(item.id);
  const [owner, setOwner] = useOption();
  const [due, setDue] = useState(item.due_at ? item.due_at.slice(0, 10) : "");
  const [root, setRoot] = useState(item.root_cause);
  useEffect(() => {
    setRoot(item.root_cause);
    setDue(item.due_at ? item.due_at.slice(0, 10) : "");
  }, [item.root_cause, item.due_at]);
  const save = (body: Parameters<typeof update.mutate>[0], what: string) => update.mutate(body, { onSuccess: () => toast.success(what) });
  const statusOptions = manualStatuses.includes(item.status) ? manualStatuses : [item.status, ...manualStatuses];
  return (
    <Card className="space-y-3 p-4 text-[13px]">
      <h3 className="text-[13px] font-semibold">Tracking</h3>
      <div>
        <Label htmlFor="rem-status">Status</Label>
        <Select
          id="rem-status"
          value={item.status}
          disabled={!manage || item.status === "closed" || item.status === "verifying"}
          onChange={(e) => save({ status: e.target.value as ItemStatus }, `Status set to ${statusLabel[e.target.value as ItemStatus]}`)}
        >
          {statusOptions.map((s) => (
            <option key={s} value={s} disabled={!manualStatuses.includes(s)}>{statusLabel[s]}</option>
          ))}
        </Select>
        <p className="mt-1 text-[11.5px] text-muted-foreground">An item closes only when a verification proves the fix (Verify fix below).</p>
      </div>
      <div>
        <Label htmlFor="rem-priority">Priority</Label>
        <Select id="rem-priority" value={item.priority} disabled={!manage} onChange={(e) => save({ priority: e.target.value as Priority }, "Priority updated")}>
          {priorities.map((p) => <option key={p} value={p}>{p}</option>)}
        </Select>
      </div>
      <div>
        <span className="mb-1 block text-[12px] font-medium">Owner</span>
        <p className="mb-1">{item.owner_email || <span className="text-muted-foreground">Unassigned</span>}</p>
        {manage && (
          <div className="flex flex-wrap items-center gap-1">
            <Button size="sm" variant="secondary" onClick={() => save({ owner_id: me.user.id }, "Assigned to you")}>Assign to me</Button>
            {can("users.read") && (
              <>
                <UserPicker value={owner} onChange={setOwner} label="New owner" />
                <Button size="sm" variant="secondary" disabled={!owner} onClick={() => owner && save({ owner_id: owner.value }, `Assigned to ${owner.label}`)}>Assign</Button>
              </>
            )}
            {item.owner_id && <Button size="sm" variant="ghost" onClick={() => save({ clear_owner: true }, "Owner removed")}>Unassign</Button>}
          </div>
        )}
      </div>
      <div>
        <span className="mb-1 block text-[12px] font-medium">Due date</span>
        <p className="mb-1"><DueDate item={item} /></p>
        {manage && (
          <div className="flex items-center gap-1">
            <Input type="date" aria-label="Due date" value={due} onChange={(e) => setDue(e.target.value)} />
            <Button size="sm" variant="secondary" disabled={!due} onClick={() => save({ due_at: new Date(`${due}T23:59:59Z`).toISOString() }, "Due date set")}>Set</Button>
            {item.due_source === "manual" && <Button size="sm" variant="ghost" onClick={() => save({ clear_due: true }, "Due date reset to the SLA")}>Use SLA</Button>}
          </div>
        )}
      </div>
      <div>
        <Label htmlFor="rem-root">Root cause</Label>
        <textarea
          id="rem-root"
          className="min-h-20 w-full rounded-md border border-border bg-surface px-2 py-1.5 text-[13px] focus-visible:outline-2 focus-visible:outline-ring"
          value={root}
          maxLength={4000}
          disabled={!manage}
          onChange={(e) => setRoot(e.target.value)}
          placeholder="Why did this happen? (for example: input passed to a SQL query without parameters)"
        />
        {manage && root !== item.root_cause && (
          <Button size="sm" className="mt-1" onClick={() => save({ root_cause: root }, "Root cause saved")} disabled={update.isPending}>Save root cause</Button>
        )}
      </div>
      {update.error && <ErrorPanel error={update.error} />}
    </Card>
  );
}

function Guidance({ item }: { item: ItemDetail }) {
  return (
    <Card className="p-4">
      <h3 className="mb-2 text-[13px] font-semibold">Secure fix guidance</h3>
      {item.guidance.length ? (
        <ul className="space-y-3">
          {item.guidance.map((g, i) => (
            <li key={i} className="text-[12.5px]">
              <div className="mb-0.5 flex flex-wrap items-center gap-2">
                <span className="font-medium">{g.title}</span>
                <EvidenceBadge evidence={g.evidence} />
                {g.link && (
                  <a href={g.link} target={g.link.startsWith("http") ? "_blank" : undefined} rel="noreferrer" className="text-primary hover:underline">
                    Open
                  </a>
                )}
              </div>
              <p className="whitespace-pre-wrap text-muted-foreground">{redactToolNames(g.text)}</p>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-[12px] text-muted-foreground">No guidance recorded yet. Request an AI review or a verified AI fix on the finding, or add a root cause.</p>
      )}
    </Card>
  );
}

function Verifications({ item, manage }: { item: ItemDetail; manage: boolean }) {
  const verify = useVerify(item.id);
  const [confirm, setConfirm] = useState(false);
  const running = item.verifications.some((v) => v.status === "queued" || v.status === "running");
  // The item's owner may verify their own item; others need
  // remediation.manage and scans.run (the server decides: can_request_verification).
  const allowed = item.can_request_verification ?? manage;
  const reason = !allowed
    ? "Only the item's owner, or someone with remediation.manage and scans.run on the repository, can verify the fix."
    : !item.can_verify ? redactToolNames(item.verify_unavailable_reason) : running ? "A verification is already running." : "";
  return (
    <Card className="p-4">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <h3 className="text-[13px] font-semibold">Fix verification</h3>
        <Button size="sm" className="ml-auto" disabled={!!reason || verify.isPending} onClick={() => setConfirm(true)} title={reason || undefined}>
          <RefreshCw /> Verify fix
        </Button>
      </div>
      {reason && <p className="mb-2 text-[12px] text-muted-foreground" data-testid="verify-reason">{reason}</p>}
      <p className="mb-2 text-[12px] text-muted-foreground">
        Verify fix re-runs the finding's own check on the affected files at the current head of the scan branch and compares the result with the scan that
        found it. The item closes only when the rescan proves the finding gone; new results in the same files are reported as regressions.
      </p>
      {verify.error && <ErrorPanel error={verify.error} />}
      {item.verifications.length ? (
        <div className="space-y-3">{item.verifications.map((v) => <VerificationCard key={v.id} v={v} />)}</div>
      ) : (
        <p className="text-[12px] text-muted-foreground">Not verified yet.</p>
      )}
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title="Verify the fix"
        confirmLabel="Queue rescan"
        destructive={false}
        pending={verify.isPending}
        error={verify.error?.message}
        onConfirm={() =>
          verify.mutate({}, {
            onSuccess: () => {
              toast.success("Targeted rescan queued");
              setConfirm(false);
            },
          })
        }
      >
        A worker will rescan {item.affected_files.length || "the"} affected file(s) with the finding's check. This uses a worker slot and takes a few minutes.
      </ConfirmDialog>
    </Card>
  );
}

const triggerLabel: Record<Verification["trigger"], string> = { manual: "Requested", fix_pr_merged: "Fix PR merged", existing_scan: "From an existing scan" };

export function VerificationCard({ v }: { v: Verification }) {
  const tone = v.result === "fixed" ? "success" : v.result === "still_present" || v.result === "regressed" ? "danger" : "warning";
  return (
    <div className="rounded-md border border-border p-3 text-[12.5px]" data-testid="verification">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        {v.result ? <Badge tone={tone}>{v.result === "fixed" && <CheckCircle2 className="size-3" aria-hidden />}{resultLabel[v.result]}</Badge> : <Badge>{v.status}</Badge>}
        <span className="text-muted-foreground">{triggerLabel[v.trigger] ?? v.trigger}{v.requested_by_email && ` by ${v.requested_by_email}`} · {formatDateTime(v.created_at)}</span>
      </div>
      {v.failure_reason && <p className="mb-1 text-danger">{redactToolNames(v.failure_reason)}</p>}
      <Table>
        <thead>
          <tr><Th /><Th>Scan</Th><Th>Commit</Th><Th className="text-right">Results</Th></tr>
        </thead>
        <tbody>
          {(["before", "after"] as const).map((k) => (
            <tr key={k}>
              <Td className="font-medium capitalize">{k}</Td>
              <Td className="font-mono text-[11.5px]">
                {v[k].scan_job_id ? <Link to="/scans/$id" params={{ id: v[k].scan_job_id! }} className="text-primary hover:underline">{v[k].scan_job_id!.slice(0, 8)}</Link> : k === "after" && v.status !== "completed" ? "pending" : "targeted rescan"}
              </Td>
              <Td className="font-mono text-[11.5px]">{shortSha(v[k].commit)}</Td>
              <Td className="tabular text-right">{v.status === "completed" || k === "before" ? v[k].result_count : "—"}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
      {v.scanner_key && (
        // Tool names stay on the configuration pages (prompt rule 3): the key is kept in the data attribute for audit.
        <p className="mt-1 text-[11.5px] text-muted-foreground" data-tool={v.scanner_key}>
          The finding's own check re-ran on {v.files.join(", ") || "the affected files"}
        </p>
      )}
      {v.findings.length > 0 && (
        <ul className="mt-1 space-y-0.5 text-[12px]">
          {v.findings.map((f) => (
            <li key={f.finding_id}>
              Finding {f.finding_id.slice(0, 8)}: {f.status_before} → {f.status_after || "—"} {f.reproduced ? (f.removed ? "(reported before, gone after)" : "(still reported)") : "(not reproduced on the baseline)"}
            </li>
          ))}
        </ul>
      )}
      {v.regressions.length > 0 && (
        <div className="mt-2">
          <p className="font-medium text-danger">New results in the changed files ({v.regressions.length})</p>
          <ul className="font-mono text-[11.5px]">
            {v.regressions.map((r, i) => <li key={i}>{r.rule_id} at {r.file}:{r.line}{r.title && ` — ${r.title}`}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}

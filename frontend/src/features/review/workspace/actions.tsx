import { useState } from "react";
import { api, ApiError } from "@/api/client";
import type { Finding, Page } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Combobox, type ComboOption } from "@/components/ui/combobox";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Input, Label, Select } from "@/components/ui/primitives";
import { reviewApi, useReviewers, useReviewMutation } from "../api";
import { dispositionLabel, priorityLabel } from "../shared";
import type { Disposition, Priority, ReviewDetail } from "../types";
import type { WorkspaceTab } from "./WorkspacePage";

export const textareaCls =
  "w-full rounded-md border border-border bg-surface px-2.5 py-2 text-[13px] text-foreground placeholder:text-muted-foreground focus-visible:outline-2 focus-visible:outline-ring aria-[invalid=true]:border-danger disabled:opacity-60";

function FieldErrors({ error }: { error: Error | null }) {
  if (!error) return null;
  const fields = error instanceof ApiError ? error.fields : undefined;
  return (
    <Alert>
      {fields ? (
        <ul className="list-disc space-y-0.5 pl-4">
          {Object.values(fields).map((m) => <li key={m}>{m}</li>)}
        </ul>
      ) : (
        error.message
      )}
    </Alert>
  );
}

const toIso = (date: string) => (date ? new Date(`${date}T17:00:00`).toISOString() : undefined);

export function AssignDialog({ d, open, onOpenChange }: { d: ReviewDetail; open: boolean; onOpenChange: (o: boolean) => void }) {
  const reviewers = useReviewers(d.repository_id, open);
  const [reviewer, setReviewer] = useState(d.reviewer_id ?? "");
  const [second, setSecond] = useState(d.independent_reviewer_id ?? "");
  const [priority, setPriority] = useState<Priority>(d.priority);
  const [due, setDue] = useState(d.due_at?.slice(0, 10) ?? "");
  const [note, setNote] = useState("");
  const m = useReviewMutation(() =>
    reviewApi.assign(d.id, {
      reviewer_id: reviewer && reviewer !== d.reviewer_id ? reviewer : undefined,
      independent_reviewer_id: second && second !== d.independent_reviewer_id ? second : undefined,
      priority: priority !== d.priority ? priority : undefined,
      due_at: due && due !== d.due_at?.slice(0, 10) ? toIso(due) : undefined,
      note: note || undefined,
    }),
  );
  const changed = (reviewer && reviewer !== d.reviewer_id) || (second && second !== d.independent_reviewer_id);
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Assign review"
      description="Only analysts holding reviews.assess on this repository are listed; independent reviewers need reviews.approve."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button disabled={!changed || m.isPending} onClick={() => m.mutate(undefined, { onSuccess: () => onOpenChange(false) })}>
            {d.reviewer_id ? "Reassign" : "Assign"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <FieldErrors error={m.error} />
        <div>
          <Label htmlFor="as-reviewer">Analyst</Label>
          <Select id="as-reviewer" className="w-full" value={reviewer} onChange={(e) => setReviewer(e.target.value)}>
            <option value="">Choose…</option>
            {(reviewers.data ?? []).filter((r) => r.can_assess && r.id !== second).map((r) => (
              <option key={r.id} value={r.id}>{r.name} · {r.open_reviews} open</option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="as-second" hint="(optional)">Independent reviewer</Label>
          <Select id="as-second" className="w-full" value={second} onChange={(e) => setSecond(e.target.value)}>
            <option value="">Any eligible reviewer</option>
            {(reviewers.data ?? []).filter((r) => r.can_approve && r.id !== reviewer).map((r) => (
              <option key={r.id} value={r.id}>{r.name}</option>
            ))}
          </Select>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <Label htmlFor="as-priority">Priority</Label>
            <Select id="as-priority" className="w-full" value={priority} onChange={(e) => setPriority(e.target.value as Priority)}>
              {(Object.keys(priorityLabel) as Priority[]).map((p) => <option key={p} value={p}>{priorityLabel[p]}</option>)}
            </Select>
          </div>
          <div>
            <Label htmlFor="as-due">Due date</Label>
            <Input id="as-due" type="date" value={due} onChange={(e) => setDue(e.target.value)} />
          </div>
        </div>
        <div>
          <Label htmlFor="as-note" hint="(optional, added as a comment)">Note to the analyst</Label>
          <Input id="as-note" value={note} onChange={(e) => setNote(e.target.value)} />
        </div>
      </div>
    </Dialog>
  );
}

const hints: Record<Disposition, string> = {
  confirmed: "A real, exploitable vulnerability. It becomes available to remediation.",
  false_positive: "Explain why the scanner detection is incorrect. The finding is closed as a false positive.",
  duplicate: "Reference the primary finding.",
  not_exploitable: "Requires evidence or a technical justification in the Exploitability tab.",
  accepted_risk: "Requires a risk owner and an expiry date, and approval by someone with findings.accept_risk.",
  mitigated: "Compensating controls neutralise the issue.",
  needs_more_information: "Keeps the review open and waiting for information.",
  out_of_scope: "The finding is outside the scope of this assessment.",
};

export function DecisionDialog({ d, open, onOpenChange, onGoto }: { d: ReviewDetail; open: boolean; onOpenChange: (o: boolean) => void; onGoto: (t: WorkspaceTab) => void }) {
  const reviewers = useReviewers(undefined, open);
  const [disp, setDisp] = useState<Disposition>("confirmed");
  const [reason, setReason] = useState("");
  const [dup, setDup] = useState<ComboOption | null>(null);
  const [dupUnavailable, setDupUnavailable] = useState(false);
  const [owner, setOwner] = useState("");
  const [expires, setExpires] = useState("");
  const [remOwner, setRemOwner] = useState("");
  const [remDue, setRemDue] = useState("");
  const [remPrio, setRemPrio] = useState<Priority>(d.priority);
  const m = useReviewMutation(() =>
    reviewApi.decision(d.id, {
      disposition: disp,
      reason,
      duplicate_of: disp === "duplicate" ? dup?.value : undefined,
      duplicate_reference_unavailable: disp === "duplicate" && dupUnavailable,
      risk_owner_id: disp === "accepted_risk" ? owner || undefined : undefined,
      risk_expires_at: disp === "accepted_risk" ? toIso(expires) : undefined,
      remediation_owner_id: disp === "confirmed" ? remOwner || undefined : undefined,
      remediation_due_at: disp === "confirmed" ? toIso(remDue) : undefined,
      remediation_priority: disp === "confirmed" ? remPrio : undefined,
    }),
  );
  const sev = d.assessed_severity ?? d.severity;
  const independent = disp !== "needs_more_information" && (disp === "accepted_risk" || d.requires_independent_review);
  const evidenceNeeded = disp !== "needs_more_information" && (d.evidence_required_for || d.evidence_required_dispositions.includes(disp)) && d.evidence_count === 0;
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="lg"
      title="Submit decision"
      description={`Final disposition for ${d.review_key}. The review status, disposition and remediation status are recorded separately.`}
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button disabled={m.isPending || reason.trim().length < 10} onClick={() => m.mutate(undefined, { onSuccess: () => onOpenChange(false) })}>
            {m.isPending ? "Submitting…" : independent ? "Submit for independent review" : disp === "needs_more_information" ? "Mark as awaiting information" : "Submit and complete"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <FieldErrors error={m.error} />
        <fieldset>
          <legend className="mb-1 text-[12px] font-medium">Final disposition</legend>
          <div className="grid gap-1.5 sm:grid-cols-2">
            {(Object.keys(dispositionLabel) as Disposition[]).map((k) => (
              <label key={k} className="flex cursor-pointer items-start gap-2 rounded-md border border-border p-2 text-[12.5px] has-checked:border-primary has-checked:bg-primary/5">
                <input type="radio" name="disposition" className="mt-0.5 accent-[var(--primary)]" checked={disp === k} onChange={() => setDisp(k)} />
                <span>
                  <span className="font-medium">{dispositionLabel[k]}</span>
                  <span className="block text-[11.5px] text-muted-foreground">{hints[k]}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
        <div>
          <Label htmlFor="dec-reason" hint={["false_positive", "not_exploitable", "accepted_risk"].includes(disp) ? "(at least 30 characters)" : "(at least 10 characters)"}>
            {disp === "false_positive" ? "Why is the scanner detection incorrect?" : disp === "not_exploitable" ? "Technical justification" : "Documented reason"}
          </Label>
          <textarea id="dec-reason" rows={4} className={textareaCls} value={reason} onChange={(e) => setReason(e.target.value)} required aria-required />
        </div>
        {disp === "duplicate" && (
          <div className="space-y-2">
            <Label htmlFor="dec-dup">Primary finding</Label>
            <Combobox
              id="dec-dup"
              value={dup}
              onChange={setDup}
              disabled={dupUnavailable}
              placeholder="Search findings in this repository…"
              queryKey={`dup-${d.repository_id}`}
              load={(q, signal) => {
                const p = new URLSearchParams({ repository_id: d.repository_id, status: "all" });
                if (q) p.set("q", q);
                return api<Page<Finding>>(`/api/v1/findings?${p}`, { signal }).then((r) =>
                  r.items.filter((f) => f.id !== d.finding_id).map((f) => ({ value: f.id, label: f.title, description: `${f.file_path || f.package_name}${f.start_line ? `:${f.start_line}` : ""}` })),
                );
              }}
            />
            <label className="flex items-center gap-1.5 text-[12.5px]">
              <input type="checkbox" className="accent-[var(--primary)]" checked={dupUnavailable} onChange={(e) => setDupUnavailable(e.target.checked)} />
              The primary finding is not in PATHOS (explain where in the reason)
            </label>
          </div>
        )}
        {disp === "accepted_risk" && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label htmlFor="dec-owner">Risk owner</Label>
              <Select id="dec-owner" className="w-full" value={owner} onChange={(e) => setOwner(e.target.value)}>
                <option value="">Choose…</option>
                {(reviewers.data ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </Select>
            </div>
            <div>
              <Label htmlFor="dec-exp">Acceptance expires</Label>
              <Input id="dec-exp" type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />
            </div>
          </div>
        )}
        {disp === "confirmed" && (
          <div className="grid grid-cols-3 gap-3">
            <div>
              <Label htmlFor="dec-rowner" hint="(becomes the finding assignee)">Remediation owner</Label>
              <Select id="dec-rowner" className="w-full" value={remOwner} onChange={(e) => setRemOwner(e.target.value)}>
                <option value="">Later</option>
                {(reviewers.data ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </Select>
            </div>
            <div>
              <Label htmlFor="dec-rdue">Target date</Label>
              <Input id="dec-rdue" type="date" value={remDue} onChange={(e) => setRemDue(e.target.value)} />
            </div>
            <div>
              <Label htmlFor="dec-rprio">Remediation priority</Label>
              <Select id="dec-rprio" className="w-full" value={remPrio} onChange={(e) => setRemPrio(e.target.value as Priority)}>
                {(Object.keys(priorityLabel) as Priority[]).map((p) => <option key={p} value={p}>{priorityLabel[p]}</option>)}
              </Select>
            </div>
          </div>
        )}
        {independent && (
          <Alert tone="warning">
            {disp === "accepted_risk"
              ? "Accepted risk is approved by an independent reviewer who holds findings.accept_risk; a risk acceptance request is opened."
              : `Independent review is required for ${sev} findings by the review configuration.`}
          </Alert>
        )}
        {evidenceNeeded && (
          <Alert tone="warning">
            This decision requires at least one evidence item.{" "}
            <button type="button" className="underline" onClick={() => onGoto("evidence")}>Add evidence</button>
          </Alert>
        )}
        {d.required_fields.length > 0 && disp !== "needs_more_information" && (
          <p className="text-[12px] text-muted-foreground">
            Required assessment fields are checked on submission.{" "}
            <button type="button" className="text-primary underline" onClick={() => onGoto("exploitability")}>Review the exploitability assessment</button>
          </p>
        )}
      </div>
    </Dialog>
  );
}

export function IndependentDialog({ d, open, onOpenChange }: { d: ReviewDetail; open: boolean; onOpenChange: (o: boolean) => void }) {
  const [outcome, setOutcome] = useState<"approved" | "rejected" | "information_requested">("approved");
  const [comments, setComments] = useState("");
  const m = useReviewMutation(() => reviewApi.independent(d.id, { outcome, comments }));
  const decision = d.decisions.findLast((x) => x.outcome === "pending_approval");
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="lg"
      title="Independent review"
      description="Your outcome is recorded separately; the first reviewer's assessment and decision are never changed."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            variant={outcome === "approved" ? "primary" : "danger"}
            disabled={m.isPending || !comments.trim() || (outcome !== "approved" && comments.trim().length < 10)}
            onClick={() => m.mutate(undefined, { onSuccess: () => onOpenChange(false) })}
          >
            {outcome === "approved" ? "Approve decision" : outcome === "rejected" ? "Reject decision" : "Request information"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <FieldErrors error={m.error} />
        {decision && (
          <div className="rounded-md border border-border bg-surface-muted/40 p-3 text-[13px]">
            <div className="font-medium">
              {decision.decided_by_name} proposed: {dispositionLabel[decision.disposition]}
            </div>
            <p className="mt-1 whitespace-pre-wrap">{decision.reason}</p>
            {decision.risk_owner_name && (
              <p className="mt-1 text-[12px] text-muted-foreground">
                Risk owner {decision.risk_owner_name}, expires {decision.risk_expires_at?.slice(0, 10)}
              </p>
            )}
            <p className="mt-2 text-[12px] text-muted-foreground">Inspect the source code, data flow and evidence tabs before deciding.</p>
          </div>
        )}
        <fieldset className="flex flex-wrap gap-3 text-[13px]">
          <legend className="mb-1 text-[12px] font-medium">Outcome</legend>
          {(["approved", "rejected", "information_requested"] as const).map((o) => (
            <label key={o} className="flex items-center gap-1.5">
              <input type="radio" name="outcome" className="accent-[var(--primary)]" checked={outcome === o} onChange={() => setOutcome(o)} />
              {o === "approved" ? "Agree and approve" : o === "rejected" ? "Reject (back to the analyst)" : "Request additional information"}
            </label>
          ))}
        </fieldset>
        <div>
          <Label htmlFor="ind-comments">Independent comments</Label>
          <textarea id="ind-comments" rows={4} className={textareaCls} value={comments} onChange={(e) => setComments(e.target.value)} />
        </div>
      </div>
    </Dialog>
  );
}

export function ReopenDialog({ d, open, onOpenChange }: { d: ReviewDetail; open: boolean; onOpenChange: (o: boolean) => void }) {
  const [reason, setReason] = useState("");
  const m = useReviewMutation(() => reviewApi.reopen(d.id, reason));
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Reopen review"
      description="Starts a new review round. The previous decision stays in the history; the finding's human outcome is reverted (a false positive or accepted risk reopens the finding)."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)} autoFocus>Cancel</Button>
          <Button variant="danger" disabled={m.isPending || reason.trim().length < 10} onClick={() => m.mutate(undefined, { onSuccess: () => onOpenChange(false) })}>
            Reopen
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <FieldErrors error={m.error} />
        <Label htmlFor="reopen-reason" hint="(at least 10 characters)">Reason</Label>
        <textarea id="reopen-reason" rows={3} className={textareaCls} value={reason} onChange={(e) => setReason(e.target.value)} />
      </div>
    </Dialog>
  );
}

export function StatusDialog({ d, open, onOpenChange }: { d: ReviewDetail; open: boolean; onOpenChange: (o: boolean) => void }) {
  const waiting = d.status === "awaiting_information";
  const [note, setNote] = useState("");
  const m = useReviewMutation(() => reviewApi.status(d.id, { status: waiting ? "in_progress" : "awaiting_information", note }));
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={waiting ? "Resume the review" : "Wait for information"}
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button disabled={m.isPending || (!waiting && note.trim().length < 5)} onClick={() => m.mutate(undefined, { onSuccess: () => onOpenChange(false) })}>
            {waiting ? "Resume" : "Mark as awaiting information"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <FieldErrors error={m.error} />
        <Label htmlFor="st-note">{waiting ? "Note (optional)" : "What information are you waiting for?"}</Label>
        <textarea id="st-note" rows={3} className={textareaCls} value={note} onChange={(e) => setNote(e.target.value)} />
      </div>
    </Dialog>
  );
}

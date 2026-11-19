import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { Alert, Input, Label, Select } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { reviewApi, useCatalog, useReviewers, useReviewMutation } from "../api";
import { priorityLabel, remediationLabel } from "../shared";
import type { Priority, RemediationStatus, ReviewDetail } from "../types";
import { textareaCls } from "./actions";
import { KV, Panel, SaveBar, useSections } from "./section";
import { ErrorPanel } from "@/components/ui/error-panel";

function Tracking({ d }: { d: ReviewDetail }) {
  const reviewers = useReviewers(undefined, d.can.remediate);
  const [status, setStatus] = useState<RemediationStatus>(d.remediation_status ?? "open");
  const [owner, setOwner] = useState(d.remediation_owner_id ?? "");
  const [due, setDue] = useState(d.remediation_due_at?.slice(0, 10) ?? "");
  const [prio, setPrio] = useState<Priority | "">(d.remediation_priority ?? "");
  const [link, setLink] = useState(d.remediation_link);
  const [note, setNote] = useState("");
  const m = useReviewMutation(() =>
    reviewApi.remediation(d.id, {
      status: status !== d.remediation_status ? status : undefined,
      owner_id: owner && owner !== d.remediation_owner_id ? owner : undefined,
      due_at: due && due !== d.remediation_due_at?.slice(0, 10) ? new Date(`${due}T17:00:00`).toISOString() : undefined,
      priority: prio && prio !== d.remediation_priority ? prio : undefined,
      link: link !== d.remediation_link ? link : undefined,
      note,
    }),
  );
  if (!d.can.remediate) {
    return (
      <KV
        rows={[
          ["Status", d.remediation_status ? remediationLabel[d.remediation_status] : "—"],
          ["Owner", d.remediation_owner_name ?? "—"],
          ["Target date", formatDateTime(d.remediation_due_at)],
          ["Priority", d.remediation_priority ? priorityLabel[d.remediation_priority] : "—"],
          ["Tracking link", d.remediation_link ? <a href={d.remediation_link} target="_blank" rel="noreferrer noopener" className="text-primary hover:underline">{d.remediation_link}</a> : "—"],
        ]}
      />
    );
  }
  return (
    <div className="space-y-3">
      {m.error && <ErrorPanel error={m.error} />}
      <div className="grid gap-3 md:grid-cols-4">
        <div>
          <Label htmlFor="rem-status">Remediation status</Label>
          <Select id="rem-status" className="w-full" value={status} onChange={(e) => setStatus(e.target.value as RemediationStatus)}>
            {(Object.keys(remediationLabel) as RemediationStatus[]).filter((s) => s !== "not_required").map((s) => <option key={s} value={s}>{remediationLabel[s]}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="rem-owner">Remediation owner</Label>
          <Select id="rem-owner" className="w-full" value={owner} onChange={(e) => setOwner(e.target.value)}>
            <option value="">Not set</option>
            {(reviewers.data ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="rem-due">Target date</Label>
          <Input id="rem-due" type="date" value={due} onChange={(e) => setDue(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="rem-prio">Priority</Label>
          <Select id="rem-prio" className="w-full" value={prio} onChange={(e) => setPrio(e.target.value as Priority)}>
            <option value="">Not set</option>
            {(Object.keys(priorityLabel) as Priority[]).map((p) => <option key={p} value={p}>{priorityLabel[p]}</option>)}
          </Select>
        </div>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <Label htmlFor="rem-link" hint="(ticket in your tracker, optional)">Tracking link</Label>
          <Input id="rem-link" type="url" value={link} onChange={(e) => setLink(e.target.value)} placeholder="https://" />
        </div>
        <div>
          <Label htmlFor="rem-note" hint={status === "verified" ? "(how was the fix verified?)" : "(optional)"}>Note</Label>
          <Input id="rem-note" value={note} onChange={(e) => setNote(e.target.value)} />
        </div>
      </div>
      <Button disabled={m.isPending} onClick={() => m.mutate(undefined, { onSuccess: () => setNote("") })}>Update remediation</Button>
      <p className="text-[11.5px] text-muted-foreground">
        The owner becomes the finding's assignee in the remediation workflow. When a scan no longer detects the finding, the status moves to Pending verification automatically.
      </p>
    </div>
  );
}

export function RemediationTab({ d }: { d: ReviewDetail }) {
  const cat = useCatalog();
  const s = useSections(d, ["remediation"]);
  const confirmed = d.disposition === "confirmed" && d.status === "completed";
  return (
    <div className="space-y-4">
      {confirmed ? (
        <Panel title="Remediation tracking" actions={<Link to="/findings" search={{ status: "all", finding: d.finding_id } as never} className="text-[12px] text-primary hover:underline">Open finding →</Link>}>
          <Tracking d={d} />
        </Panel>
      ) : (
        <Alert tone="warning">Remediation tracking starts when the review is completed as Confirmed. Prepare the guidance below while assessing.</Alert>
      )}
      <Panel title="Remediation guidance for developers">
        <div className="grid gap-3 md:grid-cols-2">
          {(cat.data?.remediation_fields ?? []).map((f) => (
            <div key={f.key} className={["recommendation", "secure_example", "custom_instructions", "explanation"].includes(f.key) ? "md:col-span-2" : undefined}>
              <Label htmlFor={`rem-${f.key}`}>{f.label}</Label>
              <textarea
                id={`rem-${f.key}`}
                rows={f.key === "secure_example" || f.key === "affected_code" ? 6 : 3}
                className={`${textareaCls} ${f.key === "secure_example" || f.key === "affected_code" ? "font-mono text-[12px]" : ""}`}
                disabled={!d.can.assess}
                value={s.draft.remediation?.[f.key] ?? ""}
                onChange={(e) => s.set("remediation", f.key, e.target.value)}
              />
            </div>
          ))}
        </div>
        <p className="mt-2 text-[11.5px] text-muted-foreground">PATHOS does not change repository code or open pull requests.</p>
        <div className="mt-3"><SaveBar s={s} editable={d.can.assess} d={d} /></div>
      </Panel>
    </div>
  );
}

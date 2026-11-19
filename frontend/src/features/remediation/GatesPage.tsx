import { useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Pencil, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Dialog } from "@/components/ui/dialog";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Badge, Card, Input, Label, Select, Table, Td, Th } from "@/components/ui/primitives";
import { EmptyStateCard, LoadingSkeleton } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useSession } from "@/features/auth/session";
import { RepoFilter } from "@/features/review/shared";
import { formatDateTime } from "@/lib/utils";
import {
  isFeatureDisabled,
  modeLabel,
  modes,
  outcomeLabel,
  outcomeTone,
  outcomes,
  stageLabel,
  stages,
  useDecisions,
  useDeleteGate,
  useGates,
  usePolicies,
  useRequestException,
  useSaveGate,
  type Decision,
  type Gate,
  type GateInput,
  type GateMode,
  type Stage,
} from "./api";
import { RemediationFrame, shortSha } from "./shared";

export interface GatesSearch {
  stage?: string;
  outcome?: string;
  decision?: string;
}
export function validateGatesSearch(s: Record<string, unknown>): GatesSearch {
  const out: GatesSearch = {};
  for (const k of ["stage", "outcome", "decision"] as const) if (typeof s[k] === "string" && s[k]) out[k] = s[k] as string;
  return out;
}

/**
 * Security gates (/remediation/gates): the gates of every stage (IDE,
 * pre-commit, pull request, CI, release, deploy), each bound to a security
 * policy, and the log of gate decisions. Rule 7: a gate blocks or asks for
 * approval only through its policy; with no gate the decision is "pass".
 */
export function GatesPage() {
  const gates = useGates();
  return (
    <RemediationFrame
      title="Security gates"
      description="Gates decide at each stage — IDE, pre-commit, pull request, CI, release and deploy — whether to pass, warn, block or ask for approval. A gate never blocks without a security policy."
      disabled={isFeatureDisabled(gates.error)}
    >
      <GatesSection />
      <DecisionLog />
    </RemediationFrame>
  );
}

function GatesSection() {
  const gates = useGates();
  const { canOrgWide } = useSession();
  const manage = canOrgWide("gates.manage");
  const [editing, setEditing] = useState<Gate | "new" | null>(null);
  const [deleting, setDeleting] = useState<Gate | null>(null);
  const del = useDeleteGate();
  return (
    <section className="mb-6" aria-labelledby="gates-h">
      <div className="mb-2 flex items-center gap-2">
        <h2 id="gates-h" className="text-[14px] font-semibold">Gates</h2>
        {manage && (
          <Button size="sm" className="ml-auto" onClick={() => setEditing("new")}>
            <Plus /> Add gate
          </Button>
        )}
      </div>
      {gates.isError ? (
        <ErrorPanel error={gates.error} title="Gates could not be loaded" />
      ) : gates.isPending ? (
        <LoadingSkeleton rows={3} label="Loading gates" />
      ) : !gates.data.length ? (
        <EmptyStateCard icon={<ShieldCheck />} title="No gates configured">
          Every evaluation passes and is recorded as “no gate configured”. Add a gate to warn, block or require approval at a stage; each gate uses one of your
          security policies.
        </EmptyStateCard>
      ) : (
        <Card>
          <Table>
            <thead>
              <tr>
                <Th>Gate</Th>
                <Th>Stage</Th>
                <Th>Mode</Th>
                <Th>Policy</Th>
                <Th>Scope</Th>
                <Th>Exceptions</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {gates.data.map((g) => (
                <tr key={g.id} className={g.enabled ? undefined : "opacity-60"}>
                  <Td className="text-[12.5px]">
                    {g.name}
                    {!g.enabled && <Badge className="ml-1">Disabled</Badge>}
                    {g.managed && <div className="text-[11px] text-muted-foreground">Managed by the repository's pull request settings</div>}
                  </Td>
                  <Td className="text-[12px]">{stageLabel[g.stage] ?? g.stage}</Td>
                  <Td><Badge tone={g.mode === "block" ? "danger" : "warning"}>{modeLabel[g.mode] ?? g.mode}</Badge></Td>
                  <Td className="text-[12px]">
                    <Link to="/admin/policies" className="text-primary hover:underline">{g.policy.name}</Link>
                    <span className="ml-1 text-muted-foreground">v{g.policy.version}</span>
                    {g.policy.enabled === false && <Badge tone="warning" className="ml-1">Policy disabled</Badge>}
                  </Td>
                  <Td className="text-[12px]">{g.repository_name || (g.repository_id ? "One repository" : g.application_id ? "One application" : "All")}</Td>
                  <Td className="text-[12px]">{g.allow_exceptions ? "Allowed" : "Not allowed"}</Td>
                  <Td className="whitespace-nowrap text-right">
                    {manage && !g.managed && (
                      <>
                        <Button size="icon" variant="ghost" aria-label={`Edit ${g.name}`} onClick={() => setEditing(g)}><Pencil /></Button>
                        <Button size="icon" variant="ghost" aria-label={`Delete ${g.name}`} onClick={() => setDeleting(g)}><Trash2 /></Button>
                      </>
                    )}
                    {g.managed && (
                      <Link to="/pull-requests" className="text-[12px] text-primary hover:underline">PR settings</Link>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      )}
      {editing && <GateDialog gate={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete gate"
        confirmLabel="Delete gate"
        pending={del.isPending}
        error={del.error?.message}
        onConfirm={() =>
          deleting &&
          del.mutate(deleting.id, {
            onSuccess: () => {
              toast.success(`Gate "${deleting.name}" deleted`);
              setDeleting(null);
            },
          })
        }
      >
        Delete “{deleting?.name}”? Evaluations at the {deleting ? stageLabel[deleting.stage] : ""} stage no longer use it. Its past decisions stay in the log.
      </ConfirmDialog>
    </section>
  );
}

function GateDialog({ gate, onClose }: { gate?: Gate; onClose: () => void }) {
  const policies = usePolicies();
  const save = useSaveGate();
  const [f, setF] = useState<GateInput>({
    name: gate?.name ?? "",
    stage: gate?.stage ?? "ci",
    policy_id: gate?.policy.id ?? "",
    mode: gate?.mode ?? "warn",
    allow_exceptions: gate?.allow_exceptions ?? true,
    repository_id: gate?.repository_id ?? null,
    application_id: gate?.application_id ?? null,
    enabled: gate?.enabled ?? true,
  });
  const set = <K extends keyof GateInput>(k: K, v: GateInput[K]) => setF((x) => ({ ...x, [k]: v }));
  const valid = f.name.trim() && f.policy_id;
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={gate ? "Edit gate" : "Add gate"}
      description="A gate applies one security policy at one stage. Block and require approval need the policy to match; otherwise the decision is pass."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button
            disabled={!valid || save.isPending}
            onClick={() =>
              save.mutate(
                { id: gate?.id, body: { ...f, name: f.name.trim() } },
                {
                  onSuccess: () => {
                    toast.success(gate ? "Gate saved" : `Gate "${f.name.trim()}" added`);
                    onClose();
                  },
                },
              )
            }
          >
            {save.isPending ? "Saving…" : "Save gate"}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-[13px]">
        <div>
          <Label htmlFor="gate-name">Name</Label>
          <Input id="gate-name" value={f.name} maxLength={200} onChange={(e) => set("name", e.target.value)} />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <Label htmlFor="gate-stage">Stage</Label>
            <Select id="gate-stage" value={f.stage} onChange={(e) => set("stage", e.target.value as Stage)}>
              {stages.map((s) => <option key={s} value={s}>{stageLabel[s]}</option>)}
            </Select>
          </div>
          <div>
            <Label htmlFor="gate-mode">When the policy matches</Label>
            <Select id="gate-mode" value={f.mode} onChange={(e) => set("mode", e.target.value as GateMode)}>
              {modes.map((m) => <option key={m} value={m}>{modeLabel[m]}</option>)}
            </Select>
          </div>
        </div>
        <div>
          <Label htmlFor="gate-policy">Security policy</Label>
          {policies.isError ? (
            <ErrorPanel error={policies.error} title="Policies could not be loaded" />
          ) : (
            <Select id="gate-policy" value={f.policy_id} onChange={(e) => set("policy_id", e.target.value)} disabled={policies.isPending}>
              <option value="">Choose a policy…</option>
              {policies.data?.map((p) => (
                <option key={p.id} value={p.id}>{p.name}{p.enabled ? "" : " (disabled)"}</option>
              ))}
            </Select>
          )}
          {policies.data?.length === 0 && (
            <p className="mt-1 text-[12px] text-muted-foreground">
              No security policies yet. <Link to="/admin/policies" className="text-primary hover:underline">Create one</Link> first: a gate cannot exist without a policy.
            </p>
          )}
        </div>
        <div>
          <span className="mb-1 block text-[12px] font-medium">Repository (optional)</span>
          <RepoFilter value={f.repository_id ?? undefined} onChange={(v) => set("repository_id", v ?? null)} />
          <p className="mt-1 text-[11.5px] text-muted-foreground">Empty: every repository the policy covers.</p>
        </div>
        <label className="flex items-center gap-1.5">
          <input type="checkbox" className="accent-[var(--primary)]" checked={f.allow_exceptions} onChange={(e) => set("allow_exceptions", e.target.checked)} />
          Allow time-limited exceptions (approved by someone other than the requester)
        </label>
        <label className="flex items-center gap-1.5">
          <input type="checkbox" className="accent-[var(--primary)]" checked={f.enabled !== false} onChange={(e) => set("enabled", e.target.checked)} />
          Enabled
        </label>
        {save.error && <ErrorPanel error={save.error} />}
      </div>
    </Dialog>
  );
}

function DecisionLog() {
  const search = useSearch({ strict: false }) as GatesSearch;
  const navigate = useNavigate();
  const set = (patch: Partial<GatesSearch>) => {
    // Functional update: two quick changes in a row both apply.
    const merge = (prev: Record<string, unknown>) => {
      const next: Record<string, unknown> = { ...prev };
      for (const [k, v] of Object.entries(patch)) {
        if (v) next[k] = v;
        else delete next[k];
      }
      return next;
    };
    void navigate({ to: "/remediation/gates", search: ((prev: Record<string, unknown>) => merge(prev)) as never, replace: true });
  };
  const list = useDecisions(search.stage, search.outcome);
  const open = list.data?.find((d) => d.id === search.decision);
  return (
    <section aria-labelledby="decisions-h">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <h2 id="decisions-h" className="text-[14px] font-semibold">Gate decisions</h2>
        <Select aria-label="Stage" value={search.stage ?? ""} onChange={(e) => set({ stage: e.target.value || undefined, decision: undefined })}>
          <option value="">All stages</option>
          {stages.map((s) => <option key={s} value={s}>{stageLabel[s]}</option>)}
        </Select>
        <Select aria-label="Decision" value={search.outcome ?? ""} onChange={(e) => set({ outcome: e.target.value || undefined, decision: undefined })}>
          <option value="">All decisions</option>
          {outcomes.map((o) => <option key={o} value={o}>{outcomeLabel[o]}</option>)}
        </Select>
      </div>
      {list.isError ? (
        <ErrorPanel error={list.error} title="Gate decisions could not be loaded" />
      ) : list.isPending ? (
        <LoadingSkeleton rows={4} label="Loading gate decisions" />
      ) : !list.data.length ? (
        <EmptyStateCard title="No gate decisions">
          Decisions appear when a pull request check finishes or a pipeline, the CLI (<code>pathos gate --stage …</code>) or a deployment calls
          POST /api/v1/gates/evaluate.
        </EmptyStateCard>
      ) : (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <Card>
            <Table>
              <thead>
                <tr>
                  <Th>When</Th>
                  <Th>Stage</Th>
                  <Th>Decision</Th>
                  <Th>Subject</Th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((d) => (
                  <tr key={d.id} className={search.decision === d.id ? "bg-primary/5" : undefined}>
                    <Td className="whitespace-nowrap text-[11.5px]">
                      <button type="button" className="text-primary hover:underline" onClick={() => set({ decision: d.id })}>{formatDateTime(d.created_at)}</button>
                    </Td>
                    <Td className="text-[12px]">{stageLabel[d.stage] ?? d.stage}</Td>
                    <Td><Badge tone={outcomeTone[d.outcome]}>{outcomeLabel[d.outcome] ?? d.outcome}</Badge></Td>
                    <Td className="text-[12px]">
                      {d.repository_name || "—"}
                      {d.pull_request ? ` #${d.pull_request}` : ""}
                      {d.commit_sha && <span className="ml-1 font-mono text-[11px] text-muted-foreground">{shortSha(d.commit_sha)}</span>}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Card>
          <Card className="p-4">{open ? <DecisionDetail d={open} /> : <p className="text-[13px] text-muted-foreground">Select a decision to see its reasons, policies and evidence.</p>}</Card>
        </div>
      )}
    </section>
  );
}

function DecisionDetail({ d }: { d: Decision }) {
  const { can } = useSession();
  const [asking, setAsking] = useState(false);
  const blocked = d.outcome === "block" || d.outcome === "approval_required";
  return (
    <div className="space-y-3 text-[12.5px]" data-testid="decision-detail">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={outcomeTone[d.outcome]}>{outcomeLabel[d.outcome]}</Badge>
        <span>{stageLabel[d.stage]} · {formatDateTime(d.created_at)}</span>
        {d.requested_by_email && <span className="text-muted-foreground">by {d.requested_by_email}</span>}
      </div>
      <div>
        <h3 className="mb-1 font-semibold">Reasons</h3>
        <ul className="list-disc space-y-0.5 pl-5">
          {d.reasons.map((r, i) => (
            <li key={i}>
              {r.message}
              {r.code === "no_policy" || r.code === "no_gate_configured" ? <Badge className="ml-1">no policy</Badge> : null}
            </li>
          ))}
        </ul>
      </div>
      {d.gates.length > 0 && (
        <div>
          <h3 className="mb-1 font-semibold">Gates and policies</h3>
          <ul className="space-y-0.5">
            {d.gates.map((g) => (
              <li key={g.id}>
                {g.name} ({modeLabel[g.mode]}) — policy {g.policy.name} v{g.policy.version}: {g.matched ? `${g.count} matching finding(s)` : "no match"} →{" "}
                {g.effect === "skipped" ? "skipped" : outcomeLabel[g.effect]}
              </li>
            ))}
          </ul>
        </div>
      )}
      <div>
        <h3 className="mb-1 font-semibold">Evidence</h3>
        <p>
          {d.evidence.scope === "new" ? "New findings of the scan" : "Open findings"}:{" "}
          {(["critical", "high", "medium", "low", "info"] as const).map((s) => `${s} ${d.evidence.by_severity?.[s] ?? 0}`).join(", ")}
        </p>
        {d.evidence.scan_job_id && (
          <Link to="/scans/$id" params={{ id: d.evidence.scan_job_id }} className="text-primary hover:underline">Scan execution →</Link>
        )}
      </div>
      {d.exceptions.length > 0 && (
        <div>
          <h3 className="mb-1 font-semibold">Exceptions</h3>
          <ul>
            {d.exceptions.map((x) => (
              <li key={x.id}>{x.status} · expires {formatDateTime(x.expires_at)}</li>
            ))}
          </ul>
        </div>
      )}
      {blocked && can("remediation.manage") && (
        <Button size="sm" variant="secondary" onClick={() => setAsking(true)}>
          {d.outcome === "approval_required" ? "Request approval" : "Request exception"}
        </Button>
      )}
      {asking && <ExceptionDialog d={d} onClose={() => setAsking(false)} />}
    </div>
  );
}

function ExceptionDialog({ d, onClose }: { d: Decision; onClose: () => void }) {
  const req = useRequestException();
  const [reason, setReason] = useState("");
  const [days, setDays] = useState("7");
  const gateOptions = d.gates.filter((g) => g.effect === "block" || g.effect === "approval_required");
  const [gateId, setGateId] = useState(gateOptions[0]?.id ?? "");
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={d.outcome === "approval_required" ? "Request approval" : "Request an exception"}
      description="Someone with the gates.approve_exception permission, other than you, must approve it. It expires automatically."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button
            disabled={reason.trim().length < 10 || req.isPending}
            onClick={() =>
              req.mutate(
                {
                  decisionId: d.id,
                  body: { reason: reason.trim(), expires_at: new Date(Date.now() + Number(days) * 86_400_000).toISOString(), gate_id: gateId || undefined },
                },
                {
                  onSuccess: () => {
                    toast.success("Request sent for approval");
                    onClose();
                  },
                },
              )
            }
          >
            Send request
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-[13px]">
        {gateOptions.length > 1 && (
          <div>
            <Label htmlFor="exc-gate">Gate</Label>
            <Select id="exc-gate" value={gateId} onChange={(e) => setGateId(e.target.value)}>
              {gateOptions.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
            </Select>
          </div>
        )}
        <div>
          <Label htmlFor="exc-reason">Reason</Label>
          <textarea
            id="exc-reason"
            className="min-h-24 w-full rounded-md border border-border bg-surface px-2 py-1.5 text-[13px] focus-visible:outline-2 focus-visible:outline-ring"
            value={reason}
            maxLength={4000}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Why should this pass? Include the compensating control and the fix plan (at least 10 characters)."
          />
        </div>
        <div>
          <Label htmlFor="exc-days">Expires after</Label>
          <Select id="exc-days" value={days} onChange={(e) => setDays(e.target.value)}>
            {["1", "3", "7", "14", "30", "90"].map((n) => <option key={n} value={n}>{n} day(s)</option>)}
          </Select>
        </div>
        {req.error && <ErrorPanel error={req.error} />}
      </div>
    </Dialog>
  );
}

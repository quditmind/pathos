import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Circle, Download, ExternalLink, GitPullRequestArrow, Loader2, MinusCircle, Sparkles, XCircle } from "lucide-react";
import { api } from "@/api/client";
import type { Repository } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Select, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import type { FixPR } from "@/features/fixprs/FixPRPanel";
import { cn, formatDateTime } from "@/lib/utils";
import { ErrorPanel } from "@/components/ui/error-panel";

export type AIFixStatus = "generating" | "rejected" | "queued" | "running" | "tests_queued" | "testing" | "verified" | "failed";

export interface AIFixStep {
  key: "policy" | "apply" | "scan" | "tests";
  label: string;
  status: "pending" | "running" | "passed" | "failed" | "skipped";
  detail: string;
}

interface ScanResult {
  rule_id: string;
  file: string;
  line?: number;
  title?: string;
}

export interface AIFixScanEvidence {
  scanner?: string;
  scanner_version?: string;
  files?: string[];
  verdict?: { reproduced: boolean; removed: boolean; new: ScanResult[]; before: ScanResult[]; after: ScanResult[]; reason?: string };
}

export interface AIFix {
  id: string;
  finding_id: string;
  repository_id: string;
  status: AIFixStatus;
  failure_reason: string;
  scanner_key: string;
  rule_id: string;
  file_path: string;
  commit_sha: string;
  base_commit: string;
  test_runner: string;
  provider: string;
  model: string;
  transmitted_sha256: string;
  summary: string;
  diff: string;
  changed_files: string[];
  steps: AIFixStep[];
  scan_evidence: AIFixScanEvidence;
  test_log?: string;
  has_reports: boolean;
  pull_request: FixPR | null;
  requested_by: string;
  created_at: string;
  updated_at: string;
  finished_at: string | null;
}

export interface AIFixEligibility {
  available: boolean;
  reason?: string;
  scanner: string;
  test_runner: string;
  fix_prs_enabled: boolean;
  can_request: boolean;
  can_open_pr: boolean;
  proposals: AIFix[];
}

const statusLabel: Record<AIFixStatus, string> = {
  generating: "Asking the AI provider",
  rejected: "Rejected",
  queued: "Waiting for a worker",
  running: "Verifying (apply and re-scan)",
  tests_queued: "Waiting for the test sandbox",
  testing: "Running the tests",
  verified: "Verified",
  failed: "Verification failed",
};
const statusTone: Record<AIFixStatus, "neutral" | "success" | "warning" | "danger"> = {
  generating: "neutral", rejected: "danger", queued: "neutral", running: "neutral", tests_queued: "neutral", testing: "neutral",
  verified: "success", failed: "danger",
};
export const aiFixActive = (s: AIFixStatus) => s === "generating" || s === "queued" || s === "running" || s === "tests_queued" || s === "testing";
const categories = ["sast", "secrets", "iac"];

/** "Propose fix" in the finding drawer: an AI-proposed diff, verified by a worker before it can become a pull request. */
export function FindingAIFix({ findingId, category }: { findingId: string; category: string }) {
  const qc = useQueryClient();
  const key = ["finding-ai-fixes", findingId];
  const shown = categories.includes(category);
  const q = useQuery({
    queryKey: key,
    queryFn: () => api<AIFixEligibility>(`/api/v1/findings/${findingId}/ai-fixes`),
    enabled: shown,
    retry: false,
    refetchInterval: (query) => (query.state.data?.proposals.some((p) => aiFixActive(p.status) || p.pull_request?.status === "creating") ? 3000 : false),
  });
  const propose = useMutation({
    mutationFn: () => api<AIFix>(`/api/v1/findings/${findingId}/ai-fixes`, { method: "POST" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: key }),
  });
  if (!shown) return null;
  if (q.isPending) return <Skeleton className="h-16" />;
  if (q.isError) return null;
  const d = q.data;
  const [latest, ...older] = d.proposals;
  const busy = latest ? aiFixActive(latest.status) : false;
  return (
    <section className="rounded-md border border-border p-3 text-[12.5px]" aria-labelledby={`ai-fix-${findingId}`}>
      <div className="mb-1 flex items-center justify-between gap-2">
        <h3 id={`ai-fix-${findingId}`} className="flex items-center gap-1.5 text-[12px] font-semibold"><Sparkles className="size-3.5" /> AI-proposed fix</h3>
        {d.available && d.can_request && (
          <Button size="sm" variant="secondary" disabled={propose.isPending || busy} onClick={() => propose.mutate()}>
            <Sparkles /> {propose.isPending ? "Requesting…" : latest ? "Propose another fix" : "Propose fix"}
          </Button>
        )}
      </div>
      {!d.available ? (
        <p className="text-muted-foreground">{d.reason}</p>
      ) : !latest ? (
        <p className="text-muted-foreground">
          {d.can_request
            ? <>The configured AI provider proposes a change to the finding's file. A worker then applies it to a fresh checkout and re-runs {d.scanner}{d.test_runner ? ` and the repository's ${d.test_runner} tests (sandboxed)` : ""}. Only a verified fix can become a pull request, and only when you open it.</>
            : "Proposing a fix needs the ai.fix permission on this repository."}
        </p>
      ) : null}
      {propose.error && <div className="mt-2"><ErrorPanel error={propose.error} /></div>}
      {latest && <ProposalCard fix={latest} elig={d} />}
      {older.length > 0 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-[11.5px] text-muted-foreground">Earlier proposals ({older.length})</summary>
          <ul className="mt-1 space-y-1">
            {older.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center gap-1.5 text-[11.5px]">
                <Badge tone={statusTone[p.status]}>{statusLabel[p.status]}</Badge>
                <span className="text-muted-foreground">{formatDateTime(p.created_at)} by {p.requested_by || "unknown"}</span>
                {p.failure_reason && <span className="basis-full text-danger">{p.failure_reason}</span>}
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}

function StepIcon({ status }: { status: AIFixStep["status"] }) {
  switch (status) {
    case "passed":
      return <CheckCircle2 className="size-3.5 shrink-0 text-success" aria-label="passed" />;
    case "failed":
      return <XCircle className="size-3.5 shrink-0 text-danger" aria-label="failed" />;
    case "skipped":
      return <MinusCircle className="size-3.5 shrink-0 text-muted-foreground" aria-label="skipped" />;
    case "running":
      return <Loader2 className="size-3.5 shrink-0 animate-spin text-muted-foreground" aria-label="running" />;
    default:
      return <Circle className="size-3.5 shrink-0 text-muted-foreground" aria-label="pending" />;
  }
}

/** A unified diff with added and removed lines marked. */
export function DiffView({ diff }: { diff: string }) {
  return (
    <pre className="max-h-80 overflow-auto rounded-md border border-border bg-muted/40 p-2 font-mono text-[11.5px] leading-5" aria-label="Proposed diff">
      {diff.replace(/\n$/, "").split("\n").map((l, i) => (
        <div
          key={i}
          className={cn(
            "whitespace-pre px-1",
            l.startsWith("+") && !l.startsWith("+++") && "bg-success/15",
            l.startsWith("-") && !l.startsWith("---") && "bg-danger/15",
            l.startsWith("@@") && "text-muted-foreground",
          )}
        >
          {l || " "}
        </div>
      ))}
    </pre>
  );
}

function ProposalCard({ fix, elig }: { fix: AIFix; elig: AIFixEligibility }) {
  const qc = useQueryClient();
  const [showLog, setShowLog] = useState(false);
  const detail = useQuery({
    queryKey: ["ai-fix", fix.id, fix.status],
    queryFn: () => api<AIFix>(`/api/v1/ai-fixes/${fix.id}`),
    enabled: showLog,
  });
  const openPR = useMutation({
    mutationFn: () => api<FixPR>(`/api/v1/ai-fixes/${fix.id}/pull-request`, { method: "POST" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["finding-ai-fixes", fix.finding_id] }),
  });
  const v = fix.scan_evidence?.verdict;
  const pr = fix.pull_request;
  const prRetry = !pr || pr.status === "failed";
  const testsPassed = fix.steps.some((s) => s.key === "tests" && s.status === "passed");
  return (
    <div className="mt-2 space-y-2">
      <div className="flex flex-wrap items-center gap-1.5">
        <Badge tone={statusTone[fix.status]}>{statusLabel[fix.status]}</Badge>
        <span className="text-[11px] text-muted-foreground">
          {formatDateTime(fix.created_at)} by {fix.requested_by || "unknown"}
          {fix.model && <> · {fix.provider} {fix.model}</>}
        </span>
      </div>
      {fix.status === "verified" ? (
        <Alert tone="success">
          Verified: {fix.scanner_key} no longer reports this finding in the changed file{fix.changed_files.length > 1 ? "s" : ""} and reports nothing new there
          {testsPassed ? `, and the ${fix.test_runner} tests pass with the change` : fix.test_runner ? " (the tests did not run; see the steps)" : ""}. Review the
          change before opening a pull request.
        </Alert>
      ) : fix.failure_reason ? (
        <Alert>{fix.failure_reason}</Alert>
      ) : null}
      {fix.summary && <p className="whitespace-pre-wrap text-muted-foreground">{fix.summary}</p>}
      {fix.diff && <DiffView diff={fix.diff} />}
      <ol className="space-y-1" aria-label="Verification steps">
        {fix.steps.map((s) => (
          <li key={s.key} className="flex items-start gap-1.5">
            <StepIcon status={s.status} />
            <div>
              <span className="font-medium">{s.label}</span>
              {s.detail && <span className="text-muted-foreground"> — {s.detail}</span>}
            </div>
          </li>
        ))}
      </ol>
      {v && (
        <div className="text-[11.5px] text-muted-foreground">
          Scanner evidence ({fix.scan_evidence.scanner} {fix.scan_evidence.scanner_version}): {v.before.length} result(s) in the changed files before the fix,{" "}
          {v.after.length} after{v.new.length > 0 && <>, <span className="text-danger">{v.new.length} new: {v.new.map((n) => `${n.rule_id} at ${n.file}:${n.line ?? "?"}`).join(", ")}</span></>}.
          {fix.has_reports && (
            <span className="ml-1 inline-flex gap-2">
              <a className="inline-flex items-center gap-0.5 text-primary hover:underline" href={`/api/v1/ai-fixes/${fix.id}/reports/before`} download>
                <Download className="size-3" /> report before
              </a>
              <a className="inline-flex items-center gap-0.5 text-primary hover:underline" href={`/api/v1/ai-fixes/${fix.id}/reports/after`} download>
                <Download className="size-3" /> report after
              </a>
            </span>
          )}
        </div>
      )}
      {fix.test_runner && fix.steps.some((s) => s.key === "tests" && (s.status === "passed" || s.status === "failed")) && (
        <div>
          <Button size="sm" variant="ghost" onClick={() => setShowLog((x) => !x)}>{showLog ? "Hide test log" : "Show test log"}</Button>
          {showLog && (detail.isPending ? <Skeleton className="h-16" /> : detail.isError ? <ErrorPanel error={detail.error} /> : (
            <pre className="max-h-72 overflow-auto rounded-md border border-border bg-muted/40 p-2 font-mono text-[11px] leading-4" aria-label="Test log">
              {detail.data.test_log || "No output."}
            </pre>
          ))}
        </div>
      )}
      {pr && (
        <div className="flex flex-wrap items-center gap-1.5">
          <GitPullRequestArrow className="size-3.5" />
          <span>Pull request: {pr.status}</span>
          {pr.pr_url && (
            <a href={pr.pr_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-0.5 text-primary hover:underline">
              #{pr.pr_number} <ExternalLink className="size-3" />
            </a>
          )}
          {pr.error && <span className="basis-full text-[11.5px] text-danger">{pr.error}</span>}
          {(pr.status === "open" || pr.status === "merged") && (
            <span className="basis-full text-[11.5px] text-muted-foreground">The finding is resolved when a later scan no longer detects it, not when the pull request is merged.</span>
          )}
        </div>
      )}
      {fix.status === "verified" && prRetry && (
        !elig.can_open_pr ? (
          <p className="text-muted-foreground">Opening a pull request needs the ai.fix, findings.triage and repos.manage permissions on this repository.</p>
        ) : !elig.fix_prs_enabled ? (
          <p className="text-muted-foreground">Fix pull requests are not enabled for this repository (repository settings, Security, Fix pull requests).</p>
        ) : (
          <Button size="sm" variant="secondary" disabled={openPR.isPending} onClick={() => openPR.mutate()}>
            <GitPullRequestArrow /> {openPR.isPending ? "Opening…" : "Open pull request"}
          </Button>
        )
      )}
      {openPR.error && <ErrorPanel error={openPR.error} />}
    </div>
  );
}

interface AIFixSettings {
  test_runner: "" | "go" | "python";
}

/** Repository setting: the test runner AI fix verification may run (executes repository code; off by default). */
export function AIFixSettingsPanel({ r }: { r: Repository }) {
  const qc = useQueryClient();
  const { can } = useSession();
  const key = ["ai-fix-settings", r.id];
  const q = useQuery({ queryKey: key, queryFn: () => api<AIFixSettings>(`/api/v1/repositories/${r.id}/ai-fix-settings`), enabled: can("scans.read"), retry: false });
  const [runner, setRunner] = useState<AIFixSettings["test_runner"]>("");
  useEffect(() => {
    if (q.data) setRunner(q.data.test_runner);
  }, [q.data]);
  const save = useMutation({
    mutationFn: () => api<AIFixSettings>(`/api/v1/repositories/${r.id}/ai-fix-settings`, { method: "PUT", body: { test_runner: runner } }),
    onSuccess: (data) => qc.setQueryData(key, data),
  });
  if (!can("scans.read")) return null;
  const manage = can("repos.manage");
  return (
    <section className="mt-5 rounded-md border border-border p-3 text-[13px]" aria-labelledby={`ai-fix-settings-${r.id}`}>
      <h3 id={`ai-fix-settings-${r.id}`} className="mb-1 flex items-center gap-1.5 text-[13px] font-semibold">
        <Sparkles className="size-4" /> AI fix verification
      </h3>
      <p className="mb-2 text-[12px] text-muted-foreground">
        AI-proposed fixes are always verified by re-running the scanner on the changed file. Optionally, the repository's tests can also run, with and
        without the fix. That executes the repository's code, so it is off unless you choose a runner: it runs only in the sandboxed fuzz worker, without
        network access and under CPU, memory and time limits. Go modules must vendor their dependencies; Python tests run with the standard library only.
      </p>
      {q.isPending ? (
        <Skeleton className="h-6 w-56" />
      ) : q.isError ? (
        <ErrorPanel error={q.error} />
      ) : (
        <div className="flex flex-wrap items-center gap-3">
          <Select aria-label="Test runner" value={runner} disabled={!manage} onChange={(e) => setRunner(e.target.value as AIFixSettings["test_runner"])}>
            <option value="">Do not run tests</option>
            <option value="go">go test ./...</option>
            <option value="python">python -m unittest discover</option>
          </Select>
          {manage && (
            <Button size="sm" variant="secondary" disabled={!q.data || q.data.test_runner === runner || save.isPending} onClick={() => save.mutate()}>
              {save.isPending ? "Saving…" : "Save"}
            </Button>
          )}
        </div>
      )}
      {save.error && <div className="mt-2"><ErrorPanel error={save.error} /></div>}
    </section>
  );
}

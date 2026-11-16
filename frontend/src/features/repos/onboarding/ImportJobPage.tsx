import { useState } from "react";
import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft, Ban, Check, ExternalLink, RotateCcw, X } from "lucide-react";
import type { ImportItem, ImportJob, ImportStatus } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Alert, Card, PageHeader, Skeleton } from "@/components/ui/primitives";
import { ProgressBar } from "@/components/ui/progress";
import { formatDateTime } from "@/lib/utils";
import { importPollInterval, isActive, useImportAction, useImportJob } from "./api";
import { ImportStatusBadge } from "./ImportStatusBadge";
import { sourceLabel } from "./ImportsPage";

export function ImportJobPage() {
  const { id } = useParams({ strict: false }) as { id: string };
  return (
    <>
      <PageHeader
        title="Import progress"
        actions={
          <Button variant="ghost" asChild>
            <Link to="/repositories/imports">
              <ArrowLeft /> Import history
            </Link>
          </Button>
        }
      />
      <ImportJobView id={id} />
    </>
  );
}

const stages: { key: ImportStatus; label: string }[] = [
  { key: "queued", label: "Queued" },
  { key: "validating", label: "Validating" },
  { key: "importing", label: "Importing" },
  { key: "registering", label: "Registering" },
  { key: "completed", label: "Completed" },
];

/** Queued → Validating → Importing → Registering → Completed; failures mark the last step. */
export function StageStepper({ status }: { status: ImportStatus }) {
  const terminalBad = status === "failed" || status === "cancelled" || status === "needs_attention";
  const current = status === "pending" || status === "draft" ? 0 : stages.findIndex((s) => s.key === status);
  return (
    <ol className="flex items-center gap-1" aria-label="Import stages">
      {stages.map((s, i) => {
        const last = i === stages.length - 1;
        const done = !terminalBad && (status === "completed" || i < current);
        const active = !terminalBad && i === current && status !== "completed";
        const bad = terminalBad && last;
        return (
          <li key={s.key} className="flex items-center gap-1" aria-current={active ? "step" : undefined}>
            <span
              title={bad ? status : s.label}
              className={
                "flex size-4 items-center justify-center rounded-full text-[9px] " +
                (done ? "bg-success text-white" : active ? "bg-primary text-primary-foreground" : bad ? (status === "needs_attention" ? "bg-warning text-white" : status === "cancelled" ? "bg-muted-foreground/60 text-white" : "bg-danger text-white") : "bg-surface-muted text-muted-foreground")
              }
            >
              {done ? <Check className="size-2.5" /> : bad ? <X className="size-2.5" /> : i + 1}
            </span>
            <span className={"hidden text-[11px] xl:inline " + (active ? "font-medium text-primary" : "text-muted-foreground")}>{bad ? "" : s.label}</span>
            <span className="sr-only">
              {s.label}
              {done ? " done" : active ? " in progress" : bad ? ` ${status}` : ""}
            </span>
            {!last && <span className="h-px w-3 bg-border" aria-hidden />}
          </li>
        );
      })}
    </ol>
  );
}

export function ImportJobView({ id }: { id: string }) {
  const job = useImportJob(id);
  const act = useImportAction(id);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const j = job.data;

  if (job.isPending) return <Skeleton className="h-64" />;
  if (job.isError)
    return (
      <Alert>
        Could not load the import: {job.error.message}{" "}
        <button className="underline" onClick={() => void job.refetch()}>
          Try again
        </button>
      </Alert>
    );
  if (!j) return null;
  const items = j.items ?? [];
  const failed = items.filter((i) => i.can_retry);
  const polling = importPollInterval(j) !== false;
  const done = j.completed_items + j.failed_items + j.attention_items;

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1 text-[13px]">
            <div className="flex items-center gap-2">
              <ImportStatusBadge status={j.status} />
              <span className="font-medium">
                {sourceLabel[j.source_type]}
                {j.scm_connection_name && ` · ${j.scm_connection_name}`}
              </span>
            </div>
            <div className="text-[12px] text-muted-foreground">
              Requested by {j.requested_by?.name || j.requested_by?.email} · {formatDateTime(j.created_at)}
              {j.completed_at && ` · finished ${formatDateTime(j.completed_at)}`}
              {j.start_scan && " · onboarding scan requested"}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {j.can_retry && failed.length > 0 && (
              <Button size="sm" variant="secondary" disabled={act.isPending} onClick={() => act.mutate({ action: "retry" })}>
                <RotateCcw /> Retry all failed ({failed.length})
              </Button>
            )}
            {j.can_cancel && (
              <Button size="sm" variant="danger-outline" disabled={act.isPending} onClick={() => setConfirmCancel(true)}>
                <Ban /> Cancel import
              </Button>
            )}
          </div>
        </div>
        <div className="mt-3 space-y-1">
          <ProgressBar value={j.total_items ? done / j.total_items : 0} label="Overall import progress" tone={j.failed_items ? "danger" : "primary"} />
          <div className="tabular flex flex-wrap gap-x-3 text-[12px] text-muted-foreground">
            <span>
              {j.completed_items} of {j.total_items} completed
            </span>
            {j.failed_items > 0 && <span className="text-danger">{j.failed_items} failed</span>}
            {j.attention_items > 0 && <span className="text-warning">{j.attention_items} need attention</span>}
            <span aria-live="polite">{polling ? "Updating every 2 seconds…" : "Up to date"}</span>
          </div>
        </div>
      </Card>
      {act.isError && <Alert>{act.error.message}</Alert>}

      <Card>
        <ul className="divide-y divide-border" aria-label="Import items">
          {items.map((it) => (
            <ItemRow key={it.id} it={it} job={j} pending={act.isPending} onRetry={(allow) => act.mutate({ action: "retry", item_ids: [it.id], allow_duplicate: allow })} />
          ))}
          {!items.length && <li className="p-4 text-[13px] text-muted-foreground">No items.</li>}
        </ul>
      </Card>

      <ConfirmDialog
        open={confirmCancel}
        onOpenChange={setConfirmCancel}
        title="Cancel this import?"
        confirmLabel="Cancel import"
        pending={act.isPending}
        error={act.isError ? act.error.message : null}
        onConfirm={() => act.mutate({ action: "cancel" }, { onSuccess: () => setConfirmCancel(false) })}
      >
        <p>Queued repositories are cancelled immediately; repositories being processed stop at the next stage. Repositories that were already registered stay registered.</p>
      </ConfirmDialog>
    </div>
  );
}

function ItemRow({ it, job, pending, onRetry }: { it: ImportItem; job: ImportJob; pending: boolean; onRetry: (allowDuplicate?: boolean) => void }) {
  const active = isActive(it.status);
  return (
    <li className="grid gap-2 px-4 py-3 text-[13px] md:grid-cols-[minmax(0,1.3fr)_auto_minmax(0,1fr)_auto] md:items-center">
      <div className="min-w-0">
        <div className="truncate font-medium">{it.display_name || `Item ${it.position + 1}`}</div>
        <div className="flex flex-wrap items-center gap-2 text-[12px] text-muted-foreground">
          <ImportStatusBadge status={it.status} />
          {it.result === "already_imported" && <span>already imported</span>}
          {it.result === "snapshot_added" && <span>new snapshot added</span>}
          {it.attempts > 1 && (
            <span>
              attempt {it.attempts}/{it.max_attempts}
            </span>
          )}
        </div>
      </div>
      <StageStepper status={it.status} />
      <div className="min-w-0 space-y-1">
        {active && <ProgressBar value={Math.min(1, Math.max(0, it.progress) / 100)} label={`Progress of ${it.display_name}`} />}
        {it.progress_message && <div className="truncate text-[12px] text-muted-foreground">{it.progress_message}</div>}
        {(it.error_code || it.error_message) && (
          <div className="text-[12px] text-danger">
            {it.error_code && <code className="mr-1 rounded bg-danger-soft px-1">{it.error_code}</code>}
            {it.error_message}
          </div>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-1.5 md:justify-end">
        {it.repository_id && (
          <Link to="/repositories" search={{ repo: it.repository_id } as never} className="inline-flex items-center gap-1 text-[12px] text-primary hover:underline">
            Repository <ExternalLink className="size-3" />
          </Link>
        )}
        {it.can_retry && job.can_retry && it.status === "needs_attention" && it.error_code === "duplicate" && (
          <Button size="sm" variant="secondary" disabled={pending} onClick={() => onRetry(true)}>
            Import anyway
          </Button>
        )}
        {it.can_retry && job.can_retry && (
          <Button size="sm" variant="ghost" disabled={pending} onClick={() => onRetry()}>
            <RotateCcw /> Retry
          </Button>
        )}
      </div>
    </li>
  );
}

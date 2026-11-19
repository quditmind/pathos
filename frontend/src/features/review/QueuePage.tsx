import { useState } from "react";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { ArrowDown, ArrowUp, ClipboardCheck, RefreshCw, UserPlus } from "lucide-react";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { cn, formatDateTime } from "@/lib/utils";
import { reviewApi, useReviewers, useReviewMutation, useReviews } from "./api";
import {
  allFilterKeys,
  DispositionBadge,
  filtersFromSearch,
  Pagination,
  priorityLabel,
  PriorityBadge,
  ReviewFilterBar,
  ReviewKeyLink,
  StatusBadge,
} from "./shared";
import type { Priority, ReviewFilters, ReviewItem } from "./types";
import { ErrorPanel } from "@/components/ui/error-panel";

export const validateReviewSearch = (s: Record<string, unknown>): ReviewFilters => filtersFromSearch(s, allFilterKeys);

type Col = { id: string; header: string; sort?: string; cell: (r: ReviewItem) => React.ReactNode; className?: string };

const columns: Col[] = [
  { id: "id", header: "Finding ID", sort: "review_key", cell: (r) => <ReviewKeyLink id={r.id} reviewKey={r.review_key} /> },
  {
    id: "title",
    header: "Vulnerability",
    sort: "title",
    cell: (r) => (
      <div className="max-w-72">
        <div className="truncate font-medium" title={r.title}>{r.title}</div>
        <div className="truncate text-[11px] text-muted-foreground">{r.rule_id}</div>
      </div>
    ),
  },
  {
    id: "severity",
    header: "Severity",
    sort: "severity",
    cell: (r) => (
      <div className="flex flex-col items-start gap-0.5">
        <SeverityBadge value={r.assessed_severity ?? r.severity} />
        {r.assessed_severity && r.assessed_severity !== r.severity && (
          <span className="text-[10.5px] text-muted-foreground" title="Scanner severity">scanner: {r.severity}</span>
        )}
      </div>
    ),
  },
  { id: "scanner", header: "Scanner", sort: "scanner", cell: (r) => <span className="text-[12px]">{r.scanner || "—"}</span> },
  {
    id: "repository",
    header: "Repository",
    sort: "repository",
    cell: (r) => (
      <div className="max-w-48">
        <div className="truncate">{r.repository_name}</div>
        <div className="font-mono text-[11px] text-muted-foreground">{r.repository_key}</div>
      </div>
    ),
  },
  { id: "application", header: "Application", sort: "application", cell: (r) => <span className="text-[12px]">{r.application_name ?? "—"}</span> },
  { id: "branch", header: "Branch", sort: "branch", cell: (r) => <span className="font-mono text-[11.5px]">{r.branch || "—"}</span> },
  {
    id: "file",
    header: "File path",
    sort: "file_path",
    cell: (r) => (
      <span className="block max-w-56 truncate font-mono text-[11.5px]" title={r.file_path}>
        {r.file_path ? `${r.file_path}${r.start_line ? `:${r.start_line}` : ""}` : "—"}
      </span>
    ),
  },
  { id: "detected", header: "Detected", sort: "detected_at", cell: (r) => <span className="tabular whitespace-nowrap text-[12px] text-muted-foreground">{formatDateTime(r.detected_at)}</span> },
  { id: "reviewer", header: "Reviewer", sort: "reviewer", cell: (r) => <span className="text-[12px]">{r.reviewer_name ?? <span className="text-muted-foreground">Unassigned</span>}</span> },
  { id: "priority", header: "Priority", sort: "priority", cell: (r) => <PriorityBadge value={r.priority} /> },
  {
    id: "status",
    header: "Review status",
    sort: "status",
    cell: (r) => (
      <div className="flex flex-col items-start gap-0.5">
        <StatusBadge status={r.status} />
        {r.disposition && <DispositionBadge value={r.disposition} />}
      </div>
    ),
  },
  {
    id: "due",
    header: "Due",
    sort: "due_at",
    cell: (r) => (
      <span className={cn("tabular whitespace-nowrap text-[12px]", r.overdue ? "font-semibold text-danger" : "text-muted-foreground")}>
        {r.due_at ? formatDateTime(r.due_at) : "—"}
        {r.overdue && <span className="sr-only"> (overdue)</span>}
      </span>
    ),
  },
];

/** Server-paginated, server-sorted review table with optional selection. */
export function ReviewsTable({
  filters,
  setFilters,
  selection,
  setSelection,
  empty,
}: {
  filters: ReviewFilters;
  setFilters: (f: ReviewFilters) => void;
  selection?: Set<string>;
  setSelection?: (s: Set<string>) => void;
  empty: React.ReactNode;
}) {
  const navigate = useNavigate();
  const page = Number(filters.page ?? 1);
  const pageSize = Number(filters.page_size ?? 25);
  const q = useReviews(filters);
  const rows = q.data?.items ?? [];
  const allSelected = !!selection && rows.length > 0 && rows.every((r) => selection.has(r.id));
  const sortBy = (key: string) => {
    const desc = filters.sort === key && filters.order !== "desc";
    setFilters({ ...filters, sort: key, order: desc ? "desc" : undefined, page: undefined });
  };
  return (
    <>
      {q.isError ? (
        <div className="p-4"><ErrorPanel error={q.error} title="Could not load reviews" /></div>
      ) : q.isPending ? (
        <div className="space-y-2 p-4">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-9" />)}</div>
      ) : rows.length === 0 ? (
        empty
      ) : (
        <Table>
          <thead>
            <tr>
              {selection && setSelection && (
                <Th className="w-8">
                  <input
                    type="checkbox"
                    aria-label="Select all reviews on this page"
                    checked={allSelected}
                    onChange={() => setSelection(allSelected ? new Set() : new Set(rows.map((r) => r.id)))}
                    className="size-3.5 accent-[var(--primary)]"
                  />
                </Th>
              )}
              {columns.map((c) => (
                <Th key={c.id} className={c.className}>
                  {c.sort ? (
                    <button
                      type="button"
                      className="inline-flex items-center gap-1 uppercase hover:text-foreground"
                      onClick={() => sortBy(c.sort!)}
                      aria-label={`Sort by ${c.header}`}
                    >
                      {c.header}
                      {filters.sort === c.sort && (filters.order === "desc" ? <ArrowDown className="size-3" /> : <ArrowUp className="size-3" />)}
                    </button>
                  ) : (
                    c.header
                  )}
                </Th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr
                key={r.id}
                className="cursor-pointer hover:bg-surface-muted/60"
                tabIndex={0}
                onClick={() => void navigate({ to: "/human-review/reviews/$id", params: { id: r.id } })}
                onKeyDown={(e) => e.key === "Enter" && void navigate({ to: "/human-review/reviews/$id", params: { id: r.id } })}
              >
                {selection && setSelection && (
                  <Td className="w-8">
                    <input
                      type="checkbox"
                      aria-label={`Select ${r.review_key}`}
                      checked={selection.has(r.id)}
                      onClick={(e) => e.stopPropagation()}
                      onChange={() => {
                        const next = new Set(selection);
                        if (next.has(r.id)) next.delete(r.id);
                        else next.add(r.id);
                        setSelection(next);
                      }}
                      className="size-3.5 accent-[var(--primary)]"
                    />
                  </Td>
                )}
                {columns.map((c) => (
                  <Td key={c.id} className={c.className}>{c.cell(r)}</Td>
                ))}
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {q.data && q.data.total > 0 && (
        <Pagination
          page={page}
          pageSize={pageSize}
          total={q.data.total}
          onPage={(p) => setFilters({ ...filters, page: String(p) })}
          onPageSize={(n) => setFilters({ ...filters, page_size: String(n), page: undefined })}
        />
      )}
    </>
  );
}

export function BulkDialog({ ids, open, onOpenChange, onDone }: { ids: string[]; open: boolean; onOpenChange: (o: boolean) => void; onDone: () => void }) {
  const reviewers = useReviewers(undefined, open);
  const [action, setAction] = useState<"assign" | "priority" | "due_date">("assign");
  const [reviewer, setReviewer] = useState("");
  const [priority, setPriority] = useState<Priority>("p2");
  const [due, setDue] = useState("");
  const [note, setNote] = useState("");
  const m = useReviewMutation(reviewApi.bulk);
  const submit = () =>
    m.mutate(
      {
        review_ids: ids,
        action,
        reviewer_id: action === "assign" ? reviewer : undefined,
        priority: action === "priority" ? priority : undefined,
        due_at: action === "due_date" && due ? new Date(`${due}T17:00:00`).toISOString() : undefined,
        note: note || undefined,
      },
      { onSuccess: () => { onOpenChange(false); onDone(); } },
    );
  const valid = action === "assign" ? !!reviewer : action === "due_date" ? !!due : true;
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={`Update ${ids.length} review${ids.length === 1 ? "" : "s"}`}
      description="The change applies to every selected review or to none."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button disabled={!valid || m.isPending} onClick={submit}>{m.isPending ? "Saving…" : "Apply"}</Button>
        </>
      }
    >
      <div className="space-y-3">
        {m.error && <ErrorPanel error={m.error} />}
        <div>
          <Label htmlFor="bulk-action">Action</Label>
          <Select id="bulk-action" value={action} onChange={(e) => setAction(e.target.value as typeof action)} className="w-full">
            <option value="assign">Assign to an analyst</option>
            <option value="priority">Set priority</option>
            <option value="due_date">Set due date</option>
          </Select>
        </div>
        {action === "assign" && (
          <>
            <div>
              <Label htmlFor="bulk-reviewer">Analyst</Label>
              <Select id="bulk-reviewer" value={reviewer} onChange={(e) => setReviewer(e.target.value)} className="w-full">
                <option value="">Choose…</option>
                {(reviewers.data ?? []).filter((r) => r.can_assess).map((r) => (
                  <option key={r.id} value={r.id}>{r.name} · {r.open_reviews} open</option>
                ))}
              </Select>
            </div>
            <div>
              <Label htmlFor="bulk-note" hint="(optional, added as a comment)">Note</Label>
              <Input id="bulk-note" value={note} onChange={(e) => setNote(e.target.value)} />
            </div>
          </>
        )}
        {action === "priority" && (
          <div>
            <Label htmlFor="bulk-priority">Priority</Label>
            <Select id="bulk-priority" value={priority} onChange={(e) => setPriority(e.target.value as Priority)} className="w-full">
              {(Object.keys(priorityLabel) as Priority[]).map((p) => <option key={p} value={p}>{priorityLabel[p]}</option>)}
            </Select>
          </div>
        )}
        {action === "due_date" && (
          <div>
            <Label htmlFor="bulk-due">Due date</Label>
            <Input id="bulk-due" type="date" value={due} onChange={(e) => setDue(e.target.value)} />
          </div>
        )}
      </div>
    </Dialog>
  );
}

export function useFilterNav(path: string) {
  const navigate = useNavigate();
  const search = useSearch({ strict: false }) as ReviewFilters;
  const filters = validateReviewSearch(search as Record<string, unknown>);
  const setFilters = (f: ReviewFilters) => {
    const clean = Object.fromEntries(Object.entries(f).filter(([, v]) => v));
    void navigate({ to: path, search: clean as never, replace: true });
  };
  const onChange = (k: keyof ReviewFilters, v?: string) => setFilters({ ...filters, [k]: v, page: undefined });
  return { filters, setFilters, onChange };
}

export function QueuePage() {
  const { filters, setFilters, onChange } = useFilterNav("/human-review/queue");
  const { can } = useSession();
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [bulk, setBulk] = useState(false);
  const sync = useReviewMutation(reviewApi.sync);
  const canAssign = can("reviews.assign");
  return (
    <>
      <PageHeader
        title="Review queue"
        description="Findings waiting for manual investigation. Findings arrive from automated triage and AI review, or are added from the Findings page."
        actions={
          canAssign && (
            <Button variant="secondary" disabled={sync.isPending} onClick={() => sync.mutate(undefined)} title="Apply the automatic queue rules now">
              <RefreshCw className={cn(sync.isPending && "animate-spin")} /> Sync queue
            </Button>
          )
        }
      />
      {sync.data && (
        <div className="mb-3">
          <Alert tone="success">{sync.data.created ? `${sync.data.created} finding(s) added to the queue.` : "The queue is up to date."}</Alert>
        </div>
      )}
      {sync.error && <div className="mb-3"><ErrorPanel error={sync.error} /></div>}
      <Card>
        <div className="space-y-2 border-b border-border p-3">
          <ReviewFilterBar
            values={{ ...filters, status: filters.status === "all" ? undefined : (filters.status ?? "open") }}
            onChange={(k, v) => onChange(k, k === "status" && !v ? "all" : v)}
            onReset={() => setFilters({})}
            show={["q", "repository", "application", "scanner", "severity", "reviewer", "status", "priority", "overdue"]}
            trailing={
              canAssign && sel.size > 0 && (
                <Button size="sm" onClick={() => setBulk(true)}>
                  <UserPlus /> Update {sel.size} selected
                </Button>
              )
            }
          />
        </div>
        <ReviewsTable
          filters={{ status: filters.status ?? "open", ...filters }}
          setFilters={setFilters}
          selection={canAssign ? sel : undefined}
          setSelection={canAssign ? setSel : undefined}
          empty={
            <EmptyState icon={<ClipboardCheck />} title="Nothing waiting for review">
              Findings marked as needing review by automated triage or AI review appear here automatically. Add others from the Findings page.
            </EmptyState>
          }
        />
      </Card>
      <BulkDialog ids={[...sel]} open={bulk} onOpenChange={setBulk} onDone={() => setSel(new Set())} />
    </>
  );
}

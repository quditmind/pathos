import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { Inbox, UserPlus, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Alert, Card, EmptyState, PageHeader, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { cn } from "@/lib/utils";
import { useWorkload } from "./api";
import { BulkDialog, ReviewsTable, useFilterNav } from "./QueuePage";
import { fmtHours, ReviewFilterBar } from "./shared";

/** Assignments: analyst workload and (re)assignment of open reviews. */
export function AssignmentsPage() {
  const { filters, setFilters, onChange } = useFilterNav("/human-review/assignments");
  const { can } = useSession();
  const canAssign = can("reviews.assign");
  const wl = useWorkload({ repository_id: filters.repository_id, application_id: filters.application_id, severity: filters.severity });
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [bulk, setBulk] = useState(false);
  const rows = (wl.data ?? []).filter((w) => !filters.reviewer || (filters.reviewer === "none" ? !w.reviewer_id : w.reviewer_id === filters.reviewer));
  const maxOpen = Math.max(1, ...rows.map((r) => r.assigned));
  return (
    <>
      <PageHeader title="Assignments" description="Analyst workload, deadlines and (re)assignment of open reviews." />
      <Card className="mb-4">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 className="text-[13px] font-semibold">Workload by analyst</h2>
        </div>
        {wl.isError ? (
          <div className="p-4"><Alert>{wl.error.message}</Alert></div>
        ) : wl.isPending ? (
          <Skeleton className="m-4 h-24" />
        ) : rows.length === 0 ? (
          <EmptyState icon={<Users />} title="No reviews yet" />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Analyst</Th>
                <Th className="text-right">Open (assigned)</Th>
                <Th className="text-right">Pending</Th>
                <Th className="text-right">In progress</Th>
                <Th className="text-right">Completed</Th>
                <Th className="text-right">Overdue</Th>
                <Th className="text-right">Avg. time to complete</Th>
                <Th className="w-48">Load</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((w) => (
                <tr key={w.reviewer_id ?? "none"}>
                  <Td>
                    <button
                      type="button"
                      className="font-medium hover:underline"
                      onClick={() => setFilters({ ...filters, reviewer: w.reviewer_id ?? "none", page: undefined })}
                    >
                      {w.reviewer_id ? w.reviewer_name : "Unassigned"}
                    </button>
                  </Td>
                  <Td className="tabular text-right">{w.assigned}</Td>
                  <Td className="tabular text-right">{w.pending}</Td>
                  <Td className="tabular text-right">{w.in_progress}</Td>
                  <Td className="tabular text-right">{w.completed}</Td>
                  <Td className={cn("tabular text-right", w.overdue > 0 && "font-semibold text-danger")}>{w.overdue}</Td>
                  <Td className="tabular text-right">{fmtHours(w.avg_completion_hours)}</Td>
                  <Td>
                    <div className="h-1.5 w-full rounded-full bg-surface-muted" role="img" aria-label={`${w.assigned} open reviews`}>
                      <div className="h-1.5 rounded-full bg-primary" style={{ width: `${(100 * w.assigned) / maxOpen}%` }} />
                    </div>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <Card>
        <div className="space-y-2 border-b border-border p-3">
          <ReviewFilterBar
            values={filters}
            onChange={onChange}
            onReset={() => setFilters({})}
            show={["q", "repository", "application", "severity", "reviewer", "priority", "overdue"]}
            trailing={
              canAssign &&
              (sel.size > 0 ? (
                <Button size="sm" onClick={() => setBulk(true)}>
                  <UserPlus /> Assign / plan {sel.size} selected
                </Button>
              ) : (
                <span className="text-[12px] text-muted-foreground">Select reviews to assign, prioritize or set due dates.</span>
              ))
            }
          />
        </div>
        <ReviewsTable
          filters={{ status: "open", ...filters }}
          setFilters={setFilters}
          selection={canAssign ? sel : undefined}
          setSelection={canAssign ? setSel : undefined}
          empty={
            <EmptyState icon={<Inbox />} title="No open reviews match">
              <Link to="/human-review/queue" className="text-primary hover:underline">Open the review queue</Link>
            </EmptyState>
          }
        />
      </Card>
      <BulkDialog ids={[...sel]} open={bulk} onOpenChange={setBulk} onDone={() => setSel(new Set())} />
    </>
  );
}

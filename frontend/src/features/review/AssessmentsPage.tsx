import { FileSearch } from "lucide-react";
import { Card, EmptyState, PageHeader } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { cn } from "@/lib/utils";
import { ReviewFilterBar } from "./shared";
import { ReviewsTable, useFilterNav } from "./QueuePage";
import type { ReviewFilters } from "./types";

const views: { key: string; label: string; f: ReviewFilters }[] = [
  { key: "mine", label: "My assessments", f: { reviewer: "me", status: "open" } },
  { key: "independent", label: "Awaiting independent review", f: { status: "awaiting_independent_review" } },
  { key: "active", label: "In progress", f: { status: "in_progress,awaiting_information,reopened" } },
  { key: "completed", label: "Completed", f: { status: "completed", sort: "completed_at", order: "desc" } },
  { key: "all", label: "All", f: {} },
];

/** Assessments: reviews being worked on or decided, by workflow view. */
export function AssessmentsPage() {
  const { filters, setFilters, onChange } = useFilterNav("/human-review/assessments");
  const { can } = useSession();
  const worker = can("reviews.assess") || can("reviews.approve") || can("reviews.assign");
  const active = views.find((v) => Object.entries(v.f).every(([k, val]) => filters[k as keyof ReviewFilters] === val) && Object.keys(v.f).length > 0);
  return (
    <>
      <PageHeader
        title="Assessments"
        description={worker ? "Manual assessments in progress, awaiting a second reviewer, and completed." : "Completed assessments you are allowed to see."}
      />
      {worker && (
        <div className="mb-3 flex flex-wrap gap-1" role="tablist" aria-label="Assessment views">
          {views.map((v) => (
            <button
              key={v.key}
              role="tab"
              type="button"
              aria-selected={active?.key === v.key || (!active && v.key === "all")}
              onClick={() => setFilters(v.f)}
              className={cn(
                "rounded-md px-2.5 py-1 text-[12.5px]",
                active?.key === v.key || (!active && v.key === "all") ? "bg-primary/10 font-medium text-primary" : "text-muted-foreground hover:bg-surface-muted",
              )}
            >
              {v.label}
            </button>
          ))}
        </div>
      )}
      <Card>
        <div className="border-b border-border p-3">
          <ReviewFilterBar
            values={filters}
            onChange={onChange}
            onReset={() => setFilters({})}
            show={["q", "date", "repository", "application", "scanner", "severity", "reviewer", "disposition"]}
          />
        </div>
        <ReviewsTable
          filters={filters}
          setFilters={setFilters}
          empty={<EmptyState icon={<FileSearch />} title="No assessments match">Change the view or filters.</EmptyState>}
        />
      </Card>
    </>
  );
}

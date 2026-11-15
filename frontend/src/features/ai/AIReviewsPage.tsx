import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { Bot, Settings } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, EmptyState, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { useAIConfigs, useAIReviews } from "./api";
import { ReviewCard } from "./ReviewCard";

export function AIReviewsPage() {
  const { canOrgWide } = useSession();
  const [status, setStatus] = useState("pending_approval");
  const reviews = useAIReviews(status);
  const configs = useAIConfigs();
  const def = configs.data?.find((c) => c.is_default);

  return (
    <>
      <PageHeader
        title="AI reviews"
        description="AI-assisted triage verdicts. Nothing changes a finding until policy allows it or a reviewer approves; Critical findings are never closed automatically."
        actions={canOrgWide("ai.configure") && <Button variant="secondary" asChild><Link to="/admin/ai"><Settings /> AI settings</Link></Button>}
      />
      <Card className="mb-4 flex flex-wrap items-center gap-3 p-3 text-[13px]">
        {configs.isPending ? <Skeleton className="h-5 w-64" /> : def ? (
          <span>
            <span className="font-medium">{def.name}</span> v{def.current.version} · {def.current.model} · approval{" "}
            <span className="font-medium">{def.current.approval_policy.replace("_", " ")}</span> ·{" "}
            {def.current.auto_review ? `auto-review on (${def.used_today}/${def.current.daily_limit} today)` : "auto-review off"}
          </span>
        ) : (
          <span className="text-muted-foreground">No AI configuration yet. Findings can still be reviewed interactively through the PATHOS MCP server.</span>
        )}
        <Select className="ml-auto" aria-label="Filter reviews" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="pending_approval">Awaiting approval</option>
          <option value="applied">Applied</option>
          <option value="rejected">Rejected</option>
          <option value="">All</option>
        </Select>
      </Card>
      {reviews.isPending ? <Skeleton className="h-40" /> : !reviews.data?.length ? (
        <Card><EmptyState icon={<Bot />} title={status === "pending_approval" ? "Nothing awaiting approval" : "No reviews"}>
          Request a review from a finding, enable auto-review, or connect your own assistant via <Link to="/settings/tokens" className="text-primary underline">MCP</Link>.
        </EmptyState></Card>
      ) : (
        <div className="space-y-3">
          {reviews.data.map((r) => (
            <div key={r.id}>
              <ReviewCard review={r} showFinding />
              <Link to="/findings" search={{ finding: r.finding_id, status: "all" } as never} className="ml-1 text-[12px] text-primary hover:underline">Open finding →</Link>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

import { useEffect, useState } from "react";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { GitCompareArrows, Lock } from "lucide-react";
import { Card, EmptyState, PageHeader } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { ComparisonView } from "./ComparisonView";
import { PickerPanel } from "./PickerPanel";
import { MIN_COMPARE, parseIds, type CompareSearch } from "./model";

export { validateCompareSearch } from "./model";

export function ComparePage() {
  const { can } = useSession();
  const search = useSearch({ strict: false }) as CompareSearch;
  const navigate = useNavigate();
  const ids = parseIds(search.ids);
  const idsKey = ids.join(",");
  const [selected, setSelected] = useState<string[]>(ids);
  // Follow the URL (back/forward, links with ?ids=).
  useEffect(() => setSelected(parseIds(idsKey)), [idsKey]);

  const set = (n: Partial<CompareSearch>) =>
    void navigate({ to: ".", search: ((prev: CompareSearch) => ({ ...prev, ...n })) as never, replace: true });

  if (!can("scans.compare")) {
    return (
      <>
        <PageHeader title="Scan comparison" />
        <Card>
          <EmptyState icon={<Lock />} title="Comparison not available">You need the scans.compare permission to compare scan executions.</EmptyState>
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Scan comparison"
        description="Compare 2–10 executions side by side: what is new, fixed, recurring or unchanged, and how profiles and engines changed."
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,400px)_minmax(0,1fr)]">
        <PickerPanel
          search={search}
          onFilter={(f) => set(f)}
          selected={selected}
          onSelectedChange={setSelected}
          onCompare={() => set({ ids: selected.join(",") })}
        />
        <div className="min-w-0">
          {ids.length >= MIN_COMPARE ? (
            <ComparisonView ids={ids} />
          ) : (
            <Card>
              <EmptyState icon={<GitCompareArrows />} title="Select executions to compare">
                Pick between 2 and 10 scan executions on the left, then choose “Compare selected”. Executions are compared in chronological order.
              </EmptyState>
            </Card>
          )}
        </div>
      </div>
    </>
  );
}

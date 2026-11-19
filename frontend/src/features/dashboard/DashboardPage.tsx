import { lazy, Suspense } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { BarChart3, Lock } from "lucide-react";
import { api } from "@/api/client";
import { isAppRoute, splitHref } from "@/lib/utils";
import type { Chart, Dashboard } from "@/api/types";
import { FilterBar, type FilterDef } from "@/components/data/FilterBar";
import { KpiCard } from "@/components/data/KpiCard";
import { Card, PageHeader, Skeleton, Spinner } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { useBusinessUnits, useRegions } from "@/features/users/api";
import { ErrorPanel } from "@/components/ui/error-panel";

const ChartBody = lazy(() => import("./Charts"));

export interface DashboardSearch {
  days?: number;
  region_id?: string;
  country_id?: string;
  business_unit_id?: string;
}

export function validateDashboardSearch(s: Record<string, unknown>): DashboardSearch {
  const str = (v: unknown) => (typeof v === "string" && /^[0-9a-f-]{36}$/i.test(v) ? v : undefined);
  const days = Number(s.days);
  return {
    days: [7, 30, 90, 365].includes(days) ? days : undefined,
    region_id: str(s.region_id),
    country_id: str(s.country_id),
    business_unit_id: str(s.business_unit_id),
  };
}

const periodLabel: Record<number, string> = { 7: "7 days", 30: "30 days", 90: "90 days", 365: "year" };

export function DashboardPage() {
  const { can } = useSession();
  const search = useSearch({ strict: false }) as DashboardSearch;
  const navigate = useNavigate();
  const days = search.days ?? 30;
  const canOrg = can("org.read");
  const regions = useRegions();
  const bus = useBusinessUnits();

  const params = new URLSearchParams({ days: String(days) });
  for (const k of ["region_id", "country_id", "business_unit_id"] as const) if (search[k]) params.set(k, search[k]!);

  const q = useQuery({
    queryKey: ["dashboard", params.toString()],
    queryFn: ({ signal }) => api<Dashboard>(`/api/v1/dashboard?${params}`, { signal }),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  });

  const set = (key: string, value: string | undefined) => {
    const next: DashboardSearch = { ...search, [key]: key === "days" ? Number(value) : value };
    if (key === "region_id") next.country_id = undefined;
    void navigate({ to: "/", search: next as never, replace: true });
  };

  const region = regions.data?.find((r) => r.id === search.region_id);
  const countries = region ? region.countries : (regions.data ?? []).flatMap((r) => r.countries);

  const filters: FilterDef[] = [
    {
      key: "days",
      label: "Period",
      options: [
        { value: "7", label: "Last 7 days" },
        { value: "30", label: "Last 30 days" },
        { value: "90", label: "Last 90 days" },
        { value: "365", label: "Last 12 months" },
      ],
    },
    ...(canOrg
      ? [
          { key: "region_id", label: "Region", allLabel: "All regions", options: (regions.data ?? []).map((r) => ({ value: r.id, label: r.name })) },
          {
            key: "country_id",
            label: "Country",
            allLabel: "All countries",
            options: [...countries].sort((a, b) => a.name.localeCompare(b.name)).map((c) => ({ value: c.id, label: c.name })),
          },
          {
            key: "business_unit_id",
            label: "Business unit",
            allLabel: "All business units",
            options: (bus.data ?? []).map((b) => ({ value: b.id, label: b.name })),
          },
        ]
      : []),
    { key: "severity", label: "Severity", allLabel: "All severities", options: [], disabled: true, disabledReason: "Available once findings arrive (phase 6)" },
    { key: "scanner", label: "Scanner", allLabel: "All scanners", options: [], disabled: true, disabledReason: "Available once scanning arrives (phase 4)" },
  ];

  const data = q.data;
  const period = periodLabel[days] ?? `${days} days`;

  return (
    <>
      <PageHeader
        title="Security posture"
        description="Organization-wide application security metrics. Select a card to drill down."
        actions={q.isFetching && !q.isPending ? <Spinner /> : null}
      />
      <Card className="mb-5 p-3">
        <FilterBar
          filters={filters}
          values={{ ...search, days: String(days) }}
          onChange={set}
          onReset={() => void navigate({ to: "/", search: { days: search.days } as never, replace: true })}
        />
      </Card>

      {q.isError ? (
        <ErrorPanel error={q.error} title="Could not load the dashboard" />
      ) : !data ? (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          {Array.from({ length: 24 }, (_, i) => (
            <Skeleton key={i} className="h-[108px]" />
          ))}
        </div>
      ) : (
        <>
          {(() => {
            const live = data.kpis.filter((k) => k.status === "ok").length;
            const pending = [...new Set(data.kpis.filter((k) => k.status === "not_yet_available").map((k) => k.phase))].sort();
            const names: Record<number, string> = { 3: "repository onboarding", 4: "scanning", 5: "AI review", 6: "vulnerability management", 7: "scheduling" };
            return pending.length ? (
              <p className="mb-4 text-[12px] text-muted-foreground">
                {live} of {data.kpis.length} indicators have data today. The rest light up with{" "}
                {pending.map((p) => `${names[p] ?? "a later phase"} (phase ${p})`).join(", ")}; no placeholder numbers are shown.
              </p>
            ) : null;
          })()}
          {data.groups.map((g) => {
            const kpis = data.kpis.filter((k) => k.group === g);
            if (!kpis.length) return null;
            return (
              <section key={g} className="mb-5" aria-labelledby={`grp-${g}`}>
                <h2 id={`grp-${g}`} className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                  {g}
                </h2>
                <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
                  {kpis.map((k) => (
                    <KpiCard key={k.key} kpi={k} period={period} />
                  ))}
                </div>
              </section>
            );
          })}
          <div className="mt-6 grid gap-4 lg:grid-cols-2">
            {[...data.charts].sort((a, b) => Number(b.status === "ok") - Number(a.status === "ok")).map((c) => (
              <ChartPanel key={c.key} chart={c} />
            ))}
          </div>
        </>
      )}
    </>
  );
}

function ChartPanel({ chart }: { chart: Chart }) {
  return (
    <Card className="p-4">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-[13px] font-semibold">{chart.title}</h3>
        {chart.status === "ok" && isAppRoute(chart.drill) && (
          <Link {...(splitHref(chart.drill) as { to: string })} className="text-[12px] text-primary hover:underline">
            View details
          </Link>
        )}
      </div>
      {chart.status === "ok" ? (
        <Suspense fallback={<Skeleton className="h-[220px]" />}>
          <ChartBody chart={chart} />
        </Suspense>
      ) : (
        <div className="flex h-[220px] flex-col items-center justify-center gap-2 rounded-md border border-dashed border-border text-center">
          {chart.status === "restricted" ? <Lock className="size-5 text-muted-foreground" /> : <BarChart3 className="size-6 text-muted-foreground" />}
          <div className="text-[13px] font-medium text-muted-foreground">
            {chart.status === "restricted" ? "Requires additional permission" : "Not yet available"}
          </div>
          {chart.status === "not_yet_available" && (
            <div className="text-[12px] text-muted-foreground/80">Data source arrives in phase {chart.phase}</div>
          )}
        </div>
      )}
    </Card>
  );
}

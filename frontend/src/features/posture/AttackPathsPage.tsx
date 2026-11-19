import { Fragment, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ChevronRight, Globe, Route } from "lucide-react";
import { api } from "@/api/client";
import { Card, EmptyState, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { KevBadge, RiskBadge } from "@/features/vuln/intel";
import { cn } from "@/lib/utils";
import { ErrorPanel } from "@/components/ui/error-panel";

interface Step {
  type: "internet" | "target" | "repository" | "application" | "component" | "image" | "workload" | "finding";
  label: string;
  sub?: string;
  link?: string;
}

interface AttackPath {
  finding_id: string;
  risk: number;
  severity: string;
  kev: boolean;
  exploit_available: boolean;
  entry: "dast_target" | "exposed_repository" | "runtime_exposure";
  steps: Step[];
  reasons: string[];
}

function target(link: string) {
  const u = new URL(link, "https://pathos.invalid");
  return { to: u.pathname, search: Object.fromEntries(u.searchParams) };
}

export function AttackPathsPage() {
  const navigate = useNavigate();
  const [minRisk, setMinRisk] = useState(50);
  const q = useQuery({
    queryKey: ["posture", "attack-paths", minRisk],
    queryFn: () => api<{ items: AttackPath[]; counts: Record<string, number>; truncated: boolean }>(`/api/v1/posture/attack-paths?min_risk=${minRisk}`),
  });
  return (
    <>
      <PageHeader
        title="Attack paths"
        description="How an attacker on the internet could reach a weakness: through a tested web application or API, or through an internet-exposed asset to its code, its container image, or a vulnerable package its code actually uses. Ordered by contextual risk."
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Select aria-label="Minimum risk" value={minRisk} onChange={(e) => setMinRisk(Number(e.target.value))}>
          {[75, 50, 25, 0].map((v) => <option key={v} value={v}>{v ? `Risk ≥ ${v}` : "Any risk"}</option>)}
        </Select>
        {q.data && (
          <span className="text-[12px] text-muted-foreground">
            {q.data.counts.dast_target ?? 0} through tested applications · {q.data.counts.exposed_repository ?? 0} through exposed assets ·{" "}
            {q.data.counts.runtime_exposure ?? 0} observed in Kubernetes clusters
          </span>
        )}
      </div>
      {q.isError ? (
        <ErrorPanel error={q.error} />
      ) : q.isPending ? (
        <Skeleton className="h-48" />
      ) : !q.data.items.length ? (
        <Card>
          <EmptyState icon={<Route />} title="No attack paths at this risk level">
            Paths need an internet-exposed asset (Public internet exposure: yes), a web or API scan target, or a workload that an Ingress or a public
            load balancer exposes in a connected Kubernetes cluster (Runtime). Unused dependencies never count.
          </EmptyState>
        </Card>
      ) : (
        <div className="space-y-2">
          {q.data.items.map((p) => (
            <Card key={p.finding_id} className="p-3">
              <div className="flex flex-wrap items-center gap-1">
                {p.steps.map((s, i) => (
                  <Fragment key={i}>
                    {i > 0 && <ChevronRight className="size-4 text-muted-foreground" aria-hidden />}
                    <button
                      type="button"
                      disabled={!s.link}
                      onClick={() => s.link && void navigate(target(s.link) as never)}
                      title={s.sub}
                      className={cn(
                        "max-w-72 rounded-md border px-2 py-1 text-left text-[12px] enabled:hover:border-primary/50",
                        s.type === "finding" ? "border-danger/40 bg-danger-soft/40" : s.type === "internet" ? "border-warning/40" : "border-border",
                      )}
                    >
                      <span className="flex items-center gap-1 truncate font-medium">
                        {s.type === "internet" && <Globe className="size-3.5" aria-hidden />}
                        {s.label}
                      </span>
                      {s.sub && <span className="block truncate text-[11px] text-muted-foreground">{s.sub}</span>}
                    </button>
                  </Fragment>
                ))}
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-[12px]">
                <RiskBadge score={p.risk} />
                {p.kev && <KevBadge />}
                <span className="text-muted-foreground">{p.reasons.join(" · ")}</span>
                <Link to="/findings" search={{ finding: p.finding_id } as never} className="ml-auto text-primary hover:underline">Open finding</Link>
              </div>
            </Card>
          ))}
          {q.data.truncated && <p className="text-[12px] text-muted-foreground">Showing the 100 riskiest paths; raise the minimum risk to focus.</p>}
        </div>
      )}
    </>
  );
}

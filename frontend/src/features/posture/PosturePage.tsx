import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { Boxes } from "lucide-react";
import { Badge, Card, EmptyState, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { RiskBadge } from "@/features/vuln/intel";
import { dimensionLabel, type Dimension, type PostureGroup, useAggregate, useAppPosture } from "./api";
import { GraphLink, Percent, SeverityBar, When, daysOptions, riskExplanation } from "./shared";
import { ErrorPanel } from "@/components/ui/error-panel";

function Metrics({ g }: { g: PostureGroup }) {
  return (
    <>
      <Td>
        <span title={riskExplanation(g)}>
          <RiskBadge score={g.max_risk == null ? null : g.risk_score} />
        </span>
      </Td>
      <Td>
        <SeverityBar open={g.open} />
      </Td>
      <Td className="tabular text-[12px]">{g.kev_open ? <Badge tone="danger">{g.kev_open}</Badge> : "0"}</Td>
      <Td className="tabular text-[12px]">{g.sla_breached ? <span className="text-danger">{g.sla_breached}</span> : "0"}</Td>
      <Td className="tabular text-[12px]">{g.mttr_days == null ? "—" : `${g.mttr_days.toFixed(1)} d`}</Td>
      <Td className="text-[12px]">
        <Percent value={g.coverage} />
      </Td>
      <Td className="text-[12px]">
        <When at={g.last_scan_at} />
      </Td>
    </>
  );
}

const metricHeads = (
  <>
    <Th>Risk</Th>
    <Th>Open findings</Th>
    <Th>KEV</Th>
    <Th>SLA breached</Th>
    <Th>Mean time to fix</Th>
    <Th>Coverage</Th>
    <Th>Last scan</Th>
  </>
);

function Applications({ days }: { days: number }) {
  const q = useAppPosture(days);
  if (q.isError) return <div className="p-4"><ErrorPanel error={q.error} /></div>;
  if (q.isPending) return <Skeleton className="m-4 h-40" />;
  if (!q.data.length) return <EmptyState icon={<Boxes />} title="No repositories in your scope" />;
  return (
    <Table>
      <thead>
        <tr>
          <Th>Application</Th>
          <Th>Repositories</Th>
          {metricHeads}
        </tr>
      </thead>
      <tbody>
        {q.data.map((a) => (
          <tr key={a.id ?? "none"}>
            <Td>
              {a.id ? (
                <>
                  <div className="font-medium">
                    <GraphLink node={`application:${a.id}`}>{a.label}</GraphLink>
                  </div>
                  <div className="text-[11.5px] text-muted-foreground">
                    <span className="font-mono">{a.application_key}</span> · <span className="capitalize">{a.criticality}</span> criticality
                    {a.business_unit && ` · ${a.business_unit}`}
                    {a.owner && ` · ${a.owner}`}
                  </div>
                </>
              ) : (
                <>
                  <div className="font-medium text-muted-foreground">{a.label}</div>
                  <Link to="/posture/unmanaged" className="text-[11.5px] text-primary hover:underline">Map these repositories</Link>
                </>
              )}
            </Td>
            <Td className="tabular text-[12px]">
              {a.repositories}
              {a.scan_targets > 0 && <span className="text-muted-foreground"> + {a.scan_targets} targets</span>}
            </Td>
            <Metrics g={a} />
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function Grouped({ by, days }: { by: Dimension; days: number }) {
  const q = useAggregate(by, days);
  if (q.isError) return <div className="p-4"><ErrorPanel error={q.error} /></div>;
  if (q.isPending) return <Skeleton className="m-4 h-40" />;
  if (!q.data.length) return <EmptyState icon={<Boxes />} title="No repositories in your scope" />;
  return (
    <Table>
      <thead>
        <tr>
          <Th>{dimensionLabel[by]}</Th>
          <Th>Repositories</Th>
          {metricHeads}
        </tr>
      </thead>
      <tbody>
        {q.data.map((g) => (
          <tr key={g.id ?? "none"}>
            <Td className={g.id ? "font-medium" : "text-muted-foreground"}>{g.label || "—"}</Td>
            <Td className="tabular text-[12px]">{g.repositories}</Td>
            <Metrics g={g} />
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export function PosturePage() {
  const [by, setBy] = useState<Dimension>("application");
  const [days, setDays] = useState(90);
  return (
    <>
      <PageHeader
        title="Application posture"
        description="Security posture rolled up from findings, scans and ownership. An application's risk is its riskiest open finding, raised by one point for each other finding with risk ≥ 50 (at most 15). Coverage is the share of repositories with a successful code, dependency and secrets scan in the last 30 days."
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Select aria-label="Group by" value={by} onChange={(e) => setBy(e.target.value as Dimension)}>
          {(Object.keys(dimensionLabel) as Dimension[]).map((d) => (
            <option key={d} value={d}>By {dimensionLabel[d].toLowerCase()}</option>
          ))}
        </Select>
        <Select aria-label="Remediation window" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {daysOptions.map((d) => <option key={d} value={d}>Fixes in the last {d} days</option>)}
        </Select>
      </div>
      <Card>{by === "application" ? <Applications days={days} /> : <Grouped by={by} days={days} />}</Card>
    </>
  );
}

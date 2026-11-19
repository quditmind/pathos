import { lazy, Suspense, useState } from "react";
import { Link } from "@tanstack/react-router";
import { UserRoundSearch } from "lucide-react";
import { Alert, Badge, Card, EmptyState, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { Tabs } from "@/features/scans/shared";
import { formatHours, useDevelopers, useInsightSettings, useTeams, useTrend } from "./api";
import { ErrorPanel } from "@/components/ui/error-panel";

const TrendChart = lazy(() => import("./TrendChart"));

const tabs = [
  ["developers", "Developers"],
  ["teams", "Teams"],
  ["trend", "Secure-coding trend"],
] as const;
type Tab = (typeof tabs)[number][0];

const note =
  "Attribution is inferred from the commits between two scans: a new finding is attributed to the author of the newest commit in that range that touched its file, a fixed finding to the author of the newest commit that touched it before the scan stopped reporting it. Findings whose file no commit in the range touched stay unattributed. Use these numbers for coaching and planning, not for individual performance ratings.";

/** Per-developer and per-team new vs fixed findings (insights.people). */
export function DeveloperInsightsPage() {
  const { canOrgWide } = useSession();
  const allowed = canOrgWide("insights.people");
  const settings = useInsightSettings(allowed);
  const [tab, setTab] = useState<Tab>("developers");
  const [days, setDays] = useState(90);
  const enabled = allowed && !!settings.data?.attribution_enabled;

  return (
    <>
      <PageHeader
        title="Developer insights"
        description="Who introduces and who fixes findings, per git author and team."
        actions={
          enabled && (
            <Select aria-label="Period" value={String(days)} onChange={(e) => setDays(Number(e.target.value))} className="w-40">
              <option value="30">Last 30 days</option>
              <option value="90">Last 90 days</option>
              <option value="180">Last 6 months</option>
              <option value="365">Last year</option>
            </Select>
          )
        }
      />
      {!allowed ? (
        <Alert tone="warning">You need the organization-wide insights.people permission to see developer attribution.</Alert>
      ) : settings.isError ? (
        <ErrorPanel error={settings.error} title="Could not load the settings" />
      ) : !settings.data ? (
        <Skeleton className="h-40" />
      ) : !settings.data.attribution_enabled ? (
        <Card className="p-4">
          <EmptyState icon={<UserRoundSearch />} title="Developer attribution is off">
            For privacy, PATHOS does not record commit authors until an administrator turns attribution on.{" "}
            {settings.data.can_manage ? (
              <Link to="/admin/developer-attribution" className="text-primary hover:underline">Open the attribution settings</Link>
            ) : (
              "Ask an administrator with settings.manage."
            )}
          </EmptyState>
        </Card>
      ) : (
        <>
          <p className="mb-3 text-[12px] text-muted-foreground">{note}</p>
          <Tabs tabs={tabs} value={tab} onChange={setTab} label="Developer insight views" idPrefix="insights" />
          <div role="tabpanel" id={`insights-panel-${tab}`} aria-labelledby={`insights-tab-${tab}`} className="pt-4">
            {tab === "developers" && <DevelopersTab days={days} />}
            {tab === "teams" && <TeamsTab days={days} />}
            {tab === "trend" && <TrendTab days={days} />}
          </div>
        </>
      )}
    </>
  );
}

function DevelopersTab({ days }: { days: number }) {
  const q = useDevelopers(days);
  if (q.isError) return <ErrorPanel error={q.error} title="Could not load developers" />;
  if (!q.data) return <Skeleton className="h-40" />;
  if (!q.data.length) {
    return (
      <EmptyState icon={<UserRoundSearch />} title="No attributed findings yet">
        Attribution starts with the second branch scan after it was turned on (the first one only records the commit to compare with).
      </EmptyState>
    );
  }
  return (
    <Card>
      <Table>
        <thead>
          <tr>
            <Th>Git author</Th>
            <Th>PATHOS user</Th>
            <Th className="text-right">Introduced</Th>
            <Th className="text-right">of which critical/high</Th>
            <Th className="text-right">Still open</Th>
            <Th className="text-right">Fixed</Th>
            <Th className="text-right">Mean time to fix</Th>
            <Th className="text-right">Repositories</Th>
          </tr>
        </thead>
        <tbody>
          {q.data.map((d) => (
            <tr key={d.author_name}>
              <Td className="font-medium">{d.author_name}</Td>
              <Td>{d.user ? d.user.name : <Badge>not linked</Badge>}</Td>
              <Td className="text-right tabular-nums">{d.introduced}</Td>
              <Td className="text-right tabular-nums">{d.introduced_critical_high}</Td>
              <Td className="text-right tabular-nums">{d.still_open}</Td>
              <Td className="text-right tabular-nums">{d.fixed}</Td>
              <Td className="text-right tabular-nums">{formatHours(d.mean_time_to_fix_hours)}</Td>
              <Td className="text-right tabular-nums">{d.repositories}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}

function TeamsTab({ days }: { days: number }) {
  const q = useTeams(days);
  if (q.isError) return <ErrorPanel error={q.error} title="Could not load teams" />;
  if (!q.data) return <Skeleton className="h-40" />;
  if (!q.data.length) return <EmptyState icon={<UserRoundSearch />} title="No attributed findings yet" />;
  return (
    <Card>
      <p className="px-4 pt-3 text-[12px] text-muted-foreground">
        Teams count the developers whose git author name an administrator linked to a team member. A developer in several teams counts in each.
      </p>
      <Table>
        <thead>
          <tr>
            <Th>Team</Th>
            <Th className="text-right">Developers</Th>
            <Th className="text-right">Introduced</Th>
            <Th className="text-right">of which critical/high</Th>
            <Th className="text-right">Still open</Th>
            <Th className="text-right">Fixed</Th>
            <Th className="text-right">Mean time to fix</Th>
          </tr>
        </thead>
        <tbody>
          {q.data.map((t) => (
            <tr key={t.id ?? t.name}>
              <Td className={t.id ? "font-medium" : "italic text-muted-foreground"}>{t.name}</Td>
              <Td className="text-right tabular-nums">{t.developers}</Td>
              <Td className="text-right tabular-nums">{t.introduced}</Td>
              <Td className="text-right tabular-nums">{t.introduced_critical_high}</Td>
              <Td className="text-right tabular-nums">{t.still_open}</Td>
              <Td className="text-right tabular-nums">{t.fixed}</Td>
              <Td className="text-right tabular-nums">{formatHours(t.mean_time_to_fix_hours)}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}

function TrendTab({ days }: { days: number }) {
  const devs = useDevelopers(days);
  const [author, setAuthor] = useState("");
  const q = useTrend(days, author);
  return (
    <Card className="space-y-3 p-4">
      <label className="flex items-center gap-2 text-[12.5px]">
        Developer
        <Select aria-label="Developer" value={author} onChange={(e) => setAuthor(e.target.value)} className="w-64">
          <option value="">Everyone</option>
          {(devs.data ?? []).map((d) => (
            <option key={d.author_name} value={d.author_name}>{d.author_name}</option>
          ))}
        </Select>
      </label>
      {q.isError ? (
        <ErrorPanel error={q.error} title="Could not load the trend" />
      ) : !q.data ? (
        <Skeleton className="h-[240px]" />
      ) : (
        <Suspense fallback={<Skeleton className="h-[240px]" />}>
          <TrendChart points={q.data} />
        </Suspense>
      )}
      {q.data && (
        <p className="text-[12px] text-muted-foreground">
          {q.data.reduce((n, p) => n + p.introduced, 0)} introduced and {q.data.reduce((n, p) => n + p.fixed, 0)} fixed in the period. More fixed than introduced
          means the backlog this group touches is shrinking.
        </p>
      )}
    </Card>
  );
}

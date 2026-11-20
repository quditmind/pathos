import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { Waypoints, Webhook } from "lucide-react";
import { Card, PageHeader, Select } from "@/components/ui/primitives";
import { ErrorPanel } from "@/components/ui/error-panel";
import { EmptyStateCard, FeatureDisabled, LoadingSkeleton } from "@/components/ui/states";
import { useApplications } from "@/features/repos/api";
import { useFeatureFlags } from "@/features/shell/meta";
import { useSession } from "@/features/auth/session";
import { CodeGraphSettingsCard } from "./CodeGraphSettings";
import { CodeGraphPanel, type CodeGraphState } from "./CodeGraphPanel";
import type { CodeGraphView } from "./views";
import type { CodeGraphSearch as Search } from "./search";

/** /codegraph/$appId: the CodeGraph of one application (the hub tab embeds CodeGraphPanel). */
export function CodeGraphPage() {
  const { appId } = useParams({ strict: false }) as { appId: string };
  const search = useSearch({ strict: false }) as Search;
  const navigate = useNavigate();
  const apps = useApplications();
  const app = apps.data?.find((a) => a.id === appId);
  // With the application profile hub (M3, flag onboarding) the breadcrumb leads to the profile's CodeGraph tab.
  const { flags } = useFeatureFlags();
  const state: CodeGraphState = { view: search.view ?? "architecture", snapshot: search.snapshot, compare: search.compare, focus: search.focus, node: search.node };
  const onStateChange = (s: CodeGraphState) =>
    void navigate({
      to: "/codegraph/$appId",
      params: { appId },
      search: { view: s.view === "architecture" ? undefined : s.view, snapshot: s.snapshot, compare: s.compare, focus: s.focus, node: s.node } as never,
      replace: s.view === state.view && s.snapshot === state.snapshot && s.compare === state.compare && s.focus === state.focus,
    });
  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 text-[12px] text-muted-foreground">
        <ol className="flex flex-wrap items-center gap-1">
          <li>
            <Link to="/applications" className="hover:underline">
              Applications
            </Link>{" "}
            /
          </li>
          <li>
            {flags.onboarding ? (
              <Link to="/applications/$id" params={{ id: appId }} search={{ tab: "codegraph" } as never} className="hover:underline">
                {app?.name ?? "Application"}
              </Link>
            ) : (
              <Link to="/applications" search={{ app: appId } as never} className="hover:underline">
                {app?.name ?? "Application"}
              </Link>
            )}{" "}
            /
          </li>
          <li aria-current="page" className="font-semibold text-foreground">
            CodeGraph
          </li>
        </ol>
      </nav>
      <PageHeader
        title={app ? `CodeGraph: ${app.name}` : "CodeGraph"}
        description="The application's code, APIs, data stores, deployment and dependencies as one graph. Every edge says how it is known: verified from code, observed at runtime, or AI-inferred."
      />
      <CodeGraphPanel applicationId={appId} applicationName={app?.name} state={state} onStateChange={onStateChange} />
    </>
  );
}

/** /codegraph and /api-endpoints: choose an application. */
export function CodeGraphIndexPage({ view }: { view?: CodeGraphView }) {
  const navigate = useNavigate();
  const { flags, isPending } = useFeatureFlags();
  const apps = useApplications();
  const { can } = useSession();
  const api = view === "api";
  const header = (
    <PageHeader
      title={api ? "API & endpoints" : "CodeGraph"}
      description={
        api
          ? "Routes and API operations found in each application's code, the handlers behind them and whether they are exposed to the internet."
          : "Choose an application to see its CodeGraph: code, APIs, data stores, deployment and dependencies, with the evidence for every edge."
      }
    />
  );
  if (isPending) return <>{header}<LoadingSkeleton rows={4} /></>;
  if (!flags.codegraph) return <>{header}<FeatureDisabled flag="codegraph" feature={api ? "API & endpoints" : "CodeGraph"} /></>;
  return (
    <>
      {header}
      {apps.isError ? (
        <ErrorPanel error={apps.error} title="Could not load the applications" onVerify={() => apps.refetch()} />
      ) : apps.isPending ? (
        <LoadingSkeleton rows={4} label="Loading applications" />
      ) : !apps.data.length ? (
        <EmptyStateCard icon={api ? <Webhook /> : <Waypoints />} title="No applications yet" action={<Link to="/applications" className="text-[13px] text-primary underline">Register an application</Link>}>
          The CodeGraph is built per application from its repositories.
        </EmptyStateCard>
      ) : (
        <Card className="p-4">
          <label className="flex flex-wrap items-center gap-2 text-[13px]">
            Application
            <Select
              aria-label="Application"
              defaultValue=""
              onChange={(e) =>
                e.target.value && void navigate({ to: "/codegraph/$appId", params: { appId: e.target.value }, search: (api ? { view: "api" } : {}) as never })
              }
            >
              <option value="">Choose an application…</option>
              {apps.data.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </Select>
          </label>
        </Card>
      )}
      {!api && can("settings.manage") && <CodeGraphSettingsCard />}
    </>
  );
}

export const CodeGraphHomePage = () => <CodeGraphIndexPage />;
export const ApiEndpointsPage = () => <CodeGraphIndexPage view="api" />;

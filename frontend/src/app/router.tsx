import { HelpDocPage, HelpHomePage, validateHelpSearch } from "@/features/help/HelpPages";
import { createRootRoute, createRoute, createRouter, Outlet, redirect } from "@tanstack/react-router";
import { ApiError, loginUrl } from "@/api/client";
import type { AuditRecord, UserStatus } from "@/api/types";
import { AppShell } from "@/components/layout/AppShell";
import { Alert, Spinner } from "@/components/ui/primitives";
import { SessionProvider, useMe } from "@/features/auth/session";
import { LoginPage } from "@/features/auth/LoginPage";
import { DashboardPage, validateDashboardSearch } from "@/features/dashboard/DashboardPage";
import { UsersPage } from "@/features/users/UsersPage";
import { OrganizationPage } from "@/features/users/OrganizationPage";
import { AuditPage } from "@/features/audit/AuditPage";
import { RepositoriesPage, validateRepoSearch } from "@/features/repos/RepositoriesPage";
import { ImportPage } from "@/features/repos/ImportPage";
import { ApplicationsPage } from "@/features/repos/ApplicationsPage";
import { ScmConnectionsPage, validateScmSearch } from "@/features/settings/ScmConnectionsPage";
import { ImportLandingPage } from "@/features/repos/onboarding/ImportLandingPage";
import { OnboardingPage, validateOnboardingSearch } from "@/features/repos/onboarding/OnboardingPage";
import { ImportsPage, validateImportsSearch } from "@/features/repos/onboarding/ImportsPage";
import { ImportJobPage } from "@/features/repos/onboarding/ImportJobPage";
import { AssetSettingsPage } from "@/features/assets/AssetSettingsPage";
import { TagsPage } from "@/features/settings/TagsPage";
import { ScansPage, validateScanSearch } from "@/features/scans/ScansPage";
import { ScanOverviewPage, validateOverviewSearch } from "@/features/scans/overview/ScanOverviewPage";
import { ScanDetailsPage, validateDetailsSearch } from "@/features/scans/details/ScanDetailsPage";
import { ComparePage, validateCompareSearch } from "@/features/scans/compare/ComparePage";
import { ProfilesPage } from "@/features/scans/ProfilesPage";
import { ScannersPage } from "@/features/scans/ScannersPage";
import { ImportResultsPage } from "@/features/scans/ImportResultsPage";
import { ScanTargetsPage } from "@/features/scans/ScanTargetsPage";
import { CompliancePage } from "@/features/compliance/CompliancePage";
import { SecuritySettingsPage } from "@/features/account/SecuritySettingsPage";
import { PullRequestChecksPage } from "@/features/prchecks/PullRequestChecksPage";
import { PosturePage } from "@/features/posture/PosturePage";
import { CoveragePage } from "@/features/posture/CoveragePage";
import { UnmanagedPage } from "@/features/posture/UnmanagedPage";
import { BenchmarkPage } from "@/features/posture/BenchmarkPage";
import { BlastRadiusPage, validateBlastSearch } from "@/features/posture/BlastRadiusPage";
import { ContextGraphPage, validateGraphSearch } from "@/features/posture/ContextGraphPage";
import { AttackPathsPage } from "@/features/posture/AttackPathsPage";
import { VulnerabilityPage } from "@/features/vuln/VulnerabilityPage";
import { SuppressionRulesPage } from "@/features/vuln/SuppressionRulesPage";
import { AnalystPage } from "@/features/ai/AnalystPage";
import { AIReportsPage } from "@/features/ai/AIReportsPage";
import { AIUsagePage } from "@/features/ai/AIUsagePage";
import { CustomRulesPage } from "@/features/scans/CustomRulesPage";
import { FindingsPage, validateFindingSearch } from "@/features/findings/FindingsPage";
import { RiskPage } from "@/features/vuln/RiskPage";
import { SchedulesPage } from "@/features/schedule/SchedulesPage";
import { NotificationsPage } from "@/features/notify/NotificationsPage";
import { SbomPage } from "@/features/vuln/SbomPage";
import { PoliciesPage } from "@/features/vuln/PoliciesPage";
import { RiskIntelPage } from "@/features/vuln/RiskIntelPage";
import { AIReviewsPage } from "@/features/ai/AIReviewsPage";
import { AISettingsPage } from "@/features/ai/AISettingsPage";
import { McpRegistryPage } from "@/features/ai/McpRegistryPage";
import { TokensPage } from "@/features/ai/TokensPage";
import { OverviewPage as ReviewOverviewPage } from "@/features/review/OverviewPage";
import { QueuePage, validateReviewSearch } from "@/features/review/QueuePage";
import { AssessmentsPage } from "@/features/review/AssessmentsPage";
import { AssignmentsPage } from "@/features/review/AssignmentsPage";
import { ReportsPage as ReviewReportsPage } from "@/features/review/ReportsPage";
import { ConfigurationsPage as ReviewConfigurationsPage } from "@/features/review/ConfigurationsPage";
import { WorkspacePage, validateWorkspaceSearch } from "@/features/review/workspace/WorkspacePage";

function Authenticated() {
  const me = useMe();
  if (me.isPending) {
    return (
      <div className="flex h-full items-center justify-center">
        <Spinner className="size-6" />
      </div>
    );
  }
  if (me.isError) {
    if (me.error instanceof ApiError && me.error.status === 401) {
      window.location.replace(`/login?return_to=${encodeURIComponent(window.location.pathname + window.location.search)}`);
      return null;
    }
    return (
      <div className="mx-auto mt-20 max-w-md px-4">
        <Alert>
          PATHOS is unavailable: {me.error.message}.{" "}
          <a className="underline" href={loginUrl()}>
            Try signing in again
          </a>
        </Alert>
      </div>
    );
  }
  return (
    <SessionProvider me={me.data}>
      <AppShell>
        <Outlet />
      </AppShell>
    </SessionProvider>
  );
}

type AuditOutcome = AuditRecord["outcome"];

function NotFound() {
  return <p className="text-[13px] text-muted-foreground">Page not found.</p>;
}

const rootRoute = createRootRoute({ component: Outlet, notFoundComponent: NotFound });
const loginRoute = createRoute({ getParentRoute: () => rootRoute, path: "/login", component: LoginPage });
const appRoute = createRoute({ getParentRoute: () => rootRoute, id: "app", component: Authenticated });
const overviewRoute = createRoute({ getParentRoute: () => appRoute, path: "/", component: DashboardPage, validateSearch: validateDashboardSearch });
const usersRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/admin/users",
  component: UsersPage,
  validateSearch: (s: Record<string, unknown>): { status?: UserStatus; user?: string } => ({
    status: s.status === "active" || s.status === "invited" || s.status === "deactivated" ? s.status : undefined,
    user: typeof s.user === "string" ? s.user : undefined,
  }),
});
const orgRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/organization", component: OrganizationPage });
const auditRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/admin/audit",
  component: AuditPage,
  validateSearch: (s: Record<string, unknown>): { action?: string; outcome?: AuditOutcome } => ({
    action: typeof s.action === "string" ? s.action.slice(0, 100) : undefined,
    outcome: s.outcome === "success" || s.outcome === "denied" || s.outcome === "failure" ? s.outcome : undefined,
  }),
});

const reposRoute = createRoute({ getParentRoute: () => appRoute, path: "/repositories", component: RepositoriesPage, validateSearch: validateRepoSearch });
const importRoute = createRoute({ getParentRoute: () => appRoute, path: "/repositories/import", component: ImportLandingPage });
const csvImportRoute = createRoute({ getParentRoute: () => appRoute, path: "/repositories/import/csv", component: ImportPage });
const onboardingRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/repositories/import/$source",
  component: OnboardingPage,
  validateSearch: validateOnboardingSearch,
});
const importsRoute = createRoute({ getParentRoute: () => appRoute, path: "/repositories/imports", component: ImportsPage, validateSearch: validateImportsSearch });
const importJobRoute = createRoute({ getParentRoute: () => appRoute, path: "/repositories/imports/$id", component: ImportJobPage });
const assetSettingsRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/assets", component: AssetSettingsPage });
const appsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/applications",
  component: ApplicationsPage,
  validateSearch: (s: Record<string, unknown>): { app?: string } => ({ app: typeof s.app === "string" ? s.app : undefined }),
});
const scmRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/scm", component: ScmConnectionsPage, validateSearch: validateScmSearch });
const tagsRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/tags", component: TagsPage });

const scansRoute = createRoute({ getParentRoute: () => appRoute, path: "/scans", component: ScansPage, validateSearch: validateScanSearch });
const scanOverviewRoute = createRoute({ getParentRoute: () => appRoute, path: "/scans/overview", component: ScanOverviewPage, validateSearch: validateOverviewSearch });
const scanCompareRoute = createRoute({ getParentRoute: () => appRoute, path: "/scans/compare", component: ComparePage, validateSearch: validateCompareSearch });
const scanDetailsRoute = createRoute({ getParentRoute: () => appRoute, path: "/scans/$id", component: ScanDetailsPage, validateSearch: validateDetailsSearch });
// Configurations: scan profiles and scanners & workers (old URLs redirect).
const profilesRoute = createRoute({ getParentRoute: () => appRoute, path: "/configurations/scan-profiles", component: ProfilesPage });
const oldProfilesRoute = createRoute({ getParentRoute: () => appRoute, path: "/scans/profiles", beforeLoad: () => { throw redirect({ to: "/configurations/scan-profiles", replace: true }); } });
const scannersRoute = createRoute({ getParentRoute: () => appRoute, path: "/configurations/scanners", component: ScannersPage });
const oldScannersRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/scanners", beforeLoad: () => { throw redirect({ to: "/configurations/scanners", replace: true }); } });
const importResultsRoute = createRoute({ getParentRoute: () => appRoute, path: "/scans/imports", component: ImportResultsPage });
const prChecksRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/pull-requests",
  component: PullRequestChecksPage,
  validateSearch: (s: Record<string, unknown>): { check?: string } => ({ check: typeof s.check === "string" ? s.check : undefined }),
});
const scanTargetsRoute = createRoute({ getParentRoute: () => appRoute, path: "/scans/targets", component: ScanTargetsPage });
const postureRoute = createRoute({ getParentRoute: () => appRoute, path: "/posture", component: PosturePage });
const coverageRoute = createRoute({ getParentRoute: () => appRoute, path: "/posture/coverage", component: CoveragePage });
const unmanagedRoute = createRoute({ getParentRoute: () => appRoute, path: "/posture/unmanaged", component: UnmanagedPage });
const benchmarkRoute = createRoute({ getParentRoute: () => appRoute, path: "/posture/benchmark", component: BenchmarkPage });
const blastRoute = createRoute({ getParentRoute: () => appRoute, path: "/posture/blast-radius", component: BlastRadiusPage, validateSearch: validateBlastSearch });
const attackRoute = createRoute({ getParentRoute: () => appRoute, path: "/posture/attack-paths", component: AttackPathsPage });
const vulnRoute = createRoute({ getParentRoute: () => appRoute, path: "/vulnerabilities/$id", component: VulnerabilityPage });
const suppressionRoute = createRoute({ getParentRoute: () => appRoute, path: "/suppression-rules", component: SuppressionRulesPage });
const analystRoute = createRoute({ getParentRoute: () => appRoute, path: "/ai/analyst", component: AnalystPage });
const aiReportsRoute = createRoute({ getParentRoute: () => appRoute, path: "/ai/reports", component: AIReportsPage });
const aiUsageRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/ai-usage", component: AIUsagePage });
const graphRoute = createRoute({ getParentRoute: () => appRoute, path: "/posture/graph", component: ContextGraphPage, validateSearch: validateGraphSearch });
const customRulesRoute = createRoute({ getParentRoute: () => appRoute, path: "/configurations/custom-rules", component: CustomRulesPage });
const findingsRoute = createRoute({ getParentRoute: () => appRoute, path: "/findings", component: FindingsPage, validateSearch: validateFindingSearch });

const schedulesRoute = createRoute({ getParentRoute: () => appRoute, path: "/scans/schedules", component: SchedulesPage });
const notifyRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/notifications", component: NotificationsPage });
const riskRoute = createRoute({ getParentRoute: () => appRoute, path: "/risk", component: RiskPage });
const sbomRoute = createRoute({ getParentRoute: () => appRoute, path: "/sbom", component: SbomPage });
const riskIntelRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/risk-intelligence", component: RiskIntelPage });
const policiesRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/policies", component: PoliciesPage });

const aiRoute = createRoute({ getParentRoute: () => appRoute, path: "/ai", component: AIReviewsPage });
const aiSettingsRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/ai", component: AISettingsPage });
const mcpRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/mcp", component: McpRegistryPage });
const complianceRoute = createRoute({ getParentRoute: () => appRoute, path: "/compliance", component: CompliancePage });
const securitySettingsRoute = createRoute({ getParentRoute: () => appRoute, path: "/settings/security", component: SecuritySettingsPage });
const tokensRoute = createRoute({ getParentRoute: () => appRoute, path: "/settings/tokens", component: TokensPage });

// Human Eye (standalone module).
const hrOverviewRoute = createRoute({ getParentRoute: () => appRoute, path: "/human-review", component: ReviewOverviewPage, validateSearch: validateReviewSearch });
const hrQueueRoute = createRoute({ getParentRoute: () => appRoute, path: "/human-review/queue", component: QueuePage, validateSearch: validateReviewSearch });
const hrAssessmentsRoute = createRoute({ getParentRoute: () => appRoute, path: "/human-review/assessments", component: AssessmentsPage, validateSearch: validateReviewSearch });
const hrAssignmentsRoute = createRoute({ getParentRoute: () => appRoute, path: "/human-review/assignments", component: AssignmentsPage, validateSearch: validateReviewSearch });
const hrReportsRoute = createRoute({ getParentRoute: () => appRoute, path: "/human-review/reports", component: ReviewReportsPage, validateSearch: validateReviewSearch });
const hrConfigRoute = createRoute({ getParentRoute: () => appRoute, path: "/human-review/configurations", component: ReviewConfigurationsPage });
const hrWorkspaceRoute = createRoute({ getParentRoute: () => appRoute, path: "/human-review/reviews/$id", component: WorkspacePage, validateSearch: validateWorkspaceSearch });

const helpRoute = createRoute({ getParentRoute: () => appRoute, path: "/help", component: HelpHomePage, validateSearch: validateHelpSearch });
const helpDocRoute = createRoute({ getParentRoute: () => appRoute, path: "/help/$section/$slug", component: HelpDocPage });

const routeTree = rootRoute.addChildren([
  loginRoute,
  appRoute.addChildren([helpRoute, helpDocRoute, overviewRoute, usersRoute, orgRoute, auditRoute, reposRoute, importRoute, csvImportRoute, onboardingRoute, importsRoute, importJobRoute, assetSettingsRoute, appsRoute, scmRoute, tagsRoute,
    scansRoute, scanOverviewRoute, scanCompareRoute, scanDetailsRoute, profilesRoute, oldProfilesRoute, scannersRoute, oldScannersRoute, importResultsRoute, scanTargetsRoute, prChecksRoute, customRulesRoute, postureRoute, coverageRoute, unmanagedRoute, benchmarkRoute, blastRoute, graphRoute, attackRoute, vulnRoute, suppressionRoute, analystRoute, aiReportsRoute, aiUsageRoute, findingsRoute, schedulesRoute, notifyRoute, riskRoute, sbomRoute, policiesRoute, riskIntelRoute, aiRoute, aiSettingsRoute, mcpRoute, tokensRoute, securitySettingsRoute, complianceRoute,
    hrOverviewRoute, hrQueueRoute, hrAssessmentsRoute, hrAssignmentsRoute, hrReportsRoute, hrConfigRoute, hrWorkspaceRoute]),
]);

export const router = createRouter({ routeTree, defaultPreload: "intent" });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

import { createRootRoute, createRoute, createRouter, Outlet } from "@tanstack/react-router";
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
import { ProfilesPage } from "@/features/scans/ProfilesPage";
import { ScannersPage } from "@/features/scans/ScannersPage";
import { FindingsPage, validateFindingSearch } from "@/features/findings/FindingsPage";
import { RiskPage } from "@/features/vuln/RiskPage";
import { SchedulesPage } from "@/features/schedule/SchedulesPage";
import { NotificationsPage } from "@/features/notify/NotificationsPage";
import { SbomPage } from "@/features/vuln/SbomPage";
import { PoliciesPage } from "@/features/vuln/PoliciesPage";
import { AIReviewsPage } from "@/features/ai/AIReviewsPage";
import { AISettingsPage } from "@/features/ai/AISettingsPage";
import { McpRegistryPage } from "@/features/ai/McpRegistryPage";
import { TokensPage } from "@/features/ai/TokensPage";

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
const profilesRoute = createRoute({ getParentRoute: () => appRoute, path: "/scans/profiles", component: ProfilesPage });
const scannersRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/scanners", component: ScannersPage });
const findingsRoute = createRoute({ getParentRoute: () => appRoute, path: "/findings", component: FindingsPage, validateSearch: validateFindingSearch });

const schedulesRoute = createRoute({ getParentRoute: () => appRoute, path: "/scans/schedules", component: SchedulesPage });
const notifyRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/notifications", component: NotificationsPage });
const riskRoute = createRoute({ getParentRoute: () => appRoute, path: "/risk", component: RiskPage });
const sbomRoute = createRoute({ getParentRoute: () => appRoute, path: "/sbom", component: SbomPage });
const policiesRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/policies", component: PoliciesPage });

const aiRoute = createRoute({ getParentRoute: () => appRoute, path: "/ai", component: AIReviewsPage });
const aiSettingsRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/ai", component: AISettingsPage });
const mcpRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/mcp", component: McpRegistryPage });
const tokensRoute = createRoute({ getParentRoute: () => appRoute, path: "/settings/tokens", component: TokensPage });

const routeTree = rootRoute.addChildren([
  loginRoute,
  appRoute.addChildren([overviewRoute, usersRoute, orgRoute, auditRoute, reposRoute, importRoute, csvImportRoute, onboardingRoute, importsRoute, importJobRoute, assetSettingsRoute, appsRoute, scmRoute, tagsRoute,
    scansRoute, profilesRoute, scannersRoute, findingsRoute, schedulesRoute, notifyRoute, riskRoute, sbomRoute, policiesRoute, aiRoute, aiSettingsRoute, mcpRoute, tokensRoute]),
]);

export const router = createRouter({ routeTree, defaultPreload: "intent" });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

import { createRootRoute, createRoute, createRouter, Outlet } from "@tanstack/react-router";
import { ApiError, loginUrl } from "@/api/client";
import { AppShell } from "@/components/layout/AppShell";
import { Alert, Spinner } from "@/components/ui/primitives";
import { SessionProvider, useMe } from "@/features/auth/session";
import { LoginPage } from "@/features/auth/LoginPage";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { UsersPage } from "@/features/users/UsersPage";
import { OrganizationPage } from "@/features/users/OrganizationPage";
import { AuditPage } from "@/features/audit/AuditPage";

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

function NotFound() {
  return <p className="text-[13px] text-muted-foreground">Page not found.</p>;
}

const rootRoute = createRootRoute({ component: Outlet, notFoundComponent: NotFound });
const loginRoute = createRoute({ getParentRoute: () => rootRoute, path: "/login", component: LoginPage });
const appRoute = createRoute({ getParentRoute: () => rootRoute, id: "app", component: Authenticated });
const overviewRoute = createRoute({ getParentRoute: () => appRoute, path: "/", component: OverviewPage });
const usersRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/users", component: UsersPage });
const orgRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/organization", component: OrganizationPage });
const auditRoute = createRoute({ getParentRoute: () => appRoute, path: "/admin/audit", component: AuditPage });

const routeTree = rootRoute.addChildren([loginRoute, appRoute.addChildren([overviewRoute, usersRoute, orgRoute, auditRoute])]);

export const router = createRouter({ routeTree, defaultPreload: "intent" });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

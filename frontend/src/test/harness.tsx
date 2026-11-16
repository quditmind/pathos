import type { ReactNode } from "react";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { vi } from "vitest";
import type { Me } from "@/api/types";
import { SessionProvider } from "@/features/auth/session";

export function me(permissions: string[] = []): Me {
  return {
    user: {
      id: "u1", organization_id: "o1", email: "ada@example.com", display_name: "Ada", status: "active",
      last_login_at: null, deactivated_at: null, created_at: "", updated_at: "",
    },
    permissions,
    org_wide_permissions: permissions,
    role_assignments: [],
    csrf_token: "csrf",
  };
}

/** Renders UI inside QueryClient, session and a memory router (for Link/useNavigate). */
export function renderApp(ui: ReactNode, opts: { permissions?: string[]; path?: string } = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const root = createRootRoute({ component: () => <>{ui}</> });
  const router = createRouter({ routeTree: root, history: createMemoryHistory({ initialEntries: [opts.path ?? "/"] }) });
  const utils = render(
    <QueryClientProvider client={qc}>
      <SessionProvider me={me(opts.permissions)}>
        <RouterProvider router={router} />
      </SessionProvider>
    </QueryClientProvider>,
  );
  return { ...utils, qc, router };
}

type Handler = (url: URL, init: RequestInit & { json?: unknown }) => unknown | Response | Promise<unknown | Response>;

/**
 * Stubs fetch with a routing table: keys are "METHOD /path" (query ignored).
 * A handler may return a Response or a JSON-serialisable body.
 */
export function mockApi(routes: Record<string, Handler>) {
  const calls: { method: string; path: string; url: URL; body: unknown }[] = [];
  const fn = vi.fn(async (input: string, init: RequestInit = {}) => {
    const url = new URL(input, "http://localhost");
    const method = (init.method ?? "GET").toUpperCase();
    const body = typeof init.body === "string" ? JSON.parse(init.body) : init.body;
    calls.push({ method, path: url.pathname, url, body });
    const h = routes[`${method} ${url.pathname}`];
    if (!h) return new Response(JSON.stringify({ error: { code: "not_found", message: `unmocked ${method} ${url.pathname}` } }), { status: 404 });
    const out = await h(url, { ...init, json: body });
    if (out instanceof Response) return out;
    return new Response(JSON.stringify(out ?? {}), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fn);
  return { fn, calls };
}

export const jsonResponse = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

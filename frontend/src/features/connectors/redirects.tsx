import { Navigate, useSearch } from "@tanstack/react-router";
import { LoadingSkeleton } from "@/components/ui/states";
import { IntegrationsPage } from "@/features/integrations/IntegrationsPage";
import { ScmConnectionsPage, type ScmSearch } from "@/features/settings/ScmConnectionsPage";
import { useFeatureFlags } from "@/features/shell/meta";

/**
 * /admin/scm and /admin/integrations (prompt §1.1): with the `connectors`
 * flag on they redirect into the Connectors hub, which embeds the same pages
 * (parity proven by e2e/tests/connectors-parity.spec.ts). With the flag off
 * they render the old pages exactly as before. Query parameters are kept, so
 * the OAuth callback (/admin/scm?oauth=…) and deep links (?connect=git) work
 * in both cases.
 */
export function ScmConnectionsRoute() {
  const { flags, isPending } = useFeatureFlags();
  const s = useSearch({ strict: false }) as ScmSearch;
  if (isPending) return <LoadingSkeleton rows={3} label="Loading SCM connections" />;
  if (flags.connectors !== true) return <ScmConnectionsPage />;
  const search: Record<string, string> = { category: "scm_ide", manage: "scm" };
  if (s.tab) search.scm_tab = s.tab;
  for (const k of ["connect", "oauth", "connection", "message"] as const) if (s[k]) search[k] = s[k]!;
  return <Navigate to="/connectors" search={search as never} replace />;
}

export function IntegrationsRoute() {
  const { flags, isPending } = useFeatureFlags();
  if (isPending) return <LoadingSkeleton rows={3} label="Loading integrations" />;
  if (flags.connectors !== true) return <IntegrationsPage />;
  return <Navigate to="/connectors" search={{ category: "monitoring", manage: "integrations" } as never} replace />;
}

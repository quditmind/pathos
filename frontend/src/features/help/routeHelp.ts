import type { HelpSection } from "./content";

/** The help article for a route: a document and, optionally, a heading anchor. */
export interface RouteArticle {
  section: HelpSection;
  slug: string;
  anchor?: string;
}

const g = (slug: string, anchor?: string): RouteArticle => ({ section: "user-guide", slug, anchor });

/**
 * Route pattern (TanStack fullPath, as declared in app/router.tsx) → help
 * article shown in the "Help for this page" drawer. A unit test fails when a
 * route has no entry or an entry points to a missing article or heading.
 */
export const routeHelp: Record<string, RouteArticle> = {
  "/login": g("sign-in-and-sso"),
  "/": g("dashboards", "security-posture-dashboard"),
  "/help": g("help-and-troubleshooting", "the-help-center"),
  "/help/troubleshooting": g("help-and-troubleshooting", "troubleshooting-centre"),
  "/help/$section/$slug": g("help-and-troubleshooting"),

  // Connect
  "/repositories/import": g("repository-import"),
  "/repositories/import/csv": g("repository-import"),
  "/repositories/import/$source": g("repository-import"),
  "/repositories/imports": g("import-history"),
  "/repositories/imports/$id": g("import-history"),
  "/admin/scm": g("provider-integrations"),
  "/admin/integrations": g("reporting-and-integrations"),

  // Inventory
  "/applications": g("applications"),
  "/applications/$id/versions": g("releases-and-vex"),
  "/repositories": g("repository-management"),
  "/scans/targets": g("scanning"),
  "/posture/unmanaged": g("posture", "unmanaged-assets"),
  "/posture/coverage": g("posture", "coverage"),
  "/admin/tags": g("repository-management"),

  // Discover
  "/posture/graph": g("posture", "context-graph"),
  "/runtime": g("runtime"),
  "/sbom": g("supply-chain"),
  "/portfolio": g("releases-and-vex"),

  // Threat model
  "/posture/attack-paths": g("posture", "attack-paths"),
  "/posture/blast-radius": g("posture", "blast-radius"),

  // Assess
  "/scans/overview": g("scanning"),
  "/scans": g("scanning"),
  "/scans/$id": g("scanning"),
  "/scans/schedules": g("scanning"),
  "/scans/compare": g("scanning"),
  "/scans/imports": g("scanning"),
  "/findings": g("findings"),
  "/vulnerabilities/$id": g("vulnerability-intelligence"),

  // Validate & intelligence
  "/ai/analyst": g("ai-analyst"),
  "/ai": g("ai-analyst"),
  "/ai/reports": g("ai-analyst"),
  "/human-review": g("human-review"),
  "/human-review/queue": g("human-review"),
  "/human-review/assessments": g("human-review"),
  "/human-review/assignments": g("human-review"),
  "/human-review/reports": g("human-review"),
  "/human-review/reviews/$id": g("human-review"),

  // Remediate & gate
  "/admin/policies": g("policies-and-compliance"),
  "/sbom/policies": g("releases-and-vex"),
  "/pull-requests": g("supply-chain", "pull-request-checks"),
  "/risk": g("findings"),
  "/suppression-rules": g("findings"),
  "/vex": g("releases-and-vex"),

  // Report & monitor
  "/executive": g("dashboards", "executive-overview"),
  "/reports": g("dashboards", "reports"),
  "/posture": g("posture", "application-posture"),
  "/posture/benchmark": g("posture", "benchmarking"),
  "/compliance": g("policies-and-compliance"),
  "/insights/developers": g("developer-insights"),

  // Configurations
  "/configurations/scan-profiles": g("security-scanning"),
  "/scans/profiles": g("security-scanning"),
  "/configurations/scanners": g("security-scanning"),
  "/admin/scanners": g("security-scanning"),
  "/configurations/scan-coverage": g("scan-coverage"),
  "/configurations/custom-rules": g("security-scanning"),
  "/admin/assets": g("asset-registration"),
  "/admin/risk-intelligence": g("vulnerability-intelligence"),
  "/admin/secret-validation": g("secret-validation"),
  "/human-review/configurations": g("human-review"),
  "/admin/ai": g("ai-analyst"),

  // Administration
  "/installation/organizations": g("administration", "organizations-multi-tenant-installations"),
  "/admin/users": g("administration", "users-and-roles"),
  "/admin/organization": g("administration", "organization-structure"),
  "/admin/developer-attribution": g("administration", "developer-attribution"),
  "/admin/notifications": g("administration", "notifications"),
  "/admin/ai-usage": g("ai-analyst"),
  "/admin/mcp": g("ai-analyst"),
  "/admin/audit": g("administration", "audit-log"),
  "/admin/feature-flags": g("navigation-and-shell", "feature-flags"),
  "/settings/security": g("sign-in-and-sso"),
  "/settings/tokens": g("reporting-and-integrations", "rest-api-tokens"),
};

/** The article for a route pattern; unknown routes fall back to the Help Center guide. */
export function articleForRoute(fullPath: string): RouteArticle {
  const p = fullPath.length > 1 ? fullPath.replace(/\/$/, "") : fullPath;
  return routeHelp[p] ?? g("help-and-troubleshooting");
}

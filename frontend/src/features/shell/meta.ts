import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { setBuildInfo } from "@/lib/buildStamp";

/** GET /api/v1/meta. Unauthenticated callers get product, vendor and version only. */
export interface Meta {
  product: string;
  vendor: string;
  version: string;
  commit?: string;
  build_date?: string;
  api_version?: string;
  feature_flags?: Record<string, boolean>;
  workers?: { name: string; family: string; version: string; online?: boolean; scanners?: Record<string, string> }[];
  scanner_packs?: { family: string; version: string }[];
}

/** Flag names reserved for future modules (server-side, per organization, default off). */
export type FeatureFlag =
  | "connectors"
  | "onboarding"
  | "codegraph"
  | "threat_models"
  | "reverse_engineering"
  | "remediation_workspace"
  | "continuous_monitoring"
  | "lifecycle_overview"
  | "scan_profile_tiers";

export const metaQueryKey = ["meta"] as const;

export function useMeta() {
  return useQuery({
    queryKey: metaQueryKey,
    queryFn: () =>
      api<Meta>("/api/v1/meta").then((m) => {
        // Client-side exports are stamped with the server's version and build.
        setBuildInfo(m);
        return m;
      }),
    staleTime: 5 * 60_000,
    retry: 1,
  });
}

/** All flags from /api/v1/meta; unknown or missing flags are off. */
export function useFeatureFlags(): { flags: Record<string, boolean>; isPending: boolean } {
  const meta = useMeta();
  return { flags: meta.data?.feature_flags ?? {}, isPending: meta.isPending };
}

/** True only when the server reports the flag as on for this organization. */
export function useFeatureFlag(name: FeatureFlag): boolean {
  return useFeatureFlags().flags[name] === true;
}

/** The frontend bundle version (Vite define from package.json). */
export const bundleVersion: string = typeof __PATHOS_BUNDLE_VERSION__ === "string" ? __PATHOS_BUNDLE_VERSION__ : "";

/** dev builds and semver pre-releases (2.0.0-rc.1) are pre-release. */
export function isPreRelease(version: string | undefined): boolean {
  if (!version) return false;
  const v = version.replace(/^v/, "");
  return v === "dev" || !/^\d+\.\d+\.\d+(\+[\w.-]+)?$/.test(v);
}

/**
 * True when the backend runs a different release than this bundle. Unknown
 * or dev versions are not compared (a dev backend always says "dev").
 */
export function versionMismatch(backend: string | undefined, bundle: string = bundleVersion): boolean {
  const norm = (v: string) => v.trim().replace(/^v/, "").split("+")[0]!;
  if (!backend || !bundle) return false;
  const b = norm(backend);
  const f = norm(bundle);
  if (b === "dev" || f === "dev" || b === "unknown") return false;
  return b !== f;
}

export function displayVersion(v: string | undefined): string {
  if (!v) return "";
  return v === "dev" || v.startsWith("v") ? v : `v${v}`;
}

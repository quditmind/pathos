import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { OAuthApp, OAuthAppRequest, OAuthStartRequest, Provider, ProviderInfo, ScmConnection } from "@/api/types";

export function useProviders() {
  return useQuery({
    queryKey: ["scm-providers"],
    queryFn: () => api<{ items: ProviderInfo[] }>("/api/v1/scm-providers").then((r) => r.items),
    staleTime: 300_000,
  });
}

/** Fallback labels while /scm-providers loads (or for unknown keys). */
export const providerLabels: Record<string, string> = {
  github: "GitHub",
  github_enterprise: "GitHub Enterprise Server",
  gitlab: "GitLab",
  bitbucket: "Bitbucket Cloud",
  azure_devops: "Azure DevOps Services",
  azure_devops_server: "Azure DevOps Server",
  upload: "Local upload",
};

export function providerLabel(key: string, providers?: ProviderInfo[]) {
  return providers?.find((p) => p.key === key)?.label ?? providerLabels[key] ?? key;
}

/** "git" or "devops" for a provider (from /scm-providers, falling back to the key). */
export function providerCategory(key: Provider | string, providers?: ProviderInfo[]): "git" | "devops" {
  return providers?.find((p) => p.key === key)?.category ?? (key.startsWith("azure_devops") ? "devops" : "git");
}

export const authTypeLabels: Record<string, string> = {
  pat: "Personal access token",
  github_app: "GitHub App",
  oauth: "OAuth",
  api_token: "API token",
  service_principal: "Service principal",
};

export function useOAuthApps(enabled = true) {
  return useQuery({
    queryKey: ["scm-oauth-apps"],
    queryFn: () => api<{ items: OAuthApp[] }>("/api/v1/scm-oauth-apps").then((r) => r.items),
    enabled,
  });
}

function useInvalidateScm() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: ["scm-oauth-apps"] });
    void qc.invalidateQueries({ queryKey: ["scm-connections"] });
  };
}

export function useSaveOAuthApp() {
  const invalidate = useInvalidateScm();
  return useMutation({
    mutationFn: ({ id, body }: { id?: string; body: OAuthAppRequest }) =>
      id ? api<OAuthApp>(`/api/v1/scm-oauth-apps/${id}`, { method: "PATCH", body }) : api<OAuthApp>("/api/v1/scm-oauth-apps", { method: "POST", body }),
    onSuccess: invalidate,
  });
}

export function useDeleteOAuthApp() {
  const invalidate = useInvalidateScm();
  return useMutation({ mutationFn: (id: string) => api<void>(`/api/v1/scm-oauth-apps/${id}`, { method: "DELETE" }), onSuccess: invalidate });
}

export function useCreateConnection() {
  const invalidate = useInvalidateScm();
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api<ScmConnection>("/api/v1/scm-connections", { method: "POST", body }),
    onSuccess: invalidate,
  });
}

export function useUpdateConnection() {
  const invalidate = useInvalidateScm();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      api<ScmConnection>(`/api/v1/scm-connections/${id}`, { method: "PATCH", body }),
    onSuccess: invalidate,
  });
}

/** Starts the provider's OAuth flow and leaves the page. */
export async function startOAuth(body: OAuthStartRequest) {
  const { authorize_url } = await api<{ authorize_url: string }>("/api/v1/scm-connections/oauth/start", { method: "POST", body });
  window.location.assign(authorize_url);
}

/** Default scopes and registration hints per provider (docs/REPOSITORY_ONBOARDING.md §7). */
export const oauthHints: Record<OAuthApp["provider"], { scopes: string; where: string; note?: string; baseUrl?: string; tenant?: boolean }> = {
  github: {
    scopes: "repo read:org",
    where: "GitHub → Settings → Developer settings → OAuth Apps → New OAuth App",
    note: "GitHub OAuth has no read-only private repository scope. Prefer a GitHub App connection for least privilege.",
  },
  github_enterprise: {
    scopes: "repo read:org",
    where: "GitHub Enterprise Server → Settings → Developer settings → OAuth Apps",
    baseUrl: "https://github.example.com",
  },
  gitlab: {
    scopes: "read_api read_repository",
    where: "GitLab → User or group settings → Applications (confidential application)",
    baseUrl: "Leave empty for gitlab.com, or e.g. https://gitlab.example.com",
  },
  bitbucket: {
    scopes: "repository account",
    where: "Bitbucket → Workspace settings → OAuth consumers → Add consumer (private, with callback URL)",
    note: "Add the webhook scope if PATHOS should create webhooks.",
  },
  azure_devops: {
    scopes: "499b84ac-1321-427f-aa17-267ca6975798/.default offline_access",
    where: "Microsoft Entra admin center → App registrations → New registration (Web platform); API permission Azure DevOps › user_impersonation",
    tenant: true,
  },
};

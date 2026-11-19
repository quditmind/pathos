import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

/** One organization the signed-in person belongs to. */
export interface Membership {
  organization_id: string;
  name: string;
  slug: string;
  status: "active" | "suspended";
  user_id: string;
  user_status: string;
}

export interface MyOrganizations {
  multi_tenant: boolean;
  installation_admin: boolean;
  active_organization_id: string;
  items: Membership[];
}

export function useMyOrganizations() {
  return useQuery({
    queryKey: ["me", "organizations"],
    queryFn: () => api<MyOrganizations>("/api/v1/me/organizations"),
    staleTime: 60_000,
  });
}

/**
 * Switches the session to another organization. The server issues a new
 * session (and CSRF token), so the app reloads from the start: no data of
 * the previous organization stays in the page or in query caches.
 */
export async function switchOrganization(organizationId: string) {
  await api("/api/v1/me/organization", { method: "POST", body: { organization_id: organizationId } });
  window.location.assign("/");
}

/** An organization as the installation API lists it. */
export interface InstallationOrganization {
  id: string;
  name: string;
  slug: string;
  status: "active" | "suspended";
  suspended_at: string | null;
  suspended_reason: string;
  created_at: string;
  users: number;
  repositories: number;
}

export interface InstallationAuditEntry {
  id: string;
  actor_email: string;
  action: string;
  organization_id: string | null;
  outcome: string;
  metadata: Record<string, unknown> | null;
  created_at: string;
}

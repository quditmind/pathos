import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type {
  BusinessUnit,
  CreateUserResponse,
  Organization,
  Page,
  Region,
  Role,
  RoleAssignment,
  ScopeType,
  User,
  UserStatus,
} from "@/api/types";

export function useUsers(q: string, status: UserStatus | "") {
  return useInfiniteQuery({
    queryKey: ["users", q, status],
    initialPageParam: "",
    queryFn: ({ pageParam, signal }) => {
      const p = new URLSearchParams({ limit: "50" });
      if (q) p.set("q", q);
      if (status) p.set("status", status);
      if (pageParam) p.set("cursor", pageParam);
      return api<Page<User>>(`/api/v1/users?${p}`, { signal });
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
}

export function useUser(id: string | null) {
  return useQuery({
    queryKey: ["user", id],
    queryFn: () => api<User>(`/api/v1/users/${id}`),
    enabled: !!id,
  });
}

export function useAssignments(userId: string | null) {
  return useQuery({
    queryKey: ["assignments", userId],
    queryFn: () => api<Page<RoleAssignment>>(`/api/v1/users/${userId}/role-assignments`).then((r) => r.items),
    enabled: !!userId,
  });
}

export function useRoles() {
  return useQuery({ queryKey: ["roles"], queryFn: () => api<Page<Role>>("/api/v1/roles").then((r) => r.items), staleTime: 300_000 });
}

export function useRegions() {
  return useQuery({ queryKey: ["regions"], queryFn: () => api<Page<Region>>("/api/v1/regions").then((r) => r.items), staleTime: 300_000 });
}

export function useBusinessUnits() {
  return useQuery({
    queryKey: ["business-units"],
    queryFn: () => api<Page<BusinessUnit>>("/api/v1/business-units").then((r) => r.items),
    staleTime: 60_000,
  });
}

export function useOrganization() {
  return useQuery({ queryKey: ["organization"], queryFn: () => api<Organization>("/api/v1/organization"), staleTime: 300_000 });
}

export interface RoleGrant {
  role_key: string;
  scope_type: ScopeType;
  scope_id?: string;
}

function useInvalidateUsers() {
  const qc = useQueryClient();
  return (userId?: string) => {
    void qc.invalidateQueries({ queryKey: ["users"] });
    if (userId) {
      void qc.invalidateQueries({ queryKey: ["user", userId] });
      void qc.invalidateQueries({ queryKey: ["assignments", userId] });
    }
  };
}

export function useInviteUser() {
  const invalidate = useInvalidateUsers();
  return useMutation({
    mutationFn: (body: { email: string; display_name: string; roles: RoleGrant[] }) =>
      api<CreateUserResponse>("/api/v1/users", { method: "POST", body }),
    onSuccess: () => invalidate(),
  });
}

export interface MFAStatus {
  configured: boolean;
  pending: boolean;
}

/** MFA state from Keycloak; errors (e.g. no Keycloak account yet) are shown inline. */
export function useUserMFA(userId: string | null) {
  return useQuery({
    queryKey: ["user-mfa", userId],
    queryFn: () => api<MFAStatus>(`/api/v1/users/${userId}/mfa`),
    enabled: !!userId,
    retry: false,
  });
}

export function useRequireMFA() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<{ changed: boolean; mfa: MFAStatus }>(`/api/v1/users/${id}/require-mfa`, { method: "POST" }),
    onSuccess: (_, id) => void qc.invalidateQueries({ queryKey: ["user-mfa", id] }),
  });
}

export function useSetUserStatus() {
  const invalidate = useInvalidateUsers();
  return useMutation({
    mutationFn: ({ id, action }: { id: string; action: "deactivate" | "reactivate" }) =>
      api<User>(`/api/v1/users/${id}/${action}`, { method: "POST" }),
    onSuccess: (_, v) => invalidate(v.id),
  });
}

export function useGrantRole(userId: string) {
  const invalidate = useInvalidateUsers();
  return useMutation({
    mutationFn: (body: RoleGrant) => api<RoleAssignment>(`/api/v1/users/${userId}/role-assignments`, { method: "POST", body }),
    onSuccess: () => invalidate(userId),
  });
}

export function useRevokeRole(userId: string) {
  const invalidate = useInvalidateUsers();
  return useMutation({
    mutationFn: (assignmentId: string) => api<void>(`/api/v1/role-assignments/${assignmentId}`, { method: "DELETE" }),
    onSuccess: () => invalidate(userId),
  });
}

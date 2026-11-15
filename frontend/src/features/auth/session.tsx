import { createContext, useContext, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, setCsrfToken } from "@/api/client";
import type { Me } from "@/api/types";

interface SessionValue {
  me: Me;
  can: (perm: string) => boolean;
  canOrgWide: (perm: string) => boolean;
  logout: () => Promise<void>;
}

const SessionContext = createContext<SessionValue | null>(null);

export function useMe() {
  return useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      const me = await api<Me>("/api/v1/me");
      setCsrfToken(me.csrf_token);
      return me;
    },
    retry: (count, err) => !(err instanceof ApiError && err.status === 401) && count < 2,
    staleTime: 60_000,
  });
}

export function SessionProvider({ me, children }: { me: Me; children: ReactNode }) {
  const qc = useQueryClient();
  const perms = new Set(me.permissions);
  const orgWide = new Set(me.org_wide_permissions ?? []);
  const value: SessionValue = {
    me,
    // UI visibility only. The API enforces every permission.
    can: (p) => perms.has(p),
    canOrgWide: (p) => orgWide.has(p),
    logout: async () => {
      const { logout_url } = await api<{ logout_url: string }>("/api/auth/logout", { method: "POST" });
      qc.clear();
      window.location.assign(logout_url);
    },
  };
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const v = useContext(SessionContext);
  if (!v) throw new Error("useSession outside SessionProvider");
  return v;
}

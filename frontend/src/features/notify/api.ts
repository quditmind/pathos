import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { Delivery, NotificationEvent, NotificationRule, NotificationTemplate, Page, SmtpSettings } from "@/api/types";

export const useEvents = () =>
  useQuery({
    queryKey: ["notify-events"],
    queryFn: () => api<{ items: NotificationEvent[]; dynamic: Record<string, string> }>("/api/v1/notifications/events"),
    staleTime: 600_000,
  });
export const useRules = () => useQuery({ queryKey: ["notify-rules"], queryFn: () => api<Page<NotificationRule>>("/api/v1/notifications/rules").then((r) => r.items) });
export const useSmtp = () => useQuery({ queryKey: ["notify-smtp"], queryFn: () => api<SmtpSettings>("/api/v1/notifications/smtp") });
export const useTemplates = () =>
  useQuery({ queryKey: ["notify-templates"], queryFn: () => api<Page<NotificationTemplate>>("/api/v1/notifications/templates").then((r) => r.items) });
export const useDeliveries = (f: { status?: string; channel?: string; event_key?: string; q?: string }, live: boolean) =>
  useQuery({
    queryKey: ["notify-deliveries", f],
    queryFn: () => {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(f)) if (v) p.set(k, v);
      return api<Page<Delivery> & { email_last_7_days: Record<string, number> }>(`/api/v1/notifications/deliveries?${p}`);
    },
    refetchInterval: live ? 5000 : 30_000,
  });
export const useDelivery = (id: string | null) =>
  useQuery({ queryKey: ["notify-delivery", id], queryFn: () => api<Delivery>(`/api/v1/notifications/deliveries/${id}`), enabled: !!id });

export function useNotifyMutation<T, V>(fn: (v: V) => Promise<T>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      for (const k of ["notify-rules", "notify-smtp", "notify-templates", "notify-deliveries"]) void qc.invalidateQueries({ queryKey: [k] });
    },
  });
}

// In-app inbox.
export const useInbox = () =>
  useQuery({
    queryKey: ["inbox"],
    queryFn: () => api<{ items: Delivery[]; unread: number }>("/api/v1/me/notifications"),
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  });
export function useMarkRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { ids?: string[]; all?: boolean }) => api("/api/v1/me/notifications/read", { method: "POST", body }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["inbox"] }),
  });
}

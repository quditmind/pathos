import * as P from "@radix-ui/react-popover";
import { useNavigate } from "@tanstack/react-router";
import { Bell, BellOff } from "lucide-react";
import { useInbox, useMarkRead } from "@/features/notify/api";
import type { Delivery } from "@/api/types";
import { cn, formatDateTime } from "@/lib/utils";

/** In-app notifications: the delivery history entries addressed to the caller. */
export function NotificationCentre() {
  const inbox = useInbox();
  const read = useMarkRead();
  const navigate = useNavigate();
  const unread = inbox.data?.unread ?? 0;
  const items = inbox.data?.items ?? [];
  const open = (n: Delivery) => {
    if (!n.read_at) read.mutate({ ids: [n.id] });
    if (n.link) {
      const url = new URL(n.link, window.location.origin);
      void navigate({ to: url.pathname as never, search: Object.fromEntries(url.searchParams) as never });
    }
  };
  return (
    <P.Root>
      <P.Trigger className="relative rounded-md p-2 text-muted-foreground hover:bg-surface-muted hover:text-foreground" aria-label={unread ? `Notifications (${unread} unread)` : "Notifications"}>
        <Bell className="size-4" />
        {unread > 0 && (
          <span className="tabular absolute right-0.5 top-0.5 min-w-4 rounded-full bg-danger px-1 text-center text-[10px] font-semibold leading-4 text-white">{unread > 99 ? "99+" : unread}</span>
        )}
      </P.Trigger>
      <P.Portal>
        <P.Content align="end" sideOffset={6} className="z-50 w-96 max-w-[calc(100vw-16px)] rounded-lg border border-border bg-surface shadow-lg">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <span className="text-[13px] font-semibold">Notifications</span>
            {unread > 0 && (
              <button className="text-[12px] text-primary hover:underline" onClick={() => read.mutate({ all: true })}>Mark all read</button>
            )}
          </div>
          {items.length === 0 ? (
            <div className="flex flex-col items-center px-6 py-8 text-center">
              <BellOff className="size-6 text-muted-foreground" />
              <p className="mt-2 text-[13px] font-medium">You&apos;re all caught up</p>
              <p className="mt-1 text-[12px] text-muted-foreground">New critical findings, SLA breaches, assignments, approvals and failed scans appear here.</p>
            </div>
          ) : (
            <ul className="max-h-[60vh] divide-y divide-border overflow-y-auto">
              {items.map((n) => (
                <li key={n.id}>
                  <P.Close asChild>
                    <button onClick={() => open(n)} className={cn("flex w-full gap-2.5 px-4 py-2.5 text-left hover:bg-surface-muted", !n.read_at && "bg-primary/5")}>
                      <span className={cn("mt-1.5 size-2 shrink-0 rounded-full", n.read_at ? "bg-transparent" : "bg-primary")} aria-hidden />
                      <span className="min-w-0">
                        <span className="line-clamp-2 text-[13px] font-medium">{n.subject.replace(/^\[PATHOS\]\s*/, "")}</span>
                        <span className="block text-[11.5px] text-muted-foreground">{formatDateTime(n.created_at)}</span>
                      </span>
                    </button>
                  </P.Close>
                </li>
              ))}
            </ul>
          )}
        </P.Content>
      </P.Portal>
    </P.Root>
  );
}

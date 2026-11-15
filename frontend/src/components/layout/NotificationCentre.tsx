import * as P from "@radix-ui/react-popover";
import { Bell, BellOff } from "lucide-react";

/**
 * Notification centre shell. Delivery (email and in-app) arrives with the
 * notification engine in phase 7; until then it shows an honest empty state.
 */
export function NotificationCentre() {
  return (
    <P.Root>
      <P.Trigger className="rounded-md p-2 text-muted-foreground hover:bg-surface-muted hover:text-foreground" aria-label="Notifications">
        <Bell className="size-4" />
      </P.Trigger>
      <P.Portal>
        <P.Content align="end" sideOffset={6} className="z-50 w-80 rounded-lg border border-border bg-surface shadow-lg">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <span className="text-[13px] font-semibold">Notifications</span>
          </div>
          <div className="flex flex-col items-center px-6 py-8 text-center">
            <BellOff className="size-6 text-muted-foreground" />
            <p className="mt-2 text-[13px] font-medium">You&apos;re all caught up</p>
            <p className="mt-1 text-[12px] text-muted-foreground">
              Alerts for new critical findings, SLA breaches and scan failures will appear here once notifications launch (phase 7).
            </p>
          </div>
        </P.Content>
      </P.Portal>
    </P.Root>
  );
}

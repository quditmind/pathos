import type { ReactNode } from "react";
import * as D from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  side = false,
  size = "md",
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  /** Render as a right-side drawer instead of a centered modal. */
  side?: boolean;
  /** Width: md (default), lg or xl. */
  size?: "md" | "lg" | "xl";
}) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-40 bg-black/30" />
        <D.Content
          className={cn(
            "fixed z-50 flex flex-col border border-border bg-surface shadow-xl focus:outline-none",
            side
              ? cn("inset-y-0 right-0 w-full", { md: "max-w-xl", lg: "max-w-2xl", xl: "max-w-3xl" }[size])
              : cn(
                  "left-1/2 top-1/2 max-h-[85vh] w-[calc(100vw-32px)] -translate-x-1/2 -translate-y-1/2 rounded-lg",
                  { md: "max-w-lg", lg: "max-w-2xl", xl: "max-w-4xl" }[size],
                ),
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div>
              <D.Title className="text-[15px] font-semibold">{title}</D.Title>
              {description ? (
                <D.Description className="mt-0.5 text-[13px] text-muted-foreground">{description}</D.Description>
              ) : (
                <D.Description className="sr-only">{title}</D.Description>
              )}
            </div>
            <D.Close className="rounded p-1 text-muted-foreground hover:bg-surface-muted" aria-label="Close">
              <X className="size-4" />
            </D.Close>
          </div>
          <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
          {footer && <div className="flex justify-end gap-2 border-t border-border px-5 py-3">{footer}</div>}
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}

import type { ReactNode } from "react";
import { CircleCheck, CircleDashed, CircleX, Clock, FilePen, Loader2, MinusCircle, TriangleAlert } from "lucide-react";
import type { ImportStatus } from "@/api/types";
import { cn } from "@/lib/utils";

const style: Record<ImportStatus, { label: string; cls: string; icon: ReactNode }> = {
  draft: { label: "Draft", cls: "bg-surface-muted text-muted-foreground", icon: <FilePen /> },
  pending: { label: "Pending", cls: "bg-surface-muted text-muted-foreground", icon: <Clock /> },
  queued: { label: "Queued", cls: "bg-surface-muted text-foreground", icon: <CircleDashed /> },
  validating: { label: "Validating", cls: "bg-primary/10 text-primary", icon: <Loader2 className="animate-spin" /> },
  importing: { label: "Importing", cls: "bg-primary/10 text-primary", icon: <Loader2 className="animate-spin" /> },
  registering: { label: "Registering", cls: "bg-primary/10 text-primary", icon: <Loader2 className="animate-spin" /> },
  completed: { label: "Completed", cls: "bg-success-soft text-success", icon: <CircleCheck /> },
  failed: { label: "Failed", cls: "bg-danger-soft text-danger", icon: <CircleX /> },
  cancelled: { label: "Cancelled", cls: "bg-surface-muted text-muted-foreground", icon: <MinusCircle /> },
  needs_attention: { label: "Needs attention", cls: "bg-warning-soft text-warning", icon: <TriangleAlert /> },
};

export const importStatusLabel = (s: ImportStatus) => style[s]?.label ?? s;

/** Status badge with icon and text (never colour alone). */
export function ImportStatusBadge({ status, className }: { status: ImportStatus; className?: string }) {
  const s = style[status] ?? style.pending;
  return (
    <span className={cn("inline-flex items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-medium [&_svg]:size-3.5", s.cls, className)} data-status={status}>
      {s.icon}
      {s.label}
    </span>
  );
}

import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert } from "@/components/ui/primitives";

/** Confirmation dialog for destructive or irreversible actions. */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  children,
  confirmLabel = "Confirm",
  destructive = true,
  pending,
  error,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: string;
  children: ReactNode;
  confirmLabel?: string;
  destructive?: boolean;
  pending?: boolean;
  error?: string | null;
  onConfirm: () => void;
}) {
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)} autoFocus>
            Cancel
          </Button>
          <Button variant={destructive ? "danger" : "primary"} disabled={pending} onClick={onConfirm}>
            {pending ? "Working…" : confirmLabel}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-[13px]">
        {error && <Alert>{error}</Alert>}
        {children}
      </div>
    </Dialog>
  );
}

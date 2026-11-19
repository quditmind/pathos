import { useEffect, useSyncExternalStore } from "react";
import { CheckCircle2, X } from "lucide-react";

/**
 * Success toasts: a short message that states what happened. Call
 * `toast.success("Scan profile saved")` anywhere; <Toaster /> (mounted once in
 * the app shell) shows it in a polite live region for five seconds.
 */
export interface ToastItem {
  id: number;
  message: string;
  tone: "success";
}

let items: ToastItem[] = [];
let nextId = 1;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

export const toast = {
  success(message: string): number {
    const id = nextId++;
    items = [...items, { id, message, tone: "success" as const }].slice(-4);
    emit();
    return id;
  },
  dismiss(id: number) {
    items = items.filter((t) => t.id !== id);
    emit();
  },
  /** Test helper. */
  clear() {
    items = [];
    emit();
  },
};

function subscribe(l: () => void) {
  listeners.add(l);
  return () => listeners.delete(l);
}

function ToastRow({ t, timeout }: { t: ToastItem; timeout: number }) {
  useEffect(() => {
    const h = setTimeout(() => toast.dismiss(t.id), timeout);
    return () => clearTimeout(h);
  }, [t.id, timeout]);
  return (
    <div
      className="pointer-events-auto flex w-80 items-start gap-2 rounded-md border border-border bg-surface px-3 py-2.5 text-[13px] shadow-lg"
    >
      <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" aria-hidden />
      <span className="flex-1">{t.message}</span>
      <button className="rounded p-0.5 text-muted-foreground hover:bg-surface-muted hover:text-foreground" aria-label="Dismiss notification" onClick={() => toast.dismiss(t.id)}>
        <X className="size-3.5" />
      </button>
    </div>
  );
}

export function Toaster({ timeout = 5000 }: { timeout?: number }) {
  const list = useSyncExternalStore(subscribe, () => items, () => items);
  return (
    <div role="status" aria-live="polite" className="pointer-events-none fixed right-4 bottom-4 z-[60] flex flex-col gap-2">
      {list.map((t) => (
        <ToastRow key={t.id} t={t} timeout={timeout} />
      ))}
    </div>
  );
}

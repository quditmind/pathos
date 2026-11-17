import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Save } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Alert, Card } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { reviewApi, useReviewMutation } from "../api";
import type { Assessment, ReviewDetail } from "../types";

type SectionKey = "answers" | "fields" | "reproduction" | "risk" | "remediation" | "dataflow_notes";

/**
 * Local draft of assessment sections with dirty tracking. Saving sends only
 * the changed keys; the API records each change in the history.
 */
export function useSections(d: ReviewDetail, keys: SectionKey[]) {
  const initial = useMemo(() => {
    const out = {} as Record<SectionKey, Record<string, string>>;
    for (const k of keys) out[k] = { ...(d.assessment[k as keyof Assessment] as Record<string, string>) };
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [d.assessment, ...keys]);
  const [draft, setDraft] = useState(initial);
  useEffect(() => setDraft(initial), [initial]);
  const [aiRef, setAiRef] = useState<string | undefined>();
  const changes = useMemo(() => {
    const out: Partial<Record<SectionKey, Record<string, string>>> = {};
    for (const k of keys) {
      const diff: Record<string, string> = {};
      const a = initial[k] ?? {};
      const b = draft[k] ?? {};
      for (const f of new Set([...Object.keys(a), ...Object.keys(b)])) if ((a[f] ?? "") !== (b[f] ?? "")) diff[f] = b[f] ?? "";
      if (Object.keys(diff).length) out[k] = diff;
    }
    return out;
  }, [draft, initial, keys]);
  const dirty = Object.keys(changes).length > 0;
  const m = useReviewMutation(() => reviewApi.assessment(d.id, { ...changes, ai_recommendation_id: aiRef }));
  const set = (section: SectionKey, key: string, value: string) => setDraft((x) => ({ ...x, [section]: { ...x[section], [key]: value } }));
  return {
    draft,
    set,
    dirty,
    save: () => m.mutate(undefined, { onSuccess: () => setAiRef(undefined) }),
    saving: m.isPending,
    error: m.error,
    saved: m.isSuccess && !dirty,
    markAI: setAiRef,
    reset: () => setDraft(initial),
  };
}

/** Sticky save bar for an editable section. */
export function SaveBar({ s, editable, d }: { s: ReturnType<typeof useSections>; editable: boolean; d: ReviewDetail }) {
  if (!editable) {
    return (
      <p className="text-[12px] text-muted-foreground">
        {d.status === "completed" ? "The review is completed: reopen it to change the assessment." : d.status === "awaiting_independent_review" ? "Locked while awaiting independent review." : "Read-only: assign the review to yourself to edit."}
      </p>
    );
  }
  return (
    <div className="sticky bottom-0 z-10 -mx-1 flex flex-wrap items-center gap-2 border-t border-border bg-background/95 px-1 py-2 backdrop-blur">
      <Button onClick={s.save} disabled={!s.dirty || s.saving}>
        <Save /> {s.saving ? "Saving…" : "Save assessment"}
      </Button>
      {s.dirty && (
        <Button variant="ghost" onClick={s.reset}>
          Discard changes
        </Button>
      )}
      <span className="text-[12px] text-muted-foreground" aria-live="polite">
        {s.dirty ? "Unsaved changes" : s.saved ? "Saved" : d.assessment.updated_by && d.assessment.updated_at ? `Last saved ${formatDateTime(d.assessment.updated_at)} by ${d.assessment.updated_by}` : ""}
      </span>
      {s.error && <div className="w-full"><Alert>{s.error.message}</Alert></div>}
    </div>
  );
}

export function Panel({ title, children, actions, className }: { title: string; children: ReactNode; actions?: ReactNode; className?: string }) {
  return (
    <Card className={className}>
      <div className="flex items-center justify-between gap-2 border-b border-border px-4 py-2.5">
        <h2 className="text-[13px] font-semibold">{title}</h2>
        {actions}
      </div>
      <div className="p-4">{children}</div>
    </Card>
  );
}

export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(120px,auto)_1fr] gap-x-4 gap-y-1.5 text-[12.5px]">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 break-words">{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

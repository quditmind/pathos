import { Link } from "@tanstack/react-router";
import { CircleCheck, Loader2, TriangleAlert } from "lucide-react";
import type { AssetSettings, ImportValidation } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert } from "@/components/ui/primitives";
import { formatBytes } from "@/lib/uploader";
import { MetadataSummary } from "../metadata/MetadataSummary";
import type { MetadataDraft, SectionKey } from "../metadata/model";

export interface ReviewItem {
  key: string;
  label: string;
  detail: string;
  size: number | null;
  display_name: string;
  asset_name: string;
}

export function ReviewStep({
  items,
  validation,
  validating,
  allowDup,
  setAllowDup,
  onRemove,
  draft,
  settings,
  showMetadata,
  onEditSection,
  startScan,
  setStartScan,
}: {
  items: ReviewItem[];
  validation: ImportValidation | null;
  validating: boolean;
  allowDup: Set<number>;
  setAllowDup: (s: Set<number>) => void;
  onRemove: (index: number) => void;
  draft: MetadataDraft;
  settings?: AssetSettings;
  showMetadata: boolean;
  onEditSection: (s: SectionKey) => void;
  startScan: boolean;
  setStartScan: (v: boolean) => void;
}) {
  const problems = new Map<number, NonNullable<ImportValidation["items"]>[number][]>();
  for (const p of validation?.items ?? []) problems.set(p.index, [...(problems.get(p.index) ?? []), p]);

  return (
    <div className="space-y-6">
      <section aria-label="Source items">
        <div className="mb-1.5 flex items-center gap-2">
          <h3 className="text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">Source ({items.length})</h3>
          {validating && (
            <span className="flex items-center gap-1 text-[12px] text-muted-foreground">
              <Loader2 className="size-3.5 animate-spin" /> Checking…
            </span>
          )}
          {!validating && validation && !validation.items.length && (
            <span className="flex items-center gap-1 text-[12px] text-success">
              <CircleCheck className="size-3.5" /> No problems found
            </span>
          )}
        </div>
        <ul className="divide-y divide-border rounded-md border border-border">
          {items.map((it, i) => {
            const ps = problems.get(i) ?? [];
            return (
              <li key={it.key} className="space-y-1.5 px-3 py-2 text-[13px]">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <div className="min-w-0">
                    <span className="font-medium">{it.display_name || it.label}</span>
                    {it.asset_name && <span className="ml-2 font-mono text-[12px] text-muted-foreground">{it.asset_name}</span>}
                    <div className="text-[12px] text-muted-foreground">
                      {it.label} · {it.detail}
                      {it.size ? ` · ${formatBytes(it.size)}` : ""}
                    </div>
                  </div>
                  {ps.length > 0 && (
                    <Button size="sm" variant="ghost" onClick={() => onRemove(i)}>
                      Remove
                    </Button>
                  )}
                </div>
                {ps.map((p) => (
                  <div key={p.code + p.message} className="flex flex-wrap items-center gap-2 rounded bg-warning-soft px-2 py-1 text-[12px] text-warning">
                    <TriangleAlert className="size-3.5" aria-hidden />
                    <span>{p.message}</span>
                    {p.repository_id && (
                      <Link to="/repositories" search={{ repo: p.repository_id } as never} className="underline">
                        View existing repository
                      </Link>
                    )}
                    {p.code === "duplicate" && (
                      <label className="ml-auto flex items-center gap-1.5 text-foreground">
                        <input
                          type="checkbox"
                          className="accent-[var(--primary)]"
                          checked={allowDup.has(i)}
                          onChange={(e) => {
                            const next = new Set(allowDup);
                            if (e.target.checked) next.add(i);
                            else next.delete(i);
                            setAllowDup(next);
                          }}
                        />
                        Import anyway
                      </label>
                    )}
                  </div>
                ))}
              </li>
            );
          })}
        </ul>
        {validation && validation.items.some((p) => p.code !== "duplicate") && (
          <div className="mt-2">
            <Alert tone="warning">Remove the repositories marked above (or change their names) before starting the import.</Alert>
          </div>
        )}
      </section>

      {showMetadata && (
        <section aria-label="Metadata">
          <h3 className="mb-2 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">Shared metadata</h3>
          <div className="rounded-md border border-border p-3">
            <MetadataSummary draft={draft} settings={settings} onEditSection={onEditSection} />
          </div>
        </section>
      )}

      {settings?.scan_on_import && (
        <label className="flex items-start gap-2 text-[13px]">
          <input type="checkbox" className="mt-0.5 accent-[var(--primary)]" checked={startScan} onChange={(e) => setStartScan(e.target.checked)} />
          <span>
            Start onboarding scan
            <span className="block text-[12px] text-muted-foreground">Queue a security scan for each repository as soon as it is registered.</span>
          </span>
        </label>
      )}
    </div>
  );
}

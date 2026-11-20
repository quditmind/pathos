import { GitCompareArrows } from "lucide-react";
import { Select } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";

/** A saved graph snapshot (one build of the graph at a commit). */
export interface SnapshotOption {
  id: string;
  created_at: string;
  commit_sha?: string;
  status?: string;
  label?: string;
  /** Applications with several repositories have one snapshot per repository. */
  repository_name?: string;
}

export function snapshotLabel(s: SnapshotOption): string {
  const commit = s.commit_sha ? s.commit_sha.slice(0, 7) : "no commit";
  return s.label ?? `${s.repository_name ? `${s.repository_name} · ` : ""}${commit} · ${formatDateTime(s.created_at)}${s.status && s.status !== "ready" ? ` (${s.status})` : ""}`;
}

/**
 * Saved snapshots and version compare: pick the snapshot to show and,
 * optionally, a base snapshot to compare it with (diff view).
 */
export function SnapshotPicker({
  snapshots,
  value,
  compareTo,
  onChange,
  onCompare,
}: {
  snapshots: SnapshotOption[];
  value?: string;
  compareTo?: string;
  onChange: (id: string) => void;
  onCompare: (id: string | undefined) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <Select aria-label="Snapshot" value={value ?? ""} onChange={(e) => onChange(e.target.value)} className="h-8 max-w-64">
        {snapshots.map((s) => (
          <option key={s.id} value={s.id}>
            {snapshotLabel(s)}
          </option>
        ))}
      </Select>
      <GitCompareArrows className="size-4 text-muted-foreground" aria-hidden />
      <Select
        aria-label="Compare with snapshot"
        value={compareTo ?? ""}
        onChange={(e) => onCompare(e.target.value || undefined)}
        className="h-8 max-w-64"
        disabled={snapshots.length < 2}
      >
        <option value="">{snapshots.length < 2 ? "Compare: needs two snapshots" : "Compare with…"}</option>
        {snapshots
          .filter((s) => s.id !== value)
          .map((s) => (
            <option key={s.id} value={s.id}>
              {snapshotLabel(s)}
            </option>
          ))}
      </Select>
    </div>
  );
}

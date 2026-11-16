import type { ReactNode } from "react";
import type { Repository } from "@/api/types";
import { Alert, Badge, Skeleton } from "@/components/ui/primitives";
import { formatBytes } from "@/lib/uploader";
import { formatDateTime } from "@/lib/utils";
import { useSnapshots, useSyncRepository, useSyncRuns } from "./api";
import { ProviderIcon, SyncStatusBadge } from "./badges";
import { SourceActions } from "./RepoActions";

function Item({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[12px] text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 break-words">{children || <span className="text-muted-foreground">—</span>}</dd>
    </div>
  );
}

export function Languages({ languages }: { languages: Record<string, number> }) {
  const entries = Object.entries(languages ?? {}).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((n, [, v]) => n + v, 0);
  if (!total) return <span className="text-muted-foreground">—</span>;
  return (
    <div className="space-y-1.5">
      <div className="flex h-2 overflow-hidden rounded-full bg-surface-muted" aria-hidden>
        {entries.slice(0, 8).map(([l, v], i) => (
          <span key={l} style={{ width: `${(100 * v) / total}%`, opacity: 1 - i * 0.1 }} className="h-full border-r-2 border-surface bg-primary last:border-r-0" />
        ))}
      </div>
      <ul className="flex flex-wrap gap-x-3 gap-y-0.5 text-[12px]">
        {entries.slice(0, 8).map(([l, v]) => (
          <li key={l}>
            {l} <span className="tabular text-muted-foreground">{((100 * v) / total).toFixed(1)}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function SourcePanel({ r }: { r: Repository }) {
  const isUpload = r.source_type === "upload";
  const sync = useSyncRepository(r.id);
  const runs = useSyncRuns(r.id);
  const snaps = useSnapshots(r.id, isUpload);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <SourceActions r={r} syncing={sync.isPending} onSync={() => sync.mutate()} />
        {sync.isSuccess && (
          <span className="text-[12px] text-success">
            Sync {sync.data.run.status === "ok" ? (sync.data.run.changed ? "found a new commit" : "complete, no changes") : `finished: ${sync.data.run.status}`}
          </span>
        )}
      </div>
      {sync.isError && <Alert>{sync.error.message}</Alert>}
      {r.sync_error && r.sync_status !== "ok" && <Alert tone="warning">Last sync: {r.sync_error}</Alert>}

      <dl className="grid gap-x-4 gap-y-2.5 sm:grid-cols-2">
        <Item label="Source">
          <ProviderIcon provider={r.provider} withLabel />
          {r.scm_connection_name && <span className="text-muted-foreground"> · {r.scm_connection_name}</span>}
        </Item>
        <Item label={isUpload ? "Archive" : "Organization / project"}>
          {isUpload ? r.current_snapshot?.archive_filename : [r.scm_organization, r.scm_project].filter(Boolean).join(" / ")}
        </Item>
        {!isUpload && <Item label="Branch">{r.scan_branch || r.default_branch}</Item>}
        <Item label={isUpload ? "Snapshot" : "Latest commit"}>
          {isUpload ? (
            r.current_snapshot && <code className="text-[12px]">{r.current_snapshot.snapshot_sha256.slice(0, 16)}</code>
          ) : r.latest_commit_sha ? (
            <span>
              <code className="text-[12px]">{r.latest_commit_sha.slice(0, 10)}</code>
              <span className="text-muted-foreground"> · {formatDateTime(r.latest_commit_at)}</span>
            </span>
          ) : null}
        </Item>
        <Item label="Size">{r.size_bytes != null ? formatBytes(r.size_bytes) : null}</Item>
        <Item label="Files">{r.file_count != null ? r.file_count.toLocaleString() : null}</Item>
        <Item label="Last sync">
          <span className="flex flex-wrap items-center gap-1.5">
            <SyncStatusBadge status={r.sync_status} />
            <span className="text-[12px] text-muted-foreground">{formatDateTime(r.last_sync_at)}</span>
          </span>
        </Item>
        <Item label="Last successful sync">{formatDateTime(r.last_sync_ok_at)}</Item>
        <div className="sm:col-span-2">
          <Item label="Languages">
            <Languages languages={r.languages} />
          </Item>
        </div>
      </dl>

      {isUpload && (
        <section aria-label="Snapshots">
          <h3 className="mb-1.5 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">Source snapshots</h3>
          {snaps.isPending ? (
            <Skeleton className="h-16" />
          ) : snaps.isError ? (
            <Alert>{snaps.error.message}</Alert>
          ) : !snaps.data.length ? (
            <p className="text-[12px] text-muted-foreground">No snapshots.</p>
          ) : (
            <ul className="divide-y divide-border rounded-md border border-border">
              {snaps.data.map((s) => (
                <li key={s.id} className="space-y-0.5 px-3 py-2 text-[12px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{s.archive_filename}</span>
                    {r.current_snapshot?.id === s.id && <Badge tone="primary">current</Badge>}
                    <Badge tone={s.malware_scan === "clean" ? "success" : "neutral"}>{s.malware_scan === "clean" ? `malware: clean${s.malware_engine ? ` (${s.malware_engine})` : ""}` : "malware scan not configured"}</Badge>
                    <span className="ml-auto tabular text-muted-foreground">{formatDateTime(s.created_at)}</span>
                  </div>
                  <div className="text-muted-foreground">
                    {s.file_count.toLocaleString()} files · {formatBytes(s.uncompressed_bytes)} uncompressed · archive {formatBytes(s.archive_size)}
                    {s.created_by && ` · by ${s.created_by.name}`}
                  </div>
                  <div className="font-mono text-[11px] text-muted-foreground" title="SHA-256 of the uploaded archive">
                    sha256 {s.archive_sha256}
                  </div>
                  {Object.keys(s.skipped ?? {}).length > 0 && (
                    <div className="text-warning">
                      Skipped: {Object.entries(s.skipped).map(([k, v]) => `${v} ${k}`).join(", ")}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <section aria-label="Sync history">
        <h3 className="mb-1.5 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">Sync history</h3>
        {runs.isPending ? (
          <Skeleton className="h-16" />
        ) : runs.isError ? (
          <Alert>{runs.error.message}</Alert>
        ) : !runs.data.length ? (
          <p className="text-[12px] text-muted-foreground">No sync runs yet.</p>
        ) : (
          <ul className="divide-y divide-border rounded-md border border-border">
            {runs.data.slice(0, 20).map((s) => (
              <li key={s.id} className="flex flex-wrap items-center gap-2 px-3 py-1.5 text-[12px]">
                <SyncStatusBadge status={s.status} />
                <span className="capitalize text-muted-foreground">{s.trigger}</span>
                {s.commit_sha && (
                  <code title={s.previous_commit_sha ? `from ${s.previous_commit_sha}` : undefined}>
                    {s.changed && s.previous_commit_sha ? `${s.previous_commit_sha.slice(0, 7)} → ` : ""}
                    {s.commit_sha.slice(0, 7)}
                  </code>
                )}
                {s.error && <span className="text-danger">{s.error}</span>}
                <span className="ml-auto tabular text-muted-foreground">{formatDateTime(s.finished_at || s.started_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

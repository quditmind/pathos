import { Link, useNavigate } from "@tanstack/react-router";
import { Radar, RefreshCw, Upload } from "lucide-react";
import { api } from "@/api/client";
import type { Repository } from "@/api/types";
import { Button } from "@/components/ui/button";
import { useSession } from "@/features/auth/session";
import { useRepoMutation } from "./api";

/** Sync / upload-new-version actions shared by the Source panel. */
export function SourceActions({ r, onSync, syncing }: { r: Repository; onSync: () => void; syncing: boolean }) {
  const navigate = useNavigate();
  if (r.archived_at || !r.can_edit) return null;
  return r.source_type === "upload" ? (
    <Button size="sm" variant="secondary" onClick={() => void navigate({ to: "/repositories/import/$source", params: { source: "local" }, search: { target: r.id } as never })}>
      <Upload /> Upload new version
    </Button>
  ) : (
    <Button size="sm" variant="secondary" disabled={syncing} onClick={onSync}>
      <RefreshCw className={syncing ? "animate-spin" : undefined} /> {syncing ? "Syncing…" : "Sync now"}
    </Button>
  );
}

export function ScanNow({ r }: { r: Repository }) {
  const { can } = useSession();
  const m = useRepoMutation(() => api<{ job_id: string; coalesced: boolean }>(`/api/v1/repositories/${r.id}/scan`, { method: "POST" }));
  if (!can("scans.run") || r.archived_at) return null;
  return (
    <>
      <Button size="sm" variant="secondary" disabled={m.isPending} onClick={() => m.mutate(undefined)}>
        <Radar /> {m.isSuccess ? (m.data.coalesced ? "Already queued" : "Scan queued") : "Scan now"}
      </Button>
      {m.isSuccess && (
        <Link to="/scans" search={{ job: m.data.job_id } as never} className="text-[12px] text-primary hover:underline">
          View scan
        </Link>
      )}
      {m.isError && <span className="text-[12px] text-danger">{m.error.message}</span>}
    </>
  );
}

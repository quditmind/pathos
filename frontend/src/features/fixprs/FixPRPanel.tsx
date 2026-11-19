import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, GitPullRequestArrow, RefreshCw } from "lucide-react";
import { api } from "@/api/client";
import type { Repository } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Badge, Input, Select, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { ErrorPanel } from "@/components/ui/error-panel";

export type FixPRStatus = "queued" | "running" | "creating" | "open" | "merged" | "closed" | "failed" | "not_supported";

export interface FixPR {
  id: string;
  repository_id: string;
  repository_name: string;
  ecosystem: string;
  package_name: string;
  current_version: string;
  target_version: string;
  grouping: "finding" | "package";
  status: FixPRStatus;
  error: string;
  base_branch: string;
  branch: string;
  changed_files: string[];
  pr_number: string;
  pr_url: string;
  finding_ids: string[];
  requested_by: string;
  created_at: string;
  updated_at: string;
  state_checked_at: string | null;
  /** dependency (manifest upgrade) or ai_code (verified AI fix). */
  kind?: "dependency" | "ai_code";
  ai_fix_id?: string | null;
}

export interface FixEligibility {
  eligible: boolean;
  reason?: string;
  ecosystem: string;
  package_name: string;
  target_version: string;
  support: { supported: boolean; reason?: string; edits?: string };
  enabled: boolean;
  grouping: "finding" | "package";
  can_request: boolean;
  requests: FixPR[];
}

const statusLabel: Record<FixPRStatus, string> = {
  queued: "Queued for a worker",
  running: "Editing the manifest",
  creating: "Opening the pull request",
  open: "Open",
  merged: "Merged",
  closed: "Closed without merging",
  failed: "Failed",
  not_supported: "Not supported",
};
const statusTone: Record<FixPRStatus, "neutral" | "success" | "warning" | "danger"> = {
  queued: "neutral", running: "neutral", creating: "neutral", open: "success", merged: "success", closed: "warning", failed: "danger", not_supported: "warning",
};
const active = (s: FixPRStatus) => s === "queued" || s === "running" || s === "creating";

/** "Open fix PR" on a dependency finding, and the fix pull requests that cover it. */
export function FindingFixPR({ findingId, category }: { findingId: string; category: string }) {
  const qc = useQueryClient();
  const key = ["finding-fix-pr", findingId];
  const q = useQuery({
    queryKey: key,
    queryFn: () => api<FixEligibility>(`/api/v1/findings/${findingId}/fix-pr`),
    enabled: category === "sca",
    retry: false,
    refetchInterval: (query) => (query.state.data?.requests.some((r) => active(r.status)) ? 3000 : false),
  });
  const [target, setTarget] = useState("");
  const [grouping, setGrouping] = useState<"" | "finding" | "package">("");
  const request = useMutation({
    mutationFn: () => api<FixPR>(`/api/v1/findings/${findingId}/fix-pr`, { method: "POST", body: { target_version: target.trim(), grouping } }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: key }),
  });
  const refresh = useMutation({
    mutationFn: (id: string) => api<FixPR>(`/api/v1/fix-prs/${id}/refresh`, { method: "POST" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: key }),
  });
  const { can } = useSession();
  if (category !== "sca") return null;
  if (q.isPending) return <Skeleton className="h-16" />;
  if (q.isError) return null;
  const d = q.data;
  const inFlight = d.requests.some((r) => active(r.status) || r.status === "open");
  return (
    <div className="rounded-md border border-border p-3 text-[12.5px]">
      <h3 className="mb-1 flex items-center gap-1.5 text-[12px] font-semibold"><GitPullRequestArrow className="size-3.5" /> Fix pull request</h3>
      {d.requests.length > 0 && (
        <ul className="mb-2 space-y-1.5">
          {d.requests.map((r) => (
            <li key={r.id} className="flex flex-wrap items-center gap-1.5">
              <Badge tone={statusTone[r.status]}>{statusLabel[r.status]}</Badge>
              {r.pr_url ? (
                <a href={r.pr_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-0.5 text-primary hover:underline">
                  #{r.pr_number} <ExternalLink className="size-3" />
                </a>
              ) : null}
              <span className="font-mono text-[11.5px]">{r.package_name} {r.current_version} → {r.target_version}</span>
              {r.finding_ids.length > 1 && <span className="text-muted-foreground">covers {r.finding_ids.length} findings</span>}
              <span className="text-[11px] text-muted-foreground">by {r.requested_by || "unknown"}, {formatDateTime(r.created_at)}</span>
              {r.status === "open" && can("findings.triage") && (
                <Button size="sm" variant="ghost" aria-label="Refresh pull request state" disabled={refresh.isPending} onClick={() => refresh.mutate(r.id)}>
                  <RefreshCw />
                </Button>
              )}
              {r.error && <div className="basis-full text-[11.5px] text-danger">{r.error}</div>}
              {r.status === "merged" && (
                <div className="basis-full text-[11.5px] text-muted-foreground">The finding is resolved when the next scan of {r.base_branch || "the branch"} no longer detects it.</div>
              )}
            </li>
          ))}
        </ul>
      )}
      {!d.eligible ? (
        <p className="text-muted-foreground">{d.reason}</p>
      ) : !d.can_request ? (
        <p className="text-muted-foreground">Upgrade to {d.target_version} is possible; opening a pull request needs the findings.triage and repos.manage permissions on this repository.</p>
      ) : inFlight ? (
        <p className="text-muted-foreground">A fix pull request for this finding is already in progress.</p>
      ) : (
        <div className="space-y-2">
          <p className="text-muted-foreground">
            PATHOS {d.support.edits ?? "edits the manifest"}. A worker edits the files as text — no package manager, build or repository code
            runs — and PATHOS opens a pull request from a new <span className="font-mono">pathos/fix/…</span> branch. It never pushes to the default branch.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Input aria-label="Target version" className="w-32 font-mono" placeholder={d.target_version} value={target} onChange={(e) => setTarget(e.target.value)} />
            <Select aria-label="Grouping" value={grouping} onChange={(e) => setGrouping(e.target.value as typeof grouping)}>
              <option value="">Repository default ({d.grouping === "package" ? "per package" : "per finding"})</option>
              <option value="package">One PR for every finding in this package version</option>
              <option value="finding">One PR for this finding only</option>
            </Select>
            <Button size="sm" variant="secondary" disabled={request.isPending} onClick={() => request.mutate()}>
              <GitPullRequestArrow /> {request.isPending ? "Requesting…" : "Open fix PR"}
            </Button>
          </div>
        </div>
      )}
      {request.error && <div className="mt-2"><ErrorPanel error={request.error} /></div>}
      {refresh.error && <div className="mt-2"><ErrorPanel error={refresh.error} /></div>}
    </div>
  );
}

interface FixSettings {
  enabled: boolean;
  grouping: "finding" | "package";
  source_type: string;
  provider: string;
}

/** Repository setting: allow fix pull requests (opt-in). */
export function FixPRSettingsPanel({ r }: { r: Repository }) {
  const qc = useQueryClient();
  const { can } = useSession();
  const key = ["fix-pr-settings", r.id];
  const q = useQuery({ queryKey: key, queryFn: () => api<FixSettings>(`/api/v1/repositories/${r.id}/fix-pr-settings`), enabled: can("scans.read"), retry: false });
  const [enabled, setEnabled] = useState(false);
  const [grouping, setGrouping] = useState<"finding" | "package">("package");
  useEffect(() => {
    if (q.data) {
      setEnabled(q.data.enabled);
      setGrouping(q.data.grouping);
    }
  }, [q.data]);
  const save = useMutation({
    mutationFn: () => api<FixSettings>(`/api/v1/repositories/${r.id}/fix-pr-settings`, { method: "PUT", body: { enabled, grouping } }),
    onSuccess: (data) => qc.setQueryData(key, data),
  });
  if (!can("scans.read")) return null;
  const manage = can("repos.manage");
  const upload = q.data?.source_type === "upload";
  const dirty = q.data && (q.data.enabled !== enabled || q.data.grouping !== grouping);
  return (
    <section className="mt-5 rounded-md border border-border p-3 text-[13px]" aria-labelledby={`fix-prs-${r.id}`}>
      <h3 id={`fix-prs-${r.id}`} className="mb-1 flex items-center gap-1.5 text-[13px] font-semibold">
        <GitPullRequestArrow className="size-4" /> Fix pull requests
      </h3>
      <p className="mb-2 text-[12px] text-muted-foreground">
        Lets people with triage and repository-management rights open a pull request that upgrades a vulnerable dependency to its fixed version.
        The connection's credential needs write access to contents and pull requests. Findings are resolved by the next scan, not by the merge.
      </p>
      {q.isPending ? (
        <Skeleton className="h-6 w-56" />
      ) : q.isError ? (
        <ErrorPanel error={q.error} />
      ) : upload ? (
        <p className="text-[12px] text-muted-foreground">Not available for uploaded repositories (no SCM connection).</p>
      ) : (
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-1.5">
            <input type="checkbox" checked={enabled} disabled={!manage} onChange={(e) => setEnabled(e.target.checked)} /> Allow fix pull requests
          </label>
          <Select aria-label="Fix PR grouping" value={grouping} disabled={!manage} onChange={(e) => setGrouping(e.target.value as "finding" | "package")}>
            <option value="package">One PR per package (all its findings)</option>
            <option value="finding">One PR per finding</option>
          </Select>
          {manage && (
            <Button size="sm" variant="secondary" disabled={!dirty || save.isPending} onClick={() => save.mutate()}>
              {save.isPending ? "Saving…" : "Save"}
            </Button>
          )}
        </div>
      )}
      {save.error && <div className="mt-2"><ErrorPanel error={save.error} /></div>}
    </section>
  );
}

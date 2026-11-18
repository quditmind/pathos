import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import { api } from "@/api/client";
import type { Repository } from "@/api/types";
import { Alert, Badge, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";

export interface PushProtectionSettings {
  enabled: boolean;
  supported: boolean;
  provider: string;
  source_type: string;
}

export interface PushedSecret {
  id: string;
  push_scan_id: string;
  ref: string;
  commit_sha: string;
  file_path: string;
  line: number | null;
  rule_id: string;
  description: string;
  created_at: string;
}

export interface PushScan {
  id: string;
  ref: string;
  before_sha: string;
  after_sha: string;
  status: "queued" | "running" | "done" | "failed" | "not_supported";
  error: string;
  files_scanned: number;
  alerts: number;
  created_at: string;
  finished_at: string | null;
}

const scanStatus: Record<PushScan["status"], string> = {
  queued: "Queued",
  running: "Scanning",
  done: "Scanned",
  failed: "Failed",
  not_supported: "Not supported",
};

/** Secret push protection: opt-in push-event scanning and its alerts. */
export function PushProtectionPanel({ r }: { r: Repository }) {
  const qc = useQueryClient();
  const { can } = useSession();
  const key = ["push-protection", r.id];
  const settings = useQuery({ queryKey: key, queryFn: () => api<PushProtectionSettings>(`/api/v1/repositories/${r.id}/push-protection`), enabled: can("scans.read") });
  const alerts = useQuery({
    queryKey: ["pushed-secrets", r.id],
    queryFn: () => api<{ items: PushedSecret[]; scans: PushScan[] }>(`/api/v1/repositories/${r.id}/pushed-secrets`),
    enabled: can("findings.read"),
  });
  const save = useMutation({
    mutationFn: (enabled: boolean) => api<PushProtectionSettings>(`/api/v1/repositories/${r.id}/push-protection`, { method: "PUT", body: { enabled } }),
    onSuccess: (data) => qc.setQueryData(key, data),
  });
  if (!can("scans.read") && !can("findings.read")) return null;
  const s = settings.data;
  const manage = can("repos.manage");

  return (
    <section className="mt-5 rounded-md border border-border p-3 text-[13px]" aria-labelledby={`push-protection-${r.id}`}>
      <h3 id={`push-protection-${r.id}`} className="mb-1 flex items-center gap-1.5 text-[13px] font-semibold">
        <KeyRound className="size-4" /> Secret push protection
      </h3>
      <p className="mb-2 text-[12px] text-muted-foreground">
        When enabled, every push received through the repository's webhook is checked for secrets in the lines its commits add, through the
        provider API. An alert names the commit, file and line; the secret value is never stored or shown. It alerts after the push; to block
        pushes, install the pre-commit or pre-receive hook (see Help: Secret push protection).
      </p>
      {settings.isPending && can("scans.read") ? (
        <Skeleton className="h-6 w-56" />
      ) : s ? (
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-1.5">
            <input
              type="checkbox"
              className="accent-[var(--primary)]"
              checked={s.enabled}
              disabled={!manage || save.isPending || (!s.supported && !s.enabled)}
              onChange={(e) => save.mutate(e.target.checked)}
            />
            Scan pushes for secrets
          </label>
          {!s.supported && (
            <span className="text-[12px] text-muted-foreground">
              {s.source_type === "upload" ? "Uploaded repositories receive no pushes." : "Available for GitHub, GitHub Enterprise Server and GitLab; use the pre-receive hook for other servers."}
            </span>
          )}
        </div>
      ) : null}
      {(settings.error || save.error) && <div className="mt-2"><Alert>{(save.error ?? settings.error)!.message}</Alert></div>}

      {alerts.data && (
        <div className="mt-3 space-y-3">
          {alerts.data.items.length > 0 ? (
            <div>
              <h4 className="mb-1 text-[12px] font-semibold">Pushed secrets ({alerts.data.items.length})</h4>
              <ul className="divide-y divide-border rounded-md border border-border">
                {alerts.data.items.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-[12px]">
                    <span>
                      <Badge tone="danger">{a.description}</Badge>{" "}
                      <span className="break-all font-mono">{a.file_path}{a.line ? `:${a.line}` : ""}</span>
                    </span>
                    <span className="text-muted-foreground">
                      {a.ref} @ <span className="font-mono">{a.commit_sha.slice(0, 12)}</span> · {formatDateTime(a.created_at)}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="mt-1 text-[12px] text-muted-foreground">Revoke and rotate each credential: removing it from the code does not remove it from the history or from clones.</p>
            </div>
          ) : (
            s?.enabled && <p className="text-[12px] text-muted-foreground">No secrets found in pushes.</p>
          )}
          {alerts.data.scans.length > 0 && (
            <div>
              <h4 className="mb-1 text-[12px] font-semibold">Recent pushes</h4>
              <ul className="space-y-1 text-[12px]">
                {alerts.data.scans.slice(0, 5).map((p) => (
                  <li key={p.id} className="flex flex-wrap items-center gap-2">
                    <Badge tone={p.status === "failed" ? "danger" : p.alerts > 0 ? "warning" : p.status === "done" ? "success" : "neutral"}>{scanStatus[p.status]}</Badge>
                    <span>{p.ref} @ <span className="font-mono">{p.after_sha.slice(0, 12)}</span></span>
                    <span className="text-muted-foreground">{p.files_scanned} files, {p.alerts} alerts · {formatDateTime(p.created_at)}</span>
                    {p.error && <span className="text-muted-foreground" title={p.error}>({p.error.length > 80 ? `${p.error.slice(0, 80)}…` : p.error})</span>}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

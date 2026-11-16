import { Cloud, GitBranch, GitFork, GitMerge, GitPullRequest, HardDriveUpload, Server } from "lucide-react";
import type { SyncStatus } from "@/api/types";
import { Badge } from "@/components/ui/primitives";
import { providerLabels } from "@/features/settings/scmApi";

const icons: Record<string, typeof GitBranch> = {
  github: GitPullRequest,
  github_enterprise: GitPullRequest,
  gitlab: GitMerge,
  bitbucket: GitFork,
  azure_devops: Cloud,
  azure_devops_server: Server,
  upload: HardDriveUpload,
};

/** Source/provider icon with an accessible name. */
export function ProviderIcon({ provider, withLabel, className }: { provider: string; withLabel?: boolean; className?: string }) {
  const Icon = icons[provider] ?? GitBranch;
  const label = providerLabels[provider] ?? provider;
  return (
    <span className={`inline-flex items-center gap-1.5 text-[12px] ${className ?? ""}`} title={label}>
      <Icon className="size-3.5 shrink-0 text-muted-foreground" aria-hidden={withLabel} aria-label={withLabel ? undefined : label} role={withLabel ? undefined : "img"} />
      {withLabel && <span>{label}</span>}
    </span>
  );
}

const sync: Record<SyncStatus, { label: string; tone: "neutral" | "success" | "warning" | "danger" }> = {
  never: { label: "Never synced", tone: "neutral" },
  ok: { label: "In sync", tone: "success" },
  failed: { label: "Sync failed", tone: "danger" },
  missing: { label: "Missing upstream", tone: "warning" },
  permission_denied: { label: "No access", tone: "danger" },
  archived_upstream: { label: "Archived upstream", tone: "warning" },
};

export const syncStatusOptions = (Object.keys(sync) as SyncStatus[]).map((k) => ({ value: k, label: sync[k].label }));

export function SyncStatusBadge({ status }: { status: SyncStatus }) {
  const s = sync[status] ?? sync.never;
  return <Badge tone={s.tone}>{s.label}</Badge>;
}

import { useEffect, useState } from "react";
import { Check, Cloud, Copy, ExternalLink, GitBranch, GitFork, GitMerge, GitPullRequest, HardDriveUpload, Server } from "lucide-react";
import type { PublicExposure, SyncStatus } from "@/api/types";
import { Badge } from "@/components/ui/primitives";
import { providerLabels } from "@/features/settings/scmApi";
import { cn } from "@/lib/utils";

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

const exposure: Record<PublicExposure, { label: string; tone: "neutral" | "success" | "danger" }> = {
  yes: { label: "Public", tone: "danger" },
  no: { label: "Not public", tone: "success" },
  unknown: { label: "Unknown", tone: "neutral" },
};

export const publicExposureOptions = [
  { value: "yes", label: "Publicly exposed" },
  { value: "no", label: "Not exposed" },
  { value: "unknown", label: "Unknown" },
];

/** Answer to "Is this application or asset publicly exposed to the internet?". */
export function PublicExposureBadge({ value }: { value: PublicExposure | "" | null | undefined }) {
  const e = exposure[value || "unknown"] ?? exposure.unknown;
  return (
    <Badge tone={e.tone}>
      <span className="sr-only">Public exposure: </span>
      {e.label}
    </Badge>
  );
}

/** External application URL: opens in a new tab without referrer or opener. */
export function ExternalUrl({ href, className }: { href: string; className?: string }) {
  if (!href) return null;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={href}
      onClick={(e) => e.stopPropagation()}
      className={cn("inline-flex min-w-0 max-w-full items-center gap-1 text-primary hover:underline", className)}
    >
      <span className="truncate">{href.replace(/^https?:\/\//i, "")}</span>
      <ExternalLink className="size-3 shrink-0" aria-hidden />
      <span className="sr-only"> (opens in a new tab)</span>
    </a>
  );
}

/** Permanent Repository ID in monospace, optionally with a copy button. Never editable. */
export function RepositoryKey({ value, copy, large, className }: { value: string; copy?: boolean; large?: boolean; className?: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(t);
  }, [copied]);
  if (!value) return null;
  return (
    <span className={cn("inline-flex items-center gap-1", className)}>
      <span className={cn("whitespace-nowrap font-mono", large ? "text-[14px] font-semibold" : "text-[12px]")}>{value}</span>
      {copy && (
        <button
          type="button"
          className="rounded p-0.5 text-muted-foreground hover:bg-surface-muted hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring"
          aria-label={`Copy Repository ID ${value}`}
          title={copied ? "Copied" : "Copy Repository ID"}
          onClick={(e) => {
            e.stopPropagation();
            void navigator.clipboard?.writeText(value).then(
              () => setCopied(true),
              () => undefined,
            );
          }}
        >
          {copied ? <Check className="size-3.5 text-success" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
        </button>
      )}
      {copy && (
        <span className="sr-only" role="status">
          {copied ? "Repository ID copied" : ""}
        </span>
      )}
    </span>
  );
}

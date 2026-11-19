import { useState } from "react";
import { ChevronDown, RefreshCw, X } from "lucide-react";
import { Wordmark, LogoMark } from "@/components/layout/Logo";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/primitives";
import { bundleVersion, displayVersion, isPreRelease, useMeta, versionMismatch } from "./meta";
import { useShell } from "./ShellProvider";

export function PreReleaseTag() {
  return (
    <Badge tone="warning" className="text-[10px]">
      Pre-release
    </Badge>
  );
}

/** "v2.2.0 ▾": the backend version; opens About PATHOS. */
export function VersionChip() {
  const meta = useMeta();
  const { open } = useShell();
  const v = meta.data?.version;
  return (
    <button
      type="button"
      onClick={() => open("about")}
      className="inline-flex h-6 items-center gap-0.5 rounded-full border border-border bg-surface-muted/60 px-2 text-[11px] font-medium text-muted-foreground hover:bg-surface-muted hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring"
      aria-label={v ? `PATHOS version ${displayVersion(v)}, about PATHOS` : "About PATHOS"}
      aria-haspopup="dialog"
      data-testid="version-chip"
    >
      {v ? displayVersion(v) : meta.isError ? "v?" : "…"}
      <ChevronDown className="size-3" aria-hidden />
    </button>
  );
}

/** Top-left brand block: [LogoMark] Quditmind | PATHOS [v… ▾]; logo only (version in the tooltip) when collapsed. */
export function BrandBlock({ collapsed = false }: { collapsed?: boolean }) {
  const meta = useMeta();
  const { open } = useShell();
  const v = meta.data?.version;
  if (collapsed) {
    return (
      <button
        type="button"
        onClick={() => open("about")}
        title={v ? `Quditmind PATHOS ${displayVersion(v)}` : "Quditmind PATHOS"}
        aria-label={v ? `Quditmind PATHOS ${displayVersion(v)}. About PATHOS` : "About PATHOS"}
        className="rounded-md focus-visible:outline-2 focus-visible:outline-ring"
      >
        <LogoMark />
      </button>
    );
  }
  return (
    <div className="flex min-w-0 items-center gap-2">
      <Wordmark />
      <VersionChip />
    </div>
  );
}

/** Non-blocking banner when this bundle is older or newer than the backend. */
export function VersionBanner() {
  const meta = useMeta();
  const [dismissed, setDismissed] = useState(false);
  const backend = meta.data?.version;
  if (dismissed || !versionMismatch(backend, bundleVersion)) return null;
  return (
    <div role="status" className="flex items-center gap-3 border-b border-border bg-primary/10 px-5 py-1.5 text-[13px] text-foreground">
      <span className="flex-1">
        A newer PATHOS version is available. Reload to update.{" "}
        <span className="text-muted-foreground">
          (This page: {displayVersion(bundleVersion)} · server: {displayVersion(backend)})
        </span>
      </span>
      <Button size="sm" onClick={() => window.location.reload()}>
        <RefreshCw /> Reload
      </Button>
      <button className="rounded p-1 text-muted-foreground hover:bg-surface-muted hover:text-foreground" aria-label="Dismiss version notice" onClick={() => setDismissed(true)}>
        <X className="size-4" />
      </button>
    </div>
  );
}

/** "Pre-release" tag in the top bar for dev and -rc builds. */
export function PreReleaseIndicator() {
  const meta = useMeta();
  return meta.data?.version && isPreRelease(meta.data.version) ? <PreReleaseTag /> : null;
}

import type { ReactNode } from "react";
import { Dialog } from "@/components/ui/dialog";
import { Badge, Skeleton } from "@/components/ui/primitives";
import { Wordmark } from "@/components/layout/Logo";
import { noticeText } from "./bundled";
import { bundleVersion, displayVersion, isPreRelease, useMeta } from "./meta";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-2 py-1.5">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

const na = <span className="text-muted-foreground">Not available</span>;

/**
 * About PATHOS: product, vendor, version, commit, build date, API version,
 * licence, third-party notices (NOTICE and docs/DEPENDENCIES.md, bundled),
 * worker and scanner pack versions. Tool names stay on the Scanners & workers
 * page; About shows packs (families) only.
 */
export function AboutDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const meta = useMeta();
  const m = meta.data;
  const packs = m?.scanner_packs ?? [];
  const workers = m?.workers ?? [];
  return (
    <Dialog open={open} onOpenChange={onOpenChange} size="lg" title="About PATHOS" description="Version, build and licence information.">
      <div className="space-y-5 text-[13px]">
        <div className="flex items-center gap-3">
          <Wordmark size="lg" />
          {m?.version && isPreRelease(m.version) && <Badge tone="warning">Pre-release</Badge>}
        </div>
        {meta.isPending ? (
          <Skeleton className="h-32" />
        ) : (
          <dl className="divide-y divide-border">
            <Row label="Product">{m?.product || "PATHOS"}</Row>
            <Row label="Vendor">{m?.vendor || "Quditmind"}</Row>
            <Row label="Version">{m?.version ? displayVersion(m.version) : meta.isError ? <span className="text-danger">Could not load: {meta.error.message}</span> : na}</Row>
            <Row label="Commit">{m?.commit ? <code className="font-mono text-[12px]">{m.commit}</code> : na}</Row>
            <Row label="Build date">{m?.build_date || na}</Row>
            <Row label="API version">{m?.api_version || na}</Row>
            <Row label="Web app bundle">{bundleVersion ? displayVersion(bundleVersion) : na}</Row>
            <Row label="Licence">
              Apache License 2.0 <span className="text-muted-foreground">(the LICENSE file ships with every distribution)</span>
            </Row>
          </dl>
        )}

        <section>
          <h3 className="mb-1.5 text-[13px] font-semibold">Scanner packs and workers</h3>
          {packs.length === 0 && workers.length === 0 ? (
            <p className="text-muted-foreground">No worker has registered yet, or your role cannot see them.</p>
          ) : (
            <table className="w-full text-[13px]">
              <thead>
                <tr className="text-left text-[11px] tracking-wide text-muted-foreground uppercase">
                  <th className="py-1 font-semibold">Pack</th>
                  <th className="py-1 font-semibold">Version</th>
                  <th className="py-1 font-semibold">Workers</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {[...new Set([...packs.map((p) => p.family), ...workers.map((w) => w.family)])].sort().map((family) => {
                  const pv = packs.find((p) => p.family === family)?.version;
                  const ws = workers.filter((w) => w.family === family);
                  return (
                    <tr key={family}>
                      <td className="py-1.5 font-medium">{family}</td>
                      <td className="py-1.5">{pv ? displayVersion(pv) : na}</td>
                      <td className="py-1.5 text-muted-foreground">
                        {ws.length ? ws.map((w) => `${w.name} ${displayVersion(w.version)}${w.online === false ? " (offline)" : ""}`).join(", ") : "None registered"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          <p className="mt-1 text-[12px] text-muted-foreground">Individual scanner versions are listed under Configurations › Scanners &amp; workers.</p>
        </section>

        <section>
          <h3 className="mb-1.5 text-[13px] font-semibold">Third-party notices</h3>
          {noticeText ? (
            <pre className="overflow-x-auto rounded-md border border-border bg-surface-muted p-3 font-mono text-[12px] whitespace-pre-wrap">{noticeText.trim()}</pre>
          ) : (
            <p className="text-muted-foreground">The NOTICE file is not bundled with this build.</p>
          )}
          <p className="mt-1 text-[12px] text-muted-foreground">
            Every bundled component, container image and scanner, with its pinned version and licence, is listed in docs/DEPENDENCIES.md and
            docs/SCANNER_CATALOG.md of the distribution.
          </p>
        </section>
      </div>
    </Dialog>
  );
}

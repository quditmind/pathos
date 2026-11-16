import { Link } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import { api } from "@/api/client";
import type { Repository, Severity } from "@/api/types";
import { Alert, Label, Select, Skeleton } from "@/components/ui/primitives";
import { JobStatusPill, SeverityBadge } from "@/components/data/Severity";
import { useSession } from "@/features/auth/session";
import { useProfiles, useScans } from "@/features/scans/api";
import { formatDateTime } from "@/lib/utils";
import { useRepoMutation, useRepositorySecurity } from "./api";
import { ScanNow } from "./RepoActions";

const severities: Severity[] = ["critical", "high", "medium", "low", "info"];

export function SecurityPanel({ r }: { r: Repository }) {
  const { can } = useSession();
  const sec = useRepositorySecurity(r.id);
  const scans = useScans({ repository_id: r.id }, true);
  const profiles = useProfiles();
  const setProfile = useRepoMutation((profile_id: string | null) => api(`/api/v1/repositories/${r.id}/scan-profile`, { method: "PUT", body: { profile_id } }));
  const recent = scans.data?.pages[0]?.items.slice(0, 5) ?? [];
  const s = sec.data;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <ScanNow r={r} />
        {can("findings.read") && (
          <Link to="/findings" search={{ repository_id: r.id } as never} className="text-[13px] text-primary hover:underline">
            All findings →
          </Link>
        )}
        {can("scans.read") && (
          <Link to="/scans" search={{ repository_id: r.id } as never} className="text-[13px] text-primary hover:underline">
            Scan history →
          </Link>
        )}
        {can("findings.read") && (
          <a href={`/api/v1/repositories/${r.id}/sbom`} className="text-[13px] text-primary hover:underline" download>
            SBOM (CycloneDX)
          </a>
        )}
      </div>

      {sec.isPending ? (
        <Skeleton className="h-32" />
      ) : sec.isError ? (
        <Alert>
          Could not load security status: {sec.error.message}{" "}
          <button className="underline" onClick={() => void sec.refetch()}>
            Try again
          </button>
        </Alert>
      ) : s ? (
        <>
          <section aria-label="Open findings">
            <h3 className="mb-1.5 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">Open findings</h3>
            <div className="grid grid-cols-5 gap-2">
              {severities.map((sev) => (
                <Link
                  key={sev}
                  to="/findings"
                  search={{ repository_id: r.id, severity: sev } as never}
                  className="rounded-md border border-border p-2 text-center hover:border-primary/40"
                  aria-label={`${s.open_findings[sev] ?? 0} open ${sev} findings`}
                >
                  <div className="tabular text-lg font-semibold">{s.open_findings[sev] ?? 0}</div>
                  <SeverityBadge value={sev} />
                </Link>
              ))}
            </div>
          </section>
          <section aria-label="Latest scan">
            <h3 className="mb-1.5 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">Latest scan</h3>
            {!s.latest_scan ? (
              <p className="flex items-center gap-2 text-[12px] text-muted-foreground">
                <ShieldAlert className="size-4" /> Not scanned yet.{s.scan_on_import ? " An onboarding scan is queued on import." : ""}
              </p>
            ) : (
              <div className="space-y-2 rounded-md border border-border p-3 text-[12px]">
                <div className="flex flex-wrap items-center gap-2">
                  <JobStatusPill status={s.latest_scan.status} />
                  <span className="text-muted-foreground">{s.latest_scan.trigger}</span>
                  <span className="text-muted-foreground">· profile {s.latest_scan.profile_name}</span>
                  <Link to="/scans" search={{ job: s.latest_scan.id } as never} className="ml-auto text-primary hover:underline">
                    {formatDateTime(s.latest_scan.finished_at ?? s.latest_scan.queued_at)}
                  </Link>
                </div>
                <div className="text-muted-foreground">
                  {s.latest_scan.commit_sha ? (
                    <>
                      Commit <code className="text-foreground">{s.latest_scan.commit_sha.slice(0, 12)}</code>
                    </>
                  ) : s.latest_scan.snapshot_id ? (
                    <>
                      Snapshot <code className="text-foreground">{s.latest_scan.snapshot_id.slice(0, 8)}</code>
                    </>
                  ) : (
                    "Source version not recorded"
                  )}
                </div>
                {s.latest_scan.scanners.length > 0 && (
                  <table className="w-full text-left">
                    <thead>
                      <tr className="text-muted-foreground">
                        <th className="py-1 font-medium">Scanner</th>
                        <th className="py-1 font-medium">Version</th>
                        <th className="py-1 font-medium">Status</th>
                        <th className="py-1 text-right font-medium">Findings</th>
                      </tr>
                    </thead>
                    <tbody>
                      {s.latest_scan.scanners.map((x) => (
                        <tr key={x.key} className="border-t border-border">
                          <td className="py-1">{x.key}</td>
                          <td className="py-1 font-mono">{x.version || "—"}</td>
                          <td className="py-1">{x.status}</td>
                          <td className="tabular py-1 text-right">{x.findings}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
          </section>
        </>
      ) : null}

      <div>
        <Label htmlFor="repo-profile">Scan profile</Label>
        <Select
          id="repo-profile"
          className="w-full"
          disabled={!r.can_manage || setProfile.isPending}
          value={r.scan_profile_id ?? ""}
          onChange={(e) => setProfile.mutate(e.target.value || null)}
        >
          <option value="">Organization default</option>
          {(profiles.data ?? [])
            .filter((p) => !p.is_default)
            .map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
        </Select>
        {setProfile.isError && <p className="mt-1 text-[12px] text-danger">{setProfile.error.message}</p>}
      </div>

      {recent.length > 0 && (
        <section aria-label="Recent scans">
          <h3 className="mb-1.5 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">Recent scans</h3>
          <ul className="divide-y divide-border rounded-md border border-border">
            {recent.map((j) => (
              <li key={j.id} className="flex items-center justify-between gap-2 px-3 py-1.5 text-[12px]">
                <JobStatusPill status={j.status} />
                <span className="tabular text-muted-foreground">
                  +{j.findings_new} / −{j.findings_fixed}
                </span>
                <Link to="/scans" search={{ job: j.id } as never} className="tabular text-primary hover:underline">
                  {formatDateTime(j.queued_at)}
                </Link>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

import { useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Binary, Play, ShieldAlert } from "lucide-react";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Alert, Card, Input, PageHeader, Table, Td, Th } from "@/components/ui/primitives";
import { EmptyStateCard, FeatureDisabled, LoadingSkeleton, PermissionDenied } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useSession } from "@/features/auth/session";
import { useFeatureFlags } from "@/features/shell/meta";
import { formatDateTime } from "@/lib/utils";
import { useArtifacts, useAuthorize, useReaSettings, useStartAnalysis, type Artifact } from "./api";
import { AnalysisStatusBadge, TrustBadge } from "./badges";
import type { ReaArtifactsSearch } from "./search";

export const MIN_REASON = 10;

/** Formats a byte count for people. */
export function bytes(n: number): string {
  if (!Number.isFinite(n)) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

/**
 * "Authorise untrusted artifact": an explicit, audited, per-artifact decision
 * with a reason. Only for artifacts PATHOS cannot tie to its own builds.
 */
export function AuthorizeDialog({ artifact, open, onOpenChange }: { artifact: Artifact; open: boolean; onOpenChange: (o: boolean) => void }) {
  const [reason, setReason] = useState("");
  const auth = useAuthorize(artifact.target_id);
  const short = reason.trim().length < MIN_REASON;
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) setReason("");
        onOpenChange(o);
      }}
      title="Authorise untrusted artifact"
      description={`${artifact.name} (${artifact.sha256.slice(0, 12)})`}
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="danger"
            disabled={short || auth.isPending}
            onClick={() =>
              auth.mutate(reason.trim(), {
                onSuccess: () => {
                  toast.success(`Authorised ${artifact.name} for analysis. The decision and its reason are in the audit log.`);
                  setReason("");
                  onOpenChange(false);
                },
              })
            }
          >
            {auth.isPending ? "Authorising…" : "Authorise this artifact"}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-[13px]">
        <Alert tone="warning">
          PATHOS cannot tie this artifact to your own builds: it has no verified signature or provenance. Analysing it parses untrusted input. The
          analysis still never runs the artifact and runs isolated (no network, read-only, no privileges), but authorise it only when you know where
          it comes from. The authorisation applies to this exact file (SHA-256) only and is recorded in the audit log with your reason.
        </Alert>
        {auth.isError && <ErrorPanel error={auth.error} title="Could not authorise the artifact" />}
        <label className="block space-y-1">
          <span className="font-medium">Reason (required)</span>
          <textarea
            aria-label="Reason"
            className="min-h-20 w-full rounded-md border border-border bg-surface px-2 py-1.5 text-[13px]"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={1000}
            placeholder="Why this artifact may be analysed, and where it comes from"
          />
          {short && <span className="text-[12px] text-muted-foreground">At least {MIN_REASON} characters.</span>}
        </label>
      </div>
    </Dialog>
  );
}

function ArtifactRow({ a, canRun, canAuthorize, ownBuildsOnly }: { a: Artifact; canRun: boolean; canAuthorize: boolean; ownBuildsOnly: boolean }) {
  const navigate = useNavigate();
  const start = useStartAnalysis();
  const [authorizing, setAuthorizing] = useState(false);
  const allowed = a.trust.status !== "untrusted";
  const last = a.last_analysis;
  const busy = last && (last.status === "queued" || last.status === "running");
  return (
    <tr data-testid="artifact-row" className="border-t border-border">
      <Td>
        <div className="font-medium">{a.name}</div>
        <div className="text-[12px] text-muted-foreground">
          {a.file_name} · {bytes(a.size)} · <code title={a.sha256}>{a.sha256.slice(0, 12)}</code>
        </div>
      </Td>
      <Td>{a.repository_name ?? "—"}</Td>
      <Td>
        <TrustBadge trust={a.trust} />
        {a.trust.status === "authorized" && a.trust.authorization && (
          <div className="mt-1 max-w-64 text-[12px] text-muted-foreground">
            “{a.trust.authorization.reason}” — {a.trust.authorization.authorized_by_email ?? a.trust.authorization.authorized_by ?? "unknown"},{" "}
            {formatDateTime(a.trust.authorization.created_at)}
          </div>
        )}
        {a.trust.provenance?.commit && <div className="mt-1 text-[12px] text-muted-foreground">Commit {a.trust.provenance.commit.slice(0, 12)}</div>}
      </Td>
      <Td>
        {last ? (
          <span className="flex flex-col gap-1">
            <AnalysisStatusBadge status={last.status} />
            <Link to="/reverse-engineering/analyses/$analysisId" params={{ analysisId: last.id }} className="text-[12px] text-primary underline">
              Open analysis
            </Link>
          </span>
        ) : (
          <span className="text-muted-foreground">Never analysed</span>
        )}
      </Td>
      <Td>
        <div className="flex flex-wrap justify-end gap-2">
          {canRun && (
            <Button
              size="sm"
              disabled={!allowed || start.isPending || !!busy}
              title={allowed ? undefined : "Untrusted artifacts are refused by default"}
              onClick={() =>
                start.mutate(
                  { target_id: a.target_id },
                  {
                    onSuccess: (an) => {
                      toast.success(`Analysis of ${a.name} queued. It runs in the isolated reverse-engineering worker.`);
                      if (an?.id) void navigate({ to: "/reverse-engineering/analyses/$analysisId", params: { analysisId: an.id } });
                    },
                  },
                )
              }
            >
              <Play /> Analyse
            </Button>
          )}
          {a.trust.status === "untrusted" && canAuthorize && (
            <Button
              size="sm"
              variant="danger-outline"
              disabled={ownBuildsOnly}
              title={ownBuildsOnly ? "The input policy allows only artifacts from your own builds" : undefined}
              onClick={() => setAuthorizing(true)}
            >
              <ShieldAlert /> Authorise untrusted artifact
            </Button>
          )}
        </div>
        {start.isError && (
          <div className="mt-2 text-left">
            <ErrorPanel error={start.error} title="Could not start the analysis" />
          </div>
        )}
        {authorizing && <AuthorizeDialog artifact={a} open={authorizing} onOpenChange={setAuthorizing} />}
      </Td>
    </tr>
  );
}

/** /reverse-engineering: build artifacts with their trust, and where to start an analysis. */
export function ArtifactsPage() {
  const search = useSearch({ strict: false }) as ReaArtifactsSearch;
  const navigate = useNavigate();
  const { flags, isPending } = useFeatureFlags();
  const { can } = useSession();
  const enabled = flags.reverse_engineering === true;
  const list = useArtifacts({ repository_id: search.repository, q: search.q }, enabled);
  const settings = useReaSettings(enabled);
  const header = (
    <PageHeader
      title="Binary analysis"
      description="Check that what you build and ship matches your source code. PATHOS analyses build artifacts statically, isolated and without running them; by default only artifacts from your own builds."
    />
  );
  if (isPending) return <>{header}<LoadingSkeleton rows={4} /></>;
  if (!enabled) return <>{header}<FeatureDisabled flag="reverse_engineering" feature="Reverse engineering" /></>;
  const ownBuildsOnly = settings.data?.input_policy === "own_builds_only";
  return (
    <>
      {header}
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-1.5 text-[13px]">
          Search
          <Input
            aria-label="Search artifacts"
            className="h-8 w-64"
            defaultValue={search.q ?? ""}
            onKeyDown={(e) => {
              if (e.key === "Enter") void navigate({ to: "/reverse-engineering", search: { ...search, q: (e.target as HTMLInputElement).value || undefined } as never });
            }}
          />
        </label>
        <span className="text-[12px] text-muted-foreground">
          Input policy:{" "}
          {ownBuildsOnly ? "only artifacts from your own builds" : "artifacts from your own builds; others only with an audited authorisation"}.{" "}
          {can("scanners.read") && (
            <Link to="/configurations/reverse-engineering" className="text-primary underline">
              Change
            </Link>
          )}
        </span>
      </div>
      {list.isError ? (
        list.error instanceof ApiError && list.error.status === 403 ? (
          <PermissionDenied permission="findings.read" what="Viewing binary analyses" />
        ) : (
          <ErrorPanel error={list.error} title="Could not load the build artifacts" onVerify={() => list.refetch()} />
        )
      ) : list.isPending ? (
        <LoadingSkeleton rows={5} label="Loading build artifacts" />
      ) : !list.data.length ? (
        <EmptyStateCard icon={<Binary />} title="No build artifacts yet" action={<Link to="/scans/targets" className="text-[13px] text-primary underline">Upload a build artifact</Link>}>
          Upload a build artifact as a scan target, with its signature or provenance so PATHOS can tie it to your own builds. It then appears here
          for analysis.
        </EmptyStateCard>
      ) : (
        <Card className="overflow-x-auto">
          <Table>
            <thead>
              <tr>
                <Th>Artifact</Th>
                <Th>Repository</Th>
                <Th>Trust</Th>
                <Th>Last analysis</Th>
                <Th className="text-right">Actions</Th>
              </tr>
            </thead>
            <tbody>
              {list.data.map((a) => (
                <ArtifactRow
                  key={a.target_id}
                  a={a}
                  canRun={can("scans.run") && can("rea.run")}
                  canAuthorize={can("rea.authorize")}
                  ownBuildsOnly={ownBuildsOnly}
                />
              ))}
            </tbody>
          </Table>
        </Card>
      )}
    </>
  );
}

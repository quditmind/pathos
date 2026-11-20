import { lazy, Suspense } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { ArrowLeft, Boxes, ExternalLink, GitBranch, Package, ShieldAlert, Sparkles } from "lucide-react";
import { api } from "@/api/client";
import type { ClassificationKind, ComponentGroup, Finding, Page, Repository } from "@/api/types";
import { catalogLabel, useAssetSettings } from "@/features/assets/api";
import { CriticalityBadge, TagChip } from "@/components/data/TagChip";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Badge, Card, EmptyState, PageHeader, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { FeatureDisabled, LoadingSkeleton } from "@/components/ui/states";
import { useSession } from "@/features/auth/session";
import { useAppPosture } from "@/features/posture/api";
import { ApplicationVersionsPage } from "@/features/releases/ApplicationVersionsPage";
import { useFeatureFlag, useFeatureFlags } from "@/features/shell/meta";
import { findingCheckLabel, redactToolNames } from "@/lib/checkKinds";
import { cn, formatDateTime } from "@/lib/utils";
import {
  fieldLabels,
  useApplicationActivity,
  useApplicationLifecycle,
  useApplicationProfile,
  useApplicationSettings,
  useInventoryMutation,
  useOnboarding,
  type ApplicationProfile,
} from "./api";
import { ClassificationForm } from "./ClassificationForm";
import { LifecycleStrip } from "./LifecycleStrip";

export const profileTabs = [
  { key: "overview", label: "Overview" },
  { key: "repositories", label: "Repositories" },
  { key: "classification", label: "Classification & tags" },
  { key: "versions", label: "Versions" },
  { key: "codegraph", label: "CodeGraph" },
  { key: "threat-model", label: "Threat model", arrives: "M5" },
  { key: "findings", label: "Findings" },
  { key: "sbom", label: "SBOM & components" },
  { key: "remediation", label: "Remediation", arrives: "M8" },
  { key: "activity", label: "Activity & audit" },
] as const;
export type ProfileTab = (typeof profileTabs)[number]["key"];

// The CodeGraph tab (M4) loads React Flow lazily, like the /codegraph route; the panel checks the codegraph flag.
const CodeGraphPanel = lazy(() => import("@/features/codegraph/CodeGraphPanel").then((m) => ({ default: m.CodeGraphPanel })));

export function validateProfileSearch(s: Record<string, unknown>): { tab?: ProfileTab } {
  const t = profileTabs.find((x) => x.key === s.tab && !("arrives" in x));
  return { tab: t?.key };
}

/** /applications/$id: the application profile hub (flag "onboarding"). */
export function ApplicationProfilePage() {
  const { id } = useParams({ strict: false }) as { id: string };
  return <ApplicationProfile id={id} />;
}

export function ApplicationProfile({ id }: { id: string }) {
  const search = useSearch({ strict: false }) as { tab?: ProfileTab };
  const navigate = useNavigate();
  const { isPending: flagsPending } = useFeatureFlags();
  const enabled = useFeatureFlag("onboarding");
  const app = useApplicationProfile(enabled ? id : undefined);
  const tab: ProfileTab = search.tab ?? "overview";

  if (flagsPending) return <LoadingSkeleton rows={4} />;
  if (!enabled) {
    return (
      <>
        <PageHeader title="Application profile" />
        <FeatureDisabled flag="onboarding" feature="The application profile" />
        <p className="mt-3 text-[13px]">
          <Link to="/applications" search={{ app: id } as never} className="text-primary hover:underline">
            Edit the application on the Applications page
          </Link>
        </p>
      </>
    );
  }
  if (app.isPending) return <LoadingSkeleton rows={6} label="Loading the application" />;
  if (app.isError) return <ErrorPanel error={app.error} title="Could not load the application" onVerify={() => app.refetch()} />;
  const a = app.data;

  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 text-[12px] text-muted-foreground">
        <Link to="/applications" className="hover:text-foreground hover:underline">
          Applications
        </Link>{" "}
        / <span className="text-foreground">{a.name}</span>
      </nav>
      <PageHeader
        title={a.name}
        description={a.description || "Application profile: everything PATHOS knows about this application across the lifecycle."}
        actions={
          <>
            <Button variant="ghost" asChild>
              <Link to="/applications">
                <ArrowLeft /> All applications
              </Link>
            </Button>
            {a.onboarding_status === "draft" && a.can_manage && (
              <Button asChild>
                <Link to="/onboarding" search={{ app: a.id } as never}>
                  Continue onboarding
                </Link>
              </Button>
            )}
          </>
        }
      />
      <div className="mb-4 flex flex-wrap items-center gap-2 text-[12.5px]">
        <span className="font-mono text-muted-foreground">{a.application_key}</span>
        <CriticalityBadge value={a.criticality} />
        <Badge tone={a.onboarding_status === "draft" ? "warning" : "success"}>{a.progress.label}</Badge>
        {a.business_unit && <Badge>{a.business_unit.name}</Badge>}
        {a.owner && <span className="text-muted-foreground">Owner: {a.owner.name}</span>}
        {a.archived_at && <Badge tone="danger">Archived</Badge>}
      </div>
      <div role="tablist" aria-label="Application profile" className="mb-4 flex gap-0.5 overflow-x-auto border-b border-border">
        {profileTabs.map((t) => {
          const disabled = "arrives" in t;
          const active = t.key === tab;
          return (
            <button
              key={t.key}
              role="tab"
              type="button"
              aria-selected={active}
              aria-disabled={disabled || undefined}
              title={disabled ? `${t.label}: arrives in ${t.arrives}` : undefined}
              onClick={() => !disabled && void navigate({ to: "/applications/$id", params: { id }, search: { tab: t.key === "overview" ? undefined : t.key } as never, replace: true })}
              className={cn(
                "whitespace-nowrap border-b-2 px-3 py-2 text-[13px]",
                active ? "border-primary font-medium text-primary" : "border-transparent text-muted-foreground",
                disabled ? "cursor-default opacity-50" : "hover:text-foreground",
              )}
            >
              {t.label}
              {disabled && <span className="ml-1 rounded bg-surface-muted px-1 text-[10px]">{t.arrives}</span>}
              {disabled && <span className="sr-only">{`, arrives in ${t.arrives}`}</span>}
            </button>
          );
        })}
      </div>
      <div role="tabpanel" aria-label={profileTabs.find((t) => t.key === tab)?.label}>
        {tab === "overview" && <OverviewTab a={a} />}
        {tab === "repositories" && <RepositoriesTab a={a} />}
        {tab === "classification" && <ClassificationTab a={a} />}
        {tab === "versions" && <ApplicationVersionsPage appId={a.id} embedded />}
        {tab === "codegraph" && (
          <Suspense fallback={<LoadingSkeleton rows={6} label="Loading CodeGraph" />}>
            <CodeGraphPanel applicationId={id} applicationName={a.name} />
          </Suspense>
        )}
        {tab === "findings" && <FindingsTab a={a} />}
        {tab === "sbom" && <SbomTab a={a} />}
        {tab === "activity" && <ActivityTab a={a} />}
      </div>
    </>
  );
}

function Stat({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <div className="rounded-md border border-border p-3">
      <div className="text-[11.5px] text-muted-foreground">{label}</div>
      <div className="mt-0.5 text-lg font-semibold tabular-nums">{value}</div>
      {hint && <div className="text-[11px] text-muted-foreground">{hint}</div>}
    </div>
  );
}

/** Catalogue kinds of the classification fields shown with labels. */
const overviewKinds: Partial<Record<string, ClassificationKind>> = {
  application_type: "application_type", data_classification: "data_classification", internet_exposure: "internet_exposure",
  authentication_model: "authentication_model", hosting_region: "hosting_region",
};

function OverviewTab({ a }: { a: ApplicationProfile }) {
  const { can } = useSession();
  const settings = useAssetSettings();
  const life = useApplicationLifecycle(a.id);
  const posture = useAppPosture(90);
  const p = posture.data?.find((x) => x.id === a.id);
  return (
    <div className="space-y-4">
      <Card className="p-4">
        <h2 className="mb-2 text-[14px] font-semibold">Lifecycle progress</h2>
        <p className="mb-3 text-[12px] text-muted-foreground">Which of the nine phases hold real data for this application. Phases without data say so.</p>
        {life.isPending ? <Skeleton className="h-16" /> : life.isError ? <ErrorPanel error={life.error} /> : <LifecycleStrip phases={life.data.phases} />}
      </Card>
      <Card className="p-4">
        <h2 className="mb-3 text-[14px] font-semibold">Security posture (last 90 days)</h2>
        {!can("findings.read") ? (
          <p className="text-[13px] text-muted-foreground">Viewing posture requires the findings permission.</p>
        ) : posture.isPending ? (
          <Skeleton className="h-20" />
        ) : posture.isError ? (
          <ErrorPanel error={posture.error} />
        ) : !p ? (
          <p className="text-[13px] text-muted-foreground">No posture data yet: the application has no scanned repositories.</p>
        ) : (
          <div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-6">
            <Stat label="Risk" value={p.risk_score} hint={p.risk_band} />
            <Stat label="Open findings" value={p.open_total} hint={`${p.open.critical} critical · ${p.open.high} high`} />
            <Stat label="Exploited (KEV) open" value={p.kev_open} />
            <Stat label="SLA breached" value={p.sla_breached} />
            <Stat label="Scan coverage" value={p.coverage == null ? "—" : `${Math.round(p.coverage)}%`} />
            <Stat label="Last scan" value={<span className="text-[13px]">{p.last_scan_at ? formatDateTime(p.last_scan_at) : "Never"}</span>} />
          </div>
        )}
        <p className="mt-2 text-[12px]">
          <Link to="/posture" className="text-primary hover:underline">
            Compare with other applications
          </Link>
        </p>
      </Card>
      <Card className="p-4">
        <h2 className="mb-2 text-[14px] font-semibold">Classification</h2>
        <dl className="grid gap-x-6 gap-y-1.5 text-[13px] sm:grid-cols-2 lg:grid-cols-3">
          {(["application_type", "languages", "frameworks", "runtimes", "data_classification", "internet_exposure", "authentication_model", "hosting_region", "environment"] as const).map((f) => {
            const v = a[f];
            const kind = overviewKinds[f];
            const text = Array.isArray(v) ? v.join(", ") : kind ? catalogLabel(settings.data, kind, v) : v;
            return (
              <div key={f} className="flex gap-2">
                <dt className="w-40 shrink-0 text-muted-foreground">{fieldLabels[f]}</dt>
                <dd className="min-w-0">
                  {text || <span className="text-muted-foreground">Not set</span>}
                  {a.detected[f] && <Sparkles className="ml-1 inline size-3 text-success" aria-label="detected" />}
                </dd>
              </div>
            );
          })}
        </dl>
        {a.tags.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {a.tags.map((t) => (
              <TagChip key={t.id} name={t.name} category={t.category_name} color={t.color} />
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function RepositoriesTab({ a }: { a: ApplicationProfile }) {
  const repos = useQuery({
    queryKey: ["repositories", { application_id: a.id, profile: true }],
    queryFn: () => api<Page<Repository>>(`/api/v1/repositories?application_id=${a.id}&limit=100`).then((r) => r.items),
  });
  const onboarding = useOnboarding(a.id);
  const pending = (onboarding.data?.sources ?? []).filter((s) => (!s.repository_id || s.status === "draft") && s.status !== "kept");
  const kept = (onboarding.data?.sources ?? []).filter((s) => s.status === "kept");
  return (
    <div className="space-y-4">
      {pending.length > 0 && (
        <Card className="p-4">
          <h2 className="mb-2 text-[14px] font-semibold">In onboarding</h2>
          <ul className="space-y-1 text-[13px]">
            {pending.map((s) => (
              <li key={s.id} className="flex flex-wrap items-center gap-2">
                <GitBranch className="size-3.5 text-muted-foreground" aria-hidden />
                <span className="font-mono">{s.full_name}</span>
                <Badge>{s.decision === "linked_existing" ? "Links an existing repository" : "Registers a new repository"}</Badge>
                {s.import_job_id && (
                  <Link to="/repositories/imports/$id" params={{ id: s.import_job_id }} className="text-primary hover:underline">
                    Import {s.import_status ?? ""}
                  </Link>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}
      {kept.length > 0 && (
        <Card className="p-4">
          <h2 className="mb-2 text-[14px] font-semibold">Kept in other applications</h2>
          <ul className="space-y-1 text-[13px]">
            {kept.map((s) => (
              <li key={s.id}>
                <span className="font-mono">{s.full_name}</span>{" "}
                <Badge>{`kept in ${s.current_application?.name ?? "another application"}`}</Badge>
              </li>
            ))}
          </ul>
        </Card>
      )}
      <Card>
        {repos.isPending ? (
          <Skeleton className="m-4 h-24" />
        ) : repos.isError ? (
          <div className="p-4">
            <ErrorPanel error={repos.error} />
          </div>
        ) : !repos.data.length ? (
          <EmptyState icon={<GitBranch />} title="No repositories in this application">
            Link repositories through onboarding or from a repository's details.
          </EmptyState>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Repository</Th>
                <Th>Repository ID</Th>
                <Th>Criticality</Th>
                <Th>Last sync</Th>
              </tr>
            </thead>
            <tbody>
              {repos.data.map((r) => (
                <tr key={r.id}>
                  <Td>
                    <Link to="/repositories" search={{ repo: r.id } as never} className="font-medium text-primary hover:underline">
                      {r.display_name || r.full_name}
                    </Link>
                    <div className="text-[12px] text-muted-foreground">{r.full_name}</div>
                  </Td>
                  <Td className="font-mono text-[12px]">{r.repository_key}</Td>
                  <Td>
                    <CriticalityBadge value={r.criticality} />
                  </Td>
                  <Td className="text-[12px] text-muted-foreground">{r.last_sync_at ? formatDateTime(r.last_sync_at) : "Never"}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  );
}

function ClassificationTab({ a }: { a: ApplicationProfile }) {
  const settings = useApplicationSettings();
  const detect = useInventoryMutation(() => api(`/api/v1/applications/${a.id}/detect`, { method: "POST" }));
  return (
    <Card className="p-4">
      {a.can_manage && (
        <div className="mb-3 flex items-center justify-end gap-2">
          {detect.isSuccess && <span className="text-[12px] text-success">Detection ran; empty fields were filled where data exists.</span>}
          <Button size="sm" variant="secondary" disabled={detect.isPending} onClick={() => detect.mutate(undefined)}>
            <Sparkles /> Detect again
          </Button>
        </div>
      )}
      {detect.isError && <div className="mb-3"><ErrorPanel error={detect.error} /></div>}
      <p className="mb-4 text-[12px] text-muted-foreground">
        Fields marked <Sparkles className="inline size-3 text-success" aria-hidden /> detected came from repository metadata or the SBOM; editing one makes it yours.
        Mandatory fields are set in Configurations › Asset settings.
      </p>
      <ClassificationForm app={a} required={settings.data?.required_fields ?? []} />
    </Card>
  );
}

function FindingsTab({ a }: { a: ApplicationProfile }) {
  const { can } = useSession();
  const findings = useQuery({
    queryKey: ["findings", { application_id: a.id, profile: true }],
    queryFn: () => api<Page<Finding>>(`/api/v1/findings?application_id=${a.id}&status=open&limit=50`),
    enabled: can("findings.read"),
  });
  if (!can("findings.read")) return <Card className="p-4 text-[13px] text-muted-foreground">Viewing findings requires the findings permission.</Card>;
  return (
    <Card>
      <div className="flex items-center justify-between border-b border-border p-3">
        <h2 className="text-[14px] font-semibold">Open findings</h2>
        <Link to="/findings" search={{ application_id: a.id } as never} className="inline-flex items-center gap-1 text-[12.5px] text-primary hover:underline">
          Open in Findings <ExternalLink className="size-3" aria-hidden />
        </Link>
      </div>
      {findings.isPending ? (
        <Skeleton className="m-4 h-24" />
      ) : findings.isError ? (
        <div className="p-4">
          <ErrorPanel error={findings.error} />
        </div>
      ) : !findings.data.items.length ? (
        <EmptyState icon={<ShieldAlert />} title="No open findings">
          No open findings in this application's repositories.
        </EmptyState>
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Severity</Th>
              <Th>Finding</Th>
              <Th>Kind of check</Th>
              <Th>Repository</Th>
              <Th>First seen</Th>
            </tr>
          </thead>
          <tbody>
            {findings.data.items.map((f) => (
              <tr key={f.id}>
                <Td>
                  <SeverityBadge value={f.severity} />
                </Td>
                <Td>
                  <Link to="/findings" search={{ finding: f.id, application_id: a.id } as never} className="font-medium text-primary hover:underline">
                    {f.title}
                  </Link>
                </Td>
                <Td className="text-[12px]">
                  {findingCheckLabel(f)}
                </Td>
                <Td className="text-[12px]">{f.repository_name}</Td>
                <Td className="whitespace-nowrap text-[12px] text-muted-foreground">{formatDateTime(f.first_seen_at)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {findings.data?.next_cursor && <p className="p-3 text-[12px] text-muted-foreground">Showing the first 50; open Findings for all of them.</p>}
    </Card>
  );
}

function SbomTab({ a }: { a: ApplicationProfile }) {
  const { can } = useSession();
  const comps = useQuery({
    queryKey: ["components", { application_id: a.id }],
    queryFn: () => api<Page<ComponentGroup>>(`/api/v1/sbom/components?application_id=${a.id}`).then((r) => r.items),
    enabled: can("sbom.read"),
  });
  if (!can("sbom.read")) return <Card className="p-4 text-[13px] text-muted-foreground">Viewing the SBOM requires the SBOM permission.</Card>;
  return (
    <Card>
      <div className="flex items-center justify-between border-b border-border p-3">
        <h2 className="text-[14px] font-semibold">Components</h2>
        <Link to="/sbom" className="inline-flex items-center gap-1 text-[12.5px] text-primary hover:underline">
          SBOM inventory <ExternalLink className="size-3" aria-hidden />
        </Link>
      </div>
      {comps.isPending ? (
        <Skeleton className="m-4 h-24" />
      ) : comps.isError ? (
        <div className="p-4">
          <ErrorPanel error={comps.error} />
        </div>
      ) : !comps.data.length ? (
        <EmptyState icon={<Package />} title="No SBOM yet">
          Components appear after the first scan of the application's repositories.
        </EmptyState>
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Component</Th>
              <Th>Version</Th>
              <Th>Licences</Th>
              <Th>Repositories</Th>
              <Th>Open vulnerabilities</Th>
            </tr>
          </thead>
          <tbody>
            {comps.data.map((c) => (
              <tr key={`${c.name}@${c.version}`}>
                <Td className="font-medium">{c.name}</Td>
                <Td className="font-mono text-[12px]">{c.version}</Td>
                <Td className="text-[12px]">{c.licenses.join(", ") || "—"}</Td>
                <Td className="text-[12px]">{c.repositories.join(", ")}</Td>
                <Td className={cn("tabular", c.open_vulnerabilities > 0 && "font-medium text-danger")}>{c.open_vulnerabilities}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

function ActivityTab({ a }: { a: ApplicationProfile }) {
  const act = useApplicationActivity(a.id);
  return (
    <Card>
      {act.data && !act.data.audit_visible && (
        <p className="border-b border-border p-3 text-[12px] text-muted-foreground">
          Showing tag changes only. Audit entries need the audit log permission (organization-wide).
        </p>
      )}
      {act.isPending ? (
        <Skeleton className="m-4 h-24" />
      ) : act.isError ? (
        <div className="p-4">
          <ErrorPanel error={act.error} />
        </div>
      ) : !act.data.items.length ? (
        <EmptyState icon={<Boxes />} title="No activity yet" />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>When</Th>
              <Th>Who</Th>
              <Th>What</Th>
              <Th>Target</Th>
            </tr>
          </thead>
          <tbody>
            {act.data.items.map((i, n) => (
              <tr key={n}>
                <Td className="whitespace-nowrap text-[12px] text-muted-foreground">{formatDateTime(i.at)}</Td>
                <Td className="text-[12px]">{i.actor || "System"}</Td>
                <Td className="text-[12.5px]">
                  {i.kind === "tags" ? <Badge tone="primary">Tags</Badge> : <Badge>Audit</Badge>} <span className="ml-1">{redactToolNames(i.summary)}</span>
                </Td>
                <Td className="text-[12px]">{redactToolNames(i.target)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

import { useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { ArrowLeft, Cable, ExternalLink, Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Badge, Card, Input, PageHeader, Select, Table, Td, Th } from "@/components/ui/primitives";
import { EmptyStateCard, FeatureDisabled, LoadingSkeleton, PartialData, PermissionDenied } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { IntegrationsPage } from "@/features/integrations/IntegrationsPage";
import { ScmConnectionsPage } from "@/features/settings/ScmConnectionsPage";
import { useFeatureFlags } from "@/features/shell/meta";
import { cn, formatDateTime } from "@/lib/utils";
import {
  categories,
  categoryLabel,
  authMethodOf,
  checkError,
  configOf,
  isFeatureDisabled,
  useCheckNow,
  useConnector,
  useConnectorChecks,
  useConnectorDetails,
  useConnectorKinds,
  useConnectors,
  useDeleteConnector,
  type Connector,
  type ConnectorDetail,
  type CheckOutcome,
  type ConnectorKind,
} from "./api";
import { ConnectorDialog } from "./ConnectorDialog";
import {
  authMethodLabel,
  configLabels,
  displayStatus,
  connectFlow,
  isHubKind,
  isSecretKey,
  kindStatusLabel,
  manageLinkFor,
  timeSince,
  type ConnectorsSearch,
  type ManageLink,
} from "./model";

const tabs = [
  { key: "connectors", label: "Connectors" },
  { key: "authentication", label: "Authentication" },
  { key: "configuration", label: "Configuration" },
  { key: "health", label: "Health" },
] as const;
type TabKey = (typeof tabs)[number]["key"];

/** Hub link with the current search merged with `patch` (undefined values drop a key). */
function useHubNav() {
  const search = useSearch({ strict: false }) as ConnectorsSearch;
  const navigate = useNavigate();
  return {
    search,
    go: (patch: Partial<ConnectorsSearch>, replace = false) => {
      const next: Record<string, unknown> = { ...search, ...patch };
      for (const k of Object.keys(next)) if (next[k] === undefined) delete next[k];
      return navigate({ to: "/connectors", search: next as never, replace });
    },
  };
}

function StatusBadge({ c }: { c: Pick<Connector, "status" | "last_check_at"> }) {
  const s = displayStatus(c);
  return (
    <Badge tone={s.tone}>
      <span className={cn("size-1.5 rounded-full", { success: "bg-success", warning: "bg-warning", danger: "bg-danger", neutral: "bg-muted-foreground" }[s.tone])} aria-hidden />
      {s.label}
    </Badge>
  );
}

function ManageButton({ link, children }: { link: ManageLink; children?: ReactNode }) {
  return (
    <Button size="sm" variant="secondary" asChild>
      <Link to={link.to as never} search={(link.search ?? {}) as never}>
        {children ?? (
          <>
            <ExternalLink /> Manage in {link.label}
          </>
        )}
      </Link>
    </Button>
  );
}

/**
 * Connectors hub (/connectors, PATHOS 3.0 M2): every external system in one
 * place, under the `connectors` feature flag. Tabs Connectors ·
 * Authentication · Configuration · Health; a rail with the nine categories.
 * Status is real only: a connector never checked says so.
 */
export function ConnectorsPage() {
  const { flags, isPending: flagsPending } = useFeatureFlags();
  const on = flags.connectors === true;
  if (flagsPending) return <LoadingSkeleton rows={4} label="Loading connectors" />;
  if (!on) {
    return (
      <>
        <PageHeader title="Connectors" description="One place for every external system PATHOS talks to." />
        <FeatureDisabled flag="connectors" feature="Connectors" />
      </>
    );
  }
  return <ConnectorsHub />;
}

function ConnectorsHub() {
  const { search, go } = useHubNav();
  const kinds = useConnectorKinds();
  const list = useConnectors();
  const [dialog, setDialog] = useState<{ kind?: string; editing?: ConnectorDetail } | null>(null);
  const tab: TabKey = search.tab ?? "connectors";
  const cat = search.category && categories.some((c) => c.id === search.category) ? search.category : "all";
  const hubKinds = (kinds.data ?? []).filter(isHubKind);

  const firstError = kinds.error ?? list.error;
  if (isFeatureDisabled(firstError)) {
    return (
      <>
        <PageHeader title="Connectors" description="One place for every external system PATHOS talks to." />
        <FeatureDisabled flag="connectors" feature="Connectors" />
      </>
    );
  }
  if (firstError instanceof ApiError && firstError.status === 403 && kinds.isError && list.isError && !search.manage) {
    const perm = typeof firstError.details?.permission === "string" ? firstError.details.permission : "integrations.read";
    return (
      <>
        <PageHeader title="Connectors" />
        <PermissionDenied permission={perm} what="Connectors" />
      </>
    );
  }

  const connectors = list.data ?? [];
  const inCat = (c: string) => cat === "all" || c === cat;
  const failing = connectors.filter((c) => displayStatus(c).key === "failing" || displayStatus(c).key === "degraded").length;

  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-1 text-[12px] text-muted-foreground">
        1 · Connect / <span className="text-foreground">Connectors</span>
      </nav>
      <PageHeader
        title="Connectors"
        description="One place for every external system PATHOS talks to: what is connected, how it signs in, how it is configured and whether it works."
        actions={
          hubKinds.length > 0 && (
            <Button onClick={() => setDialog({})}>
              <Plus /> Add connector
            </Button>
          )
        }
      />
      <div className="mb-3 flex gap-1 border-b border-border" role="tablist" aria-label="Connector views">
        {tabs.map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={tab === t.key}
            onClick={() => void go({ tab: t.key === "connectors" ? undefined : t.key, manage: undefined, connect: undefined, scm_tab: undefined })}
            className={cn(
              "-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 text-[13px] font-medium",
              tab === t.key ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {t.label}
            {t.key === "health" && failing > 0 && <Badge tone="danger">{failing}</Badge>}
          </button>
        ))}
      </div>
      {(kinds.isError || list.isError) && !(kinds.isError && list.isError) && (
        <div className="mb-3">
          <PartialData missing={[kinds.isError ? "the connector catalogue" : "the connected systems"]} />
        </div>
      )}
      <div className="grid gap-4 md:grid-cols-[200px_minmax(0,1fr)]">
        <CategoryRail cat={cat} kinds={kinds.data} connectors={list.data} onPick={(c) => void go({ category: c === "all" ? undefined : c, manage: undefined, connector: undefined, connect: undefined, scm_tab: undefined })} />
        <div className="min-w-0 space-y-4" aria-live="polite">
          {/* The embedded pages use their own APIs, so they work even when the connectors API does not answer. */}
          {tab === "connectors" && search.manage === "scm" ? (
            <Embedded onBack={() => void go({ manage: undefined, connect: undefined, scm_tab: undefined, connection: undefined, oauth: undefined, message: undefined })}>
              <ScmConnectionsPage embedded />
            </Embedded>
          ) : tab === "connectors" && search.manage === "integrations" ? (
            <Embedded onBack={() => void go({ manage: undefined })}>
              <IntegrationsPage embedded />
            </Embedded>
          ) : kinds.isError && list.isError ? (
            <ErrorPanel error={list.error} title="Connectors could not be loaded" />
          ) : tab === "connectors" ? (
            kinds.isPending || list.isPending ? (
              <LoadingSkeleton rows={4} label="Loading connectors" />
            ) : (
              <ConnectorsTab
                kinds={(kinds.data ?? []).filter((k) => inCat(k.category))}
                allKinds={kinds.data ?? []}
                connectors={connectors.filter((c) => inCat(c.category))}
                selected={search.connector}
                onSelect={(id) => void go({ connector: id }, true)}
                onCreate={(k) => setDialog({ kind: k })}
                onEdit={(d) => setDialog({ editing: d })}
              />
            )
          ) : list.isPending ? (
            <LoadingSkeleton rows={4} label="Loading connectors" />
          ) : tab === "authentication" ? (
            <AuthenticationTab connectors={connectors.filter((c) => inCat(c.category))} kinds={kinds.data ?? []} />
          ) : tab === "configuration" ? (
            <ConfigurationTab connectors={connectors.filter((c) => inCat(c.category))} kinds={kinds.data ?? []} onEdit={(d) => setDialog({ editing: d })} />
          ) : (
            <HealthTab connectors={connectors.filter((c) => inCat(c.category))} kinds={kinds.data ?? []} />
          )}
        </div>
      </div>
      <ConnectorDialog open={!!dialog} onOpenChange={(o) => !o && setDialog(null)} kinds={dialog?.editing ? (kinds.data ?? []) : hubKinds} initialKind={dialog?.kind} editing={dialog?.editing} />
    </>
  );
}

function Embedded({ onBack, children }: { onBack: () => void; children: ReactNode }) {
  return (
    <div>
      <Button size="sm" variant="ghost" className="mb-2" onClick={onBack}>
        <ArrowLeft /> All connectors
      </Button>
      {children}
    </div>
  );
}

function CategoryRail({ cat, kinds, connectors, onPick }: { cat: string; kinds?: ConnectorKind[]; connectors?: Connector[]; onPick: (c: string) => void }) {
  const rows = [{ id: "all", label: "All categories" }, ...categories];
  return (
    <nav aria-label="Connector categories" className="flex gap-0.5 overflow-x-auto rounded-lg border border-border bg-surface-muted/50 p-1.5 md:flex-col md:self-start">
      {rows.map((r) => {
        const conns = connectors?.filter((c) => r.id === "all" || c.category === r.id) ?? [];
        const nKinds = kinds?.filter((k) => r.id === "all" || k.category === r.id).length;
        const bad = conns.some((c) => displayStatus(c).key === "failing");
        return (
          <button
            key={r.id}
            type="button"
            aria-pressed={cat === r.id}
            onClick={() => onPick(r.id)}
            title={`${conns.length} connected${nKinds !== undefined ? ` · ${nKinds} kinds` : ""}`}
            className={cn(
              "flex items-center justify-between gap-2 whitespace-nowrap rounded-md px-2 py-1.5 text-left text-[12.5px] focus-visible:outline-2 focus-visible:outline-ring",
              cat === r.id ? "bg-primary/10 font-semibold text-primary" : "text-foreground hover:bg-surface",
            )}
          >
            <span className="flex items-center gap-1.5">
              {bad && <span className="size-1.5 rounded-full bg-danger" aria-hidden />}
              {r.label}
              {bad && <span className="sr-only">, has failing connectors</span>}
            </span>
            <span className="font-mono text-[11px] text-muted-foreground">
              {connectors ? conns.length : "–"}
              {nKinds !== undefined && <span className="opacity-70">/{nKinds}</span>}
              <span className="sr-only"> connected{nKinds !== undefined ? ` of ${nKinds} kinds` : ""}</span>
            </span>
          </button>
        );
      })}
    </nav>
  );
}

/** Connectors tab: connected systems first, then the kinds not connected yet. */
function ConnectorsTab({
  kinds,
  allKinds,
  connectors,
  selected,
  onSelect,
  onCreate,
  onEdit,
}: {
  kinds: ConnectorKind[];
  allKinds: ConnectorKind[];
  connectors: Connector[];
  selected?: string;
  onSelect: (id: string) => void;
  onCreate: (kind: string) => void;
  onEdit: (d: ConnectorDetail) => void;
}) {
  const kindOf = (k: string) => allKinds.find((x) => x.kind === k);
  const unconnected = kinds.filter((k) => !connectors.some((c) => c.kind === k.kind));
  const sel = connectors.find((c) => c.id === selected);
  if (!kinds.length && !connectors.length) {
    return <EmptyStateCard title="Nothing in this category yet" icon={<Cable />}>Connectors of this category appear here once PATHOS supports them.</EmptyStateCard>;
  }
  return (
    <>
      {connectors.length > 0 && (
        <section aria-label="Connected">
          <h2 className="mb-2 text-[12px] font-semibold tracking-wide text-muted-foreground uppercase">Connected ({connectors.length})</h2>
          <div className="grid grid-cols-[repeat(auto-fill,minmax(210px,1fr))] gap-2.5">
            {connectors.map((c) => (
              <button
                key={c.id}
                type="button"
                aria-pressed={c.id === selected}
                onClick={() => onSelect(c.id)}
                className={cn(
                  "flex flex-col gap-1.5 rounded-lg border bg-surface p-3 text-left focus-visible:outline-2 focus-visible:outline-ring",
                  c.id === selected ? "border-primary ring-1 ring-primary" : "border-border hover:border-primary/60",
                )}
              >
                <span className="flex items-start justify-between gap-2">
                  <span className="min-w-0 truncate text-[13px] font-semibold">{c.name}</span>
                  <StatusBadge c={c} />
                </span>
                <span className="text-[11.5px] text-muted-foreground">{kindOf(c.kind)?.label ?? c.kind}</span>
                <span className="text-[11.5px] text-muted-foreground">
                  Last check: {c.last_check_at ? timeSince(c.last_check_at) : "never"} · Last sync: {c.last_sync_at ? timeSince(c.last_sync_at) : "never"}
                </span>
                {c.last_error_code && <code className="text-[11px] text-danger">{c.last_error_code}</code>}
              </button>
            ))}
          </div>
        </section>
      )}
      {sel && <DetailPanel c={sel} kind={kindOf(sel.kind)} onEdit={onEdit} />}
      {unconnected.length > 0 && (
        <section aria-label="Not connected">
          <h2 className="mb-2 text-[12px] font-semibold tracking-wide text-muted-foreground uppercase">Not connected ({unconnected.length})</h2>
          <div className="grid grid-cols-[repeat(auto-fill,minmax(210px,1fr))] gap-2.5">
            {unconnected.map((k) => (
              <KindCard key={k.kind} k={k} onCreate={onCreate} />
            ))}
          </div>
        </section>
      )}
    </>
  );
}

function KindCard({ k, onCreate }: { k: ConnectorKind; onCreate: (kind: string) => void }) {
  const st = kindStatusLabel[k.status] ?? kindStatusLabel.planned;
  const flow = k.status !== "planned" ? connectFlow(k) : undefined;
  const hub = isHubKind(k);
  return (
    <div className="flex flex-col gap-1.5 rounded-lg border border-border bg-surface p-3">
      <span className="text-[13px] font-semibold">{k.label}</span>
      <span className="text-[11.5px] text-muted-foreground">{categoryLabel(k.category)} · Not connected</span>
      {k.auth_methods.length > 0 && <span className="text-[11.5px] text-muted-foreground">{k.auth_methods.map(authMethodLabel).join(" · ")}</span>}
      <span className="flex flex-wrap gap-1">
        <Badge tone={st.tone}>{st.label}</Badge>
        {k.offline_ok && <Badge>Offline OK</Badge>}
        {k.direction === "inbound" && <Badge>Calls PATHOS</Badge>}
      </span>
      {k.note && k.status !== "existing" && <span className="text-[11.5px] text-muted-foreground">{k.note}</span>}
      <span className="mt-auto pt-1">
        {k.status === "planned" ? (
          <span className="text-[12px] text-muted-foreground">Not available yet</span>
        ) : hub ? (
          <Button size="sm" onClick={() => onCreate(k.kind)} aria-label={`Connect ${k.label}`}>
            <Plus /> Connect
          </Button>
        ) : flow ? (
          <Button size="sm" asChild>
            <Link to={flow.to as never} search={(flow.search ?? {}) as never} aria-label={`Connect ${k.label} (${flow.label})`}>
              <Plus /> Connect
            </Link>
          </Button>
        ) : k.docs_slug ? (
          <Link className="text-[12px] text-primary underline" to="/help/$section/$slug" params={{ section: "user-guide", slug: k.docs_slug.split("#")[0]! }} hash={k.docs_slug.split("#")[1]}>
            How to set it up
          </Link>
        ) : null}
      </span>
    </div>
  );
}

/** Selected connector: details, Check now, latest failure and the health history. */
function DetailPanel({ c, kind, onEdit }: { c: Connector; kind?: ConnectorKind; onEdit: (d: ConnectorDetail) => void }) {
  const detail = useConnector(c.id);
  const checks = useConnectorChecks(c.id);
  const check = useCheckNow();
  const del = useDeleteConnector();
  const [confirmDelete, setConfirmDelete] = useState(false);
  const link = manageLinkFor(c);
  const canManage = c.can_manage !== false;
  const hubRow = canManage && (c.source?.table === "connectors" || (!link && kind && isHubKind(kind)));
  const checkable = canManage && c.checked_by !== "";
  const latest = check.data?.result ?? checks.data?.[0] ?? detail.data?.last_check ?? undefined;
  const failure = checkError(latest);
  const pending = check.data?.pending || isPending(c);
  const run = () => check.mutateAsync(c.id).then((r) => announce(c.name, r), () => undefined);

  return (
    <Card className="p-4" aria-label={`${c.name} details`} role="region">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">{categoryLabel(c.category)}</div>
          <h2 className="text-[15px] font-semibold">{c.name}</h2>
          <p className="text-[12.5px] text-muted-foreground">{kind?.label ?? c.kind}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {checkable && (
            <Button size="sm" onClick={() => void run()} disabled={check.isPending}>
              <RefreshCw className={check.isPending ? "motion-safe:animate-spin" : undefined} /> {check.isPending ? "Checking…" : "Check now"}
            </Button>
          )}
          {link && <ManageButton link={link} />}
          {hubRow && detail.data && (
            <>
              <Button size="sm" variant="secondary" onClick={() => onEdit(detail.data!)}>
                <Pencil /> Edit
              </Button>
              <Button size="sm" variant="danger-outline" onClick={() => setConfirmDelete(true)} aria-label={`Delete ${c.name}`}>
                <Trash2 />
              </Button>
            </>
          )}
        </div>
      </div>
      <dl className="mt-3 grid grid-cols-[120px_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
        <dt className="text-muted-foreground">Status</dt>
        <dd>
          <StatusBadge c={c} />
        </dd>
        <dt className="text-muted-foreground">Last check</dt>
        <dd>{c.last_check_at ? `${formatDateTime(c.last_check_at)} (${timeSince(c.last_check_at)})` : "Never checked"}</dd>
        <dt className="text-muted-foreground">Last sync</dt>
        <dd>{c.last_sync_at ? `${formatDateTime(c.last_sync_at)} (${timeSince(c.last_sync_at)})` : "Never"}</dd>
        <dt className="text-muted-foreground">Sign-in</dt>
        <dd>{authMethodOf(detail.data) ? authMethodLabel(authMethodOf(detail.data)) : kind?.auth_methods.map(authMethodLabel).join(" · ") || "—"}</dd>
        <dt className="text-muted-foreground">Air-gapped</dt>
        <dd>{kind ? (kind.offline_ok ? "Works offline or on a private network" : "Needs internet access to the vendor") : "—"}</dd>
      </dl>
      {pending && <p className="mt-3 text-[12.5px] text-muted-foreground" role="status">A health check is queued; the jobs service runs it and the result appears in the health history.</p>}
      {latest?.steps && latest.steps.length > 0 && (
        <ul className="mt-3 space-y-0.5 text-[12.5px]" aria-label="Last check steps">
          {latest.steps.map((st, i) => (
            <li key={`${st.check}-${i}`} className="flex flex-wrap items-center gap-2">
              <Badge tone={st.status === "pass" ? "success" : st.status === "warn" ? "warning" : st.status === "fail" ? "danger" : "neutral"}>{stepLabel(st.status)}</Badge>
              <span className="font-medium">{st.check.replace(/_/g, " ")}</span>
              {st.error_code && <code className="text-[11.5px]">{st.error_code}</code>}
              {st.detail && <span className="text-muted-foreground">{st.detail}</span>}
            </li>
          ))}
        </ul>
      )}
      {check.isError && (
        <div className="mt-3">
          <ErrorPanel error={check.error} title="The health check could not run" onVerify={run} />
        </div>
      )}
      {failure && (
        <div className="mt-3">
          <ErrorPanel error={failure} title={`${c.name} is failing`} onVerify={run} />
        </div>
      )}
      <h3 className="mt-4 mb-1.5 text-[12px] font-semibold tracking-wide text-muted-foreground uppercase">Health history</h3>
      {checks.isPending ? (
        <LoadingSkeleton rows={2} label="Loading health history" />
      ) : checks.isError ? (
        <ErrorPanel error={checks.error} title="Health history could not be loaded" />
      ) : !checks.data.length ? (
        <p className="text-[12.5px] text-muted-foreground">No checks yet. “Check now” runs the first one.</p>
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Checked</Th>
              <Th>Result</Th>
              <Th>Duration</Th>
              <Th>Error code</Th>
            </tr>
          </thead>
          <tbody>
            {checks.data.slice(0, 20).map((h, i) => {
              const e = checkError(h);
              return (
                <tr key={h.id ?? `${h.checked_at}-${i}`}>
                  <Td className="text-[12px]">{formatDateTime(h.checked_at)}</Td>
                  <Td>
                    <StatusBadge c={{ status: h.status, last_check_at: h.checked_at }} />
                  </Td>
                  <Td className="tabular text-[12px]">{h.duration_ms} ms</Td>
                  <Td className="text-[12px]">{e?.errorCode ? <code>{e.errorCode}</code> : e ? e.message : "—"}</Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      )}
      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={`Delete connector “${c.name}”?`}
        confirmLabel="Delete connector"
        pending={del.isPending}
        onConfirm={() =>
          del.mutate(c.id, {
            onSuccess: () => {
              setConfirmDelete(false);
              toast.success(`Connector “${c.name}” deleted.`);
            },
          })
        }
      >
        Its stored credential and health history are deleted too.
        {del.isError && (
          <div className="mt-2">
            <ErrorPanel error={del.error} />
          </div>
        )}
      </ConfirmDialog>
    </Card>
  );
}

/** Success toast for Check now; failures show in the error panel instead. */
function announce(name: string, r: CheckOutcome) {
  if (r.pending) toast.success(`Health check of “${name}” requested. The jobs service runs it; the result appears in the health history.`);
  else if (!checkError(r.result)) toast.success(`Health check of “${name}” passed.`);
}

/** A check was requested after the last one finished. */
const isPending = (c: Connector) => !!c.check_requested_at && (!c.last_check_at || c.check_requested_at > c.last_check_at);

const stepLabel = (s: string) => ({ pass: "Passed", warn: "Warning", fail: "Failed", skipped: "Skipped" })[s] ?? s;

function credentialText(d: ConnectorDetail | undefined): { text: string; tone: "success" | "neutral" } {
  if (!d?.credential) return { text: "—", tone: "neutral" };
  return d.credential.set || d.credential.ref ? { text: "Set", tone: "success" } : { text: "Not set", tone: "neutral" };
}

function storedIn(d: ConnectorDetail | undefined): string {
  const ref = d?.credential?.ref;
  if (ref) return `${ref.provider === "openbao" ? "OpenBao" : ref.provider === "vault" ? "HashiCorp Vault" : ref.provider}${ref.path ? ` · ${ref.path}` : ""}${ref.key ? `#${ref.key}` : ""}`;
  if (d?.credential?.set) return "PATHOS (encrypted)";
  return "—";
}

function scopesOf(d: ConnectorDetail | undefined): string[] {
  if (!d) return [];
  if (Array.isArray(d.scopes)) return d.scopes;
  const s = d.config?.scopes;
  return Array.isArray(s) ? s.filter((x): x is string => typeof x === "string") : [];
}

function NoConnectors() {
  return (
    <EmptyStateCard title="No connections in this category yet" icon={<Cable />}>
      Connected systems appear here. Open the Connectors tab and choose Connect on a card to add one.
    </EmptyStateCard>
  );
}

/** Authentication tab: method, credential set or not (never the value), where it is kept, scopes. */
function AuthenticationTab({ connectors, kinds }: { connectors: Connector[]; kinds: ConnectorKind[] }) {
  const details = useConnectorDetails(connectors.map((c) => c.id));
  if (!connectors.length) return <NoConnectors />;
  const missing = details.filter((d) => d.isError).length;
  return (
    <>
      {missing > 0 && <PartialData missing={[`authentication details of ${missing} connector${missing === 1 ? "" : "s"}`]} />}
      <Card>
        <Table>
          <thead>
            <tr>
              <Th>Connection</Th>
              <Th>Method</Th>
              <Th>Credential</Th>
              <Th>Stored in</Th>
              <Th>Expires</Th>
              <Th>Scopes</Th>
              <Th />
            </tr>
          </thead>
          <tbody>
            {connectors.map((c, i) => {
              const d = details[i]?.data;
              const cred = credentialText(d);
              const sc = scopesOf(d);
              const link = manageLinkFor(c);
              return (
                <tr key={c.id}>
                  <Td>
                    <div className="font-medium">{c.name}</div>
                    <div className="text-[11.5px] text-muted-foreground">{kinds.find((k) => k.kind === c.kind)?.label ?? c.kind}</div>
                  </Td>
                  <Td className="text-[12.5px]">{details[i]?.isPending ? "…" : authMethodLabel(authMethodOf(d))}</Td>
                  <Td>
                    <Badge tone={cred.tone}>{cred.text}</Badge>
                    {d?.credential?.updated_at && <div className="text-[11px] text-muted-foreground">updated {formatDateTime(d.credential.updated_at)}</div>}
                  </Td>
                  <Td className="text-[12px]">{storedIn(d)}</Td>
                  <Td className="text-[12px]">{d?.credential?.expires_at ? formatDateTime(d.credential.expires_at) : "—"}</Td>
                  <Td className="text-[12px]">{sc.length ? <code className="break-words">{sc.join(", ")}</code> : "—"}</Td>
                  <Td className="text-right">{link && <ManageButton link={link}>Rotate</ManageButton>}</Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      </Card>
      <p className="text-[12px] text-muted-foreground">
        Credentials are write-only: PATHOS shows the method, scopes and expiry, never the value. Rotate a credential on the page that manages the connection.
      </p>
    </>
  );
}

function fmtValue(v: unknown): string {
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (Array.isArray(v)) return v.map(String).join(", ");
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "object") return "…";
  return String(v);
}

/** Configuration tab: non-secret configuration of each connector; secret-looking fields only as set / not set. */
function ConfigurationTab({ connectors, kinds, onEdit }: { connectors: Connector[]; kinds: ConnectorKind[]; onEdit: (d: ConnectorDetail) => void }) {
  const details = useConnectorDetails(connectors.map((c) => c.id));
  if (!connectors.length) return <NoConnectors />;
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      {connectors.map((c, i) => {
        const q = details[i];
        const d = q?.data;
        const cfg = configOf(d);
        const shown = new Set<string>();
        const rows: [string, string][] = [];
        for (const [k, label] of configLabels) {
          if (k in cfg && !rows.some(([l]) => l === label)) {
            rows.push([label, fmtValue(cfg[k])]);
            shown.add(k);
          } else if (k in cfg) shown.add(k);
        }
        const caKnown = ["ca_bundle_set", "ca_set", "ca_pem_set"].some((k) => k in cfg);
        // Present yes/no only when the source reports it; never guessed.
        if (!caKnown && d) rows.push(["Custom CA certificate", "ca_bundle_pem" in cfg || "ca_pem" in cfg ? "Yes" : "ca_bundle" in cfg ? fmtValue(cfg.ca_bundle) : "Not reported"]);
        shown.add("ca_pem").add("ca_bundle_pem").add("ca_bundle").add("scopes").add("auth_method").add("auth_type").add("credential_ref");
        for (const [k, v] of Object.entries(cfg)) {
          if (shown.has(k)) continue;
          if (isSecretKey(k)) rows.push([k.replace(/_/g, " "), v ? "Set" : "Not set"]);
          else if (typeof v !== "object" || Array.isArray(v)) rows.push([k.replace(/_/g, " "), fmtValue(v)]);
        }
        const sc = scopesOf(d);
        const link = manageLinkFor(c);
        const hub = c.source?.table === "connectors";
        return (
          <Card key={c.id} className="p-4">
            <div className="mb-2 flex items-start justify-between gap-2">
              <div>
                <h2 className="text-[14px] font-semibold">{c.name}</h2>
                <p className="text-[11.5px] text-muted-foreground">{kinds.find((k) => k.kind === c.kind)?.label ?? c.kind}</p>
              </div>
              <StatusBadge c={c} />
            </div>
            {q?.isPending ? (
              <LoadingSkeleton rows={2} label={`Loading the configuration of ${c.name}`} />
            ) : q?.isError ? (
              <ErrorPanel error={q.error} title="Configuration could not be loaded" />
            ) : (
              <dl className="grid grid-cols-[150px_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
                <dt className="text-muted-foreground">Authentication</dt>
                <dd>{authMethodLabel(authMethodOf(d))}</dd>
                <dt className="text-muted-foreground">Credential</dt>
                <dd>{credentialText(d).text}</dd>
                {rows.map(([l, v]) => (
                  <FragmentRow key={l} label={l} value={v} />
                ))}
                <dt className="text-muted-foreground">Scopes</dt>
                <dd>{sc.length ? <code className="break-words">{sc.join(", ")}</code> : "—"}</dd>
              </dl>
            )}
            <div className="mt-3 flex gap-2">
              {link && <ManageButton link={link}>Change configuration</ManageButton>}
              {hub && d && (
                <Button size="sm" variant="secondary" onClick={() => onEdit(d)}>
                  <Pencil /> Edit
                </Button>
              )}
            </div>
          </Card>
        );
      })}
    </div>
  );
}

function FragmentRow({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-muted-foreground first-letter:uppercase">{label}</dt>
      <dd className="break-words">{value}</dd>
    </>
  );
}

/** Health tab: every connector with status, last error code, time since the last check, and a filter. */
function HealthTab({ connectors, kinds }: { connectors: Connector[]; kinds: ConnectorKind[] }) {
  const { search, go } = useHubNav();
  const check = useCheckNow();
  const [checking, setChecking] = useState<string | null>(null);
  const q = (search.q ?? "").toLowerCase();
  const rows = useMemo(
    () =>
      connectors
        .filter((c) => !search.status || displayStatus(c).key === search.status)
        .filter((c) => !q || c.name.toLowerCase().includes(q) || c.kind.toLowerCase().includes(q) || c.last_error_code.toLowerCase().includes(q))
        .sort((a, b) => rank(displayStatus(a).key) - rank(displayStatus(b).key) || a.name.localeCompare(b.name)),
    [connectors, search.status, q],
  );
  return (
    <>
      <div className="flex flex-wrap items-end gap-2">
        <div>
          <label htmlFor="cx-health-status" className="mb-1 block text-[12px] font-medium">
            Status
          </label>
          <Select id="cx-health-status" value={search.status ?? ""} onChange={(e) => void go({ status: (e.target.value || undefined) as ConnectorsSearch["status"] }, true)}>
            <option value="">All statuses</option>
            <option value="failing">Failing</option>
            <option value="degraded">Degraded</option>
            <option value="healthy">Healthy</option>
            <option value="unknown">Unknown</option>
            <option value="never">Never checked</option>
            <option value="disabled">Disabled</option>
          </Select>
        </div>
        <div className="min-w-56 flex-1">
          <label htmlFor="cx-health-q" className="mb-1 block text-[12px] font-medium">
            Search
          </label>
          <Input id="cx-health-q" defaultValue={search.q ?? ""} placeholder="Name, kind or error code" onChange={(e) => void go({ q: e.target.value || undefined }, true)} />
        </div>
      </div>
      {check.isError && <ErrorPanel error={check.error} title="The health check could not run" />}
      {!connectors.length ? (
        <NoConnectors />
      ) : !rows.length ? (
        <EmptyStateCard title="No connector matches the filter">Clear the status or search filter to see every connector.</EmptyStateCard>
      ) : (
        <Card>
          <Table>
            <thead>
              <tr>
                <Th>Status</Th>
                <Th>Connector</Th>
                <Th>Category</Th>
                <Th>Last error code</Th>
                <Th>Last check</Th>
                <Th>Last sync</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id}>
                  <Td>
                    <StatusBadge c={c} />
                  </Td>
                  <Td>
                    <div className="font-medium">{c.name}</div>
                    <div className="text-[11.5px] text-muted-foreground">{kinds.find((k) => k.kind === c.kind)?.label ?? c.kind}</div>
                  </Td>
                  <Td className="text-[12px]">{categoryLabel(c.category)}</Td>
                  <Td className="text-[12px]">
                    {c.last_error_code ? (
                      <Link to="/help/troubleshooting" search={{ q: c.last_error_code } as never} className="font-mono text-danger underline">
                        {c.last_error_code}
                      </Link>
                    ) : (
                      "—"
                    )}
                  </Td>
                  <Td className="text-[12px]">
                    <span title={c.last_check_at ? formatDateTime(c.last_check_at) : undefined}>{c.last_check_at ? timeSince(c.last_check_at) : "Never checked"}</span>
                  </Td>
                  <Td className="text-[12px]">{c.last_sync_at ? timeSince(c.last_sync_at) : "—"}</Td>
                  <Td className="whitespace-nowrap text-right">
                    {c.can_manage !== false && c.checked_by !== "" && <Button
                      size="sm"
                      variant="secondary"
                      aria-label={`Check ${c.name} now`}
                      disabled={checking === c.id}
                      onClick={() => {
                        setChecking(c.id);
                        check.mutate(c.id, { onSettled: () => setChecking(null), onSuccess: (r) => announce(c.name, r) })
                      }}
                    >
                      <RefreshCw /> {checking === c.id ? "Checking…" : "Check now"}
                    </Button>}
                    <Button size="sm" variant="ghost" onClick={() => void go({ tab: undefined, connector: c.id, category: c.category })}>
                      Details
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      )}
    </>
  );
}

const rank = (k: string) => ["failing", "degraded", "unknown", "never", "healthy", "disabled"].indexOf(k);

/** Session helper reused by the redirect wrappers. */
export function useConnectorsFlag(): { on: boolean; pending: boolean } {
  const { flags, isPending } = useFeatureFlags();
  return { on: flags.connectors === true, pending: isPending };
}

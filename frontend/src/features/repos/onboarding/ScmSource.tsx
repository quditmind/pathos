import { useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { Archive, ChevronDown, ChevronRight, ExternalLink, GitBranch, Lock, Plug, Search } from "lucide-react";
import type { DiscoveredRepo, ProviderInfo, ScmConnection } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Combobox } from "@/components/ui/combobox";
import { Badge, Card, EmptyState, Input, Select, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { providerCategory, providerLabel } from "@/features/settings/scmApi";
import { formatBytes } from "@/lib/uploader";
import { useDebounced } from "@/lib/useDebounced";
import { cn, formatDateTime } from "@/lib/utils";
import { slugify } from "../metadata/model";
import { useRemoteRepoDetails, useRemoteRepositories, useScmOrganizations, useScmProjects } from "./api";
import { ErrorPanel } from "@/components/ui/error-panel";

export interface ScmItem {
  repo: DiscoveredRepo;
  /** "" = default branch */
  branch: string;
  full_history: boolean;
  display_name: string;
  asset_name: string;
}

export interface ScmState {
  connectionId: string;
  organization: string;
  project: string;
  items: ScmItem[];
}

export const emptyScmState: ScmState = { connectionId: "", organization: "", project: "", items: [] };

export function ConnectionStatusBadge({ c }: { c: ScmConnection }) {
  const tone = c.status === "ok" ? "success" : c.status === "untested" ? "neutral" : c.status === "expired" ? "warning" : "danger";
  const label = { ok: "Connected", untested: "Untested", error: "Error", expired: "Expired", revoked: "Revoked" }[c.status] ?? c.status;
  return <Badge tone={tone}>{label}</Badge>;
}

export function ScmSource({
  category,
  connections,
  providers,
  state,
  setState,
}: {
  category: "git" | "devops";
  connections: ScmConnection[] | undefined;
  providers: ProviderInfo[] | undefined;
  state: ScmState;
  setState: (s: ScmState) => void;
}) {
  const { canOrgWide } = useSession();
  const list = (connections ?? []).filter((c) => providerCategory(c.provider, providers) === category);
  const conn = list.find((c) => c.id === state.connectionId);
  const usable = (c: ScmConnection) => c.status !== "expired" && c.status !== "revoked";

  useEffect(() => {
    if (!state.connectionId) {
      const first = list.find(usable);
      if (first) setState({ ...emptyScmState, connectionId: first.id });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [list.length, state.connectionId]);

  if (!connections) return <Skeleton className="h-40" />;
  if (!list.length) {
    const what = category === "git" ? "GitHub, GitLab or Bitbucket" : "Azure DevOps";
    return (
      <Card>
        <EmptyState icon={<Plug />} title={`No ${category === "git" ? "Git" : "DevOps"} provider is connected`}>
          {canOrgWide("scm.manage") ? (
            <>
              <p>Connect {what} first; you will come back here afterwards.</p>
              <Button asChild className="mt-3">
                <Link to="/admin/scm" search={{ connect: category } as never}>
                  <Plug /> Connect a provider
                </Link>
              </Button>
            </>
          ) : (
            <p>
              An administrator with the <strong>SCM management</strong> permission must connect {what} under Administration → SCM connections before
              repositories can be imported from it.
            </p>
          )}
        </EmptyState>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <fieldset>
        <legend className="mb-1.5 text-[12px] font-medium">Connection</legend>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {list.map((c) => (
            <label
              key={c.id}
              className={cn(
                "flex cursor-pointer flex-col gap-1 rounded-md border p-3 text-[12px] has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-ring",
                state.connectionId === c.id ? "border-primary bg-primary/5" : "border-border hover:bg-surface-muted/60",
                !usable(c) && "cursor-not-allowed opacity-60",
              )}
            >
              <span className="flex items-center justify-between gap-2">
                <span className="flex items-center gap-2 text-[13px] font-medium">
                  <input
                    type="radio"
                    name="scm-connection"
                    className="accent-[var(--primary)]"
                    disabled={!usable(c)}
                    checked={state.connectionId === c.id}
                    onChange={() => setState({ ...emptyScmState, connectionId: c.id })}
                  />
                  {c.name}
                </span>
                <ConnectionStatusBadge c={c} />
              </span>
              <span className="text-muted-foreground">
                {providerLabel(c.provider, providers)}
                {c.account && ` · ${c.account}`}
              </span>
              {!usable(c) && <span className="text-warning">Reconnect it under SCM connections to use it.</span>}
            </label>
          ))}
        </div>
      </fieldset>
      {conn && <Browser key={conn.id} conn={conn} state={state} setState={setState} />}
    </div>
  );
}

function Browser({ conn, state, setState }: { conn: ScmConnection; state: ScmState; setState: (s: ScmState) => void }) {
  const caps = conn.capabilities ?? { organizations: true, projects: false, server_search: true };
  const orgs = useScmOrganizations(conn.id, caps.organizations);
  const projects = useScmProjects(conn.id, state.organization, caps.projects && (!caps.organizations || !!state.organization));
  const [q, setQ] = useState("");
  const dq = useDebounced(q.trim(), 350);
  const orgReady = !caps.organizations || !!state.organization || (orgs.isSuccess && !orgs.data.length);
  const repos = useRemoteRepositories(conn.id, { organization: state.organization, project: state.project, q: dq }, orgReady);
  const [focus, setFocus] = useState<string | null>(null);

  useEffect(() => {
    if (caps.organizations && !state.organization && orgs.data?.length === 1) setState({ ...state, organization: orgs.data[0]!.name });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgs.data]);

  const rows = repos.data?.pages.flatMap((p) => p.items) ?? [];
  const selected = new Map(state.items.map((i) => [i.repo.external_id, i]));
  const toggle = (r: DiscoveredRepo) => {
    if (selected.has(r.external_id)) setState({ ...state, items: state.items.filter((i) => i.repo.external_id !== r.external_id) });
    else {
      setState({ ...state, items: [...state.items, { repo: r, branch: "", full_history: false, display_name: r.name, asset_name: slugify(r.name) }] });
      setFocus(r.external_id);
    }
  };
  const update = (id: string, p: Partial<ScmItem>) => setState({ ...state, items: state.items.map((i) => (i.repo.external_id === id ? { ...i, ...p } : i)) });
  const visibleIds = rows.filter((r) => !r.imported_id).map((r) => r.external_id);
  const allSelected = visibleIds.length > 0 && visibleIds.every((id) => selected.has(id));

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,380px)]">
      <div className="space-y-3">
        <div className="flex flex-wrap gap-2">
          {caps.organizations && (
            <div className="min-w-56 flex-1">
              <label htmlFor="scm-org" className="mb-1 block text-[12px] font-medium">
                {conn.provider === "bitbucket" ? "Workspace" : conn.provider.startsWith("azure") ? "Organization" : conn.provider === "gitlab" ? "Group" : "Organization or user"}
              </label>
              <Combobox
                id="scm-org"
                placeholder={orgs.isPending ? "Loading…" : "Search…"}
                clearable={false}
                value={state.organization ? { value: state.organization, label: orgs.data?.find((o) => o.name === state.organization)?.display_name || state.organization } : null}
                onChange={(o) => o && setState({ ...state, organization: o.value, project: "", items: [] })}
                options={(orgs.data ?? []).map((o) => ({ value: o.name, label: o.display_name || o.name, description: o.kind }))}
              />
            </div>
          )}
          {caps.projects && (
            <div className="min-w-56 flex-1">
              <label htmlFor="scm-project" className="mb-1 block text-[12px] font-medium">
                Project
              </label>
              <Combobox
                id="scm-project"
                placeholder={projects.isFetching ? "Loading…" : "All projects"}
                disabled={caps.organizations && !state.organization}
                value={state.project ? { value: state.project, label: state.project } : null}
                onChange={(o) => setState({ ...state, project: o?.value ?? "" })}
                options={(projects.data ?? []).map((p) => ({ value: p.name, label: p.name, description: p.description }))}
              />
            </div>
          )}
        </div>
        {orgs.isError && <ErrorPanel error={orgs.error} title="Could not list organizations" />}
        {projects.isError && <ErrorPanel error={projects.error} title="Could not list projects" />}

        <Card>
          <div className="flex items-center gap-2 border-b border-border p-2.5">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input aria-label="Search repositories" placeholder="Search repositories" className="pl-8" value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
            <label className="flex items-center gap-1.5 whitespace-nowrap text-[12px]">
              <input
                type="checkbox"
                className="accent-[var(--primary)]"
                checked={allSelected}
                disabled={!visibleIds.length}
                onChange={() => {
                  if (allSelected) setState({ ...state, items: state.items.filter((i) => !visibleIds.includes(i.repo.external_id)) });
                  else
                    setState({
                      ...state,
                      items: [
                        ...state.items,
                        ...rows
                          .filter((r) => !r.imported_id && !selected.has(r.external_id))
                          .map((r) => ({ repo: r, branch: "", full_history: false, display_name: r.name, asset_name: slugify(r.name) })),
                      ],
                    });
                }}
              />
              Select all loaded
            </label>
          </div>
          {!orgReady ? (
            <p className="p-4 text-[13px] text-muted-foreground">Choose an organization to list its repositories.</p>
          ) : repos.isPending ? (
            <div className="space-y-2 p-3">
              {Array.from({ length: 5 }, (_, i) => (
                <Skeleton key={i} className="h-10" />
              ))}
            </div>
          ) : repos.isError ? (
            <div className="space-y-2 p-3">
              <ErrorPanel error={repos.error} />
              <Button size="sm" variant="secondary" onClick={() => void repos.refetch()}>
                Try again
              </Button>
            </div>
          ) : !rows.length ? (
            <EmptyState icon={<GitBranch />} title={dq ? `No repositories match “${dq}”` : "No repositories found"}>
              Check that the connection's credential can read the repositories you expect.
            </EmptyState>
          ) : (
            <ul className="max-h-[28rem] divide-y divide-border overflow-y-auto" aria-label="Repositories">
              {rows.map((r) => {
                const imported = !!r.imported_id;
                return (
                  <li key={r.external_id} className={cn("flex items-start gap-2.5 px-3 py-2", imported && "bg-surface-muted/40")}>
                    <input
                      type="checkbox"
                      className="mt-1 accent-[var(--primary)]"
                      aria-label={`Select ${r.full_name}`}
                      disabled={imported}
                      checked={selected.has(r.external_id)}
                      onChange={() => toggle(r)}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5 text-[13px] font-medium">
                        <span className="truncate">{r.full_name}</span>
                        {r.visibility !== "public" && <Lock className="size-3 text-muted-foreground" aria-label={r.visibility} />}
                        {r.archived && (
                          <Badge>
                            <Archive className="size-3" /> archived
                          </Badge>
                        )}
                        {imported && (
                          <Link to="/repositories" search={{ repo: r.imported_id } as never} className="text-[12px] font-normal text-primary hover:underline">
                            Already imported →
                          </Link>
                        )}
                      </div>
                      <div className="truncate text-[12px] text-muted-foreground">
                        {[r.language, r.default_branch && `default ${r.default_branch}`, r.pushed_at && `pushed ${formatDateTime(r.pushed_at)}`, r.size_bytes ? formatBytes(r.size_bytes) : ""]
                          .filter(Boolean)
                          .join(" · ")}
                      </div>
                      {r.description && <div className="truncate text-[12px] text-muted-foreground">{r.description}</div>}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
          {repos.hasNextPage && (
            <div className="flex justify-center border-t border-border p-2">
              <Button size="sm" variant="secondary" disabled={repos.isFetchingNextPage} onClick={() => void repos.fetchNextPage()}>
                {repos.isFetchingNextPage ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </Card>
      </div>

      <div>
        <div className="mb-1.5 text-[12px] font-medium">Selected ({state.items.length})</div>
        {!state.items.length ? (
          <p className="rounded-md border border-dashed border-border p-4 text-[13px] text-muted-foreground">Select one or more repositories. All of them receive the metadata you enter next.</p>
        ) : (
          <ul className="space-y-2">
            {state.items.map((it) => (
              <SelectedItem
                key={it.repo.external_id}
                conn={conn}
                item={it}
                expanded={focus === it.repo.external_id}
                onToggle={() => setFocus(focus === it.repo.external_id ? null : it.repo.external_id)}
                onChange={(p) => update(it.repo.external_id, p)}
                onRemove={() => toggle(it.repo)}
              />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function SelectedItem({
  conn,
  item,
  expanded,
  onToggle,
  onChange,
  onRemove,
}: {
  conn: ScmConnection;
  item: ScmItem;
  expanded: boolean;
  onToggle: () => void;
  onChange: (p: Partial<ScmItem>) => void;
  onRemove: () => void;
}) {
  const r = item.repo;
  // Details (branches, commit, languages) load lazily: when expanded or when the branch list is opened.
  const [wanted, setWanted] = useState(false);
  const details = useRemoteRepoDetails(
    conn.id,
    expanded || wanted ? { external_id: r.external_id, full_name: r.full_name, organization: r.organization, project: r.project } : null,
  );
  const d = details.data;
  const langs = Object.entries(d?.languages ?? {}).sort((a, b) => b[1] - a[1]);
  const langTotal = langs.reduce((n, [, v]) => n + v, 0) || 1;
  const branchId = `branch-${r.external_id}`;
  return (
    <li className="rounded-md border border-border bg-surface p-2.5 text-[12px]">
      <div className="flex items-center gap-1.5">
        <button type="button" onClick={onToggle} aria-expanded={expanded} className="flex min-w-0 flex-1 items-center gap-1 text-left text-[13px] font-medium">
          {expanded ? <ChevronDown className="size-4 shrink-0" /> : <ChevronRight className="size-4 shrink-0" />}
          <span className="truncate">{r.full_name}</span>
        </button>
        <Button type="button" size="sm" variant="ghost" onClick={onRemove} aria-label={`Remove ${r.full_name}`}>
          Remove
        </Button>
      </div>
      <div className="mt-2 grid gap-2 sm:grid-cols-2">
        <label htmlFor={branchId} className="text-muted-foreground">
          Branch
          <Select
            id={branchId}
            className="mt-0.5 w-full"
            value={item.branch}
            onFocus={() => setWanted(true)}
            onMouseDown={() => setWanted(true)}
            onChange={(e) => onChange({ branch: e.target.value })}
          >
            <option value="">Default ({r.default_branch || "auto"})</option>
            {(d?.branches ?? [])
              .filter((b) => !b.is_default)
              .map((b) => (
                <option key={b.name} value={b.name}>
                  {b.name}
                </option>
              ))}
          </Select>
          {details.isFetching && <span className="text-[11px]">Loading branches…</span>}
        </label>
        <label className="flex items-center gap-1.5 self-end pb-1.5" title="Clone the complete history so secret scanning covers past commits (slower).">
          <input type="checkbox" className="accent-[var(--primary)]" checked={item.full_history} onChange={(e) => onChange({ full_history: e.target.checked })} />
          Full history
        </label>
        <label className="text-muted-foreground">
          Display name
          <Input className="mt-0.5" value={item.display_name} maxLength={200} onChange={(e) => onChange({ display_name: e.target.value })} aria-invalid={!item.display_name.trim() || undefined} />
        </label>
        <label className="text-muted-foreground">
          Asset name
          <Input className="mt-0.5 font-mono" value={item.asset_name} maxLength={100} onChange={(e) => onChange({ asset_name: e.target.value })} aria-invalid={!item.asset_name.trim() || undefined} />
        </label>
      </div>
      {details.isError && <p className="mt-1.5 text-danger">Could not load details: {details.error.message}</p>}
      {expanded && (
        <div className="mt-2 space-y-1.5 rounded bg-surface-muted/60 p-2" aria-label={`Preview of ${r.full_name}`}>
          {details.isPending ? (
            <Skeleton className="h-14" />
          ) : d ? (
            <>
              {d.latest_commit && (
                <div>
                  <span className="text-muted-foreground">Latest commit </span>
                  <code>{d.latest_commit.sha.slice(0, 10)}</code> {d.latest_commit.message.split("\n")[0]}
                  <span className="text-muted-foreground"> · {d.latest_commit.author} · {formatDateTime(d.latest_commit.committed_at)}</span>
                </div>
              )}
              <div>
                <span className="text-muted-foreground">Branches </span>
                {d.branches.length}
                <span className="text-muted-foreground"> · Access </span>
                <span className={d.permission === "unknown" ? "text-warning" : undefined}>{d.permission}</span>
              </div>
              {langs.length > 0 && (
                <div className="flex flex-wrap gap-x-2">
                  {langs.slice(0, 6).map(([l, v]) => (
                    <span key={l}>
                      {l} <span className="text-muted-foreground">{Math.round((100 * v) / langTotal)}%</span>
                    </span>
                  ))}
                </div>
              )}
              {r.url && (
                <a href={r.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
                  Open in provider <ExternalLink className="size-3" />
                </a>
              )}
            </>
          ) : null}
        </div>
      )}
    </li>
  );
}

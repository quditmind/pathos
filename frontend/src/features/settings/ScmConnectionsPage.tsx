import { useEffect, useState } from "react";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { KeyRound, LogIn, Plug, Plus, RefreshCw, RotateCw, Trash2 } from "lucide-react";
import { api, ApiError } from "@/api/client";
import type { OAuthApp, ProviderInfo, ScmConnection } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Card, EmptyState, Input, PageHeader, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { useConnections, useRepoMutation } from "@/features/repos/api";
import { ConnectionStatusBadge } from "@/features/repos/onboarding/ScmSource";
import { formatDateTime } from "@/lib/utils";
import { AuthFields, authFieldBody } from "./AuthFields";
import { ConnectProviderDialog } from "./ConnectProviderDialog";
import { CopyButton, OAuthAppsSection } from "./OAuthAppsSection";
import { authTypeLabels, providerLabel, startOAuth, useProviders, useUpdateConnection } from "./scmApi";
import { ErrorPanel } from "@/components/ui/error-panel";

export interface ScmSearch {
  tab?: "oauth";
  connect?: "git" | "devops" | "any";
  oauth?: "success" | "error";
  connection?: string;
  message?: string;
}

export function validateScmSearch(s: Record<string, unknown>): ScmSearch {
  const str = (v: unknown, max = 300) => (typeof v === "string" && v.length <= max ? v : undefined);
  return {
    tab: s.tab === "oauth" ? "oauth" : undefined,
    connect: s.connect === "git" || s.connect === "devops" || s.connect === "any" ? s.connect : undefined,
    oauth: s.oauth === "success" || s.oauth === "error" ? s.oauth : undefined,
    connection: str(s.connection, 64),
    message: str(s.message),
  };
}

export function ScmConnectionsPage() {
  const { canOrgWide } = useSession();
  const manage = canOrgWide("scm.manage");
  const search = useSearch({ strict: false }) as ScmSearch;
  const navigate = useNavigate();
  const conns = useConnections();
  const providers = useProviders();
  const [notice, setNotice] = useState<{ tone: "success" | "danger"; text: string } | null>(null);
  const [connectOpen, setConnectOpen] = useState(!!search.connect && manage);
  const [createOAuthFor, setCreateOAuthFor] = useState<OAuthApp["provider"] | null>(null);
  const tab = search.tab ?? "connections";

  // OAuth callback result: show it once, then clear the query.
  useEffect(() => {
    if (!search.oauth) return;
    setNotice(
      search.oauth === "success"
        ? { tone: "success", text: "The provider connection was authorised and saved." }
        : { tone: "danger", text: `The provider sign-in did not complete: ${search.message || "unknown error"}` },
    );
    void navigate({ to: "/admin/scm", search: (search.tab ? { tab: search.tab } : {}) as never, replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search.oauth]);

  const setTab = (t: "connections" | "oauth") => void navigate({ to: "/admin/scm", search: (t === "oauth" ? { tab: "oauth" } : {}) as never, replace: true });

  return (
    <>
      <PageHeader
        title="SCM connections"
        description="Git and DevOps providers used to discover and import repositories and receive webhooks. Credentials are encrypted at rest and never shown again."
        actions={
          manage && (
            <Button onClick={() => setConnectOpen(true)}>
              <Plus /> Connect provider
            </Button>
          )
        }
      />
      {notice && (
        <div className="mb-3">
          <Alert tone={notice.tone}>
            {notice.text}{" "}
            <button className="underline" onClick={() => setNotice(null)}>
              Dismiss
            </button>
          </Alert>
        </div>
      )}
      <div className="mb-4 flex gap-1 border-b border-border" role="tablist" aria-label="SCM settings">
        {(
          [
            ["connections", "Connections"],
            ["oauth", "OAuth applications"],
          ] as const
        ).map(([k, l]) => (
          <button
            key={k}
            role="tab"
            aria-selected={tab === k}
            onClick={() => setTab(k)}
            className={`-mb-px border-b-2 px-3 py-1.5 text-[13px] ${tab === k ? "border-primary font-medium text-primary" : "border-transparent text-muted-foreground hover:text-foreground"}`}
          >
            {l}
          </button>
        ))}
      </div>

      {tab === "oauth" ? (
        <OAuthAppsSection manage={manage} createFor={createOAuthFor} onCreateHandled={() => setCreateOAuthFor(null)} />
      ) : conns.isPending ? (
        <Skeleton className="h-32" />
      ) : conns.isError ? (
        <Alert>
          {conns.error.message}{" "}
          <button className="underline" onClick={() => void conns.refetch()}>
            Try again
          </button>
        </Alert>
      ) : !conns.data.length ? (
        <Card>
          <EmptyState icon={<Plug />} title="No connections yet">
            Connect GitHub, GitLab, Bitbucket or Azure DevOps to start importing repositories.
            {manage && (
              <div className="mt-3">
                <Button onClick={() => setConnectOpen(true)}>
                  <Plus /> Connect provider
                </Button>
              </div>
            )}
          </EmptyState>
        </Card>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {conns.data.map((c) => (
            <ConnectionCard key={c.id} c={c} providers={providers.data} manage={manage} highlight={search.connection === c.id} onNotice={setNotice} />
          ))}
        </div>
      )}

      <ConnectProviderDialog
        open={connectOpen}
        onOpenChange={(o) => {
          setConnectOpen(o);
          if (!o && search.connect) void navigate({ to: "/admin/scm", search: {} as never, replace: true });
        }}
        providers={providers.data}
        category={search.connect === "git" || search.connect === "devops" ? search.connect : undefined}
        onCreated={(c) => setNotice({ tone: "success", text: `Connection “${c.name}” created${c.status === "ok" ? " and verified" : ""}.` })}
        onRegisterOAuthApp={(p) => {
          setCreateOAuthFor(p as OAuthApp["provider"]);
          setTab("oauth");
        }}
      />
      {providers.isError && (
        <div className="mt-3">
          <Alert tone="warning">Provider catalog unavailable: {providers.error.message}</Alert>
        </div>
      )}
    </>
  );
}

function ConnectionCard({
  c,
  providers,
  manage,
  highlight,
  onNotice,
}: {
  c: ScmConnection;
  providers?: ProviderInfo[];
  manage: boolean;
  highlight: boolean;
  onNotice: (n: { tone: "success" | "danger"; text: string }) => void;
}) {
  const test = useRepoMutation((id: string) => api<ScmConnection>(`/api/v1/scm-connections/${id}/test`, { method: "POST" }));
  const webhook = useRepoMutation((id: string) => api<{ webhook_url: string; webhook_secret: string }>(`/api/v1/scm-connections/${id}/webhook-secret`, { method: "POST" }));
  const del = useRepoMutation((id: string) => api(`/api/v1/scm-connections/${id}`, { method: "DELETE" }));
  const resync = useRepoMutation((id: string) =>
    api<{ checked: number; updated: number; missing: number; archived_upstream: number }>(`/api/v1/scm-connections/${id}/resync`, { method: "POST" }),
  );
  const [secret, setSecret] = useState<{ url: string; secret: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [reconnectError, setReconnectError] = useState<string | null>(null);
  const error = test.error ?? webhook.error ?? resync.error;
  const isOAuth = c.auth_type === "oauth";
  const needsReconnect = c.status === "expired" || c.status === "revoked";
  const expiresSoon = c.token_expires_at && new Date(c.token_expires_at).getTime() - Date.now() < 7 * 86400_000;

  const reconnect = async () => {
    if (!c.oauth_app_id) return setReconnectError("This connection has no OAuth application; delete it and connect again.");
    try {
      await startOAuth({ oauth_app_id: c.oauth_app_id, connection_id: c.id, return_to: "/admin/scm" });
    } catch (e) {
      setReconnectError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Card className={`p-4 ${highlight ? "ring-2 ring-primary/40" : ""}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="font-semibold">{c.name}</div>
          <div className="text-[12px] text-muted-foreground">
            {providerLabel(c.provider, providers)} · {c.auth_type === "github_app" ? `GitHub App ${c.github_app_id ?? ""}` : authTypeLabels[c.auth_type] ?? c.auth_type}
            {c.owner && ` · ${c.owner}`}
          </div>
          {c.account && <div className="text-[12px]">Signed in as <span className="font-medium">{c.account}</span></div>}
          <div className="truncate text-[12px] text-muted-foreground">{c.base_url}</div>
        </div>
        <ConnectionStatusBadge c={c} />
      </div>
      {c.status_message && c.status !== "ok" && <p className="mt-2 text-[12px] text-danger">{c.status_message}</p>}
      {c.status === "ok" && c.status_message && <p className="mt-2 text-[12px] text-muted-foreground">{c.status_message}</p>}
      {needsReconnect && (
        <div className="mt-2">
          <Alert tone="warning">
            The credential {c.status === "expired" ? "expired and could not be refreshed" : "was revoked at the provider"}.{" "}
            {isOAuth ? "Reconnect to authorise PATHOS again." : "Rotate the credential to continue."}
          </Alert>
        </div>
      )}
      <div className="mt-3 space-y-0.5 text-[12px] text-muted-foreground">
        <div>
          {c.repository_count} repositories · checked {formatDateTime(c.last_checked_at)}
        </div>
        {c.token_expires_at && (
          <div className={expiresSoon ? "text-warning" : undefined}>
            Token expires {formatDateTime(c.token_expires_at)}
            {isOAuth && " (refreshed automatically)"}
          </div>
        )}
        {c.organizations?.length > 0 && <div>Limited to: {c.organizations.join(", ")}</div>}
      </div>
      {resync.isSuccess && (
        <p className="mt-1 text-[12px] text-success">
          Re-synced: {resync.data.checked} checked, {resync.data.updated} updated
          {resync.data.missing ? `, ${resync.data.missing} no longer visible` : ""}
        </p>
      )}
      {test.isSuccess && <p className="mt-1 text-[12px] text-success">Test {test.data.status === "ok" ? "succeeded" : `finished: ${test.data.status_message || test.data.status}`}.</p>}
      {error && <p className="mt-1 text-[12px] text-danger">{error.message}</p>}
      {reconnectError && <p className="mt-1 text-[12px] text-danger">{reconnectError}</p>}
      {manage && (
        <>
          {c.webhook_url && (
            <div className="mt-3 flex items-center gap-2 rounded-md bg-surface-muted/60 p-2 text-[12px]">
              <div className="min-w-0 flex-1">
                <div className="text-muted-foreground">Webhook URL{c.provider.startsWith("azure") ? " (service hooks with basic auth)" : ""}</div>
                <code className="break-all">{c.webhook_url}</code>
              </div>
              <CopyButton value={c.webhook_url} label="webhook URL" />
            </div>
          )}
          <div className="mt-3 flex flex-wrap gap-2">
            {isOAuth && (
              <Button size="sm" variant={needsReconnect ? "primary" : "secondary"} onClick={() => void reconnect()}>
                <LogIn /> Reconnect
              </Button>
            )}
            <Button size="sm" variant="secondary" disabled={test.isPending} onClick={() => test.mutate(c.id)}>
              <RefreshCw /> Test
            </Button>
            {!isOAuth && (
              <Button size="sm" variant={needsReconnect ? "primary" : "secondary"} onClick={() => setRotating(true)}>
                <RotateCw /> Rotate credential
              </Button>
            )}
            <Button
              size="sm"
              variant="secondary"
              disabled={resync.isPending || c.repository_count === 0}
              title="Refresh names, default branches, visibility and archive state of imported repositories (also runs nightly)"
              onClick={() => resync.mutate(c.id)}
            >
              <RefreshCw /> Re-sync metadata
            </Button>
            <Button size="sm" variant="secondary" disabled={webhook.isPending} onClick={() => webhook.mutate(c.id, { onSuccess: (r) => setSecret({ url: r.webhook_url, secret: r.webhook_secret }) })}>
              <KeyRound /> New webhook secret
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="ml-auto text-danger"
              disabled={c.repository_count > 0}
              title={c.repository_count > 0 ? "Archive or delete its repositories first" : "Delete connection"}
              aria-label={`Delete connection ${c.name}`}
              onClick={() => setConfirmDelete(true)}
            >
              <Trash2 />
            </Button>
          </div>
        </>
      )}
      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={`Delete connection “${c.name}”?`}
        confirmLabel="Delete connection"
        pending={del.isPending}
        error={del.error?.message}
        onConfirm={() =>
          del.mutate(c.id, {
            onSuccess: () => {
              setConfirmDelete(false);
              onNotice({ tone: "success", text: `Connection “${c.name}” deleted.` });
            },
          })
        }
      >
        <p>
          PATHOS asks {providerLabel(c.provider, providers)} to revoke the credential where the provider supports it (GitHub and GitLab tokens), then destroys the stored secret.
          Webhooks pointing at this connection stop working.
        </p>
        <p className="text-muted-foreground">For other providers, also revoke the token or app authorisation at the provider.</p>
      </ConfirmDialog>
      {rotating && <RotateDialog c={c} providers={providers} onClose={() => setRotating(false)} onDone={() => onNotice({ tone: "success", text: `Credential of “${c.name}” rotated.` })} />}
      <Dialog
        open={!!secret}
        onOpenChange={(o) => !o && setSecret(null)}
        title="Webhook secret"
        description="Copy it now: it is not shown again."
        footer={<Button onClick={() => setSecret(null)}>Done</Button>}
      >
        {secret && (
          <div className="space-y-3 text-[13px]">
            <CopyField label="Payload URL" value={secret.url} />
            <CopyField label="Secret (GitHub/GitLab/Bitbucket: webhook secret · Azure DevOps: basic auth password)" value={secret.secret} />
            <p className="text-[12px] text-muted-foreground">GitHub: content type application/json, events “Pushes” and “Pull requests”.</p>
          </div>
        )}
      </Dialog>
    </Card>
  );
}

function CopyField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="mb-1 text-[12px] text-muted-foreground">{label}</div>
      <div className="flex gap-2">
        <Input readOnly value={value} className="font-mono text-[12px]" aria-label={label} onFocus={(e) => e.target.select()} />
        <CopyButton value={value} label={label} />
      </div>
    </div>
  );
}

function RotateDialog({ c, providers, onClose, onDone }: { c: ScmConnection; providers?: ProviderInfo[]; onClose: () => void; onDone: () => void }) {
  const method = providers?.find((p) => p.key === c.provider)?.auth_methods.find((m) => m.key === c.auth_type);
  const fields = (method?.fields ?? []).filter((f) => f.secret);
  const [values, setValues] = useState<Record<string, string>>({});
  const update = useUpdateConnection();
  const errs = update.error instanceof ApiError ? update.error.fields : undefined;
  const filled = fields.some((f) => (values[f.name] ?? "").trim());
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={`Rotate credential of “${c.name}”`}
      description="The new credential replaces the stored one immediately and is tested."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={!filled || update.isPending}
            onClick={() =>
              update.mutate(
                { id: c.id, body: authFieldBody(fields, values, { skipBlankSecrets: true }) },
                {
                  onSuccess: () => {
                    onDone();
                    onClose();
                  },
                },
              )
            }
          >
            {update.isPending ? "Saving…" : "Replace credential"}
          </Button>
        </>
      }
    >
      {update.isError && !errs && (
        <div className="mb-3">
          <ErrorPanel error={update.error} />
        </div>
      )}
      {!providers ? (
        <Skeleton className="h-20" />
      ) : !fields.length ? (
        <p className="text-[13px] text-muted-foreground">This authentication method has no rotatable secret. Delete the connection and connect again instead.</p>
      ) : (
        <AuthFields fields={fields} values={values} onChange={(n, v) => setValues((x) => ({ ...x, [n]: v }))} errors={errs} optionalSecrets={fields.length > 1} />
      )}
    </Dialog>
  );
}

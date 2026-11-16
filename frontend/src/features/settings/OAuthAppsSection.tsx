import { useState } from "react";
import { Copy, KeyRound, Pencil, Plus, Trash2 } from "lucide-react";
import { ApiError } from "@/api/client";
import type { OAuthApp, OAuthAppRequest } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Card, EmptyState, Input, Select, Skeleton } from "@/components/ui/primitives";
import { FormField } from "@/features/repos/metadata/fields";
import { formatDateTime } from "@/lib/utils";
import { oauthHints, providerLabels, useDeleteOAuthApp, useOAuthApps, useSaveOAuthApp } from "./scmApi";

const oauthProviders = Object.keys(oauthHints) as OAuthApp["provider"][];

export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      variant="secondary"
      size="sm"
      aria-label={`Copy ${label}`}
      onClick={() =>
        void navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        })
      }
    >
      <Copy /> {copied ? "Copied" : "Copy"}
    </Button>
  );
}

export function OAuthAppsSection({ manage, createFor, onCreateHandled }: { manage: boolean; createFor?: OAuthApp["provider"] | null; onCreateHandled?: () => void }) {
  const apps = useOAuthApps(manage);
  const del = useDeleteOAuthApp();
  const [editing, setEditing] = useState<OAuthApp | "new" | null>(null);
  const [deleting, setDeleting] = useState<OAuthApp | null>(null);
  const creating = editing === "new" || !!createFor;

  if (!manage) return <Alert tone="warning">Managing OAuth applications requires the SCM management permission.</Alert>;

  return (
    <div className="space-y-3">
      <div className="flex items-start justify-between gap-3">
        <p className="max-w-2xl text-[13px] text-muted-foreground">
          OAuth applications let users connect providers by signing in, instead of pasting tokens. Register the application at the provider with the redirect URI shown, then enter
          its client ID and secret here. Secrets are stored encrypted and never shown again.
        </p>
        <Button onClick={() => setEditing("new")}>
          <Plus /> Register application
        </Button>
      </div>
      {apps.isPending ? (
        <Skeleton className="h-32" />
      ) : apps.isError ? (
        <Alert>
          {apps.error.message}{" "}
          <button className="underline" onClick={() => void apps.refetch()}>
            Try again
          </button>
        </Alert>
      ) : !apps.data.length ? (
        <Card>
          <EmptyState icon={<KeyRound />} title="No OAuth applications">
            Register one to offer “Sign in with GitHub / GitLab / Bitbucket / Microsoft” when connecting providers.
          </EmptyState>
        </Card>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {apps.data.map((a) => (
            <Card key={a.id} className="space-y-2 p-4 text-[13px]">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="font-semibold">{a.name}</div>
                  <div className="text-[12px] text-muted-foreground">
                    {providerLabels[a.provider]}
                    {a.base_url && ` · ${a.base_url}`}
                    {a.tenant_id && ` · tenant ${a.tenant_id}`}
                  </div>
                </div>
                <div className="flex gap-0.5">
                  <Button size="icon" variant="ghost" aria-label={`Edit ${a.name}`} onClick={() => setEditing(a)}>
                    <Pencil />
                  </Button>
                  <Button size="icon" variant="ghost" className="text-danger" aria-label={`Delete ${a.name}`} onClick={() => setDeleting(a)}>
                    <Trash2 />
                  </Button>
                </div>
              </div>
              <div className="text-[12px]">
                <span className="text-muted-foreground">Client ID </span>
                <code className="break-all">{a.client_id}</code>
              </div>
              <div className="text-[12px]">
                <span className="text-muted-foreground">Scopes </span>
                <code>{a.scopes || "—"}</code>
              </div>
              <div className="flex items-center gap-2 rounded-md bg-surface-muted/60 p-2 text-[12px]">
                <div className="min-w-0 flex-1">
                  <div className="text-muted-foreground">Redirect URI</div>
                  <code className="break-all">{a.redirect_uri}</code>
                </div>
                <CopyButton value={a.redirect_uri} label="redirect URI" />
              </div>
              <div className="text-[12px] text-muted-foreground">
                {a.connection_count} connection{a.connection_count === 1 ? "" : "s"} · registered {formatDateTime(a.created_at)}
              </div>
            </Card>
          ))}
        </div>
      )}
      {(editing || createFor) && (
        <OAuthAppDialog
          app={editing && editing !== "new" ? editing : null}
          initialProvider={creating ? createFor ?? undefined : undefined}
          onClose={() => {
            setEditing(null);
            onCreateHandled?.();
          }}
        />
      )}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete “${deleting?.name}”?`}
        confirmLabel="Delete application"
        pending={del.isPending}
        error={del.error?.message}
        onConfirm={() => deleting && del.mutate(deleting.id, { onSuccess: () => setDeleting(null) })}
      >
        <p>The client secret is destroyed.</p>
        {!!deleting?.connection_count && (
          <p className="text-warning">
            {deleting.connection_count} connection{deleting.connection_count === 1 ? " uses" : "s use"} this application: their tokens can no longer be refreshed and they will need
            to be reconnected with another application.
          </p>
        )}
      </ConfirmDialog>
    </div>
  );
}

function OAuthAppDialog({ app, initialProvider, onClose }: { app: OAuthApp | null; initialProvider?: OAuthApp["provider"]; onClose: () => void }) {
  const p0 = app?.provider ?? initialProvider ?? "github";
  const [f, setF] = useState({
    provider: p0,
    name: app?.name ?? providerLabels[p0] ?? "",
    base_url: app?.base_url ?? "",
    tenant_id: app?.tenant_id ?? "",
    client_id: app?.client_id ?? "",
    client_secret: "",
    scopes: app?.scopes ?? oauthHints[p0].scopes,
  });
  const save = useSaveOAuthApp();
  const fields = save.error instanceof ApiError ? save.error.fields : undefined;
  const hint = oauthHints[f.provider];
  const redirect = app?.redirect_uri ?? `${window.location.origin}/api/v1/scm-oauth/callback`;
  const showBase = f.provider === "github_enterprise" || f.provider === "gitlab";

  const submit = () => {
    const body: OAuthAppRequest = {
      name: f.name.trim(),
      base_url: showBase ? f.base_url.trim() : "",
      tenant_id: hint.tenant ? f.tenant_id.trim() : "",
      client_id: f.client_id.trim(),
      scopes: f.scopes.trim(),
    };
    if (!app) body.provider = f.provider;
    if (f.client_secret) body.client_secret = f.client_secret;
    save.mutate({ id: app?.id, body }, { onSuccess: onClose });
  };
  const valid = f.name.trim() && f.client_id.trim() && (app || f.client_secret) && (!hint.tenant || f.tenant_id.trim()) && (f.provider !== "github_enterprise" || f.base_url.trim());

  return (
    <Dialog
      open
      size="lg"
      onOpenChange={(o) => !o && onClose()}
      title={app ? `Edit ${app.name}` : "Register OAuth application"}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!valid || save.isPending}>
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {save.isError && !fields && <Alert>{save.error.message}</Alert>}
        <div className="grid gap-3 sm:grid-cols-2">
          <FormField label="Provider" required>
            <Select
              className="w-full"
              disabled={!!app}
              value={f.provider}
              onChange={(e) => {
                const p = e.target.value as OAuthApp["provider"];
                setF({ ...f, provider: p, scopes: oauthHints[p].scopes, name: f.name === providerLabels[f.provider] ? providerLabels[p]! : f.name });
              }}
            >
              {oauthProviders.map((p) => (
                <option key={p} value={p}>
                  {providerLabels[p]}
                </option>
              ))}
            </Select>
          </FormField>
          <FormField label="Name" required error={fields?.name}>
            <Input value={f.name} maxLength={100} onChange={(e) => setF({ ...f, name: e.target.value })} />
          </FormField>
        </div>
        <div className="rounded-md border border-border bg-surface-muted/50 p-3 text-[12px]">
          <div className="font-medium">Register at the provider</div>
          <p className="mt-0.5 text-muted-foreground">{hint.where}</p>
          {hint.note && <p className="mt-1 text-warning">{hint.note}</p>}
          <div className="mt-2 flex items-center gap-2">
            <div className="min-w-0 flex-1">
              <div className="text-muted-foreground">Redirect / callback URI{app ? "" : " (preview)"}</div>
              <Input readOnly value={redirect} className="font-mono text-[12px]" aria-label="Redirect URI" onFocus={(e) => e.target.select()} />
            </div>
            <div className="self-end">
              <CopyButton value={redirect} label="redirect URI" />
            </div>
          </div>
        </div>
        {showBase && (
          <FormField label="Base URL" required={f.provider === "github_enterprise"} error={fields?.base_url} hint={hint.baseUrl}>
            <Input type="url" value={f.base_url} onChange={(e) => setF({ ...f, base_url: e.target.value })} />
          </FormField>
        )}
        {hint.tenant && (
          <FormField label="Tenant ID" required error={fields?.tenant_id} hint="Microsoft Entra directory (tenant) ID.">
            <Input value={f.tenant_id} onChange={(e) => setF({ ...f, tenant_id: e.target.value })} />
          </FormField>
        )}
        <div className="grid gap-3 sm:grid-cols-2">
          <FormField label="Client ID" required error={fields?.client_id}>
            <Input value={f.client_id} autoComplete="off" onChange={(e) => setF({ ...f, client_id: e.target.value })} />
          </FormField>
          <FormField label="Client secret" required={!app} error={fields?.client_secret} hint={app ? "Leave blank to keep the current secret." : "Write-only: it is never shown again."}>
            <Input type="password" autoComplete="new-password" value={f.client_secret} onChange={(e) => setF({ ...f, client_secret: e.target.value })} />
          </FormField>
        </div>
        <FormField label="Scopes" error={fields?.scopes} hint={`Recommended: ${hint.scopes}`}>
          <Input className="font-mono" value={f.scopes} onChange={(e) => setF({ ...f, scopes: e.target.value })} />
        </FormField>
      </div>
    </Dialog>
  );
}

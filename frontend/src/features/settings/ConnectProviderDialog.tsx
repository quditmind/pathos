import { useState } from "react";
import { ArrowLeft, ExternalLink, LogIn } from "lucide-react";
import { ApiError } from "@/api/client";
import type { AuthMethod, ProviderInfo, ScmConnection } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Input, Select, Skeleton } from "@/components/ui/primitives";
import { FormField } from "@/features/repos/metadata/fields";
import { cn } from "@/lib/utils";
import { AuthFields, authFieldBody, missingAuthFields } from "./AuthFields";
import { startOAuth, useCreateConnection, useOAuthApps } from "./scmApi";

type Step = "provider" | "method" | "details";

/** "Connect provider" wizard: provider → auth method → credentials or OAuth redirect. */
export function ConnectProviderDialog({
  open,
  onOpenChange,
  providers,
  category,
  onCreated,
  onRegisterOAuthApp,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  providers: ProviderInfo[] | undefined;
  category?: "git" | "devops";
  onCreated: (c: ScmConnection) => void;
  onRegisterOAuthApp: (provider: ProviderInfo["key"]) => void;
}) {
  const [step, setStep] = useState<Step>("provider");
  const [provider, setProvider] = useState<ProviderInfo | null>(null);
  const [method, setMethod] = useState<AuthMethod | null>(null);
  const [f, setF] = useState({ name: "", base_url: "", owner: "", oauth_app_id: "" });
  const [values, setValues] = useState<Record<string, string>>({});
  const [missing, setMissing] = useState<string[]>([]);
  const [oauthError, setOauthError] = useState<string | null>(null);
  const [redirecting, setRedirecting] = useState(false);
  const create = useCreateConnection();
  const apps = useOAuthApps(open);

  const reset = () => {
    setStep("provider");
    setProvider(null);
    setMethod(null);
    setF({ name: "", base_url: "", owner: "", oauth_app_id: "" });
    setValues({});
    setMissing([]);
    setOauthError(null);
    create.reset();
  };
  const close = () => {
    reset();
    onOpenChange(false);
  };

  const list = (providers ?? []).filter((p) => !category || p.category === category);
  const fieldErrors = create.error instanceof ApiError ? create.error.fields : undefined;
  const extraFields = (method?.fields ?? []).filter((x) => !["name", "base_url", "owner"].includes(x.name));
  const appsForProvider = (apps.data ?? []).filter((a) => a.provider === provider?.key);

  const submit = async () => {
    if (!provider || !method) return;
    if (method.oauth) {
      if (!f.oauth_app_id) return setOauthError("Choose an OAuth application.");
      setOauthError(null);
      setRedirecting(true);
      try {
        await startOAuth({ oauth_app_id: f.oauth_app_id, name: f.name.trim() || undefined, owner: f.owner.trim() || undefined, return_to: "/admin/scm" });
      } catch (e) {
        setRedirecting(false);
        setOauthError(e instanceof Error ? e.message : String(e));
      }
      return;
    }
    const miss = missingAuthFields(extraFields, values);
    if (!f.name.trim()) miss.unshift("Name");
    if (provider.base_url_required && !f.base_url.trim()) miss.push("Base URL");
    setMissing(miss);
    if (miss.length) return;
    const body: Record<string, unknown> = {
      name: f.name.trim(),
      provider: provider.key,
      auth_type: method.key,
      ...(f.base_url.trim() ? { base_url: f.base_url.trim() } : {}),
      ...(f.owner.trim() ? { owner: f.owner.trim() } : {}),
      ...authFieldBody(extraFields, values),
    };
    create.mutate(body, {
      onSuccess: (c) => {
        onCreated(c);
        close();
      },
    });
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => (o ? onOpenChange(true) : close())}
      size="lg"
      title="Connect a provider"
      description={
        step === "provider" ? "Choose where your repositories live." : step === "method" ? `How PATHOS authenticates to ${provider?.label}.` : `${provider?.label} · ${method?.label}`
      }
      footer={
        <>
          {step !== "provider" && (
            <Button variant="ghost" className="mr-auto" onClick={() => setStep(step === "details" ? "method" : "provider")}>
              <ArrowLeft /> Back
            </Button>
          )}
          <Button variant="secondary" onClick={close}>
            Cancel
          </Button>
          {step === "details" && (
            <Button onClick={() => void submit()} disabled={create.isPending || redirecting}>
              {method?.oauth ? (
                <>
                  <LogIn /> {redirecting ? "Redirecting…" : `Continue with ${provider?.label}`}
                </>
              ) : create.isPending ? (
                "Connecting…"
              ) : (
                "Connect"
              )}
            </Button>
          )}
        </>
      }
    >
      {step === "provider" &&
        (!providers ? (
          <Skeleton className="h-40" />
        ) : (
          <div className="grid gap-2 sm:grid-cols-2">
            {list.map((p) => (
              <button
                key={p.key}
                type="button"
                onClick={() => {
                  setProvider(p);
                  setMethod(p.auth_methods.length === 1 ? p.auth_methods[0]! : null);
                  setF({ name: p.label, base_url: "", owner: "", oauth_app_id: "" });
                  setValues({});
                  setStep(p.auth_methods.length === 1 ? "details" : "method");
                }}
                className="flex flex-col items-start gap-1 rounded-md border border-border p-3 text-left hover:border-primary/50 hover:bg-primary/5 focus-visible:outline-2 focus-visible:outline-ring"
              >
                <span className="flex w-full items-center justify-between gap-2 text-[13px] font-medium">
                  {p.label}
                  <Badge>{p.category === "git" ? "Git" : "DevOps"}</Badge>
                </span>
                <span className="text-[12px] text-muted-foreground">{p.auth_methods.map((m) => m.label).join(" · ")}</span>
              </button>
            ))}
            {!list.length && <p className="text-[13px] text-muted-foreground">No providers available.</p>}
          </div>
        ))}

      {step === "method" && provider && (
        <fieldset className="space-y-2">
          <legend className="sr-only">Authentication method</legend>
          {provider.auth_methods.map((m) => (
            <label
              key={m.key}
              className={cn(
                "flex cursor-pointer items-start gap-2.5 rounded-md border p-3 has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-ring",
                method?.key === m.key ? "border-primary bg-primary/5" : "border-border hover:bg-surface-muted/60",
              )}
            >
              <input type="radio" name="auth-method" className="mt-1 accent-[var(--primary)]" checked={method?.key === m.key} onChange={() => setMethod(m)} />
              <span className="min-w-0 flex-1 text-[13px]">
                <span className="flex items-center gap-2 font-medium">
                  {m.label}
                  {m.oauth && <Badge tone="primary">browser sign-in</Badge>}
                </span>
                <span className="block text-[12px] text-muted-foreground">{m.description}</span>
                {m.docs_url && (
                  <a href={m.docs_url} target="_blank" rel="noopener noreferrer" className="mt-0.5 inline-flex items-center gap-1 text-[12px] text-primary hover:underline">
                    Provider documentation <ExternalLink className="size-3" />
                  </a>
                )}
              </span>
            </label>
          ))}
          <div className="flex justify-end pt-1">
            <Button disabled={!method} onClick={() => setStep("details")}>
              Continue
            </Button>
          </div>
        </fieldset>
      )}

      {step === "details" && provider && method && (
        <div className="space-y-3">
          {create.isError && !fieldErrors && <Alert>{create.error.message}</Alert>}
          {missing.length > 0 && <Alert>Required: {missing.join(", ")}</Alert>}
          {oauthError && <Alert>{oauthError}</Alert>}
          <div className="grid gap-3 sm:grid-cols-2">
            <FormField label="Connection name" required={!method.oauth} error={fieldErrors?.name}>
              <Input value={f.name} maxLength={100} onChange={(e) => setF({ ...f, name: e.target.value })} />
            </FormField>
            {provider.owner_label && (
              <FormField label={provider.owner_label} error={fieldErrors?.owner} hint="Optional: limit discovery to this scope.">
                <Input value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} />
              </FormField>
            )}
          </div>
          {method.oauth ? (
            <div className="space-y-2">
              <FormField label="OAuth application" required error={fieldErrors?.oauth_app_id} hint="Registered under the OAuth applications tab.">
                <Select className="w-full" value={f.oauth_app_id} onChange={(e) => setF({ ...f, oauth_app_id: e.target.value })}>
                  <option value="">{apps.isPending ? "Loading…" : "Choose…"}</option>
                  {appsForProvider.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name}
                      {a.base_url ? ` (${a.base_url})` : ""}
                    </option>
                  ))}
                </Select>
              </FormField>
              {apps.isSuccess && !appsForProvider.length && (
                <Alert tone="warning">
                  No OAuth application is registered for {provider.label}.{" "}
                  <button
                    type="button"
                    className="underline"
                    onClick={() => {
                      close();
                      onRegisterOAuthApp(provider.key);
                    }}
                  >
                    Register one
                  </button>{" "}
                  first.
                </Alert>
              )}
              <p className="text-[12px] text-muted-foreground">
                You will be sent to {provider.label} to approve access, then returned here. The token is stored encrypted and never shown.
              </p>
            </div>
          ) : (
            <>
              {(provider.base_url_required || provider.default_base_url || provider.base_url_help) && (
                <FormField label="Base URL" required={provider.base_url_required} error={fieldErrors?.base_url} hint={provider.base_url_help || undefined}>
                  <Input type="url" placeholder={provider.default_base_url || "https://"} value={f.base_url} onChange={(e) => setF({ ...f, base_url: e.target.value })} />
                </FormField>
              )}
              <AuthFields fields={extraFields} values={values} onChange={(n, v) => setValues((x) => ({ ...x, [n]: v }))} errors={fieldErrors} />
              <p className="text-[12px] text-muted-foreground">Use a read-only credential: PATHOS only lists repositories and branches and clones code. Secrets are encrypted at rest and never shown again.</p>
            </>
          )}
        </div>
      )}
    </Dialog>
  );
}

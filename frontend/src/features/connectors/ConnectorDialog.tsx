import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Input, Label, Select } from "@/components/ui/primitives";
import { toast } from "@/components/ui/toast";
import { authMethodOf, categoryLabel, useCreateConnector, useUpdateConnector, type ConfigField, type ConnectorDetail, type ConnectorKind, type NewConnector } from "./api";
import { authMethodLabel } from "./model";

type CredentialMode = "stored" | "ref";

/** A Vault/OpenBao reference as the API accepts it: vault:<mount>/<path>#<key>. */
export const secretRefPattern = /^vault:[^\s/#]+\/[^\s#]+#[^\s#]+$/;

/** Fields shown for a creatable kind that describes no form (older servers). */
const fallbackFields = (k: ConnectorKind | undefined): ConfigField[] => [
  { key: "base_url", label: "Base URL", type: "url", required: false, help: "https://… of the server or API" },
  ...(k?.auth_methods.length ? [{ key: "auth_method", label: "Authentication method", type: "select" as const, required: true, options: k.auth_methods }] : []),
  { key: "ca_bundle_pem", label: "Private CA bundle (PEM)", type: "pem", required: false, help: "Only for a certificate issued by a private CA." },
  ...(k?.secret_refs ? [{ key: "credential_ref", label: "Credential as a Vault/OpenBao reference", type: "secret_ref" as const, required: false }] : []),
];

/** Auth methods that need no credential in PATHOS (Vault Kubernetes auth uses the pod's service-account token). */
const noCredentialMethods = new Set(["kubernetes", "none"]);

/** Label of the write-only credential for an auth method. */
function credentialLabel(kind: string, method: string): string {
  if (method === "ssh_key") return "SSH private key (deploy key)";
  if (kind === "vault" && method === "approle") return "AppRole secret ID";
  return method ? authMethodLabel(method) : "Secret";
}

const str = (v: unknown) => (typeof v === "string" ? v : "");

/**
 * Create (POST /connectors) or edit (PUT /connectors/{id}) a connector of a
 * creatable kind. The form is the kind's `config_fields` from the catalogue.
 * The credential is write-only: it is never read back, and an empty field on
 * edit keeps the stored one. Kinds with `secret_refs` can instead name a
 * Vault/OpenBao secret (`vault:<mount>/<path>#<key>`), resolved at use time.
 */
export function ConnectorDialog({
  open,
  onOpenChange,
  kinds,
  initialKind,
  editing,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  kinds: ConnectorKind[];
  initialKind?: string;
  editing?: ConnectorDetail;
}) {
  const create = useCreateConnector();
  const update = useUpdateConnector();
  const [kind, setKind] = useState("");
  const [name, setName] = useState("");
  const [values, setValues] = useState<Record<string, string | boolean>>({});
  const [mode, setMode] = useState<CredentialMode>("stored");
  const [credential, setCredential] = useState("");

  const fieldsOf = (k: string) => {
    const kd = kinds.find((x) => x.kind === k);
    return kd?.config_fields?.length ? kd.config_fields : fallbackFields(kd);
  };
  const initialValues = (k: string, cfg: Record<string, unknown>) => {
    const out: Record<string, string | boolean> = {};
    for (const f of fieldsOf(k)) {
      if (f.type === "boolean") out[f.key] = cfg[f.key] === true;
      else if (f.type === "pem") out[f.key] = ""; // never read back: paste to replace
      else out[f.key] = str(cfg[f.key]) || (f.type === "select" ? (f.options?.[0] ?? "") : "");
    }
    return out;
  };

  useEffect(() => {
    if (!open) return;
    const k = editing?.kind ?? initialKind ?? kinds[0]?.kind ?? "";
    const cfg = { ...(editing?.config ?? {}) };
    if (editing && !cfg.auth_method) cfg.auth_method = authMethodOf(editing) ?? "";
    setKind(k);
    setName(editing?.name ?? "");
    setValues(initialValues(k, cfg));
    setMode(str(cfg.credential_ref) ? "ref" : "stored");
    setCredential("");
    create.reset();
    update.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, editing?.id, initialKind]);

  const kd = kinds.find((x) => x.kind === kind);
  const fields = fieldsOf(kind);
  const refField = kd?.secret_refs ? fields.find((f) => f.key === "credential_ref") : undefined;
  const formFields = fields.filter((f) => f !== refField);
  const method = str(values.auth_method);
  const needsCredential = !noCredentialMethods.has(method);
  const ref = str(values.credential_ref).trim();
  const caSet = !!editing && ["ca_bundle_set", "ca_set", "ca_pem_set", "ca_bundle_pem", "has_ca_bundle"].some((k) => !!editing.config?.[k] && editing.config[k] !== "no");
  const mutation = editing ? update : create;
  const missing = formFields.filter((f) => f.required && f.type !== "boolean" && !str(values[f.key]).trim());
  const refInvalid = mode === "ref" && !secretRefPattern.test(ref);
  const valid =
    !!kind && name.trim().length > 0 && !missing.length && (mode === "ref" ? !refInvalid : !!editing || !needsCredential || credential.length > 0);

  const set = (key: string, v: string | boolean) => setValues((x) => ({ ...x, [key]: v }));

  const submit = () => {
    const config: Record<string, unknown> = {};
    for (const f of formFields) {
      const v = values[f.key];
      if (f.type === "boolean") {
        if (v) config[f.key] = true;
      } else if (typeof v === "string" && v.trim()) config[f.key] = v.trim();
    }
    if (refField && mode === "ref") config.credential_ref = ref;
    const body: NewConnector = { kind, name: name.trim(), config };
    if (mode === "stored" && needsCredential && credential) body.credential = credential;
    const done = () => {
      toast.success(editing ? `Connector “${body.name}” saved.` : `Connector “${body.name}” added. Run “Check now” to see its health.`);
      setCredential("");
      onOpenChange(false);
    };
    if (editing) update.mutate({ id: editing.id, body }, { onSuccess: done });
    else create.mutate(body, { onSuccess: done });
  };

  const fieldId = (key: string) => `cx-f-${key}`;
  const renderField = (f: ConfigField) => {
    const id = fieldId(f.key);
    const label = (
      <>
        {f.label}
        {f.required && <span aria-hidden="true"> *</span>}
      </>
    );
    const hint = f.type === "pem" && caSet ? "A CA bundle is set; paste a new one to replace it" : f.help;
    const v = values[f.key];
    switch (f.type) {
      case "boolean":
        return (
          <label key={f.key} className="flex items-center gap-2 text-[13px] sm:col-span-2">
            <input id={id} type="checkbox" checked={v === true} onChange={(e) => set(f.key, e.target.checked)} /> {f.label}
            {f.help && <span className="text-[12px] text-muted-foreground">{f.help}</span>}
          </label>
        );
      case "select":
        return (
          <div key={f.key}>
            <Label htmlFor={id} hint={hint}>
              {label}
            </Label>
            <Select id={id} value={str(v)} onChange={(e) => set(f.key, e.target.value)}>
              {(f.options ?? []).map((o) => (
                <option key={o} value={o}>
                  {f.key === "auth_method" ? authMethodLabel(o) : o}
                </option>
              ))}
            </Select>
          </div>
        );
      case "pem":
      case "textarea":
        return (
          <div key={f.key} className="sm:col-span-2">
            <Label htmlFor={id} hint={hint}>
              {label}
            </Label>
            <textarea
              id={id}
              value={str(v)}
              onChange={(e) => set(f.key, e.target.value)}
              rows={3}
              spellCheck={false}
              placeholder={f.type === "pem" ? "-----BEGIN CERTIFICATE-----" : undefined}
              className="w-full rounded-md border border-border bg-surface px-2.5 py-1.5 font-mono text-[12px] focus-visible:outline-2 focus-visible:outline-ring"
            />
          </div>
        );
      default:
        return (
          <div key={f.key}>
            <Label htmlFor={id} hint={hint}>
              {label}
            </Label>
            <Input
              id={id}
              value={str(v)}
              onChange={(e) => set(f.key, e.target.value)}
              inputMode={f.type === "url" ? "url" : undefined}
              placeholder={f.type === "secret_ref" ? "vault:secret/pathos/app#token" : f.type === "url" ? "https://" : undefined}
              aria-required={f.required || undefined}
            />
          </div>
        );
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="lg"
      title={editing ? `Edit ${editing.name}` : "Add connector"}
      description="Credentials are write-only: PATHOS encrypts them and never shows them again."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!valid || mutation.isPending}>
            {mutation.isPending ? "Saving…" : editing ? "Save" : "Add connector"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {mutation.isError && <ErrorPanel error={mutation.error} title="The connector was not saved" onVerify={submit} />}
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="cx-kind">Kind</Label>
            <Select
              id="cx-kind"
              value={kind}
              disabled={!!editing}
              onChange={(e) => {
                setKind(e.target.value);
                setValues(initialValues(e.target.value, {}));
                setMode("stored");
              }}
            >
              {kinds.map((k) => (
                <option key={k.kind} value={k.kind}>
                  {k.label} ({categoryLabel(k.category)})
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="cx-name">Name</Label>
            <Input id="cx-name" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} placeholder="For example: Internal Git server" />
          </div>
          {formFields.map(renderField)}
        </div>
        {kd?.note && <p className="text-[12px] text-muted-foreground">{kd.note}</p>}
        {(needsCredential || refField) && (
          <fieldset className="space-y-2 rounded-md border border-border p-3">
            <legend className="px-1 text-[12px] font-medium">Credential</legend>
            {refField && method !== "ssh_key" && (
              <div className="flex flex-wrap gap-4 text-[13px]" role="radiogroup" aria-label="Where the credential is kept">
                <label className="flex items-center gap-1.5">
                  <input type="radio" name="cx-cred" checked={mode === "stored"} onChange={() => setMode("stored")} /> Store in PATHOS (encrypted)
                </label>
                <label className="flex items-center gap-1.5">
                  <input type="radio" name="cx-cred" checked={mode === "ref"} onChange={() => setMode("ref")} /> Reference a secret in Vault or OpenBao
                </label>
              </div>
            )}
            {mode === "ref" && refField && method !== "ssh_key" ? (
              <div>
                <Label htmlFor="cx-ref" hint="vault:<mount>/<path>#<key>">
                  Secret reference
                </Label>
                <Input
                  id="cx-ref"
                  value={ref}
                  onChange={(e) => set("credential_ref", e.target.value)}
                  placeholder="vault:secret/pathos/git#token"
                  aria-invalid={(ref !== "" && refInvalid) || undefined}
                />
                {ref !== "" && refInvalid && <p className="mt-1 text-[12px] text-danger">Use vault:&lt;mount&gt;/&lt;path&gt;#&lt;key&gt;.</p>}
                <p className="mt-1 text-[12px] text-muted-foreground">
                  PATHOS stores only the reference and reads the secret when it connects. The Vault/OpenBao connection itself is a connector under IAM &amp; Secrets.
                </p>
              </div>
            ) : needsCredential ? (
              <div>
                <Label htmlFor="cx-secret" hint={editing ? (editing.credential?.set ? "Set. Leave empty to keep it." : "Not set") : "Write-only; never shown again"}>
                  {credentialLabel(kind, method)}
                </Label>
                {method === "ssh_key" ? (
                  <textarea
                    id="cx-secret"
                    value={credential}
                    onChange={(e) => setCredential(e.target.value)}
                    rows={4}
                    spellCheck={false}
                    autoComplete="off"
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                    className="w-full rounded-md border border-border bg-surface px-2.5 py-1.5 font-mono text-[12px] focus-visible:outline-2 focus-visible:outline-ring"
                  />
                ) : (
                  <Input id="cx-secret" type="password" autoComplete="new-password" value={credential} onChange={(e) => setCredential(e.target.value)} />
                )}
              </div>
            ) : null}
          </fieldset>
        )}
      </div>
    </Dialog>
  );
}

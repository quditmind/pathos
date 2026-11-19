import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { ApiError } from "@/api/client";
import type { ScmConnection } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Dialog } from "@/components/ui/dialog";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Badge, Label } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { useUpdateConnection } from "./scmApi";

/** Providers that may sit behind a certificate from a private CA (self-hosted servers). */
export const selfHostedProviders = new Set(["github_enterprise", "gitlab", "bitbucket_data_center", "azure_devops_server", "generic_git"]);

/** Whether the CA bundle section applies to a connection (gitlab.com and other cloud services never need one). */
export function caBundleApplies(c: Pick<ScmConnection, "provider" | "base_url" | "has_ca_bundle">): boolean {
  if (c.has_ca_bundle) return true;
  if (!selfHostedProviders.has(c.provider)) return false;
  if (c.provider === "gitlab") return !!c.base_url && !/^https:\/\/gitlab\.com(\/|$)/i.test(c.base_url);
  return true;
}

/** AB:CD:… for a hex SHA-256 fingerprint. */
export const formatFingerprint = (hex: string) => (hex.match(/.{1,2}/g) ?? []).join(":").toUpperCase();

/**
 * Private CA bundle of an SCM connection (connectors feature): the
 * certificates' subject, expiry and SHA-256 fingerprint (the PEM itself is
 * never returned), and, with scm.manage, replace (PATCH ca_bundle_pem) or
 * remove it (PATCH ca_bundle_pem: ""). A change resets the connection to
 * untested.
 */
export function CABundleSection({ c, manage, onNotice }: { c: ScmConnection; manage: boolean; onNotice: (n: { tone: "success" | "danger"; text: string }) => void }) {
  const [editing, setEditing] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [pem, setPem] = useState("");
  const update = useUpdateConnection();
  const certs = c.ca_certificates ?? [];
  const fieldError = update.error instanceof ApiError ? update.error.fields?.ca_bundle_pem : undefined;

  const save = (value: string, done: () => void) =>
    update.mutate(
      { id: c.id, body: { ca_bundle_pem: value } },
      {
        onSuccess: () => {
          done();
          onNotice({
            tone: "success",
            text: value ? `CA bundle of “${c.name}” saved. Test the connection to verify it.` : `CA bundle of “${c.name}” removed. Test the connection to verify it.`,
          });
        },
      },
    );

  return (
    <section aria-label={`Private CA bundle of ${c.name}`} className="mt-3 rounded-md border border-border p-2.5 text-[12px]">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 font-medium">
          <ShieldCheck className="size-3.5" aria-hidden /> Private CA bundle
        </div>
        <Badge tone={c.has_ca_bundle ? "primary" : "neutral"}>{c.has_ca_bundle ? `${certs.length} certificate${certs.length === 1 ? "" : "s"}` : "Not set"}</Badge>
      </div>
      {c.has_ca_bundle ? (
        <ul className="mt-2 space-y-1.5">
          {certs.map((cert) => (
            <li key={cert.sha256_fingerprint} className="rounded bg-surface-muted/60 p-1.5">
              <div className="break-words font-medium">{cert.subject || "(no subject)"}</div>
              <div className={cert.expired ? "text-danger" : "text-muted-foreground"}>
                {cert.expired ? "Expired " : "Expires "}
                {formatDateTime(cert.not_after)}
                {!cert.is_ca && " · not a CA certificate"}
              </div>
              <div className="text-muted-foreground">
                SHA-256 <code className="break-all font-mono text-[11px]">{formatFingerprint(cert.sha256_fingerprint)}</code>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-1 text-muted-foreground">Add one only when the server's certificate is issued by a private certificate authority.</p>
      )}
      {manage && (
        <div className="mt-2 flex gap-2">
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              update.reset();
              setPem("");
              setEditing(true);
            }}
          >
            {c.has_ca_bundle ? "Replace CA bundle" : "Add CA bundle"}
          </Button>
          {c.has_ca_bundle && (
            <Button
              size="sm"
              variant="ghost"
              className="text-danger"
              onClick={() => {
                update.reset();
                setRemoving(true);
              }}
            >
              Remove
            </Button>
          )}
        </div>
      )}
      <Dialog
        open={editing}
        onOpenChange={setEditing}
        title={`CA bundle of “${c.name}”`}
        description="PEM certificates of the private CA that issued the server certificate. They are added to the system trust store for this connection and its clones only; the PEM is not shown again."
        footer={
          <>
            <Button variant="secondary" onClick={() => setEditing(false)}>
              Cancel
            </Button>
            <Button disabled={!pem.trim() || update.isPending} onClick={() => save(pem.trim(), () => setEditing(false))}>
              {update.isPending ? "Saving…" : "Save CA bundle"}
            </Button>
          </>
        }
      >
        {update.isError && !fieldError && (
          <div className="mb-3">
            <ErrorPanel error={update.error} title="The CA bundle was not saved" />
          </div>
        )}
        <Label htmlFor={`ca-pem-${c.id}`} hint="One or more -----BEGIN CERTIFICATE----- blocks; never a private key">
          CA certificates (PEM)
        </Label>
        <textarea
          id={`ca-pem-${c.id}`}
          value={pem}
          onChange={(e) => setPem(e.target.value)}
          rows={8}
          spellCheck={false}
          aria-invalid={!!fieldError || undefined}
          placeholder="-----BEGIN CERTIFICATE-----"
          className="w-full rounded-md border border-border bg-surface px-2.5 py-1.5 font-mono text-[12px] focus-visible:outline-2 focus-visible:outline-ring"
        />
        {fieldError && <p className="mt-1 text-[12px] text-danger">{fieldError}</p>}
      </Dialog>
      <ConfirmDialog
        open={removing}
        onOpenChange={setRemoving}
        title={`Remove the CA bundle of “${c.name}”?`}
        confirmLabel="Remove CA bundle"
        destructive
        pending={update.isPending}
        error={update.error?.message}
        onConfirm={() => save("", () => setRemoving(false))}
      >
        <p>The connection then trusts only the system certificate authorities; if the server's certificate comes from a private CA, its checks and clones fail with PTH-CONN-1004.</p>
      </ConfirmDialog>
    </section>
  );
}

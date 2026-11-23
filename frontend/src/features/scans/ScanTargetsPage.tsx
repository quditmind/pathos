import { useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Boxes, Container, FileJson, Globe, Package, Pencil, Play, Plus, Radar, ShieldAlert, ShieldCheck, Smartphone, Trash2 } from "lucide-react";
import { api, ApiError, getCsrfToken } from "@/api/client";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { RepoFilter } from "@/features/review/shared";
import { formatDateTime } from "@/lib/utils";
import type { CatalogScanner } from "@/api/types";
import { useCatalog } from "./api";
import { ErrorPanel } from "@/components/ui/error-panel";

export type TargetKind = "image" | "url" | "api" | "sbom" | "artifact" | "endpoints" | "mobile-app" | "llm-endpoint";
/** Kinds added on this page (declared endpoints are managed from the repository). */
const creatableKinds: TargetKind[] = ["image", "url", "api", "sbom", "artifact", "mobile-app", "llm-endpoint"];
/** Targets whose content is an uploaded file. */
const uploaded = (k: TargetKind) => k === "sbom" || k === "artifact" || k === "mobile-app";
/** Targets whose signature can be verified (cosign). */
const signable = (k: TargetKind) => k === "image" || k === "artifact" || k === "mobile-app";
/** Running systems PATHOS sends requests to (they need an authorization statement). */
export const liveKind = (k: TargetKind) => k === "url" || k === "api" || k === "llm-endpoint";

/** Sigstore verification policy of an image or artifact target. */
export interface SignatureConfig {
  mode: "" | "key" | "keyless";
  public_key?: string;
  identity?: string;
  identity_regexp?: string;
  issuer?: string;
  require?: boolean;
  attestation?: string;
  ignore_tlog?: boolean;
}

export interface SignatureVerification {
  status: "verified" | "unsigned" | "invalid" | "skipped" | "error";
  mode: "none" | "key" | "keyless";
  required: boolean;
  attestation_status: "" | "verified" | "missing" | "invalid" | "skipped" | "error";
  details: {
    subject?: string;
    detail?: string;
    offline?: boolean;
    signatures?: { digest?: string; identity?: string; issuer?: string }[] | null;
    attestation?: { type: string; status: string; detail?: string; predicate_type?: string; builder_id?: string; source_repository?: string } | null;
  };
  scan_job_id: string | null;
  verified_at: string;
}

const attestationTypes = ["slsaprovenance", "slsaprovenance02", "slsaprovenance1", "spdx", "spdxjson", "cyclonedx", "vuln", "openvex", "link"];

export interface ScanTarget {
  id: string;
  repository_id: string;
  repository_name: string;
  kind: TargetKind;
  name: string;
  reference: string;
  egress_host: string;
  config: { rate_limit?: number; min_severity?: string; nuclei?: boolean; signature?: SignatureConfig; tools?: string[]; model?: string;
    /** Image targets: the image is built from the repository's code (its code findings are deployed where the image runs). */
    built_from_repository?: boolean };
  api_spec?: string;
  sbom_format: string;
  sbom_components: number;
  sbom_size: number;
  auth_type: "none" | "basic" | "header";
  auth_username: string;
  auth_header_name: string;
  has_secret: boolean;
  authorized_by: string | null;
  authorized_at: string | null;
  authorization_note: string;
  /** Intrusive testing (active scans, fuzzing) authorized separately; url and api targets only. */
  intrusive_authorized_by?: string | null;
  intrusive_authorized_at?: string | null;
  intrusive_authorization_note?: string;
  enabled: boolean;
  scanners: string[];
  /** An artifact's signature or Sigstore bundle was uploaded. */
  has_signature?: boolean;
  /** An artifact's provenance attestation (Sigstore bundle) was uploaded. */
  has_provenance?: boolean;
  /** Latest signature verification evidence (image and artifact targets). */
  last_verification?: SignatureVerification | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  open_findings: number;
  last_scan: { id: string; scan_key: string; status: string; queued_at: string; finished_at: string | null; error: string } | null;
}

export const targetKindLabel: Record<TargetKind, string> = {
  image: "Container image",
  url: "Web application (DAST)",
  api: "API (OpenAPI)",
  sbom: "SBOM",
  artifact: "Build artifact",
  endpoints: "Declared public endpoints",
  "mobile-app": "Mobile app (APK, AAB, IPA)",
  "llm-endpoint": "LLM endpoint",
};

const kindIcon: Record<TargetKind, React.ReactNode> = {
  image: <Container className="size-4" />,
  url: <Globe className="size-4" />,
  api: <Boxes className="size-4" />,
  sbom: <FileJson className="size-4" />,
  artifact: <Package className="size-4" />,
  endpoints: <Radar className="size-4" />,
  "mobile-app": <Smartphone className="size-4" />,
  "llm-endpoint": <Bot className="size-4" />,
};

const kindHelp: Record<TargetKind, string> = {
  image: "Trivy pulls the image from its registry and reports vulnerable OS and language packages.",
  url: "Nuclei checks the running application for misconfigurations, exposures and known vulnerabilities. Intrusive, brute-force and denial-of-service checks never run.",
  api: "Nuclei's DAST templates test each operation of your OpenAPI document. Intrusive, brute-force and denial-of-service checks never run.",
  sbom: "Grype matches the SBOM's components against vulnerability databases, for software you receive but cannot scan as source.",
  artifact:
    "Trivy looks for vulnerable components inside a release artifact (zip or tar archive, Java archive, binary), and every executable and shared library in it is checked for binary hardening (PIE, RELRO, stack canaries, NX, FORTIFY_SOURCE, RPATH; ASLR, DEP, CFG and SafeSEH on Windows). Archives are validated and extracted on a worker; nothing in them is run.",
  endpoints:
    "Verification of a repository's declared public URLs, domains and IPs (DNS, reachability, TLS, security headers). It is enabled and authorized on the repository's Details tab.",
  "mobile-app":
    "An Android (APK, AAB) or iOS (IPA) package. Its native code is checked for binary hardening; the mobile tools of the worker-mobile image (mobsfscan, APKLeaks, Quark-Engine, the PATHOS manifest, signing, Info.plist and entitlement checks) run when you select them below. The package is read on a worker, never run.",
  "llm-endpoint":
    "A chat completions API of an LLM application (OpenAI-compatible request format). The red-teaming tools of the worker-ai image (garak, promptfoo) send attack prompts to it: they need your authorization statement and the intrusive testing flag.",
};

const verificationTone: Record<string, "success" | "warning" | "danger" | "neutral"> = {
  verified: "success",
  unsigned: "danger",
  invalid: "danger",
  skipped: "warning",
  error: "warning",
};

/** The latest signature verification of a target. */
export function VerificationBadge({ v }: { v: SignatureVerification }) {
  const title = [
    v.details.detail,
    ...(v.details.signatures ?? []).map((s) => [s.identity, s.issuer].filter(Boolean).join(" · ")),
    v.details.attestation ? `Attestation ${v.details.attestation.type}: ${v.details.attestation.status}${v.details.attestation.builder_id ? ` (builder ${v.details.attestation.builder_id})` : ""}` : "",
    v.details.offline ? "Offline: transparency log not checked" : "",
    `Checked ${formatDateTime(v.verified_at)}`,
  ].filter(Boolean).join("\n");
  return (
    <span className="inline-flex items-center gap-1" title={title}>
      <Badge tone={verificationTone[v.status] ?? "neutral"}><ShieldCheck className="size-3" /> Signature {v.status}</Badge>
      {v.attestation_status && <Badge tone={verificationTone[v.attestation_status === "missing" ? "unsigned" : v.attestation_status] ?? "neutral"}>Attestation {v.attestation_status}</Badge>}
      {v.required && <span className="text-[11px] text-muted-foreground">required</span>}
    </span>
  );
}

const statusTone: Record<string, "success" | "warning" | "danger" | "neutral"> = {
  succeeded: "success",
  partial: "warning",
  failed: "danger",
  cancelled: "neutral",
  queued: "neutral",
  running: "neutral",
};

interface FormState {
  repository_id?: string;
  kind: TargetKind;
  name: string;
  reference: string;
  api_spec: string;
  auth_type: "none" | "basic" | "header";
  auth_username: string;
  auth_header_name: string;
  auth_secret: string;
  rate_limit: string;
  min_severity: string;
  authorized: boolean;
  authorization_note: string;
  enabled: boolean;
  signature: SignatureConfig;
  /** Artifact signature or Sigstore bundle text; undefined = unchanged. */
  signature_material?: string;
  /** Artifact provenance attestation (Sigstore bundle); undefined = unchanged. */
  provenance_material?: string;
  /** Manifest tools that also run for the target. */
  tools: string[];
  intrusive_authorized: boolean;
  intrusive_note: string;
  /** Model name sent to an LLM endpoint. */
  model: string;
  /** Image targets: built from the repository's code. */
  built_from_repository: boolean;
}

/** Manifest targets a tool must list to scan a target kind. */
const toolTargetsFor: Partial<Record<TargetKind, string[]>> = {
  image: ["image"],
  url: ["url"],
  api: ["api", "url"],
  artifact: ["binary", "mobile-app", "model"],
  "mobile-app": ["mobile-app"],
  "llm-endpoint": ["llm-endpoint"],
};

/** Tools of family worker images and operator plugins that scan a target kind. */
export function targetTools(catalog: CatalogScanner[], kind: TargetKind): CatalogScanner[] {
  const want = toolTargetsFor[kind] ?? [];
  return catalog.filter((s) => s.worker_family !== "core" && s.worker_family !== "intel" && s.adapter_available && (s.targets ?? []).some((t) => want.includes(t)));
}

const emptyForm = (kind: TargetKind): FormState => ({
  kind,
  name: "",
  reference: "",
  api_spec: "",
  auth_type: "none",
  auth_username: "",
  auth_header_name: kind === "image" ? "" : "Authorization",
  auth_secret: "",
  rate_limit: "",
  min_severity: "",
  authorized: false,
  authorization_note: "",
  enabled: true,
  signature: { mode: "" },
  tools: [],
  intrusive_authorized: false,
  intrusive_note: "",
  model: "",
  built_from_repository: false,
});

/** The signature policy as sent to the API (fields of the mode only). */
export function signaturePayload(s: SignatureConfig): SignatureConfig | undefined {
  if (!s.mode) return undefined;
  const base = { mode: s.mode, require: !!s.require, attestation: s.attestation || undefined, ignore_tlog: !!s.ignore_tlog };
  if (s.mode === "key") return { ...base, public_key: s.public_key ?? "" };
  return { ...base, identity: s.identity_regexp ? undefined : s.identity, identity_regexp: s.identity_regexp || undefined, issuer: s.issuer ?? "" };
}

function SignatureFields({ f, set, kind, target }: { f: FormState; set: (p: Partial<FormState>) => void; kind: TargetKind; target: ScanTarget | null }) {
  const s = f.signature;
  const setS = (p: Partial<SignatureConfig>) => set({ signature: { ...s, ...p } });
  const onFile = async (file: File | undefined) => {
    if (file) set({ signature_material: (await file.text()).trim() });
  };
  const onProvenance = async (file: File | undefined) => {
    if (file) set({ provenance_material: (await file.text()).trim() });
  };
  const artifact = kind === "artifact" || kind === "mobile-app";
  return (
    <fieldset className="rounded-md border border-border p-3">
      <legend className="px-1 text-[12px] font-medium">Signature verification (Sigstore cosign)</legend>
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <Label htmlFor="sig-mode">Verify</Label>
          <Select id="sig-mode" className="w-full" value={s.mode} onChange={(e) => setS({ mode: e.target.value as SignatureConfig["mode"] })}>
            <option value="">Off</option>
            <option value="key">With a public key</option>
            <option value="keyless">Keyless (certificate identity and OIDC issuer)</option>
          </Select>
        </div>
        {s.mode && kind === "image" && (
          <div>
            <Label htmlFor="sig-att" hint="(optional)">Attestation to verify</Label>
            <Select id="sig-att" className="w-full" value={s.attestation ?? ""} onChange={(e) => setS({ attestation: e.target.value })}>
              <option value="">None</option>
              {attestationTypes.map((t) => <option key={t} value={t}>{t}</option>)}
            </Select>
          </div>
        )}
        {s.mode && artifact && (
          <div>
            <Label htmlFor="sig-att" hint="(optional)">Build provenance to verify</Label>
            <Select id="sig-att" className="w-full" value={s.attestation ?? ""} onChange={(e) => setS({ attestation: e.target.value })}>
              <option value="">None</option>
              {attestationTypes.filter((t) => t.startsWith("slsaprovenance")).map((t) => <option key={t} value={t}>{t}</option>)}
            </Select>
          </div>
        )}
      </div>
      {s.mode === "key" && (
        <div className="mt-3">
          <Label htmlFor="sig-key" hint="(PEM, e.g. cosign.pub)">Public key</Label>
          <textarea id="sig-key" spellCheck={false} value={s.public_key ?? ""} onChange={(e) => setS({ public_key: e.target.value })}
            placeholder="-----BEGIN PUBLIC KEY-----" className="h-24 w-full rounded-md border border-border bg-surface px-3 py-2 font-mono text-[11.5px] focus-visible:outline-2 focus-visible:outline-ring" />
        </div>
      )}
      {s.mode === "keyless" && (
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <div>
            <Label htmlFor="sig-id" hint="(exact)">Certificate identity</Label>
            <Input id="sig-id" className="font-mono text-[12px]" value={s.identity ?? ""} onChange={(e) => setS({ identity: e.target.value })}
              placeholder="https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main" />
          </div>
          <div>
            <Label htmlFor="sig-idre" hint="(instead of the exact identity)">Identity regular expression</Label>
            <Input id="sig-idre" className="font-mono text-[12px]" value={s.identity_regexp ?? ""} onChange={(e) => setS({ identity_regexp: e.target.value })}
              placeholder="^https://github.com/acme/" />
          </div>
          <div className="md:col-span-2">
            <Label htmlFor="sig-iss">OIDC issuer</Label>
            <Input id="sig-iss" className="font-mono text-[12px]" value={s.issuer ?? ""} onChange={(e) => setS({ issuer: e.target.value })}
              placeholder="https://token.actions.githubusercontent.com" />
          </div>
        </div>
      )}
      {s.mode && (
        <div className="mt-3 space-y-1.5">
          <label className="flex items-start gap-2 text-[12.5px]">
            <input type="checkbox" className="mt-0.5 accent-[var(--primary)]" checked={!!s.require} onChange={(e) => setS({ require: e.target.checked })} />
            <span>Require a valid signature{s.attestation ? " and attestation" : ""}: otherwise a high-severity finding is created and the security gate fails.</span>
          </label>
          {s.mode === "key" && (
            <label className="flex items-start gap-2 text-[12.5px]">
              <input type="checkbox" className="mt-0.5 accent-[var(--primary)]" checked={!!s.ignore_tlog} onChange={(e) => setS({ ignore_tlog: e.target.checked })} />
              <span>The signatures are not in a transparency log (private signing without Rekor)</span>
            </label>
          )}
        </div>
      )}
      {s.mode && (kind === "artifact" || kind === "mobile-app") && (
        <div className="mt-3">
          <Label htmlFor="sig-file" hint={target?.has_signature && f.signature_material === undefined ? "(uploaded; choose a file to replace)" : "(cosign sign-blob output)"}>
            Signature (base64) or Sigstore bundle (.sigstore.json)
          </Label>
          <input id="sig-file" type="file" accept=".sig,.json,.bundle,.txt" onChange={(e) => void onFile(e.target.files?.[0])}
            className="block text-[12.5px] file:mr-2 file:rounded-md file:border file:border-border file:bg-surface file:px-2 file:py-1" />
        </div>
      )}
      {s.mode && artifact && s.attestation && (
        <div className="mt-3">
          <Label htmlFor="prov-file" hint={target?.has_provenance && f.provenance_material === undefined ? "(uploaded; choose a file to replace)" : "(cosign attest-blob --bundle output)"}>
            Provenance attestation (Sigstore bundle, .sigstore.json)
          </Label>
          <input id="prov-file" type="file" accept=".json,.bundle" onChange={(e) => void onProvenance(e.target.files?.[0])}
            className="block text-[12.5px] file:mr-2 file:rounded-md file:border file:border-border file:bg-surface file:px-2 file:py-1" />
        </div>
      )}
      <p className="mt-2 text-[11.5px] text-muted-foreground">
        The verification result is kept as evidence with each scan. Keyless verification uses the public Sigstore infrastructure (Fulcio, Rekor);
        offline, only key-based verification runs.
      </p>
    </fieldset>
  );
}

/**
 * Additional tools (family worker images, operator plugins) for a target,
 * and the separate authorization of intrusive testing.
 */
function ToolFields({ f, set, target, addressChanged }: { f: FormState; set: (p: Partial<FormState>) => void; target: ScanTarget | null; addressChanged: boolean }) {
  const catalog = useCatalog();
  const tools = targetTools(catalog.data ?? [], f.kind);
  const live = liveKind(f.kind);
  const selected = tools.filter((t) => f.tools.includes(t.key));
  const needsIntrusive = selected.some((t) => t.intrusive);
  // Tools selected earlier whose worker is not registered any more stay listed.
  const missing = f.tools.filter((k) => !tools.some((t) => t.key === k));
  if (!toolTargetsFor[f.kind] || (!tools.length && !missing.length)) return null;
  const toggle = (k: string) => set({ tools: f.tools.includes(k) ? f.tools.filter((x) => x !== k) : [...f.tools, k] });
  return (
    <fieldset className="rounded-md border border-border p-3">
      <legend className="px-1 text-[12px] font-medium">Additional tools</legend>
      <p className="mb-2 text-[11.5px] text-muted-foreground">Tools of family worker images and operator plugins that scan this kind of target. They run in addition to the built-in scanners.</p>
      <div className="grid gap-1.5 md:grid-cols-2">
        {tools.map((t) => (
          <label key={t.key} className="flex items-start gap-2 text-[12.5px]">
            <input type="checkbox" className="mt-0.5 accent-[var(--primary)]" checked={f.tools.includes(t.key)} onChange={() => toggle(t.key)} />
            <span>
              <span className="font-medium">{t.name}</span>{" "}
              {t.intrusive ? <Badge tone="danger">intrusive</Badge> : t.network === "target" ? <Badge tone="warning">sends requests</Badge> : null}
              {!t.runnable && <span className="block text-[11px] text-muted-foreground">No online worker provides it now.</span>}
            </span>
          </label>
        ))}
        {missing.map((k) => (
          <label key={k} className="flex items-center gap-2 text-[12.5px] text-muted-foreground">
            <input type="checkbox" className="accent-[var(--primary)]" checked onChange={() => toggle(k)} />
            <span className="font-mono text-[11.5px]">{k}</span> (not registered by any worker)
          </label>
        ))}
      </div>
      {live && (
        <div className="mt-3 rounded-md border border-danger/40 bg-danger/5 p-3">
          <label className="flex items-start gap-2 text-[12.5px]">
            <input type="checkbox" className="mt-0.5 accent-[var(--primary)]" checked={f.intrusive_authorized} onChange={(e) => set({ intrusive_authorized: e.target.checked })} />
            <span>
              <span className="font-medium">Intrusive testing of this application is authorized.</span>
              <span className="block text-[11.5px] text-muted-foreground">
                Intrusive tools send attack traffic (active scans, fuzzing, injection probes) that can change data or degrade the service. They run only with this flag, in addition to the authorization above; setting and withdrawing it is audited.
                {target?.intrusive_authorized_by && !addressChanged ? ` Currently: ${target.intrusive_authorized_by}, ${formatDateTime(target.intrusive_authorized_at!)}.` : ""}
                {addressChanged && target?.intrusive_authorized_at ? " A new address withdraws it unless you confirm it again." : ""}
              </span>
            </span>
          </label>
          {f.intrusive_authorized && (
            <div className="mt-2">
              <Label htmlFor="tgt-inote" hint="(optional)">Intrusive testing reference</Label>
              <Input id="tgt-inote" value={f.intrusive_note} maxLength={2000} onChange={(e) => set({ intrusive_note: e.target.value })} placeholder="e.g. penetration test window, change ticket" />
            </div>
          )}
          {needsIntrusive && !f.intrusive_authorized && (
            <p className="mt-2 text-[11.5px] text-danger">An intrusive tool is selected: scans of this target are refused until intrusive testing is authorized.</p>
          )}
        </div>
      )}
    </fieldset>
  );
}

async function uploadTarget(kind: TargetKind, fd: FormData): Promise<ScanTarget> {
  const res = await fetch(`/api/v1/scan-targets/${kind}`, { method: "POST", body: fd, credentials: "same-origin", headers: { Accept: "application/json", "X-CSRF-Token": getCsrfToken() } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data?.error?.code ?? "error", data?.error?.message ?? res.statusText, data?.request_id, undefined, data);
  return data as ScanTarget;
}

function TargetDialog({ open, onClose, target, initialKind }: { open: boolean; onClose: () => void; target: ScanTarget | null; initialKind: TargetKind }) {
  const qc = useQueryClient();
  // Loaded once per opening: a background refetch must not reset edits.
  const full = useQuery({
    queryKey: ["scan-target", target?.id],
    queryFn: () => api<ScanTarget>(`/api/v1/scan-targets/${target!.id}`),
    enabled: open && !!target,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  });
  const [f, setF] = useState<FormState>(emptyForm(initialKind));
  const [file, setFile] = useState<File | null>(null);
  const [secretTouched, setSecretTouched] = useState(false);
  useEffect(() => {
    if (!open) return;
    setFile(null);
    setSecretTouched(false);
    if (!target) {
      setF(emptyForm(initialKind));
      return;
    }
    const t = full.data ?? target;
    setF({
      repository_id: t.repository_id,
      kind: t.kind,
      name: t.name,
      reference: t.reference,
      api_spec: t.api_spec ?? "",
      auth_type: t.auth_type,
      auth_username: t.auth_username,
      auth_header_name: t.auth_header_name || (t.kind === "image" ? "" : "Authorization"),
      auth_secret: "",
      rate_limit: t.config.rate_limit ? String(t.config.rate_limit) : "",
      min_severity: t.config.min_severity ?? "",
      authorized: false,
      authorization_note: t.authorization_note,
      enabled: t.enabled,
      signature: { mode: "", ...t.config.signature },
      tools: t.config.tools ?? [],
      intrusive_authorized: !!t.intrusive_authorized_at,
      intrusive_note: t.intrusive_authorization_note ?? "",
      model: t.config.model ?? "",
      built_from_repository: !!t.config.built_from_repository,
    });
  }, [open, target, initialKind, full.data]);
  const set = (p: Partial<FormState>) => setF((x) => ({ ...x, ...p }));
  const live = liveKind(f.kind);
  const addressChanged = !!target && live && f.reference.trim() !== target.reference;
  const save = useMutation({
    mutationFn: async () => {
      const signature = signable(f.kind) ? signaturePayload(f.signature) : undefined;
      if (uploaded(f.kind) && !target) {
        const fd = new FormData();
        fd.set("repository_id", f.repository_id!);
        fd.set("name", f.name);
        fd.set("file", file!);
        if ((f.kind === "artifact" || f.kind === "mobile-app") && f.signature_material) fd.set("signature", f.signature_material);
        if ((f.kind === "artifact" || f.kind === "mobile-app") && f.provenance_material) fd.set("provenance", f.provenance_material);
        const created = await uploadTarget(f.kind, fd);
        // The verification policy is set right after the upload.
        if (signature) return api<ScanTarget>(`/api/v1/scan-targets/${created.id}`, { method: "PUT", body: { config: { signature } } });
        return created;
      }
      const body: Record<string, unknown> = {
        name: f.name,
        enabled: f.enabled,
        authorization_note: f.authorization_note,
        authorized: f.authorized,
      };
      if (!uploaded(f.kind)) {
        body.reference = f.reference.trim();
        body.auth_type = f.auth_type;
        body.auth_username = f.auth_username;
        body.auth_header_name = f.auth_header_name;
        if (!target || secretTouched) body.auth_secret = f.auth_secret;
        if (live && f.kind !== "llm-endpoint") body.config = { rate_limit: f.rate_limit ? Number(f.rate_limit) : undefined, min_severity: f.min_severity || undefined };
        if (f.kind === "llm-endpoint") body.config = { rate_limit: f.rate_limit ? Number(f.rate_limit) : undefined, model: f.model.trim() };
        if (f.kind === "api") body.api_spec = f.api_spec;
      }
      if (signable(f.kind)) body.config = { ...(body.config as object | undefined), signature };
      if (toolTargetsFor[f.kind]) body.config = { ...(body.config as object | undefined), tools: f.tools.length ? f.tools : undefined };
      if (f.kind === "image") body.config = { ...(body.config as object | undefined), built_from_repository: f.built_from_repository || undefined };
      if (live && (!target || f.intrusive_authorized !== !!target.intrusive_authorized_at || f.intrusive_note !== (target.intrusive_authorization_note ?? ""))) {
        body.intrusive_authorized = f.intrusive_authorized;
        body.intrusive_authorization_note = f.intrusive_note;
      }
      if ((f.kind === "artifact" || f.kind === "mobile-app") && f.signature_material !== undefined) body.signature_material = f.signature_material;
      if ((f.kind === "artifact" || f.kind === "mobile-app") && f.provenance_material !== undefined) body.provenance_material = f.provenance_material;
      if (target) return api<ScanTarget>(`/api/v1/scan-targets/${target.id}`, { method: "PUT", body });
      return api<ScanTarget>("/api/v1/scan-targets", { method: "POST", body: { ...body, repository_id: f.repository_id, kind: f.kind } });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scan-targets"] });
      qc.removeQueries({ queryKey: ["scan-target"] });
      onClose();
    },
  });
  const needsAuthorization = live && (!target || addressChanged);
  const ok =
    !!f.repository_id &&
    f.name.trim() !== "" &&
    (uploaded(f.kind) ? !!target || !!file : f.reference.trim() !== "") &&
    (f.kind !== "api" || f.api_spec.trim() !== "") &&
    (f.kind !== "llm-endpoint" || f.model.trim() !== "") &&
    (!needsAuthorization || f.authorized) &&
    (f.auth_type !== "basic" || f.auth_username.trim() !== "") &&
    (f.auth_type !== "header" || f.auth_header_name.trim() !== "") &&
    (f.signature.mode !== "key" || !!f.signature.public_key?.trim()) &&
    (f.signature.mode !== "keyless" || (!!f.signature.issuer?.trim() && !!(f.signature.identity?.trim() || f.signature.identity_regexp?.trim())));
  const onApiFile = async (file: File | undefined) => {
    if (file) set({ api_spec: await file.text() });
  };
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      size="lg"
      title={target ? `Edit ${target.name}` : `Add ${targetKindLabel[f.kind].toLowerCase()}`}
      description={kindHelp[f.kind]}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button disabled={!ok || save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : target ? "Save" : "Add target"}</Button>
        </>
      }
    >
      {target && full.isPending ? (
        <Skeleton className="h-64" />
      ) : (
      <div className="space-y-3">
        {save.error && <ErrorPanel error={save.error} />}
        {!target && (
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <Label htmlFor="tgt-kind">Kind</Label>
              <Select id="tgt-kind" className="w-full" value={f.kind} onChange={(e) => setF({ ...emptyForm(e.target.value as TargetKind), repository_id: f.repository_id, name: f.name })}>
                {creatableKinds.map((k) => <option key={k} value={k}>{targetKindLabel[k]}</option>)}
              </Select>
            </div>
            <div>
              <span className="mb-1 block text-[12px] font-medium">Repository</span>
              <RepoFilter value={f.repository_id} onChange={(v) => set({ repository_id: v })} />
              <p className="mt-1 text-[11.5px] text-muted-foreground">Findings belong to this repository's application, owners and scope.</p>
            </div>
          </div>
        )}
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <Label htmlFor="tgt-name">Name</Label>
            <Input id="tgt-name" value={f.name} maxLength={200} onChange={(e) => set({ name: e.target.value })} placeholder={f.kind === "image" ? "e.g. Payments API image" : f.kind === "sbom" ? "e.g. Vendor appliance 4.2" : f.kind === "artifact" ? "e.g. payments-service 2.3.0 release" : f.kind === "mobile-app" ? "e.g. Payments app 5.1 (Android)" : f.kind === "llm-endpoint" ? "e.g. Support assistant (staging)" : "e.g. Payments staging"} />
          </div>
          {!uploaded(f.kind) && (
            <div>
              <Label htmlFor="tgt-ref">{f.kind === "image" ? "Image reference" : f.kind === "llm-endpoint" ? "Chat completions URL" : "Base URL"}</Label>
              <Input id="tgt-ref" className="font-mono text-[12px]" value={f.reference} maxLength={1000} onChange={(e) => set({ reference: e.target.value })}
                placeholder={f.kind === "image" ? "ghcr.io/acme/payments:1.4.2" : f.kind === "llm-endpoint" ? "https://assistant.staging.example.com/v1/chat/completions" : "https://staging.payments.example.com"} />
            </div>
          )}
        </div>
        {f.kind === "llm-endpoint" && (
          <div>
            <Label htmlFor="tgt-model" hint="(the request's model field)">Model</Label>
            <Input id="tgt-model" className="font-mono text-[12px]" value={f.model} maxLength={200} onChange={(e) => set({ model: e.target.value })} placeholder="e.g. support-assistant-v2" />
          </div>
        )}
        {f.kind === "sbom" && !target && (
          <div>
            <Label htmlFor="tgt-file" hint="(at most 64 MiB; .gz accepted)">SBOM: CycloneDX JSON or SPDX 2.x JSON</Label>
            <input id="tgt-file" type="file" accept=".json,.gz" onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="block text-[12.5px] file:mr-2 file:rounded-md file:border file:border-border file:bg-surface file:px-2 file:py-1" />
          </div>
        )}
        {f.kind === "mobile-app" && !target && (
          <div>
            <Label htmlFor="tgt-file" hint="(at most 200 MiB)">Package: Android .apk or .aab, iOS .ipa</Label>
            <input id="tgt-file" type="file" accept=".apk,.aab,.ipa" onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="block text-[12.5px] file:mr-2 file:rounded-md file:border file:border-border file:bg-surface file:px-2 file:py-1" />
          </div>
        )}
        {f.kind === "artifact" && !target && (
          <div>
            <Label htmlFor="tgt-file" hint="(at most 200 MiB)">Artifact: zip, tar or tar.gz archive, Java archive (.jar, .war, .ear) or binary</Label>
            <input id="tgt-file" type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="block text-[12.5px] file:mr-2 file:rounded-md file:border file:border-border file:bg-surface file:px-2 file:py-1" />
          </div>
        )}
        {f.kind === "api" && (
          <div>
            <Label htmlFor="tgt-spec" hint="(OpenAPI 3 or Swagger 2, YAML or JSON; every server must be on the base URL's host)">OpenAPI document</Label>
            <input aria-label="Load OpenAPI file" type="file" accept=".yaml,.yml,.json" onChange={(e) => void onApiFile(e.target.files?.[0])}
              className="mb-1 block text-[12px] file:mr-2 file:rounded-md file:border file:border-border file:bg-surface file:px-2 file:py-0.5" />
            <textarea id="tgt-spec" spellCheck={false} value={f.api_spec} onChange={(e) => set({ api_spec: e.target.value })}
              className="h-40 w-full rounded-md border border-border bg-surface px-3 py-2 font-mono text-[12px] focus-visible:outline-2 focus-visible:outline-ring" />
          </div>
        )}
        {!uploaded(f.kind) && (
          <fieldset className="rounded-md border border-border p-3">
            <legend className="px-1 text-[12px] font-medium">Authentication</legend>
            <div className="grid gap-3 md:grid-cols-3">
              <div>
                <Label htmlFor="tgt-auth">Type</Label>
                <Select id="tgt-auth" className="w-full" value={f.auth_type} onChange={(e) => set({ auth_type: e.target.value as FormState["auth_type"] })}>
                  <option value="none">None</option>
                  <option value="basic">{f.kind === "image" ? "Registry username and token" : "Basic (username and password)"}</option>
                  {f.kind !== "image" && <option value="header">Request header (token, API key, cookie)</option>}
                </Select>
              </div>
              {f.auth_type === "basic" && (
                <div>
                  <Label htmlFor="tgt-user">Username</Label>
                  <Input id="tgt-user" autoComplete="off" value={f.auth_username} onChange={(e) => set({ auth_username: e.target.value })} />
                </div>
              )}
              {f.auth_type === "header" && (
                <div>
                  <Label htmlFor="tgt-hname">Header name</Label>
                  <Input id="tgt-hname" value={f.auth_header_name} onChange={(e) => set({ auth_header_name: e.target.value })} placeholder="Authorization" />
                </div>
              )}
              {f.auth_type !== "none" && (
                <div>
                  <Label htmlFor="tgt-secret" hint={target?.has_secret && !secretTouched ? "(stored; leave empty to keep)" : "(encrypted at rest)"}>
                    {f.auth_type === "header" ? "Header value" : f.kind === "image" ? "Password or token" : "Password"}
                  </Label>
                  <Input id="tgt-secret" type="password" autoComplete="new-password" value={f.auth_secret}
                    onChange={(e) => { set({ auth_secret: e.target.value }); setSecretTouched(true); }} />
                </div>
              )}
            </div>
          </fieldset>
        )}
        {live && (
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <Label htmlFor="tgt-rate" hint={f.kind === "llm-endpoint" ? "(1-100; promptfoo waits between requests, garak sends one at a time)" : "(1-100, default 20)"}>Requests per second</Label>
              <Input id="tgt-rate" type="number" min={1} max={100} value={f.rate_limit} onChange={(e) => set({ rate_limit: e.target.value })} />
            </div>
            {f.kind !== "llm-endpoint" && <div>
              <Label htmlFor="tgt-sev">Checks to run</Label>
              <Select id="tgt-sev" className="w-full" value={f.min_severity} onChange={(e) => set({ min_severity: e.target.value })}>
                <option value="">All severities (including informational)</option>
                <option value="low">Low and above</option>
                <option value="medium">Medium and above</option>
                <option value="high">High and critical</option>
                <option value="critical">Critical only</option>
              </Select>
            </div>}
          </div>
        )}
        {live && (
          <div className="rounded-md border border-warning/40 bg-warning/5 p-3">
            <label className="flex items-start gap-2 text-[12.5px]">
              <input type="checkbox" className="mt-0.5 accent-[var(--primary)]" checked={f.authorized} onChange={(e) => set({ authorized: e.target.checked })} />
              <span>
                <span className="font-medium">I am authorized to security-test this application{addressChanged ? " at its new address" : ""}.</span>
                <span className="block text-[11.5px] text-muted-foreground">
                  Scans send real requests to it. Your name and the time are recorded with the target{target?.authorized_by ? ` (currently: ${target.authorized_by}, ${formatDateTime(target.authorized_at!)})` : ""}.
                </span>
              </span>
            </label>
            <div className="mt-2">
              <Label htmlFor="tgt-note" hint="(optional)">Authorization reference</Label>
              <Input id="tgt-note" value={f.authorization_note} maxLength={2000} onChange={(e) => set({ authorization_note: e.target.value })} placeholder="e.g. change ticket, owner's approval" />
            </div>
          </div>
        )}
        <ToolFields f={f} set={set} target={target} addressChanged={addressChanged} />
        {f.kind === "image" && (
          <label className="flex items-start gap-2 text-[12.5px]">
            <input type="checkbox" className="mt-0.5 accent-[var(--primary)]" checked={f.built_from_repository} onChange={(e) => set({ built_from_repository: e.target.checked })} />
            <span>This image is built from the repository's code: where it runs, the repository's code findings count as deployed (runtime context). Leave off for third-party or unrelated images.</span>
          </label>
        )}
        {signable(f.kind) && <SignatureFields f={f} set={set} kind={f.kind} target={target} />}
        {target && (
          <label className="flex items-center gap-1.5 text-[13px]">
            <input type="checkbox" className="accent-[var(--primary)]" checked={f.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled
          </label>
        )}
        {!uploaded(f.kind) && (
          <p className="text-[11.5px] text-muted-foreground">
            Workers reach targets only through the egress proxy. {f.kind === "image" ? "Docker Hub and ghcr.io are allowed by default; add any other registry" : "Add the application's host name"} to <code>deploy/egress/allowlist.txt</code>; private addresses also need an
            override in <code>deploy/egress/conf.d</code>.
          </p>
        )}
      </div>
      )}
    </Dialog>
  );
}

export function ScanTargetsPage() {
  const { can } = useSession();
  const qc = useQueryClient();
  const [kind, setKind] = useState<"" | TargetKind>("");
  const [repo, setRepo] = useState<string | undefined>();
  const [dialog, setDialog] = useState<{ target: ScanTarget | null; kind: TargetKind } | null>(null);
  const [del, setDel] = useState<ScanTarget | null>(null);
  const params = new URLSearchParams();
  if (kind) params.set("kind", kind);
  if (repo) params.set("repository_id", repo);
  const list = useQuery({
    queryKey: ["scan-targets", kind, repo],
    queryFn: () => api<{ items: ScanTarget[] }>(`/api/v1/scan-targets?${params}`).then((r) => r.items),
    refetchInterval: (q) => (q.state.data?.some((t) => t.last_scan && ["queued", "running"].includes(t.last_scan.status)) ? 5000 : false),
  });
  const scan = useMutation({
    mutationFn: (id: string) => api<{ job_id: string; coalesced: boolean }>(`/api/v1/scan-targets/${id}/scan`, { method: "POST" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["scan-targets"] }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/api/v1/scan-targets/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      setDel(null);
      void qc.invalidateQueries({ queryKey: ["scan-targets"] });
    },
  });
  const canManage = can("repos.manage");
  const canRun = can("scans.run");
  return (
    <>
      <PageHeader
        title="Scan targets"
        description="Scan what is deployed, not only the source: container images, running web applications and APIs (DAST), release artifacts, and SBOMs of software you receive. Each target belongs to a repository, so its findings reach the right application and owners."
        actions={canManage && <Button onClick={() => setDialog({ target: null, kind: "image" })}><Plus /> Add target</Button>}
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Select aria-label="Filter by kind" value={kind} onChange={(e) => setKind(e.target.value as "" | TargetKind)}>
          <option value="">All kinds</option>
          {(Object.keys(targetKindLabel) as TargetKind[]).map((k) => <option key={k} value={k}>{targetKindLabel[k]}</option>)}
        </Select>
        <RepoFilter value={repo} onChange={setRepo} />
      </div>
      {scan.error && <div className="mb-3"><ErrorPanel error={scan.error} /></div>}
      {scan.data && (
        <div className="mb-3">
          <Alert tone="success">
            Scan {scan.data.coalesced ? "already queued" : "queued"}.{" "}
            <Link to="/scans/$id" params={{ id: scan.data.job_id }} className="underline">Follow the execution</Link>
          </Alert>
        </div>
      )}
      <Card>
        {list.isError ? (
          <div className="p-4"><ErrorPanel error={list.error} /></div>
        ) : list.isPending ? (
          <Skeleton className="m-4 h-32" />
        ) : !list.data.length ? (
          <EmptyState icon={<Container />} title="No scan targets">
            {canManage ? "Add a container image, a running application, an API, a build artifact or an SBOM." : "Targets are added by people who manage repositories."}
          </EmptyState>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Target</Th>
                <Th>Kind</Th>
                <Th>Repository</Th>
                <Th>Open findings</Th>
                <Th>Last scan</Th>
                <Th className="text-right">Actions</Th>
              </tr>
            </thead>
            <tbody>
              {list.data.map((t) => (
                <tr key={t.id} className={t.enabled ? undefined : "opacity-60"}>
                  <Td>
                    <div className="flex items-center gap-2 font-medium">
                      {kindIcon[t.kind]} {t.name}
                      {!t.enabled && <Badge>disabled</Badge>}
                    </div>
                    <div className="max-w-md truncate font-mono text-[11.5px] text-muted-foreground" title={t.reference}>
                      {t.kind === "sbom" ? `${t.reference} · ${t.sbom_format.toUpperCase()} · ${t.sbom_components} components` : t.reference}
                    </div>
                    {t.last_verification && <div className="mt-0.5"><VerificationBadge v={t.last_verification} /></div>}
                    {(t.kind === "url" || t.kind === "api" || t.kind === "endpoints") && t.authorized_by && (
                      <div className="flex items-center gap-1 text-[11px] text-muted-foreground" title={t.authorization_note}>
                        <ShieldAlert className="size-3" /> Authorized by {t.authorized_by}, {formatDateTime(t.authorized_at!)}
                      </div>
                    )}
                    {t.intrusive_authorized_at && (
                      <div className="flex items-center gap-1 text-[11px] text-danger" title={t.intrusive_authorization_note}>
                        <ShieldAlert className="size-3" /> Intrusive testing authorized by {t.intrusive_authorized_by ?? "a former user"}, {formatDateTime(t.intrusive_authorized_at)}
                      </div>
                    )}
                  </Td>
                  <Td className="text-[12px]">{targetKindLabel[t.kind]}</Td>
                  <Td className="text-[12px]">{t.repository_name}</Td>
                  <Td>
                    {t.open_findings > 0 ? (
                      <Link to="/findings" search={{ scan_target_id: t.id } as never} className="text-[12px] text-primary hover:underline">{t.open_findings} open</Link>
                    ) : (
                      <span className="text-[12px] text-muted-foreground">none</span>
                    )}
                  </Td>
                  <Td className="text-[12px]">
                    {t.last_scan ? (
                      <div>
                        <Link to="/scans/$id" params={{ id: t.last_scan.id }} className="font-mono text-primary hover:underline">{t.last_scan.scan_key}</Link>{" "}
                        <Badge tone={statusTone[t.last_scan.status] ?? "neutral"}>{t.last_scan.status}</Badge>
                        <div className="text-[11px] text-muted-foreground" title={t.last_scan.error}>{formatDateTime(t.last_scan.finished_at ?? t.last_scan.queued_at)}</div>
                      </div>
                    ) : (
                      <span className="text-muted-foreground">never</span>
                    )}
                  </Td>
                  <Td className="whitespace-nowrap text-right">
                    {canRun && (
                      <Button size="sm" variant="secondary" disabled={!t.enabled || scan.isPending} onClick={() => scan.mutate(t.id)} aria-label={`Scan ${t.name}`}>
                        <Play /> Scan
                      </Button>
                    )}
                    {canManage && (
                      <>
                        {t.kind === "endpoints" ? (
                          <Link to="/repositories" search={{ repo: t.repository_id } as never} className="mx-2 text-[12px] text-primary hover:underline" aria-label={`Manage ${t.name} in the repository`}>
                            Manage
                          </Link>
                        ) : (
                          <Button size="icon" variant="ghost" aria-label={`Edit ${t.name}`} onClick={() => setDialog({ target: t, kind: t.kind })}><Pencil /></Button>
                        )}
                        <Button size="icon" variant="ghost" aria-label={`Delete ${t.name}`} onClick={() => setDel(t)}><Trash2 /></Button>
                      </>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <TargetDialog open={!!dialog} onClose={() => setDialog(null)} target={dialog?.target ?? null} initialKind={dialog?.kind ?? "image"} />
      <ConfirmDialog
        open={!!del}
        onOpenChange={(o) => !o && setDel(null)}
        title={`Delete ${del?.name ?? "target"}?`}
        confirmLabel="Delete"
        pending={remove.isPending}
        error={remove.error?.message}
        onConfirm={() => del && remove.mutate(del.id)}
      >
        The target and its stored credential are removed. A target with findings cannot be deleted (its findings keep their evidence); disable it instead.
      </ConfirmDialog>
    </>
  );
}

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Pencil, Send, Trash2, Webhook } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { useEvents } from "./api";
import { ErrorPanel } from "@/components/ui/error-panel";

export interface WebhookEndpoint {
  id: string;
  name: string;
  format: "json" | "slack" | "teams";
  host: string;
  signed: boolean;
  events: string[];
  min_severity: string | null;
  allow_private: boolean;
  enabled: boolean;
  /** Private CA bundle (PEM) added to the system trust store for this endpoint. */
  ca_bundle_pem?: string;
  created_at: string;
  last_status: string | null;
  last_delivery_at: string | null;
  failed_24h: number;
}
interface Delivery {
  id: string;
  event_key: string;
  status: string;
  attempts: number;
  response_status: number | null;
  error: string;
  created_at: string;
  delivered_at: string | null;
  next_attempt_at: string;
}

const formatLabel = { json: "JSON (signed)", slack: "Slack", teams: "Microsoft Teams" };

function WebhookDialog({ open, onClose, hook, onCreated }: { open: boolean; onClose: () => void; hook: WebhookEndpoint | null; onCreated: (secret: string | null) => void }) {
  const qc = useQueryClient();
  const events = useEvents();
  const [name, setName] = useState("");
  const [format, setFormat] = useState<WebhookEndpoint["format"]>("json");
  const [url, setUrl] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [minSev, setMinSev] = useState("");
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [sign, setSign] = useState(true);
  const [caBundle, setCaBundle] = useState("");
  useEffect(() => {
    if (!open) return;
    setName(hook?.name ?? "");
    setFormat(hook?.format ?? "json");
    setUrl("");
    setSelected(hook?.events ?? ["findings.new", "policy.violated"]);
    setMinSev(hook?.min_severity ?? "");
    setAllowPrivate(hook?.allow_private ?? false);
    setSign(true);
    setCaBundle(hook?.ca_bundle_pem ?? "");
  }, [open, hook]);
  const save = useMutation({
    mutationFn: () =>
      api<{ webhook: WebhookEndpoint; signing_secret?: string } | WebhookEndpoint>(hook ? `/api/v1/notifications/webhooks/${hook.id}` : "/api/v1/notifications/webhooks", {
        method: hook ? "PUT" : "POST",
        body: { name, format, url: url || undefined, events: selected, min_severity: minSev || null, allow_private: allowPrivate, enabled: hook?.enabled ?? true,
          sign: format === "json" && sign, ca_bundle_pem: caBundle },
      }),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ["webhooks"] });
      onCreated("signing_secret" in r ? r.signing_secret ?? null : null);
      onClose();
    },
  });
  const toggle = (k: string) => setSelected((x) => (x.includes(k) ? x.filter((y) => y !== k) : [...x, k]));
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      size="lg"
      title={hook ? `Edit ${hook.name}` : "New webhook"}
      description="PATHOS POSTs the chosen notification events to this URL. Only https URLs; internal addresses need the explicit option below."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button disabled={!name.trim() || (!hook && !url.trim()) || !selected.length || save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save"}</Button>
        </>
      }
    >
      <div className="space-y-3 text-[13px]">
        {save.error && <ErrorPanel error={save.error} />}
        <div className="grid gap-3 md:grid-cols-2">
          <div><Label htmlFor="wh-name">Name</Label><Input id="wh-name" value={name} maxLength={120} onChange={(e) => setName(e.target.value)} placeholder="e.g. Security channel" /></div>
          <div>
            <Label htmlFor="wh-format">Format</Label>
            <Select id="wh-format" value={format} onChange={(e) => setFormat(e.target.value as WebhookEndpoint["format"])}>
              {Object.entries(formatLabel).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </Select>
          </div>
        </div>
        <div>
          <Label htmlFor="wh-url" hint={hook ? `(leave empty to keep the current URL on ${hook.host})` : "(stored encrypted; Slack and Teams URLs are secrets)"}>URL</Label>
          <Input id="wh-url" type="url" className="font-mono text-[12px]" value={url} onChange={(e) => setUrl(e.target.value)}
            placeholder={format === "slack" ? "https://hooks.slack.com/services/…" : format === "teams" ? "https://…webhook.office.com/… or a Workflows URL" : "https://siem.example.com/pathos"} />
        </div>
        <fieldset>
          <legend className="mb-1 text-[12px] font-medium">Events</legend>
          {events.isPending ? <Skeleton className="h-16" /> : (
            <div className="grid gap-x-3 gap-y-1 sm:grid-cols-2">
              {events.data?.items.filter((e) => e.key !== "smtp.test").map((e) => (
                <label key={e.key} className="flex items-center gap-1.5 text-[12.5px]">
                  <input type="checkbox" className="accent-[var(--primary)]" checked={selected.includes(e.key)} onChange={() => toggle(e.key)} /> {e.label}
                </label>
              ))}
            </div>
          )}
        </fieldset>
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <Label htmlFor="wh-sev">Only when severity is at least</Label>
            <Select id="wh-sev" value={minSev} onChange={(e) => setMinSev(e.target.value)}>
              <option value="">Any (events without severity always)</option>
              {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{s}</option>)}
            </Select>
          </div>
          <div className="space-y-1 pt-5">
            {!hook && format === "json" && (
              <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={sign} onChange={(e) => setSign(e.target.checked)} /> Sign requests (HMAC-SHA256)</label>
            )}
            {format !== "json" && (
              <div className="text-[12px] text-muted-foreground">{formatLabel[format]} cannot verify signatures: deliveries are not signed. Keep the URL secret.</div>
            )}
            <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={allowPrivate} onChange={(e) => setAllowPrivate(e.target.checked)} /> Allow an internal (private network) address</label>
          </div>
        </div>
        <div>
          <Label htmlFor="wh-ca" hint="(optional; PEM certificates of a private CA, added to the system trust store for this endpoint only)">Private CA bundle</Label>
          <textarea id="wh-ca" className="min-h-20 w-full rounded-md border border-border bg-surface px-2.5 py-1.5 font-mono text-[12px] focus:outline-none focus:ring-1 focus:ring-[color:var(--ring)]"
            value={caBundle} onChange={(e) => setCaBundle(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
        </div>
      </div>
    </Dialog>
  );
}

function Deliveries({ hook }: { hook: WebhookEndpoint }) {
  const q = useQuery({ queryKey: ["webhook-deliveries", hook.id], queryFn: () => api<{ items: Delivery[] }>(`/api/v1/notifications/webhooks/${hook.id}/deliveries`).then((r) => r.items) });
  if (q.isError) return <ErrorPanel error={q.error} />;
  if (q.isPending) return <Skeleton className="h-16" />;
  if (!q.data.length) return <p className="text-[12px] text-muted-foreground">No deliveries yet.</p>;
  return (
    <Table>
      <thead><tr><Th>Event</Th><Th>Status</Th><Th>Attempts</Th><Th>Response</Th><Th>When</Th></tr></thead>
      <tbody>
        {q.data.map((d) => (
          <tr key={d.id}>
            <Td className="font-mono text-[11.5px]">{d.event_key}</Td>
            <Td><Badge tone={d.status === "succeeded" ? "success" : d.status === "failed" ? "danger" : "warning"}>{d.status}</Badge>{d.error && <div className="text-[11px] text-danger">{d.error}</div>}</Td>
            <Td className="tabular text-[12px]">{d.attempts}{d.status === "pending" && <div className="text-[11px] text-muted-foreground">next {formatDateTime(d.next_attempt_at)}</div>}</Td>
            <Td className="tabular text-[12px]">{d.response_status ?? "—"}</Td>
            <Td className="whitespace-nowrap text-[11.5px] text-muted-foreground">{formatDateTime(d.delivered_at ?? d.created_at)}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export function WebhooksTab() {
  const qc = useQueryClient();
  const [dialog, setDialog] = useState<{ hook: WebhookEndpoint | null } | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [tested, setTested] = useState<Record<string, string>>({});
  const list = useQuery({ queryKey: ["webhooks"], queryFn: () => api<{ items: WebhookEndpoint[] }>("/api/v1/notifications/webhooks").then((r) => r.items) });
  const test = useMutation({
    mutationFn: (id: string) => api<{ ok: boolean; status: number; error?: string }>(`/api/v1/notifications/webhooks/${id}/test`, { method: "POST" }),
    onSuccess: (r, id) => setTested((t) => ({ ...t, [id]: r.ok ? `Delivered (HTTP ${r.status})` : `Failed: ${r.error ?? r.status}` })),
  });
  const toggle = useMutation({
    mutationFn: (h: WebhookEndpoint) => api(`/api/v1/notifications/webhooks/${h.id}`, { method: "PUT", body: { name: h.name, format: h.format, events: h.events, min_severity: h.min_severity, allow_private: h.allow_private, enabled: !h.enabled } }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["webhooks"] }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/api/v1/notifications/webhooks/${id}`, { method: "DELETE" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["webhooks"] }),
  });
  const selected = list.data?.find((h) => h.id === open);
  return (
    <Card className="p-4">
      <div className="mb-3 flex flex-wrap items-start gap-2">
        <div>
          <h2 className="text-[13px] font-semibold">Outbound webhooks</h2>
          <p className="text-[12px] text-muted-foreground">Send notification events to a SIEM, a chat channel (Slack, Microsoft Teams) or any service. Deliveries are retried with back-off for about nine hours.</p>
        </div>
        <Button className="ml-auto" onClick={() => setDialog({ hook: null })}><Webhook /> New webhook</Button>
      </div>
      {(test.error ?? toggle.error ?? remove.error) && <div className="mb-2"><Alert>{(test.error ?? toggle.error ?? remove.error)!.message}</Alert></div>}
      {list.isError ? <ErrorPanel error={list.error} /> : list.isPending ? <Skeleton className="h-20" /> : !list.data.length ? (
        <EmptyState icon={<Webhook />} title="No webhooks">Nothing is sent outside PATHOS until you add one.</EmptyState>
      ) : (
        <Table>
          <thead><tr><Th>Webhook</Th><Th>Events</Th><Th>Last delivery</Th><Th className="text-right">Manage</Th></tr></thead>
          <tbody>
            {list.data.map((h) => (
              <tr key={h.id} className={h.enabled ? undefined : "opacity-60"}>
                <Td>
                  <div className="flex items-center gap-1.5 font-medium">{h.name}{!h.enabled && <Badge>disabled</Badge>}</div>
                  <div className="text-[11.5px] text-muted-foreground">{formatLabel[h.format]} · {h.host}{h.signed ? " · signed" : ""}{h.allow_private ? " · internal address" : ""}</div>
                  {tested[h.id] && <div className="text-[11.5px]">{tested[h.id]}</div>}
                </Td>
                <Td className="max-w-72 text-[12px]">{h.events.join(", ")}{h.min_severity && <span className="text-muted-foreground"> · ≥ {h.min_severity}</span>}</Td>
                <Td className="text-[12px]">
                  {h.last_status ? <Badge tone={h.last_status === "succeeded" ? "success" : "danger"}>{h.last_status}</Badge> : <span className="text-muted-foreground">—</span>}
                  {h.failed_24h > 0 && <div className="text-[11px] text-danger">{h.failed_24h} failed in 24 h</div>}
                  <button type="button" className="block text-[11.5px] text-primary hover:underline" onClick={() => setOpen(open === h.id ? null : h.id)}>{open === h.id ? "Hide" : "Deliveries"}</button>
                </Td>
                <Td className="whitespace-nowrap text-right">
                  <Button size="sm" variant="ghost" onClick={() => test.mutate(h.id)} disabled={test.isPending}><Send /> Test</Button>
                  <Button size="sm" variant="ghost" onClick={() => toggle.mutate(h)}>{h.enabled ? "Disable" : "Enable"}</Button>
                  <Button size="icon" variant="ghost" aria-label={`Edit ${h.name}`} onClick={() => setDialog({ hook: h })}><Pencil /></Button>
                  <Button size="icon" variant="ghost" aria-label={`Delete ${h.name}`} onClick={() => { if (window.confirm(`Delete the webhook “${h.name}”?`)) remove.mutate(h.id); }}><Trash2 /></Button>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {selected && <div className="mt-4"><h3 className="mb-1 text-[13px] font-semibold">Deliveries to {selected.name}</h3><Deliveries hook={selected} /></div>}
      <WebhookDialog open={!!dialog} onClose={() => setDialog(null)} hook={dialog?.hook ?? null} onCreated={(s) => s && setSecret(s)} />
      <Dialog open={!!secret} onOpenChange={(o) => !o && setSecret(null)} title="Signing secret" description="Copy it now: it is not shown again." footer={<Button onClick={() => setSecret(null)}>Done</Button>}>
        {secret && (
          <div className="space-y-2 text-[13px]">
            <div className="flex gap-2"><Input readOnly value={secret} className="font-mono text-[12px]" onFocus={(e) => e.target.select()} />
              <Button variant="secondary" size="icon" aria-label="Copy secret" onClick={() => void navigator.clipboard?.writeText(secret)}><Copy /></Button></div>
            <p className="text-[12px] text-muted-foreground">
              Verify each request: <code>X-PATHOS-Signature</code> is <code>sha256=</code> + hex HMAC-SHA256 of <code>{"<X-PATHOS-Timestamp>.<body>"}</code> with this secret.
              Reject old timestamps to stop replays.
            </p>
          </div>
        )}
      </Dialog>
    </Card>
  );
}

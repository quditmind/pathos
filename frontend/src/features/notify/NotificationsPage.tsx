import { useEffect, useState } from "react";
import { Bell, Mail, Plus, RotateCcw, Send, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import type { Delivery, NotificationRule, NotificationTemplate, Severity, SmtpSettings } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { useRepositories } from "@/features/repos/api";
import { useBusinessUnits, useRegions, useRoles, useUsers } from "@/features/users/api";
import { cn, formatDateTime } from "@/lib/utils";
import { useDeliveries, useDelivery, useEvents, useNotifyMutation, useRules, useSmtp, useTemplates } from "./api";
import { WebhooksTab } from "./WebhooksTab";
import { ErrorPanel } from "@/components/ui/error-panel";

const tabs = [
  { key: "rules", label: "Rules" },
  { key: "email", label: "Email (SMTP)" },
  { key: "templates", label: "Templates" },
  { key: "webhooks", label: "Webhooks" },
  { key: "history", label: "Delivery history" },
] as const;
type Tab = (typeof tabs)[number]["key"];

export function NotificationsPage() {
  const [tab, setTab] = useState<Tab>(() => {
    try {
      return (localStorage.getItem("pathos.notify.tab") as Tab) || "rules";
    } catch {
      return "rules";
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem("pathos.notify.tab", tab);
    } catch { /* storage unavailable */ }
  }, [tab]);
  return (
    <>
      <PageHeader title="Notifications" description="Who hears about what. Rules match events (new findings, SLA breaches, failed scans, approvals) to recipients by email and in-app." />
      <div role="tablist" className="mb-3 flex gap-1 border-b border-border">
        {tabs.map((t) => (
          <button key={t.key} role="tab" aria-selected={tab === t.key} onClick={() => setTab(t.key)}
            className={cn("-mb-px border-b-2 px-3 py-2 text-[13px] font-medium", tab === t.key ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground")}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === "rules" && <RulesTab />}
      {tab === "email" && <SmtpTab onTest={() => setTab("history")} />}
      {tab === "templates" && <TemplatesTab />}
      {tab === "history" && <HistoryTab />}
      {tab === "webhooks" && <WebhooksTab />}
    </>
  );
}

// ---------------------------------------------------------------- rules

type RuleDraft = Omit<NotificationRule, "id" | "scope_name" | "system" | "updated_at"> & { id?: string; system?: boolean; emailsText: string };

const blankRule: RuleDraft = {
  name: "", enabled: true, event_key: "findings.new", min_severity: null, scope_type: "organization", scope_id: null,
  recipients: { roles: [], users: [], emails: [], dynamic: [] }, email: true, in_app: true, emailsText: "",
};

function RulesTab() {
  const rules = useRules();
  const events = useEvents();
  const [draft, setDraft] = useState<RuleDraft | null>(null);
  const toggle = useNotifyMutation((r: NotificationRule) => api(`/api/v1/notifications/rules/${r.id}`, { method: "PUT", body: { ...r, enabled: !r.enabled } }));
  const del = useNotifyMutation((id: string) => api(`/api/v1/notifications/rules/${id}`, { method: "DELETE" }));
  const label = (k: string) => events.data?.items.find((e) => e.key === k)?.label ?? k;
  const dyn = events.data?.dynamic ?? {};
  const roles = useRoles();
  const roleName = (k: string) => roles.data?.find((r) => r.key === k)?.name ?? k;

  const columns: Column<NotificationRule>[] = [
    {
      id: "name", header: "Rule", required: true,
      cell: (r) => <div><div className="flex items-center gap-2 font-medium">{r.name}{r.system && <Badge>built-in</Badge>}{!r.enabled && <Badge tone="warning">off</Badge>}</div>
        <div className="text-[12px] text-muted-foreground">{label(r.event_key)}{r.min_severity && ` · ${r.min_severity} and above`}{r.scope_type !== "organization" && ` · ${r.scope_name}`}</div></div>,
      csv: (r) => r.name,
    },
    {
      id: "to", header: "Recipients",
      cell: (r) => <div className="flex max-w-md flex-wrap gap-1 text-[11.5px]">
        {r.recipients.dynamic.map((d) => <Badge key={d} tone="primary">{dyn[d] ?? d}</Badge>)}
        {r.recipients.roles.map((k) => <Badge key={k}>{roleName(k)}</Badge>)}
        {r.recipients.users.length > 0 && <Badge>{r.recipients.users.length} user{r.recipients.users.length > 1 ? "s" : ""}</Badge>}
        {r.recipients.emails.map((e) => <Badge key={e}>{e}</Badge>)}
      </div>,
      csv: (r) => [...r.recipients.dynamic, ...r.recipients.roles, ...r.recipients.emails].join(";"),
    },
    { id: "ch", header: "Channels", cell: (r) => <span className="flex gap-1.5 text-muted-foreground">{r.email && <Mail className="size-4" aria-label="email" />}{r.in_app && <Bell className="size-4" aria-label="in-app" />}</span>, csv: (r) => [r.email && "email", r.in_app && "in_app"].filter(Boolean).join(";") },
    {
      id: "actions", header: "", required: true,
      cell: (r) => <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
        <Button size="sm" variant="ghost" onClick={() => toggle.mutate(r)}>{r.enabled ? "Disable" : "Enable"}</Button>
        {!r.system && <Button size="sm" variant="ghost" className="text-danger" aria-label="Delete rule" onClick={() => confirm(`Delete rule "${r.name}"?`) && del.mutate(r.id)}><Trash2 /></Button>}
      </div>,
    },
  ];
  return (
    <>
      {(toggle.error ?? del.error) && <div className="mb-3"><Alert>{(toggle.error ?? del.error)!.message}</Alert></div>}
      <Card>
        <DataTable tableId="notify-rules" exportName="pathos-notification-rules" columns={columns} rows={rules.data ?? []} rowKey={(r) => r.id}
          isPending={rules.isPending} error={rules.error}
          onRowClick={(r) => setDraft({ ...r, emailsText: r.recipients.emails.join("\n") })}
          toolbar={<Button size="sm" className="ml-auto" onClick={() => setDraft({ ...blankRule })}><Plus /> New rule</Button>}
          empty={<EmptyState icon={<Bell />} title="No rules" />} />
      </Card>
      <RuleDialog draft={draft} onClose={() => setDraft(null)} />
    </>
  );
}

function RuleDialog({ draft, onClose }: { draft: RuleDraft | null; onClose: () => void }) {
  const [d, setD] = useState<RuleDraft>(blankRule);
  useEffect(() => { if (draft) setD(draft); }, [draft]);
  const events = useEvents();
  const roles = useRoles();
  const users = useUsers("", "active");
  const regions = useRegions();
  const bus = useBusinessUnits();
  const repos = useRepositories({});
  const ev = events.data?.items.find((e) => e.key === d.event_key);
  const rc = d.recipients;
  const toggleIn = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
  const save = useNotifyMutation(() => {
    const body = {
      name: d.name, enabled: d.enabled, event_key: d.event_key, min_severity: d.min_severity, scope_type: d.scope_type, scope_id: d.scope_id,
      recipients: { ...rc, emails: d.emailsText.split(/[\s,;]+/).filter(Boolean) }, email: d.email, in_app: d.in_app,
    };
    return d.id ? api(`/api/v1/notifications/rules/${d.id}`, { method: "PUT", body }) : api("/api/v1/notifications/rules", { method: "POST", body });
  });
  const scopes = d.scope_type === "region" ? (regions.data ?? []).map((r) => ({ id: r.id, name: r.name }))
    : d.scope_type === "business_unit" ? (bus.data ?? []).map((b) => ({ id: b.id, name: b.name }))
      : d.scope_type === "repository" ? (repos.data?.pages.flatMap((p) => p.items) ?? []).map((r) => ({ id: r.id, name: r.full_name })) : [];
  const userList = users.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <Dialog open={!!draft} onOpenChange={(o) => !o && onClose()} title={d.id ? `Edit rule${d.system ? " (built-in)" : ""}` : "New notification rule"}
      footer={<><Button variant="secondary" onClick={onClose}>Cancel</Button><Button disabled={!d.name.trim() || save.isPending} onClick={() => save.mutate(undefined, { onSuccess: onClose })}>Save rule</Button></>}>
      <div className="space-y-3">
        {save.isError && <ErrorPanel error={save.error} />}
        <div><Label htmlFor="r-name">Name</Label><Input id="r-name" value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} /></div>
        <div>
          <Label htmlFor="r-ev">Event</Label>
          <Select id="r-ev" className="w-full" disabled={d.system} value={d.event_key}
            onChange={(e) => setD({ ...d, event_key: e.target.value, min_severity: null, scope_type: "organization", scope_id: null, recipients: { ...rc, dynamic: [] } })}>
            {(events.data?.items ?? []).map((e) => <option key={e.key} value={e.key}>{e.label}</option>)}
          </Select>
          {ev && <p className="mt-1 text-[12px] text-muted-foreground">{ev.description}</p>}
        </div>
        <div className="grid grid-cols-2 gap-3">
          {ev?.severity && (
            <div>
              <Label htmlFor="r-sev">Minimum severity</Label>
              <Select id="r-sev" className="w-full" value={d.min_severity ?? ""} onChange={(e) => setD({ ...d, min_severity: (e.target.value || null) as Severity | null })}>
                <option value="">Any</option>
                {(["critical", "high", "medium", "low"] as const).map((s) => <option key={s} value={s}>{s[0]!.toUpperCase() + s.slice(1)} and above</option>)}
              </Select>
            </div>
          )}
          {ev?.repository && (
            <div>
              <Label htmlFor="r-scope">Scope</Label>
              <Select id="r-scope" className="w-full" value={d.scope_type} onChange={(e) => setD({ ...d, scope_type: e.target.value as RuleDraft["scope_type"], scope_id: null })}>
                <option value="organization">Whole organization</option><option value="region">Region</option><option value="business_unit">Business unit</option><option value="repository">Repository</option>
              </Select>
            </div>
          )}
        </div>
        {d.scope_type !== "organization" && (
          <Select aria-label="Scope target" className="w-full" value={d.scope_id ?? ""} onChange={(e) => setD({ ...d, scope_id: e.target.value || null })}>
            <option value="">Choose…</option>
            {scopes.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </Select>
        )}
        {!!ev?.dynamic.length && (
          <div>
            <Label htmlFor="r-dyn">Dynamic recipients</Label>
            <div id="r-dyn" className="flex flex-wrap gap-3 text-[13px]">
              {ev.dynamic.map((k) => (
                <label key={k} className="flex items-center gap-1.5"><input type="checkbox" checked={rc.dynamic.includes(k)} onChange={() => setD({ ...d, recipients: { ...rc, dynamic: toggleIn(rc.dynamic, k) } })} />{events.data?.dynamic[k] ?? k}</label>
              ))}
            </div>
          </div>
        )}
        <div>
          <Label htmlFor="r-roles" hint="users holding the role at a scope covering the repository">Roles</Label>
          <div id="r-roles" className="flex flex-wrap gap-x-3 gap-y-1 text-[13px]">
            {(roles.data ?? []).map((r) => (
              <label key={r.key} className="flex items-center gap-1.5"><input type="checkbox" checked={rc.roles.includes(r.key)} onChange={() => setD({ ...d, recipients: { ...rc, roles: toggleIn(rc.roles, r.key) } })} />{r.name}</label>
            ))}
          </div>
        </div>
        {userList.length > 0 && (
          <div>
            <Label htmlFor="r-users">Specific users</Label>
            <Select id="r-users" multiple className="h-24 w-full" value={rc.users} onChange={(e) => setD({ ...d, recipients: { ...rc, users: Array.from(e.target.selectedOptions, (o) => o.value) } })}>
              {userList.map((u) => <option key={u.id} value={u.id}>{u.display_name || u.email}</option>)}
            </Select>
          </div>
        )}
        <div>
          <Label htmlFor="r-emails" hint="e.g. a team list; one per line">External addresses</Label>
          <textarea id="r-emails" rows={2} value={d.emailsText} onChange={(e) => setD({ ...d, emailsText: e.target.value })}
            className="w-full rounded-md border border-border bg-surface p-2 text-[13px] focus-visible:outline-2 focus-visible:outline-ring" />
        </div>
        <div className="flex flex-wrap gap-4 text-[13px]">
          <label className="flex items-center gap-1.5"><input type="checkbox" checked={d.email} onChange={(e) => setD({ ...d, email: e.target.checked })} /> Email</label>
          <label className="flex items-center gap-1.5"><input type="checkbox" checked={d.in_app} onChange={(e) => setD({ ...d, in_app: e.target.checked })} /> In-app</label>
          <label className="flex items-center gap-1.5"><input type="checkbox" checked={d.enabled} onChange={(e) => setD({ ...d, enabled: e.target.checked })} /> Enabled</label>
        </div>
      </div>
    </Dialog>
  );
}

// ----------------------------------------------------------------- SMTP

function SmtpTab({ onTest }: { onTest: () => void }) {
  const smtp = useSmtp();
  const [d, setD] = useState<SmtpSettings | null>(null);
  const [password, setPassword] = useState<string | null>(null);
  const [to, setTo] = useState("");
  useEffect(() => { if (smtp.data) setD(smtp.data); }, [smtp.data]);
  const save = useNotifyMutation(() => api<SmtpSettings>("/api/v1/notifications/smtp", { method: "PUT", body: { ...d, password: password ?? undefined } }));
  const test = useNotifyMutation(() => api<{ id: string; to: string }>("/api/v1/notifications/smtp/test", { method: "POST", body: to ? { to } : {} }));
  if (!d) return <Skeleton className="h-64" />;
  return (
    <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
      <Card className="space-y-3 p-4">
        {save.isError && <ErrorPanel error={save.error} />}
        {save.isSuccess && <Alert tone="success">Saved.</Alert>}
        <label className="flex items-center gap-2 text-[13px] font-medium"><input type="checkbox" checked={d.enabled} onChange={(e) => setD({ ...d, enabled: e.target.checked })} /> Send email notifications</label>
        <div className="grid grid-cols-[1fr_110px] gap-3">
          <div><Label htmlFor="m-host">SMTP host</Label><Input id="m-host" value={d.host} placeholder="smtp.example.com" onChange={(e) => setD({ ...d, host: e.target.value })} /></div>
          <div><Label htmlFor="m-port">Port</Label><Input id="m-port" type="number" value={d.port} onChange={(e) => setD({ ...d, port: Number(e.target.value) })} /></div>
        </div>
        <div>
          <Label htmlFor="m-tls" hint="STARTTLS never falls back to clear text">Security</Label>
          <Select id="m-tls" className="w-full" value={d.tls_mode} onChange={(e) => setD({ ...d, tls_mode: e.target.value as SmtpSettings["tls_mode"] })}>
            <option value="starttls">STARTTLS (port 587)</option><option value="tls">Implicit TLS (port 465)</option><option value="none">None (internal relay or development only)</option>
          </Select>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div><Label htmlFor="m-user">Username</Label><Input id="m-user" autoComplete="off" value={d.username} onChange={(e) => setD({ ...d, username: e.target.value })} /></div>
          <div>
            <Label htmlFor="m-pass">Password</Label>
            <Input id="m-pass" type="password" autoComplete="new-password" placeholder={d.has_password ? "•••••••• (unchanged)" : ""} value={password ?? ""} onChange={(e) => setPassword(e.target.value)} />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div><Label htmlFor="m-from">From address</Label><Input id="m-from" value={d.from_address} placeholder="pathos@example.com" onChange={(e) => setD({ ...d, from_address: e.target.value })} /></div>
          <div><Label htmlFor="m-name">From name</Label><Input id="m-name" value={d.from_name} onChange={(e) => setD({ ...d, from_name: e.target.value })} /></div>
        </div>
        <div className="flex items-center gap-2">
          <Button disabled={save.isPending} onClick={() => save.mutate(undefined, { onSuccess: () => setPassword(null) })}>Save</Button>
          {d.has_password && <Button variant="ghost" onClick={() => setPassword("")}>Remove password</Button>}
        </div>
      </Card>
      <Card className="space-y-2 p-4">
        <h2 className="text-[13px] font-semibold">Send a test email</h2>
        <p className="text-[12px] text-muted-foreground">Queued like any notification and delivered by the jobs service, so it tests the real path. Leave empty to send to yourself.</p>
        {test.isError && <ErrorPanel error={test.error} />}
        {test.isSuccess && <Alert tone="success">Queued for {test.data.to}. Watch its status in the delivery history.</Alert>}
        <Input aria-label="Test recipient" placeholder="you@example.com" value={to} onChange={(e) => setTo(e.target.value)} />
        <div className="flex gap-2">
          <Button variant="secondary" disabled={test.isPending || !d.enabled} onClick={() => test.mutate(undefined)}><Send /> Send test</Button>
          {test.isSuccess && <Button variant="ghost" onClick={onTest}>View history</Button>}
        </div>
      </Card>
    </div>
  );
}

// ------------------------------------------------------------ templates

function TemplatesTab() {
  const list = useTemplates();
  const [sel, setSel] = useState<string>("");
  const t = list.data?.find((x) => x.event_key === sel) ?? list.data?.[0];
  const [draft, setDraft] = useState<{ subject: string; body: string } | null>(null);
  const [preview, setPreview] = useState<{ subject: string; body: string } | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => { if (t) { setDraft({ subject: t.subject, body: t.body }); setPreview(null); setErr(""); } }, [t?.event_key, t?.subject, t?.body]);
  useEffect(() => {
    if (!t || !draft) return;
    const h = setTimeout(() => {
      api<{ subject: string; body: string }>(`/api/v1/notifications/templates/${t.event_key}/preview`, { method: "POST", body: draft })
        .then((p) => { setPreview(p); setErr(""); }).catch((e: Error) => setErr(e.message));
    }, 350);
    return () => clearTimeout(h);
  }, [draft, t]);
  const save = useNotifyMutation(() => api(`/api/v1/notifications/templates/${t!.event_key}`, { method: "PUT", body: draft }));
  const reset = useNotifyMutation(() => api(`/api/v1/notifications/templates/${t!.event_key}`, { method: "DELETE" }));
  if (!list.data || !t || !draft) return <Skeleton className="h-64" />;
  const dirty = draft.subject !== t.subject || draft.body !== t.body;
  return (
    <div className="grid gap-4 lg:grid-cols-[220px_1fr_1fr]">
      <Card className="p-1.5">
        {list.data.map((x: NotificationTemplate) => (
          <button key={x.event_key} onClick={() => setSel(x.event_key)}
            className={cn("flex w-full items-center justify-between rounded px-2.5 py-1.5 text-left text-[13px]", x.event_key === t.event_key ? "bg-primary/10 font-medium text-primary" : "hover:bg-surface-muted")}>
            {x.label}{x.customized && <span className="size-1.5 rounded-full bg-primary" title="customized" />}
          </button>
        ))}
      </Card>
      <Card className="space-y-2 p-4">
        <div className="flex items-center justify-between"><h2 className="text-[13px] font-semibold">{t.label}</h2>{t.customized && <Badge tone="primary">customized</Badge>}</div>
        <p className="text-[12px] text-muted-foreground">Go text/template syntax, e.g. <code>{"{{.Repository}}"}</code>, <code>{"{{range .Findings}}…{{end}}"}</code>. Templates are validated against sample data on save.</p>
        {(save.error ?? reset.error) && <Alert>{(save.error ?? reset.error)!.message}</Alert>}
        <Label htmlFor="t-sub">Subject</Label>
        <Input id="t-sub" className="font-mono" value={draft.subject} onChange={(e) => setDraft({ ...draft, subject: e.target.value })} />
        <Label htmlFor="t-body">Body</Label>
        <textarea id="t-body" rows={14} value={draft.body} onChange={(e) => setDraft({ ...draft, body: e.target.value })}
          className="w-full rounded-md border border-border bg-surface p-2 font-mono text-[12px] focus-visible:outline-2 focus-visible:outline-ring" />
        <div className="flex gap-2">
          <Button disabled={!dirty || !!err || save.isPending} onClick={() => save.mutate(undefined)}>Save template</Button>
          {t.customized && <Button variant="ghost" onClick={() => reset.mutate(undefined)}><RotateCcw /> Reset to default</Button>}
        </div>
      </Card>
      <Card className="p-4">
        <h2 className="mb-2 text-[13px] font-semibold">Preview (sample data)</h2>
        {err ? <Alert>{err}</Alert> : preview ? (
          <div className="text-[12.5px]">
            <div className="mb-2 border-b border-border pb-2 font-medium">{preview.subject}</div>
            <pre className="whitespace-pre-wrap break-words font-sans text-muted-foreground">{preview.body}</pre>
          </div>
        ) : <Skeleton className="h-40" />}
      </Card>
    </div>
  );
}

// --------------------------------------------------------------- history

const statusTone: Record<Delivery["status"], "primary" | "warning" | "danger" | "neutral"> = { sent: "primary", pending: "warning", failed: "danger", suppressed: "neutral" };

function HistoryTab() {
  const [status, setStatus] = useState("");
  const [channel, setChannel] = useState("email");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const list = useDeliveries({ status, channel, q: q.trim() || undefined }, true);
  const events = useEvents();
  const retry = useNotifyMutation((id: string) => api(`/api/v1/notifications/deliveries/${id}/retry`, { method: "POST" }));
  const label = (k: string) => (k === "smtp.test" ? "Test email" : events.data?.items.find((e) => e.key === k)?.label ?? k);
  const stats = list.data?.email_last_7_days;
  const columns: Column<Delivery>[] = [
    { id: "when", header: "Created", className: "tabular whitespace-nowrap text-[12px]", cell: (d) => formatDateTime(d.created_at), csv: (d) => d.created_at },
    { id: "event", header: "Event", cell: (d) => <span className="text-[12px]">{label(d.event_key)}</span>, csv: (d) => d.event_key },
    { id: "to", header: "Recipient", cell: (d) => <span className="text-[12px]">{d.recipient}</span>, csv: (d) => d.recipient },
    { id: "subject", header: "Subject", required: true, cell: (d) => <span className="block max-w-md truncate">{d.subject}</span>, csv: (d) => d.subject },
    {
      id: "status", header: "Status",
      cell: (d) => <div><Badge tone={statusTone[d.status]}>{d.status}</Badge>{d.attempts > 1 && <span className="ml-1 text-[11px] text-muted-foreground">{d.attempts} attempts</span>}
        {d.last_error && <div className="max-w-xs truncate text-[11px] text-danger" title={d.last_error}>{d.last_error}</div>}</div>,
      csv: (d) => d.status,
    },
    {
      id: "actions", header: "",
      cell: (d) => d.channel === "email" && (d.status === "failed" || d.status === "suppressed") && (
        <Button size="sm" variant="secondary" onClick={(e) => { e.stopPropagation(); retry.mutate(d.id); }}>Retry</Button>
      ),
    },
  ];
  return (
    <>
      {stats && (
        <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
          {(["sent", "pending", "failed", "suppressed"] as const).map((k) => (
            <Card key={k} className="p-3"><div className="text-[12px] capitalize text-muted-foreground">{k} · 7 days</div><div className="tabular text-lg font-semibold">{stats[k] ?? 0}</div></Card>
          ))}
        </div>
      )}
      {retry.isError && <div className="mb-3"><ErrorPanel error={retry.error} /></div>}
      <Card>
        <DataTable tableId="notify-history" exportName="pathos-notification-deliveries" columns={columns} rows={list.data?.items ?? []} rowKey={(d) => d.id}
          isPending={list.isPending} error={list.error} onRowClick={(d) => setOpen(d.id)}
          empty={<EmptyState icon={<Mail />} title="No deliveries match" />}
          toolbar={<>
            <Input aria-label="Search deliveries" placeholder="Subject or recipient" className="max-w-xs" value={q} onChange={(e) => setQ(e.target.value)} />
            <Select aria-label="Channel" value={channel} onChange={(e) => setChannel(e.target.value)}><option value="email">Email</option><option value="in_app">In-app</option><option value="">All channels</option></Select>
            <Select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">Any status</option><option value="sent">Sent</option><option value="pending">Pending</option><option value="failed">Failed</option><option value="suppressed">Suppressed</option>
            </Select>
          </>} />
      </Card>
      <DeliveryDialog id={open} onClose={() => setOpen(null)} />
    </>
  );
}

function DeliveryDialog({ id, onClose }: { id: string | null; onClose: () => void }) {
  const d = useDelivery(id);
  return (
    <Dialog side open={!!id} onOpenChange={(o) => !o && onClose()} title={d.data?.subject ?? "Delivery"} description={d.data ? `${d.data.channel === "email" ? "Email" : "In-app"} to ${d.data.recipient}` : undefined}>
      {!d.data ? <Skeleton className="h-40" /> : (
        <div className="space-y-3 text-[13px]">
          <div className="flex flex-wrap gap-2"><Badge tone={statusTone[d.data.status]}>{d.data.status}</Badge>
            <span className="text-muted-foreground">{d.data.rule_name ? `Rule: ${d.data.rule_name}` : "No rule (test or system)"} · created {formatDateTime(d.data.created_at)}{d.data.sent_at && ` · sent ${formatDateTime(d.data.sent_at)}`}</span></div>
          {d.data.last_error && <Alert>{d.data.last_error}</Alert>}
          <pre className="whitespace-pre-wrap break-words rounded-md border border-border bg-surface-muted/40 p-3 font-sans text-[12.5px]">{d.data.body}</pre>
        </div>
      )}
    </Dialog>
  );
}

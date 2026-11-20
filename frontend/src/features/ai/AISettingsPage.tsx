import { useEffect, useState, type FormEvent } from "react";
import { CheckCircle2, CircleAlert, Plus, RefreshCw, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import type { AIConfiguration, AIProvider } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { useAIConfigs, useAIMutation, useAIProviders } from "./api";
import { FINDING_CATEGORIES, categoryName } from "@/lib/findingCategories";
import { ErrorPanel } from "@/components/ui/error-panel";
import { ModelPerTask } from "./ModelPerTask";

const kindLabel = { anthropic: "Anthropic (Claude)", openai: "OpenAI", xai: "xAI (Grok)", self_hosted: "Self-hosted (Ollama, vLLM, LM Studio…)" };

export function AISettingsPage() {
  const providers = useAIProviders();
  const configs = useAIConfigs();
  const [adding, setAdding] = useState(false);
  const test = useAIMutation((id: string) => api(`/api/v1/ai/providers/${id}/test`, { method: "POST" }));
  const del = useAIMutation((id: string) => api(`/api/v1/ai/providers/${id}`, { method: "DELETE" }));
  const def = configs.data?.find((c) => c.is_default);

  return (
    <>
      <PageHeader title="AI settings" description="AI providers and the review configuration. API keys are encrypted at rest; Claude subscriptions cannot be used for automated reviews (use an API key, or interactive review via MCP)."
        actions={<Button onClick={() => setAdding(true)}><Plus /> Add provider</Button>} />
      {(test.error ?? del.error) && <div className="mb-3"><Alert>{(test.error ?? del.error)!.message}</Alert></div>}
      <h2 className="mb-2 text-[13px] font-semibold">Providers</h2>
      {providers.isPending ? <Skeleton className="h-20" /> : !providers.data?.length ? (
        <Card className="mb-6"><EmptyState title="No AI providers">Add an Anthropic, OpenAI or xAI API key to enable automated reviews.</EmptyState></Card>
      ) : (
        <div className="mb-6 grid gap-3 lg:grid-cols-2">
          {providers.data.map((p: AIProvider) => (
            <Card key={p.id} className="flex items-start justify-between gap-3 p-4">
              <div className="min-w-0">
                <div className="font-medium">{p.name}</div>
                <div className="text-[12px] text-muted-foreground">{kindLabel[p.kind]}{p.base_url && ` · ${p.base_url}`}</div>
                <div className={`mt-1 flex items-center gap-1 text-[12px] ${p.status === "ok" ? "text-success" : p.status === "error" ? "text-danger" : "text-muted-foreground"}`}>
                  {p.status === "ok" ? <CheckCircle2 className="size-3.5" /> : <CircleAlert className="size-3.5" />}{p.status_message || p.status}
                </div>
              </div>
              <div className="flex gap-1">
                <Button size="icon" variant="ghost" aria-label="Test provider" disabled={test.isPending} onClick={() => test.mutate(p.id)}><RefreshCw /></Button>
                <Button size="icon" variant="ghost" aria-label="Delete provider" onClick={() => confirm(`Delete ${p.name}? Its key is destroyed.`) && del.mutate(p.id)}><Trash2 /></Button>
              </div>
            </Card>
          ))}
        </div>
      )}
      <h2 className="mb-2 text-[13px] font-semibold">Review configuration</h2>
      {providers.data?.length ? <ConfigEditor config={def} providers={providers.data} /> : <p className="text-[13px] text-muted-foreground">Add a provider first.</p>}
      <ModelPerTask configs={configs.data ?? []} />
      <ProviderDialog open={adding} onOpenChange={setAdding} />
    </>
  );
}

function ProviderDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const blank = { name: "", kind: "anthropic", api_key: "", base_url: "", test_model: "" };
  const [f, setF] = useState(blank);
  const create = useAIMutation((body: unknown) => api<AIProvider>("/api/v1/ai/providers", { method: "POST", body }));
  const close = () => { setF(blank); create.reset(); onOpenChange(false); };
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate(f, { onSuccess: close }); };
  return (
    <Dialog open={open} onOpenChange={(o) => (o ? onOpenChange(true) : close())} title="Add AI provider"
      description="The key is tested immediately with a tiny request."
      footer={<><Button variant="secondary" onClick={close}>Cancel</Button><Button type="submit" form="prov-form" disabled={create.isPending}>{create.isPending ? "Testing…" : "Add"}</Button></>}>
      <form id="prov-form" onSubmit={submit} className="space-y-3">
        {create.isError && <ErrorPanel error={create.error} />}
        <div className="grid grid-cols-2 gap-3">
          <div><Label htmlFor="pv-name">Name</Label><Input id="pv-name" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
          <div><Label htmlFor="pv-kind">Provider</Label>
            <Select id="pv-kind" className="w-full" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
              {Object.entries(kindLabel).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </Select></div>
        </div>
        {f.kind === "self_hosted" && (
          <Alert tone="warning">Runs on your own hardware: code never leaves your network. Any OpenAI-compatible server works. For Ollama on this host use <code>http://host.docker.internal:11434/v1</code>; with the bundled profile use <code>http://ollama:11434/v1</code>. Pull the model first (<code>ollama pull qwen2.5-coder:14b</code>).</Alert>
        )}
        <div><Label htmlFor="pv-key" hint={f.kind === "self_hosted" ? "(optional; most local servers need none)" : undefined}>API key</Label><Input id="pv-key" required={f.kind !== "self_hosted"} type="password" autoComplete="off" value={f.api_key} onChange={(e) => setF({ ...f, api_key: e.target.value })} /></div>
        {f.kind !== "anthropic" && (
          <div><Label htmlFor="pv-model" hint="(used for the connection test)">Model</Label><Input id="pv-model" required value={f.test_model} onChange={(e) => setF({ ...f, test_model: e.target.value })} /></div>
        )}
        <div><Label htmlFor="pv-url" hint={f.kind === "self_hosted" ? "(required: the OpenAI-compatible endpoint, usually ending in /v1)" : "(optional: API gateway or regional endpoint, https)"}>Base URL</Label>
          <Input id="pv-url" required={f.kind === "self_hosted"} placeholder={f.kind === "self_hosted" ? "http://host.docker.internal:11434/v1" : undefined} value={f.base_url} onChange={(e) => setF({ ...f, base_url: e.target.value })} /></div>
      </form>
    </Dialog>
  );
}

function ConfigEditor({ config, providers }: { config?: AIConfiguration; providers: AIProvider[] }) {
  const init = () => ({
    name: config?.name ?? "Default",
    provider_id: config?.current.provider_id ?? providers[0]!.id,
    model: config?.current.model ?? "",
    effort: config?.current.effort ?? "medium",
    instructions: config?.current.instructions ?? "",
    auto_review: config?.current.auto_review ?? false,
    categories: config?.current.categories ?? ["sast", "sca", "iac"],
    min_severity: config?.current.min_severity ?? "medium",
    approval_policy: config?.current.approval_policy ?? "always",
    allow_self_approval: config?.current.allow_self_approval ?? false,
    daily_limit: config?.current.daily_limit ?? 200,
    send_code_context: config?.current.send_code_context ?? true,
    redaction_patterns: (config?.current.redaction_patterns ?? []).join("\n"),
    change_note: "",
  });
  const [f, setF] = useState(init);
  useEffect(() => setF(init()), [config?.current.id]); // eslint-disable-line react-hooks/exhaustive-deps
  const save = useAIMutation((body: unknown) =>
    config ? api(`/api/v1/ai/configurations/${config.id}`, { method: "PUT", body }) : api("/api/v1/ai/configurations", { method: "POST", body }));
  const prov = providers.find((p) => p.id === f.provider_id);
  const toggleCat = (c: string) => setF({ ...f, categories: f.categories.includes(c) ? f.categories.filter((x) => x !== c) : [...f.categories, c] });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate({ ...f, is_default: true, redaction_patterns: f.redaction_patterns.split("\n").map((s) => s.trim()).filter(Boolean) });
  };
  return (
    <Card className="p-4">
      <form onSubmit={submit} className="space-y-4 text-[13px]">
        {save.isError && <ErrorPanel error={save.error} />}
        {save.isSuccess && <Alert tone="success">Saved as a new version.</Alert>}
        <div className="grid gap-3 sm:grid-cols-4">
          <div><Label htmlFor="c-prov">Provider</Label>
            <Select id="c-prov" className="w-full" value={f.provider_id} onChange={(e) => setF({ ...f, provider_id: e.target.value })}>
              {providers.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </Select></div>
          <div><Label htmlFor="c-model" hint={prov?.default_model ? `(default ${prov.default_model})` : "(required)"}>Model</Label>
            <Input id="c-model" value={f.model} placeholder={prov?.default_model} onChange={(e) => setF({ ...f, model: e.target.value })} /></div>
          <div><Label htmlFor="c-effort">Effort</Label>
            <Select id="c-effort" className="w-full capitalize" value={f.effort} onChange={(e) => setF({ ...f, effort: e.target.value as "medium" })}>
              {["low", "medium", "high"].map((v) => <option key={v} value={v}>{v}</option>)}
            </Select></div>
          <div><Label htmlFor="c-approval">Human approval</Label>
            <Select id="c-approval" className="w-full" value={f.approval_policy} onChange={(e) => setF({ ...f, approval_policy: e.target.value as "always" })}>
              <option value="always">Always</option>
              <option value="false_positives">Only false positives</option>
              <option value="never">Never (false positives and Critical still require approval)</option>
            </Select></div>
        </div>
        <label className="flex items-center gap-2"><input type="checkbox" className="accent-[var(--primary)]" checked={f.auto_review} onChange={(e) => setF({ ...f, auto_review: e.target.checked })} /> Review new findings automatically after each scan</label>
        <div className="grid gap-3 sm:grid-cols-3">
          <div><div className="mb-1 text-[12px] font-medium">Finding types</div>
            <div className="flex flex-wrap gap-2">{FINDING_CATEGORIES.filter((c) => c !== "dast").map((c) => (
              <label key={c} className="flex items-center gap-1 text-[12px]"><input type="checkbox" className="accent-[var(--primary)]" checked={f.categories.includes(c)} onChange={() => toggleCat(c)} />{categoryName(c)}</label>))}</div></div>
          <div><Label htmlFor="c-min">Minimum severity</Label>
            <Select id="c-min" className="w-full capitalize" value={f.min_severity} onChange={(e) => setF({ ...f, min_severity: e.target.value as "medium" })}>
              {["info", "low", "medium", "high", "critical"].map((v) => <option key={v} value={v}>{v}</option>)}
            </Select></div>
          <div><Label htmlFor="c-limit">Automated reviews per day</Label><Input id="c-limit" type="number" min={1} value={f.daily_limit} onChange={(e) => setF({ ...f, daily_limit: Number(e.target.value) })} /></div>
        </div>
        <label className="flex items-center gap-2"><input type="checkbox" className="accent-[var(--primary)]" checked={f.send_code_context} onChange={(e) => setF({ ...f, send_code_context: e.target.checked })} /> Send redacted code context (never sent for secret findings)</label>
        <div>
          <label className="flex items-center gap-2"><input type="checkbox" className="accent-[var(--primary)]" checked={f.allow_self_approval} onChange={(e) => setF({ ...f, allow_self_approval: e.target.checked })} /> Allow self-approval of interactive (MCP) reviews</label>
          <p className="ml-6 text-[12px] text-muted-foreground">For single-person installations: the person whose own assistant (e.g. Claude Code with a Pro/Max plan) submitted a review may approve it. Leave off when a team can provide a second reviewer. Every self-approval is marked in the audit log; Critical false positives still need a written note.</p>
        </div>
        <div><Label htmlFor="c-ins" hint="(trusted guidance appended to the system prompt)">Organization instructions</Label>
          <textarea id="c-ins" rows={3} maxLength={8000} value={f.instructions} onChange={(e) => setF({ ...f, instructions: e.target.value })} className="w-full rounded-md border border-border bg-surface p-2 text-[13px] focus-visible:outline-2 focus-visible:outline-ring" /></div>
        <div><Label htmlFor="c-red" hint="(one regular expression per line, in addition to built-in secret patterns)">Extra redaction patterns</Label>
          <textarea id="c-red" rows={2} value={f.redaction_patterns} onChange={(e) => setF({ ...f, redaction_patterns: e.target.value })} className="w-full rounded-md border border-border bg-surface p-2 font-mono text-[12px] focus-visible:outline-2 focus-visible:outline-ring" /></div>
        <div className="flex items-end gap-3">
          <div className="flex-1"><Label htmlFor="c-note" hint="(recorded with the version)">Change note</Label><Input id="c-note" value={f.change_note} onChange={(e) => setF({ ...f, change_note: e.target.value })} /></div>
          <Button type="submit" disabled={save.isPending}>{config ? `Save as version ${config.current.version + 1}` : "Create configuration"}</Button>
        </div>
      </form>
    </Card>
  );
}

import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CloudDownload, RotateCcw, Upload } from "lucide-react";
import { api, ApiError, getCsrfToken } from "@/api/client";
import type { FeedRun, IntelFeed, RiskModel, RiskWeights } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, Input, Label, PageHeader, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";

type ModelResponse = { model: RiskModel; defaults: RiskWeights; pending_recompute: number };

async function uploadFeed(feed: string, file: File): Promise<FeedRun> {
  const fd = new FormData();
  fd.set("file", file);
  const res = await fetch(`/api/v1/intel/feeds/${feed}/import`, {
    method: "POST",
    body: fd,
    credentials: "same-origin",
    headers: { Accept: "application/json", "X-CSRF-Token": getCsrfToken() },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data?.error?.code ?? "error", data?.error?.message ?? res.statusText);
  return data as FeedRun;
}

function FeedCard({ f, editable }: { f: IntelFeed; editable: boolean }) {
  const qc = useQueryClient();
  const [url, setUrl] = useState(f.url);
  const [hours, setHours] = useState(f.interval_hours);
  const file = useRef<HTMLInputElement>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["intel-feeds"] });
  const save = useMutation({ mutationFn: (body: object) => api(`/api/v1/intel/feeds/${f.feed}`, { method: "PUT", body }), onSuccess: refresh });
  const run = useMutation({ mutationFn: () => api<FeedRun>(`/api/v1/intel/feeds/${f.feed}/run`, { method: "POST" }), onSuccess: refresh, onError: refresh });
  const imp = useMutation({ mutationFn: (fl: File) => uploadFeed(f.feed, fl), onSuccess: refresh, onError: refresh });
  const last = f.last_run;
  const err = save.error ?? run.error ?? imp.error;
  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="text-[14px] font-semibold">{f.label}</h2>
          <p className="text-[12px] text-muted-foreground">
            {f.records.toLocaleString()} records
            {f.last_success && ` · data as of ${f.last_success.as_of || formatDateTime(f.last_success.started_at)}`}
          </p>
        </div>
        <Badge tone={f.enabled ? "success" : "neutral"}>{f.enabled ? "Online updates on" : "Online updates off"}</Badge>
      </div>
      {err && <div className="mt-2"><Alert>{err.message}</Alert></div>}
      {last && (
        <p className="mt-2 text-[12px]">
          Last update: {formatDateTime(last.started_at)} · {last.mode === "file" ? "file import" : "download"} ·{" "}
          <span className={last.status === "failed" ? "text-danger" : last.status === "succeeded" ? "text-success" : ""}>{last.status}</span>
          {last.status === "failed" && last.error && <span className="text-danger">: {last.error}</span>}
          {f.next_due && f.enabled && <span className="text-muted-foreground"> · next download due {formatDateTime(f.next_due)}</span>}
        </p>
      )}
      {editable && (
        <div className="mt-3 space-y-3">
          <div className="grid gap-3 md:grid-cols-[1fr_120px]">
            <div>
              <Label htmlFor={`url-${f.feed}`} hint="(https; a mirror for restricted networks)">Download URL</Label>
              <Input id={`url-${f.feed}`} value={url} onChange={(e) => setUrl(e.target.value)} className="font-mono text-[12px]" />
            </div>
            <div>
              <Label htmlFor={`hours-${f.feed}`}>Every (hours)</Label>
              <Input id={`hours-${f.feed}`} type="number" min={1} max={720} value={hours} onChange={(e) => setHours(Number(e.target.value))} />
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" disabled={save.isPending || (url === f.url && hours === f.interval_hours)} onClick={() => save.mutate({ url, interval_hours: hours })}>
              Save
            </Button>
            <Button size="sm" variant="secondary" disabled={save.isPending} onClick={() => save.mutate({ enabled: !f.enabled })}>
              {f.enabled ? "Turn off online updates" : "Turn on online updates"}
            </Button>
            <Button size="sm" disabled={run.isPending} onClick={() => run.mutate()}>
              <CloudDownload /> {run.isPending ? "Downloading…" : "Download now"}
            </Button>
            <Button size="sm" variant="secondary" disabled={imp.isPending} onClick={() => file.current?.click()}>
              <Upload /> {imp.isPending ? "Importing…" : "Import file (offline)"}
            </Button>
            <input
              ref={file}
              type="file"
              className="hidden"
              accept={f.feed === "epss" ? ".csv,.gz" : ".json,.gz"}
              aria-label={`Import ${f.label} file`}
              onChange={(e) => {
                const fl = e.target.files?.[0];
                if (fl) imp.mutate(fl);
                e.target.value = "";
              }}
            />
          </div>
        </div>
      )}
    </Card>
  );
}

const groups: { key: keyof RiskWeights; label: string; keys: string[] }[] = [
  { key: "severity", label: "Base score by severity (0-10, used without CVSS)", keys: ["critical", "high", "medium", "low", "info"] },
  { key: "criticality", label: "Business criticality multiplier", keys: ["critical", "high", "medium", "low"] },
  { key: "exposure", label: "Internet exposure multiplier", keys: ["yes", "unknown", "no"] },
  { key: "reachability", label: "Reachability multiplier", keys: ["reachable", "unknown", "not_reachable"] },
  { key: "confidence", label: "Scanner confidence multiplier", keys: ["high", "medium", "low", "unknown"] },
];

const scalars: { key: keyof RiskWeights; label: string; hint: string }[] = [
  { key: "kev", label: "Likelihood when in CISA KEV", hint: "0-1" },
  { key: "exploit_available", label: "Likelihood with a public exploit", hint: "0-1" },
  { key: "epss_weight", label: "EPSS percentile weight", hint: "0-1" },
  { key: "likelihood_unknown", label: "Likelihood without any signal", hint: "0-1, never 0" },
  { key: "human_confirmed", label: "Confirmed by a human reviewer", hint: "multiplier" },
  { key: "compensating_controls", label: "Compensating controls recorded", hint: "multiplier" },
  { key: "fix_available", label: "Fix available", hint: "multiplier" },
];

function ModelEditor({ data, editable }: { data: ModelResponse; editable: boolean }) {
  const qc = useQueryClient();
  const [w, setW] = useState<RiskWeights>(data.model.weights);
  const [note, setNote] = useState("");
  useEffect(() => setW(data.model.weights), [data.model]);
  const save = useMutation({
    mutationFn: (weights: RiskWeights) => api<ModelResponse>("/api/v1/risk-model", { method: "PUT", body: { weights, change_note: note } }),
    onSuccess: () => {
      setNote("");
      void qc.invalidateQueries({ queryKey: ["risk-model"] });
      void qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });
  const num = (v: string) => (v === "" ? 0 : Number(v));
  const changed = JSON.stringify(w) !== JSON.stringify(data.model.weights);
  return (
    <Card className="p-4">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-[14px] font-semibold">Risk model {data.model.is_default ? "(built-in default)" : `v${data.model.version}`}</h2>
          <p className="text-[12px] text-muted-foreground">
            score = 10 × base × (0.5 + likelihood) × context ÷ 1.75, capped at 100. Severity is never changed.
            {data.pending_recompute > 0 && ` ${data.pending_recompute.toLocaleString()} findings are being re-scored.`}
          </p>
        </div>
      </div>
      {save.error && <div className="mb-2"><Alert>{save.error.message}</Alert></div>}
      <fieldset disabled={!editable} className="space-y-4">
        <div className="flex items-center gap-2 text-[13px]">
          <input id="use-cvss" type="checkbox" className="size-3.5 accent-[var(--primary)]" checked={w.use_cvss} onChange={(e) => setW({ ...w, use_cvss: e.target.checked })} />
          <label htmlFor="use-cvss">Use the CVSS base score when the scanner reports one</label>
        </div>
        {groups.map((g) => (
          <fieldset key={g.key}>
            <legend className="mb-1 text-[12px] font-medium">{g.label}</legend>
            <div className="flex flex-wrap gap-3">
              {g.keys.map((k) => (
                <label key={k} className="flex items-center gap-1.5 text-[12.5px]">
                  <span className="w-24 capitalize text-muted-foreground">{k.replace("_", " ")}</span>
                  <Input
                    type="number"
                    step="0.05"
                    className="w-20"
                    aria-label={`${g.label}: ${k}`}
                    value={(w[g.key] as Record<string, number>)[k] ?? ""}
                    onChange={(e) => setW({ ...w, [g.key]: { ...(w[g.key] as Record<string, number>), [k]: num(e.target.value) } })}
                  />
                </label>
              ))}
            </div>
          </fieldset>
        ))}
        <div className="grid gap-3 md:grid-cols-2">
          {scalars.map((sc) => (
            <label key={sc.key} className="flex items-center justify-between gap-2 text-[12.5px]">
              <span>
                {sc.label} <span className="text-muted-foreground">({sc.hint})</span>
              </span>
              <Input type="number" step="0.05" className="w-24" value={w[sc.key] as number} onChange={(e) => setW({ ...w, [sc.key]: num(e.target.value) })} />
            </label>
          ))}
        </div>
        {editable && (
          <div className="flex flex-wrap items-end gap-2">
            <div className="min-w-64 flex-1">
              <Label htmlFor="model-note" hint="(optional)">Change note</Label>
              <Input id="model-note" value={note} onChange={(e) => setNote(e.target.value)} />
            </div>
            <Button variant="ghost" onClick={() => setW(data.defaults)}>
              <RotateCcw /> Defaults
            </Button>
            <Button disabled={!changed || save.isPending} onClick={() => save.mutate(w)}>
              {save.isPending ? "Saving…" : "Save as new version"}
            </Button>
          </div>
        )}
      </fieldset>
    </Card>
  );
}

function History() {
  const q = useQuery({ queryKey: ["risk-model", "history"], queryFn: () => api<{ items: RiskModel[] }>("/api/v1/risk-model/history").then((r) => r.items) });
  if (!q.data?.length) return null;
  return (
    <Card>
      <h2 className="border-b border-border px-4 py-2.5 text-[13px] font-semibold">Model history</h2>
      <Table>
        <thead>
          <tr>
            <Th>Version</Th>
            <Th>Changed by</Th>
            <Th>When</Th>
            <Th>Note</Th>
          </tr>
        </thead>
        <tbody>
          {q.data.map((m) => (
            <tr key={m.version}>
              <Td className="tabular">v{m.version}</Td>
              <Td>{m.created_by ?? "—"}</Td>
              <Td className="tabular text-[12px] text-muted-foreground">{formatDateTime(m.created_at)}</Td>
              <Td className="text-[12px]">{m.change_note || "—"}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}

export function RiskIntelPage() {
  const { canOrgWide } = useSession();
  const editable = canOrgWide("settings.manage");
  const feeds = useQuery({ queryKey: ["intel-feeds"], queryFn: () => api<{ items: IntelFeed[] }>("/api/v1/intel/feeds").then((r) => r.items) });
  const model = useQuery({ queryKey: ["risk-model"], queryFn: () => api<ModelResponse>("/api/v1/risk-model"), refetchInterval: (q) => (q.state.data?.pending_recompute ? 5000 : false) });
  return (
    <>
      <PageHeader
        title="Risk & intelligence"
        description="Vulnerability intelligence feeds (EPSS, CISA KEV) and the contextual risk model that ranks findings beyond CVSS."
      />
      <div className="space-y-4">
        {feeds.isError && <Alert>{feeds.error.message}</Alert>}
        <div className="grid gap-4 lg:grid-cols-2">
          {feeds.isPending ? [0, 1].map((i) => <Skeleton key={i} className="h-40" />) : (feeds.data ?? []).map((f) => <FeedCard key={f.feed} f={f} editable={editable} />)}
        </div>
        {model.isError && <Alert>{model.error.message}</Alert>}
        {model.data ? <ModelEditor data={model.data} editable={editable} /> : <Skeleton className="h-64" />}
        <History />
      </div>
    </>
  );
}

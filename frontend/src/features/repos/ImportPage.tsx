import { useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import { ArrowLeft, CheckCircle2, FileSpreadsheet, ListChecks, Search, XCircle } from "lucide-react";
import type { ImportResponse } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { TagChip } from "@/components/data/TagChip";
import { useBusinessUnits, useRegions } from "@/features/users/api";
import { cn } from "@/lib/utils";
import { importCsv, importRepos, useApplications, useConnections, useDiscover, useInvalidateRepos, useTagCategories } from "./api";
import { ErrorPanel } from "@/components/ui/error-panel";

const csvTemplate = `repository,application,business_unit,country,environment,criticality,tags,scan_branch
acme/payments-api,Checkout,Finance,DE,production,high,Team:Payments,main
`;

export function ImportPage() {
  const conns = useConnections();
  const [connId, setConnId] = useState("");
  const [mode, setMode] = useState<"select" | "csv">("select");
  const [result, setResult] = useState<ImportResponse | null>(null);
  const active = connId || conns.data?.[0]?.id || "";

  return (
    <>
      <PageHeader
        title="Bulk import"
        description="Select repositories from an SCM connection or onboard them from a CSV file."
        actions={
          <Button variant="ghost" asChild>
            <Link to="/repositories/import">
              <ArrowLeft /> All import methods
            </Link>
          </Button>
        }
      />
      {conns.isPending ? (
        <Skeleton className="h-24" />
      ) : !conns.data?.length ? (
        <Card>
          <EmptyState icon={<ListChecks />} title="No SCM connections">
            An administrator must first connect GitHub or Azure DevOps under{" "}
            <Link to="/admin/scm" className="text-primary underline">SCM connections</Link>.
          </EmptyState>
        </Card>
      ) : (
        <>
          <Card className="mb-4 flex flex-wrap items-end gap-4 p-4">
            <div>
              <Label htmlFor="conn">Connection</Label>
              <Select id="conn" value={active} onChange={(e) => { setConnId(e.target.value); setResult(null); }} className="min-w-64">
                {conns.data.map((c) => (
                  <option key={c.id} value={c.id}>{c.name} ({c.provider.replace("_", " ")})</option>
                ))}
              </Select>
            </div>
            <div className="flex rounded-md border border-border p-0.5" role="tablist">
              {(["select", "csv"] as const).map((m) => (
                <button key={m} role="tab" aria-selected={mode === m} onClick={() => { setMode(m); setResult(null); }}
                  className={cn("flex items-center gap-1.5 rounded px-3 py-1.5 text-[13px]", mode === m ? "bg-primary/10 font-medium text-primary" : "text-muted-foreground")}>
                  {m === "select" ? <ListChecks className="size-4" /> : <FileSpreadsheet className="size-4" />}
                  {m === "select" ? "Select repositories" : "CSV bulk onboarding"}
                </button>
              ))}
            </div>
          </Card>
          {result && <Results result={result} />}
          {mode === "select" ? <SelectImport connId={active} onResult={setResult} /> : <CsvImport connId={active} onResult={setResult} />}
        </>
      )}
    </>
  );
}

function SelectImport({ connId, onResult }: { connId: string; onResult: (r: ImportResponse) => void }) {
  const disc = useDiscover(connId);
  const apps = useApplications();
  const bus = useBusinessUnits();
  const regions = useRegions();
  const cats = useTagCategories();
  const invalidate = useInvalidateRepos();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [d, setD] = useState({ application_id: "", business_unit_id: "", country_id: "", environment: "production", criticality: "medium" });
  const [tags, setTags] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const items = useMemo(
    () => (disc.data?.items ?? []).filter((r) => !q || r.full_name.toLowerCase().includes(q.toLowerCase())),
    [disc.data, q],
  );
  const selectable = items.filter((r) => !r.imported_id);
  const missingMandatory = (cats.data ?? []).filter((c) => c.is_mandatory && !c.tags.some((t) => tags.has(t.id)));

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const nul = (v: string) => v || undefined;
      const res = await importRepos({
        scm_connection_id: connId,
        repositories: [...sel].map((external_id) => ({ external_id })),
        defaults: { application_id: nul(d.application_id), business_unit_id: nul(d.business_unit_id), country_id: nul(d.country_id),
          environment: d.environment, criticality: d.criticality, tag_ids: [...tags] },
      });
      onResult(res);
      setSel(new Set());
      invalidate();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
      <Card>
        <div className="flex items-center gap-2 border-b border-border p-3">
          <div className="relative w-full max-w-xs">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input aria-label="Filter repositories" placeholder="Filter by name" className="pl-8" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <span className="ml-auto text-[12px] text-muted-foreground">
            {disc.data ? `${disc.data.items.length} found · ${disc.data.items.filter((r) => r.imported_id).length} already imported` : ""}
          </span>
        </div>
        {disc.isPending ? (
          <div className="space-y-2 p-4">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-8" />)}</div>
        ) : disc.isError ? (
          <div className="p-4"><ErrorPanel error={disc.error} title="Discovery failed" /></div>
        ) : (
          <div className="max-h-[60vh] overflow-y-auto">
            <Table>
              <thead>
                <tr>
                  <Th className="w-8">
                    <input type="checkbox" aria-label="Select all" className="accent-[var(--primary)]"
                      checked={selectable.length > 0 && selectable.every((r) => sel.has(r.external_id))}
                      onChange={(e) => setSel(e.target.checked ? new Set(selectable.map((r) => r.external_id)) : new Set())} />
                  </Th>
                  <Th>Repository</Th>
                  <Th>Default branch</Th>
                  <Th>Visibility</Th>
                  <Th>Status</Th>
                </tr>
              </thead>
              <tbody>
                {items.map((r) => (
                  <tr key={r.external_id} className={r.imported_id ? "opacity-60" : ""}>
                    <Td className="w-8">
                      <input type="checkbox" aria-label={`Select ${r.full_name}`} disabled={!!r.imported_id} className="accent-[var(--primary)]"
                        checked={sel.has(r.external_id)}
                        onChange={() => { const n = new Set(sel); if (n.has(r.external_id)) n.delete(r.external_id); else n.add(r.external_id); setSel(n); }} />
                    </Td>
                    <Td>
                      <div className="font-medium">{r.full_name}</div>
                      {r.description && <div className="max-w-md truncate text-[12px] text-muted-foreground">{r.description}</div>}
                    </Td>
                    <Td className="text-[12px]">{r.default_branch || "—"}</Td>
                    <Td className="text-[12px] capitalize">{r.visibility}</Td>
                    <Td>{r.imported_id ? <Badge tone="success">imported</Badge> : r.archived ? <Badge>archived in SCM</Badge> : null}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            {disc.data?.truncated && <div className="p-3 text-[12px] text-warning">Discovery is capped at 5,000 repositories; narrow the connection owner to see more.</div>}
          </div>
        )}
      </Card>

      <Card className="h-fit space-y-3 p-4">
        <h2 className="text-[13px] font-semibold">Placement & classification</h2>
        <p className="text-[12px] text-muted-foreground">Applied to every selected repository. You can adjust each one afterwards.</p>
        {[
          ["application_id", "Application", (apps.data ?? []).map((a) => [a.id, a.name])],
          ["business_unit_id", "Business unit", (bus.data ?? []).map((b) => [b.id, b.name])],
          ["country_id", "Country", (regions.data ?? []).flatMap((rg) => rg.countries.map((c) => [c.id, c.name])).sort((a, b) => a[1]!.localeCompare(b[1]!))],
        ].map(([key, label, opts]) => (
          <div key={key as string}>
            <Label htmlFor={`d-${key}`}>{label as string}</Label>
            <Select id={`d-${key}`} className="w-full" value={d[key as keyof typeof d]} onChange={(e) => setD({ ...d, [key as string]: e.target.value })}>
              <option value="">None</option>
              {(opts as string[][]).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </Select>
          </div>
        ))}
        <div className="grid grid-cols-2 gap-2">
          <div>
            <Label htmlFor="d-env">Environment</Label>
            <Select id="d-env" className="w-full capitalize" value={d.environment} onChange={(e) => setD({ ...d, environment: e.target.value })}>
              {["production", "staging", "development", "test", "other"].map((v) => <option key={v} value={v}>{v}</option>)}
            </Select>
          </div>
          <div>
            <Label htmlFor="d-crit">Criticality</Label>
            <Select id="d-crit" className="w-full capitalize" value={d.criticality} onChange={(e) => setD({ ...d, criticality: e.target.value })}>
              {["critical", "high", "medium", "low"].map((v) => <option key={v} value={v}>{v}</option>)}
            </Select>
          </div>
        </div>
        {(cats.data ?? []).map((c) => (
          <div key={c.id}>
            <div className="mb-1 text-[12px] font-medium">{c.name} {c.is_mandatory && <span className="text-danger">*</span>}</div>
            <div className="flex flex-wrap gap-1.5">
              {c.tags.map((t) => (
                <button key={t.id} type="button"
                  onClick={() => {
                    const n = new Set(tags);
                    if (n.has(t.id)) n.delete(t.id);
                    else { if (!c.allow_multiple) c.tags.forEach((x) => n.delete(x.id)); n.add(t.id); }
                    setTags(n);
                  }}
                  className={tags.has(t.id) ? "rounded ring-2 ring-primary" : "rounded opacity-60 hover:opacity-100"}>
                  <TagChip name={t.name} color={t.color} />
                </button>
              ))}
            </div>
          </div>
        ))}
        {error && <Alert>{error}</Alert>}
        {missingMandatory.length > 0 && sel.size > 0 && (
          <p className="text-[12px] text-warning">Choose a tag in: {missingMandatory.map((c) => c.name).join(", ")}</p>
        )}
        <Button className="w-full" disabled={!sel.size || busy || missingMandatory.length > 0} onClick={() => void run()}>
          {busy ? "Importing…" : `Import ${sel.size || ""} ${sel.size === 1 ? "repository" : "repositories"}`}
        </Button>
      </Card>
    </div>
  );
}

function CsvImport({ connId, onResult }: { connId: string; onResult: (r: ImportResponse) => void }) {
  const [csv, setCsv] = useState(csvTemplate);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [previewed, setPreviewed] = useState(false);
  const invalidate = useInvalidateRepos();

  const run = async (dry: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const res = await importCsv(connId, csv, dry);
      onResult(res);
      setPreviewed(dry);
      if (!dry) invalidate();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="space-y-3 p-4">
      <p className="text-[13px] text-muted-foreground">
        Columns: <code>repository</code> (required, as <code>owner/name</code> or <code>project/name</code>), <code>application</code>,{" "}
        <code>business_unit</code>, <code>country</code> (ISO code), <code>environment</code>, <code>criticality</code>, <code>tags</code>{" "}
        (<code>Category:Tag</code> separated by <code>;</code>), <code>scan_branch</code>. Names must already exist in PATHOS.
      </p>
      <div className="flex items-center gap-2">
        <input type="file" accept=".csv,text/csv" aria-label="Upload CSV file" className="text-[13px]"
          onChange={(e) => { const f = e.target.files?.[0]; if (f) void f.text().then((t) => { setCsv(t); setPreviewed(false); }); }} />
      </div>
      <textarea aria-label="CSV content" value={csv} onChange={(e) => { setCsv(e.target.value); setPreviewed(false); }} rows={10}
        className="w-full rounded-md border border-border bg-surface p-2 font-mono text-[12px] focus-visible:outline-2 focus-visible:outline-ring" />
      {error && <Alert>{error}</Alert>}
      <div className="flex gap-2">
        <Button variant="secondary" disabled={busy || !csv.trim()} onClick={() => void run(true)}>Validate (dry run)</Button>
        <Button disabled={busy || !previewed} onClick={() => void run(false)} title={previewed ? undefined : "Validate first"}>Import</Button>
      </div>
    </Card>
  );
}

function Results({ result }: { result: ImportResponse }) {
  const counts = result.results.reduce<Record<string, number>>((m, r) => ({ ...m, [r.status]: (m[r.status] ?? 0) + 1 }), {});
  return (
    <Card className="mb-4">
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3 text-[13px]">
        <span className="font-semibold">{result.dry_run ? "Validation result" : "Import result"}</span>
        {Object.entries(counts).map(([k, v]) => (
          <Badge key={k} tone={k === "error" ? "danger" : k === "imported" || k === "would_import" ? "success" : "neutral"}>{v} {k.replace("_", " ")}</Badge>
        ))}
      </div>
      <div className="max-h-72 overflow-y-auto">
        <Table>
          <tbody>
            {result.results.map((r, i) => (
              <tr key={`${r.external_id}-${i}`}>
                <Td className="w-8">{r.status === "error" ? <XCircle className="size-4 text-danger" /> : <CheckCircle2 className="size-4 text-success" />}</Td>
                {r.line ? <Td className="tabular w-16 text-[12px] text-muted-foreground">line {r.line}</Td> : null}
                <Td className="font-medium">{r.full_name || r.external_id}</Td>
                <Td className="text-[12px]">{r.status.replace("_", " ")}</Td>
                <Td className="text-[12px] text-danger">{r.error}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </div>
    </Card>
  );
}

import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileUp, Upload } from "lucide-react";
import { api, ApiError, getCsrfToken } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { RepoFilter } from "@/features/review/shared";
import { formatDateTime } from "@/lib/utils";
import { TOOL_CATEGORIES, categoryName } from "@/lib/findingCategories";
import { ErrorPanel } from "@/components/ui/error-panel";

export interface ImportJob {
  id: string;
  kind: "results" | "sbom";
  format: string;
  tool: string;
  scanner_key: string | null;
  category: string;
  repository_id: string;
  repository_name: string;
  scan_job_id: string | null;
  scan_key: string | null;
  file_name: string;
  sha256: string;
  size_bytes: number;
  commit_sha: string;
  resolve_missing: boolean;
  status: "succeeded" | "failed";
  records: number;
  error: string;
  created_by: string | null;
  created_at: string;
}

/** Categories an import may declare (every finding category except end of life). */
const importCategories = TOOL_CATEGORIES.map((c) => [c, c === "other" ? "Other (custom tools)" : categoryName(c)] as const);

const formatLabel: Record<string, string> = { sarif: "SARIF 2.1", grype: "Grype JSON", pathos: "PATHOS findings JSON", cyclonedx: "CycloneDX", spdx: "SPDX", unknown: "Not recognised" };

/** A result format the server can import (GET /api/v1/imports/formats). */
export interface ImportFormat {
  id: string;
  label: string;
  /** The tool name imports default to; empty for generic formats (SARIF, PATHOS JSON, CSV), which need one. */
  tool: string;
  /** Default category; empty: each finding keeps its own (e.g. Trivy vulnerabilities, misconfigurations and secrets). */
  category: string;
  media: string;
}

function useImportFormats() {
  return useQuery({
    queryKey: ["import-formats"],
    queryFn: () => api<{ results: ImportFormat[] }>("/api/v1/imports/formats").then((r) => r.results),
    staleTime: Infinity,
  });
}

async function upload(path: string, fd: FormData): Promise<ImportJob> {
  const res = await fetch(path, { method: "POST", body: fd, credentials: "same-origin", headers: { Accept: "application/json", "X-CSRF-Token": getCsrfToken() } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data?.error?.code ?? "error", data?.error?.message ?? res.statusText, data?.request_id, undefined, data);
  return data as ImportJob;
}

function ImportForm({ kind, formats }: { kind: "results" | "sbom"; formats?: ImportFormat[] }) {
  const qc = useQueryClient();
  const [repo, setRepo] = useState<string | undefined>();
  const [tool, setTool] = useState("");
  const [format, setFormat] = useState("");
  const [category, setCategory] = useState("");
  const [commit, setCommit] = useState("");
  const [branch, setBranch] = useState("");
  const [resolve, setResolve] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [key, setKey] = useState(0);
  const m = useMutation({
    mutationFn: () => {
      const fd = new FormData();
      fd.set("repository_id", repo!);
      if (tool.trim()) fd.set("tool", tool);
      if (kind === "results") {
        if (format) fd.set("format", format);
        if (category) fd.set("category", category);
        if (commit) fd.set("commit_sha", commit);
        if (branch) fd.set("branch", branch);
        fd.set("resolve_missing", String(resolve));
      }
      fd.set("file", file!);
      return upload(kind === "results" ? "/api/v1/imports/results" : "/api/v1/imports/sbom", fd);
    },
    onSuccess: () => {
      setFile(null);
      setKey((k) => k + 1);
      void qc.invalidateQueries({ queryKey: ["imports"] });
      void qc.invalidateQueries({ queryKey: ["findings"] });
    },
    onError: () => void qc.invalidateQueries({ queryKey: ["imports"] }),
  });
  const selected = formats?.find((f) => f.id === format);
  // Generic formats (SARIF, PATHOS JSON, CSV) need the tool's name; detected
  // formats get it from the server, which explains when one is missing.
  const toolRequired = kind === "results" && !!selected && !selected.tool;
  const ok = repo && file && (!toolRequired || tool.trim());
  const defaultCategory = selected ? (selected.category ? categoryName(selected.category) : "per finding") : "from the format";
  return (
    <form
      key={key}
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (ok) m.mutate();
      }}
    >
      {m.error && <ErrorPanel error={m.error} />}
      {m.data && (
        <Alert tone="success">
          Imported {m.data.records} {kind === "results" ? "findings" : "components"} ({formats?.find((f) => f.id === m.data.format)?.label ?? formatLabel[m.data.format] ?? m.data.format}).{" "}
          {m.data.scan_job_id && (
            <Link to="/scans/$id" params={{ id: m.data.scan_job_id }} className="underline">
              {m.data.scan_key}
            </Link>
          )}
        </Alert>
      )}
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <span className="mb-1 block text-[12px] font-medium">Repository</span>
          <RepoFilter value={repo} onChange={setRepo} />
        </div>
        <div>
          <Label htmlFor={`${kind}-tool`} hint={kind === "sbom" || !toolRequired ? "(optional)" : undefined}>
            {kind === "results" ? "Tool that produced the results" : "Generated by"}
          </Label>
          <Input
            id={`${kind}-tool`}
            value={tool}
            maxLength={100}
            onChange={(e) => setTool(e.target.value)}
            placeholder={kind === "results" ? (selected?.tool ? `default: ${selected.tool}` : "e.g. Snyk Code, Burp Suite, Contrast") : "e.g. cdxgen"}
          />
        </div>
        {kind === "results" && (
          <>
            <div>
              <Label htmlFor="imp-format">Format</Label>
              <Select id="imp-format" className="w-full" value={format} onChange={(e) => setFormat(e.target.value)}>
                <option value="">Detect from the file</option>
                {(formats ?? []).map((f) => <option key={f.id} value={f.id}>{f.label}</option>)}
              </Select>
            </div>
            <div>
              <Label htmlFor="imp-cat">Category</Label>
              <Select id="imp-cat" className="w-full" value={category} onChange={(e) => setCategory(e.target.value)}>
                <option value="">Default ({defaultCategory})</option>
                {importCategories.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <Label htmlFor="imp-commit" hint="(optional)">Commit SHA</Label>
                <Input id="imp-commit" value={commit} onChange={(e) => setCommit(e.target.value.trim())} className="font-mono text-[12px]" />
              </div>
              <div>
                <Label htmlFor="imp-branch" hint="(optional)">Branch</Label>
                <Input id="imp-branch" value={branch} onChange={(e) => setBranch(e.target.value)} />
              </div>
            </div>
          </>
        )}
      </div>
      <div>
        <Label htmlFor={`${kind}-file`} hint="(at most 64 MiB; .gz accepted)">
          {kind === "results" ? `Report${selected ? `: ${selected.label}` : ` (${formats?.length ?? "several"} formats supported)`}` : "SBOM: CycloneDX JSON or SPDX 2.x JSON"}
        </Label>
        <input
          id={`${kind}-file`}
          type="file"
          accept={kind === "results" ? ".json,.sarif,.jsonl,.ndjson,.xml,.nessus,.csv,.gz" : ".json,.gz"}
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className="block text-[12.5px] file:mr-2 file:rounded-md file:border file:border-border file:bg-surface file:px-2 file:py-1"
        />
      </div>
      {kind === "results" && (
        <label className="flex items-start gap-2 text-[12.5px]">
          <input type="checkbox" className="mt-0.5 accent-[var(--primary)]" checked={resolve} onChange={(e) => setResolve(e.target.checked)} />
          <span>
            This file is the tool's complete result for the repository
            <span className="block text-[11.5px] text-muted-foreground">Findings from this tool that the file no longer reports are marked fixed. Leave off for partial results.</span>
          </span>
        </label>
      )}
      <Button type="submit" disabled={!ok || m.isPending}>
        <Upload /> {m.isPending ? "Importing…" : kind === "results" ? "Import results" : "Import SBOM"}
      </Button>
    </form>
  );
}

export function ImportResultsPage() {
  const { can } = useSession();
  const formats = useImportFormats();
  const labelOf = (id: string) => formats.data?.find((f) => f.id === id)?.label ?? formatLabel[id] ?? id;
  const hist = useQuery({ queryKey: ["imports"], queryFn: () => api<{ items: ImportJob[] }>("/api/v1/imports/history").then((r) => r.items) });
  const canImport = can("scans.run");
  return (
    <>
      <PageHeader
        title="Import results"
        description="Bring results from tools PATHOS does not run (other scanners, DAST and IAST tools, fuzzers, CI pipelines) and SBOMs into PATHOS. Imported findings are de-duplicated, risk-scored and reviewable like scan findings."
      />
      {canImport ? (
        <div className="mb-4 grid gap-4 xl:grid-cols-2">
          <Card className="p-4">
            <h2 className="mb-3 text-[14px] font-semibold">Scanner results</h2>
            {formats.isError && <Alert tone="warning">The format list could not be loaded; the format is detected from the file.</Alert>}
            <ImportForm kind="results" formats={formats.data} />
          </Card>
          <Card className="p-4">
            <h2 className="mb-3 text-[14px] font-semibold">Software bill of materials</h2>
            <p className="mb-3 text-[12px] text-muted-foreground">Replaces the repository's component inventory; licence policies apply immediately.</p>
            <ImportForm kind="sbom" />
          </Card>
        </div>
      ) : (
        <div className="mb-4"><Alert tone="warning">Importing needs the scans.run permission on the repository.</Alert></div>
      )}
      <Card>
        <h2 className="border-b border-border px-4 py-2.5 text-[13px] font-semibold">Import history</h2>
        {hist.isError ? (
          <div className="p-4"><ErrorPanel error={hist.error} /></div>
        ) : hist.isPending ? (
          <Skeleton className="m-4 h-24" />
        ) : !hist.data?.length ? (
          <EmptyState icon={<FileUp />} title="Nothing imported yet" />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>When</Th>
                <Th>Kind</Th>
                <Th>Tool</Th>
                <Th>Repository</Th>
                <Th>Format</Th>
                <Th>Result</Th>
                <Th>Execution</Th>
                <Th>By</Th>
              </tr>
            </thead>
            <tbody>
              {hist.data.map((j) => (
                <tr key={j.id}>
                  <Td className="tabular whitespace-nowrap text-[12px] text-muted-foreground">{formatDateTime(j.created_at)}</Td>
                  <Td className="text-[12px]">{j.kind === "sbom" ? "SBOM" : categoryName(j.category)}</Td>
                  <Td className="text-[12px]">{j.tool || "—"}</Td>
                  <Td className="text-[12px]">{j.repository_name}</Td>
                  <Td className="text-[12px]">{labelOf(j.format)}</Td>
                  <Td className="text-[12px]">
                    {j.status === "succeeded" ? (
                      <Badge tone="success">{j.records} {j.kind === "sbom" ? "components" : "findings"}</Badge>
                    ) : (
                      <span className="text-danger" title={j.error}>Failed: {j.error.slice(0, 80)}</span>
                    )}
                  </Td>
                  <Td>
                    {j.scan_job_id ? (
                      <Link to="/scans/$id" params={{ id: j.scan_job_id }} className="font-mono text-[12px] text-primary hover:underline">{j.scan_key}</Link>
                    ) : "—"}
                  </Td>
                  <Td className="text-[12px]">{j.created_by ?? "—"}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}

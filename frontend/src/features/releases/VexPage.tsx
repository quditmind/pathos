import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { Check, Download, FileCheck2, Upload, X } from "lucide-react";
import { api } from "@/api/client";
import type { Severity } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, EmptyState, Input, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { SeverityBadge } from "@/components/data/Severity";
import { useSession } from "@/features/auth/session";
import { useRepositories } from "@/features/repos/api";
import { formatDateTime } from "@/lib/utils";
import { ImportSummary } from "./ApplicationVersionsPage";
import { readVexFile, useReleasesMutation, useSuggestions, useVexImports, vexStatusLabel, type ImportResult, type VexSuggestion } from "./api";
import { ErrorPanel } from "@/components/ui/error-panel";

/**
 * VEX review: statements imported from OpenVEX or CycloneDX documents are
 * suggestions. A reviewer other than the importer, with findings.accept_risk,
 * approves or rejects each one.
 */
export function VexPage() {
  const { can } = useSession();
  const [status, setStatus] = useState("pending");
  const sug = useSuggestions(status);
  const imports = useVexImports();
  return (
    <>
      <PageHeader title="VEX statements"
        description="Import and export Vulnerability Exploitability eXchange (OpenVEX, CycloneDX VEX). Imported not-affected and fixed statements are suggestions: a second person approves them before a finding changes, and a fixed statement never closes a finding (only a scan does)." />
      {(can("findings.triage") || can("findings.export")) && <RepositoryVex />}
      <Card className="mb-4">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h2 className="text-[14px] font-semibold">Suggestions</h2>
          <Select aria-label="Suggestion status" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="pending">Pending review</option><option value="approved">Approved</option><option value="rejected">Rejected</option><option value="">All</option>
          </Select>
        </div>
        {sug.isError ? <ErrorPanel error={sug.error} /> : sug.isPending ? <Skeleton className="h-24" /> : !sug.data.length ? (
          <EmptyState icon={<FileCheck2 />} title={status === "pending" ? "Nothing to review" : "No suggestions"}>Import a VEX document for a repository or an application version.</EmptyState>
        ) : (
          <div className="space-y-2">{sug.data.map((s) => <SuggestionCard key={s.id} s={s} />)}</div>
        )}
      </Card>
      <Card>
        <h2 className="mb-3 text-[14px] font-semibold">Imports</h2>
        {imports.isError ? <ErrorPanel error={imports.error} /> : imports.isPending ? <Skeleton className="h-16" /> : !imports.data.length ? (
          <p className="text-[13px] text-muted-foreground">No VEX documents imported yet.</p>
        ) : (
          <Table>
            <thead><tr><Th>Imported</Th><Th>For</Th><Th>Document</Th><Th>Statements</Th><Th>Matched</Th><Th>Pending</Th></tr></thead>
            <tbody>
              {imports.data.map((i) => (
                <tr key={i.id}>
                  <Td className="text-[12px]">{formatDateTime(i.created_at)}{i.imported_by && <div className="text-muted-foreground">{i.imported_by}</div>}</Td>
                  <Td className="text-[12.5px]">{i.repository || `${i.application} ${i.version}`}</Td>
                  <Td className="text-[12px]"><div>{i.filename || "—"} <Badge>{i.format}</Badge></div><div className="font-mono text-[11px] text-muted-foreground" title={i.document_sha256}>sha256:{i.document_sha256.slice(0, 16)}…{i.author && ` · ${i.author}`}</div></Td>
                  <Td className="tabular">{i.statements}</Td>
                  <Td className="tabular">{i.matched}</Td>
                  <Td className="tabular">{i.pending}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}

function SuggestionCard({ s }: { s: VexSuggestion }) {
  const [note, setNote] = useState("");
  const decide = useReleasesMutation((action: "approve" | "reject") =>
    api(`/api/v1/vex-suggestions/${s.id}/${action}`, { method: "POST", body: { note } }));
  return (
    <div className="rounded-md border border-border p-3 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge value={s.severity as Severity} />
        <Link to="/vulnerabilities/$id" params={{ id: s.vulnerability }} className="font-mono text-primary hover:underline">{s.vulnerability}</Link>
        <Badge tone={s.vex_status === "not_affected" ? "success" : "neutral"}>{vexStatusLabel[s.vex_status]}</Badge>
        <span className="font-medium">{s.finding_title}</span>
        <span className="text-muted-foreground">{s.repository}{s.package_name && ` · ${s.package_name}@${s.package_version}`}</span>
        <Link to="/findings" search={{ finding: s.finding_id } as never} className="text-primary hover:underline">finding ({s.finding_status.replace("_", " ")})</Link>
      </div>
      {(s.justification || s.impact_statement) && (
        <p className="mt-1 text-muted-foreground">{s.justification && <span className="font-mono">{s.justification}</span>}{s.justification && s.impact_statement && " — "}{s.impact_statement}</p>
      )}
      <p className="mt-1 text-[11.5px] text-muted-foreground">
        Imported by {s.requested_by || "a user"} on {formatDateTime(s.created_at)}
        {s.status !== "pending" && <> · {s.status} by {s.decided_by || "a reviewer"}{s.decided_at && ` on ${formatDateTime(s.decided_at)}`}{s.decision_note && `: ${s.decision_note}`}</>}
      </p>
      {s.vex_status === "fixed" && s.status === "pending" && (
        <p className="mt-1 text-[11.5px] text-muted-foreground">Approving records the vendor's statement; the finding is resolved only when a scan no longer detects it.</p>
      )}
      {s.status === "pending" && (s.can_decide ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Input aria-label="Decision note" placeholder="Note (optional)" className="max-w-sm" value={note} maxLength={2000} onChange={(e) => setNote(e.target.value)} />
          <Button size="sm" disabled={decide.isPending} onClick={() => decide.mutate("approve")}><Check /> Approve</Button>
          <Button size="sm" variant="secondary" disabled={decide.isPending} onClick={() => decide.mutate("reject")}><X /> Reject</Button>
        </div>
      ) : (
        <p className="mt-2 text-[11.5px] text-warning">{s.cannot_decide_reason}</p>
      ))}
      {decide.isError && <div className="mt-2"><ErrorPanel error={decide.error} /></div>}
    </div>
  );
}

function RepositoryVex() {
  const { can } = useSession();
  const repos = useRepositories({});
  const list = repos.data?.pages.flatMap((p) => p.items) ?? [];
  const [repo, setRepo] = useState("");
  const [result, setResult] = useState<ImportResult | null>(null);
  const [fileErr, setFileErr] = useState<string | null>(null);
  const importVex = useReleasesMutation(({ doc, name }: { doc: unknown; name: string }) =>
    api<ImportResult>(`/api/v1/repositories/${repo}/vex?filename=${encodeURIComponent(name)}`, { method: "POST", body: doc }));
  const onFile = async (f: File | undefined) => {
    setFileErr(null); setResult(null);
    if (!f) return;
    try {
      const doc = await readVexFile(f);
      importVex.mutate({ doc, name: f.name }, { onSuccess: setResult });
    } catch (e) {
      setFileErr((e as Error).message);
    }
  };
  const btn = "inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-[12.5px] hover:bg-muted";
  return (
    <Card className="mb-4">
      <h2 className="mb-1 text-[14px] font-semibold">Repository VEX</h2>
      <p className="mb-3 text-[12.5px] text-muted-foreground">For an application release, use the version's page (Applications → Versions).</p>
      <div className="flex flex-wrap items-center gap-2">
        <Select aria-label="Repository for VEX" value={repo} onChange={(e) => { setRepo(e.target.value); setResult(null); }}>
          <option value="">Choose a repository…</option>
          {list.map((r) => <option key={r.id} value={r.id}>{r.full_name}</option>)}
        </Select>
        {repo && can("findings.export") && (
          <>
            <a className={btn} href={`/api/v1/repositories/${repo}/vex?format=openvex`} download><Download className="size-3.5" /> OpenVEX</a>
            <a className={btn} href={`/api/v1/repositories/${repo}/vex?format=cyclonedx`} download><Download className="size-3.5" /> CycloneDX VEX</a>
          </>
        )}
        {repo && can("findings.triage") && (
          <label className={`${btn} cursor-pointer`}>
            <Upload className="size-3.5" /> {importVex.isPending ? "Importing…" : "Import VEX"}
            <input type="file" accept=".json,application/json" className="sr-only" aria-label="Import repository VEX document" onChange={(e) => { void onFile(e.target.files?.[0]); e.target.value = ""; }} />
          </label>
        )}
      </div>
      {(fileErr || importVex.isError) && <div className="mt-2"><Alert>{fileErr ?? importVex.error?.message}</Alert></div>}
      {result && <div className="mt-2"><ImportSummary r={result} /></div>}
    </Card>
  );
}

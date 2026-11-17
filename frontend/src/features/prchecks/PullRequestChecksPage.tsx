import { useEffect, useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { GitPullRequest, RefreshCw } from "lucide-react";
import { api } from "@/api/client";
import type { Severity } from "@/api/types";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, EmptyState, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { RepoFilter } from "@/features/review/shared";
import { formatDateTime } from "@/lib/utils";

export interface PRCheck {
  id: string;
  repository_id: string;
  repository_name: string;
  scan_job_id: string;
  scan_status: string;
  pull_request: number;
  head_ref: string;
  head_sha: string;
  status: "pending" | "passed" | "failed" | "error";
  gate_severity: string;
  new_findings: number;
  new_by_severity: Record<string, number>;
  existing_findings: number;
  summary: string;
  status_posted: string;
  status_error: string;
  created_at: string;
  finished_at: string | null;
}
interface PRFinding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  scanner_key: string;
  rule_id: string;
  file_path: string;
  start_line: number | null;
  cve: string | null;
  is_new: boolean;
  existing_finding_id: string | null;
}

const statusTone = { pending: "neutral", passed: "success", failed: "danger", error: "warning" } as const;
const statusLabel = { pending: "Pending", passed: "Passed", failed: "Blocked", error: "Error" };
const postedLabel: Record<string, string> = {
  "": "Not posted yet",
  pending: "Pending status posted",
  final: "Result posted to the pull request",
  failed: "Could not post the status",
  not_supported: "Statuses not available",
};

function Settings() {
  const qc = useQueryClient();
  const { can } = useSession();
  const [repo, setRepo] = useState<string | undefined>();
  const q = useQuery({
    queryKey: ["pr-settings", repo],
    queryFn: () => api<{ enabled: boolean; gate_severity: string; source_type: string }>(`/api/v1/repositories/${repo}/pr-settings`),
    enabled: !!repo,
  });
  const [enabled, setEnabled] = useState(false);
  const [gate, setGate] = useState("high");
  useEffect(() => {
    if (q.data) {
      setEnabled(q.data.enabled);
      setGate(q.data.gate_severity);
    }
  }, [q.data]);
  const save = useMutation({
    mutationFn: () => api(`/api/v1/repositories/${repo}/pr-settings`, { method: "PUT", body: { enabled, gate_severity: gate } }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["pr-settings", repo] }),
  });
  const manage = can("repos.manage");
  return (
    <Card className="mb-4 p-4">
      <h2 className="mb-1 text-[13px] font-semibold">Repository settings</h2>
      <p className="mb-3 text-[12px] text-muted-foreground">
        When enabled, every pull request event from the repository's webhook queues a scan of the PR head with the repository's scan profile.
        The result is posted to the PR as the commit status <code>PATHOS / security</code>; make it a required check in branch protection to block merges.
        The SCM credential needs permission to write commit statuses.
      </p>
      <div className="flex flex-wrap items-end gap-3">
        <div><span className="mb-1 block text-[12px] font-medium">Repository</span><RepoFilter value={repo} onChange={setRepo} /></div>
        {repo && q.isPending && <Skeleton className="h-8 w-64" />}
        {repo && q.data && (
          <>
            <label className="flex items-center gap-1.5 text-[13px]">
              <input type="checkbox" className="accent-[var(--primary)]" checked={enabled} disabled={!manage || q.data.source_type === "upload"} onChange={(e) => setEnabled(e.target.checked)} />
              Check pull requests
            </label>
            <div>
              <Label htmlFor="pr-gate">Block when a new finding is</Label>
              <Select id="pr-gate" value={gate} disabled={!manage} onChange={(e) => setGate(e.target.value)}>
                <option value="critical">Critical</option>
                <option value="high">High or above</option>
                <option value="medium">Medium or above</option>
                <option value="low">Low or above</option>
                <option value="none">Never (report only)</option>
              </Select>
            </div>
            {manage && <Button onClick={() => save.mutate()} disabled={save.isPending}>{save.isPending ? "Saving…" : "Save"}</Button>}
            {q.data.source_type === "upload" && <span className="text-[12px] text-muted-foreground">Uploaded repositories have no pull requests.</span>}
          </>
        )}
      </div>
      {(q.error || save.error) && <div className="mt-3"><Alert>{(q.error ?? save.error)!.message}</Alert></div>}
      {save.isSuccess && <p className="mt-2 text-[12px] text-success">Saved.</p>}
    </Card>
  );
}

function CheckDetail({ id }: { id: string }) {
  const qc = useQueryClient();
  const { can } = useSession();
  const q = useQuery({ queryKey: ["pr-check", id], queryFn: () => api<{ check: PRCheck; findings: PRFinding[] }>(`/api/v1/pr-checks/${id}`) });
  const repost = useMutation({
    mutationFn: () => api<PRCheck>(`/api/v1/pr-checks/${id}/repost`, { method: "POST" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["pr-check", id] });
      void qc.invalidateQueries({ queryKey: ["pr-checks"] });
    },
  });
  if (q.isError) return <Alert>{q.error.message}</Alert>;
  if (q.isPending) return <Skeleton className="h-48" />;
  const { check: c, findings } = q.data;
  const fresh = findings.filter((f) => f.is_new);
  const known = findings.filter((f) => !f.is_new);
  return (
    <div className="space-y-3 text-[13px]">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-[15px] font-semibold">{c.repository_name} #{c.pull_request}</h2>
        <Badge tone={statusTone[c.status]}>{statusLabel[c.status]}</Badge>
        <Link to="/scans/$id" params={{ id: c.scan_job_id }} className="ml-auto text-[12px] text-primary hover:underline">Scan execution →</Link>
      </div>
      <p className="text-[12px] text-muted-foreground">
        <span className="font-mono">{c.head_ref}</span> at <span className="font-mono">{c.head_sha.slice(0, 12)}</span> · {formatDateTime(c.created_at)}
      </p>
      {c.summary && <p>{c.summary}</p>}
      <div className="flex flex-wrap items-center gap-2 text-[12px]">
        <span className={c.status_posted === "failed" ? "text-danger" : "text-muted-foreground"}>{postedLabel[c.status_posted] ?? c.status_posted}</span>
        {c.status_error && <span className="text-danger">: {c.status_error}</span>}
        {can("scans.run") && c.status !== "pending" && (
          <Button size="sm" variant="secondary" onClick={() => repost.mutate()} disabled={repost.isPending}><RefreshCw /> Post status again</Button>
        )}
      </div>
      {repost.error && <Alert>{repost.error.message}</Alert>}
      <h3 className="font-semibold">Introduced by this pull request ({fresh.length})</h3>
      {fresh.length ? <FindingTable rows={fresh} /> : <p className="text-[12px] text-muted-foreground">{c.status === "pending" ? "The scan has not finished." : "No new findings."}</p>}
      {known.length > 0 && (
        <details>
          <summary className="cursor-pointer text-[12.5px] font-medium">Already known on the scan branch ({known.length})</summary>
          <p className="my-1 text-[11.5px] text-muted-foreground">Open, accepted or marked false positive on the scan branch; they do not block the pull request.</p>
          <FindingTable rows={known} />
        </details>
      )}
    </div>
  );
}

function FindingTable({ rows }: { rows: PRFinding[] }) {
  return (
    <Table>
      <thead><tr><Th>Severity</Th><Th>Finding</Th><Th>Location</Th><Th>Scanner</Th></tr></thead>
      <tbody>
        {rows.map((f) => (
          <tr key={f.id}>
            <Td><SeverityBadge value={f.severity} /></Td>
            <Td className="text-[12.5px]">
              {f.existing_finding_id ? <Link to="/findings" search={{ finding: f.existing_finding_id, status: "all" } as never} className="text-primary hover:underline">{f.title}</Link> : f.title}
              {f.cve && <span className="ml-1 font-mono text-[11px] text-muted-foreground">{f.cve}</span>}
            </Td>
            <Td className="max-w-64 truncate font-mono text-[11.5px]"><span title={f.file_path}>{f.file_path}{f.start_line ? `:${f.start_line}` : ""}</span></Td>
            <Td className="text-[12px]">{f.scanner_key}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export function PullRequestChecksPage() {
  const search = useSearch({ strict: false }) as { check?: string };
  const navigate = useNavigate();
  const [repo, setRepo] = useState<string | undefined>();
  const [status, setStatus] = useState("");
  const list = useQuery({
    queryKey: ["pr-checks", repo, status],
    queryFn: () => {
      const p = new URLSearchParams();
      if (repo) p.set("repository_id", repo);
      if (status) p.set("status", status);
      return api<{ items: PRCheck[] }>(`/api/v1/pr-checks?${p}`).then((r) => r.items);
    },
    refetchInterval: (q) => (q.state.data?.some((c) => c.status === "pending") ? 10000 : false),
  });
  const open = search.check;
  const setOpen = (id: string) => void navigate({ to: "/pull-requests", search: { check: id } as never });
  return (
    <>
      <PageHeader
        title="Pull request checks"
        description="Security results for pull requests. Only what a pull request introduces counts: findings already known on the scan branch never block it, and PR scans never change the repository's findings."
      />
      <Settings />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <RepoFilter value={repo} onChange={setRepo} />
        <Select aria-label="Result" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All results</option>
          {(Object.keys(statusLabel) as (keyof typeof statusLabel)[]).map((s) => <option key={s} value={s}>{statusLabel[s]}</option>)}
        </Select>
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <Card>
          {list.isError ? <div className="p-3"><Alert>{list.error.message}</Alert></div> : list.isPending ? <Skeleton className="m-3 h-24" /> : !list.data.length ? (
            <EmptyState icon={<GitPullRequest />} title="No pull request checks">Enable checks for a repository above; results appear when its webhook reports a pull request.</EmptyState>
          ) : (
            <Table>
              <thead><tr><Th>Pull request</Th><Th>Result</Th><Th className="text-right">New</Th><Th>When</Th></tr></thead>
              <tbody>
                {list.data.map((c) => (
                  <tr key={c.id} className={open === c.id ? "bg-primary/5" : undefined}>
                    <Td>
                      <button type="button" className="text-left text-[12.5px] text-primary hover:underline" onClick={() => setOpen(c.id)}>{c.repository_name} #{c.pull_request}</button>
                      <div className="font-mono text-[11px] text-muted-foreground">{c.head_ref}</div>
                    </Td>
                    <Td><Badge tone={statusTone[c.status]}>{statusLabel[c.status]}</Badge></Td>
                    <Td className="tabular text-right text-[12px]">{c.status === "pending" ? "—" : c.new_findings}</Td>
                    <Td className="whitespace-nowrap text-[11.5px] text-muted-foreground">{formatDateTime(c.created_at)}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
        <Card className="p-4">{open ? <CheckDetail key={open} id={open} /> : <p className="text-[13px] text-muted-foreground">Select a check.</p>}</Card>
      </div>
    </>
  );
}

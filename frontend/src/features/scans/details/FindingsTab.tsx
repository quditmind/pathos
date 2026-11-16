import { useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { ShieldCheck } from "lucide-react";
import type { ScanFinding, ScanJob } from "@/api/types";
import { Alert, Badge, Card, EmptyState } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { FilterBar } from "@/components/data/FilterBar";
import { SeverityBadge } from "@/components/data/Severity";
import { useSession } from "@/features/auth/session";
import { useScanFindings } from "../api";
import { severities } from "../shared";

export function affectedComponent(f: ScanFinding): string {
  if (f.package_name) return `${f.package_name}${f.package_version ? `@${f.package_version}` : ""}`;
  if (f.file_path) return `${f.file_path}${f.start_line ? `:${f.start_line}` : ""}`;
  return "—";
}

const columns: Column<ScanFinding>[] = [
  { id: "severity", header: "Severity", required: true, cell: (f) => <SeverityBadge value={f.severity} />, csv: (f) => f.severity },
  {
    id: "title",
    header: "Title",
    required: true,
    cell: (f) => (
      <div className="max-w-md">
        <div className="flex items-center gap-1.5">
          <Link to="/findings" search={{ finding: f.id } as never} onClick={(e) => e.stopPropagation()} className="truncate font-medium hover:underline">{f.title}</Link>
          {f.is_new && <Badge tone="danger">new</Badge>}
        </div>
        <div className="font-mono text-[11px] text-muted-foreground">{f.cve || f.rule_id}</div>
      </div>
    ),
    csv: (f) => f.title,
  },
  { id: "component", header: "Affected component", className: "max-w-xs truncate font-mono text-[11.5px]", cell: affectedComponent, csv: affectedComponent },
  { id: "engine", header: "Engine", className: "whitespace-nowrap text-[12px]", cell: (f) => f.scanner || f.scanner_keys.join(", "), csv: (f) => f.scanner },
  { id: "evidence", header: "Evidence", className: "max-w-xs truncate font-mono text-[11.5px]", cell: (f) => <span title={f.evidence}>{f.evidence || "—"}</span>, csv: (f) => f.evidence },
  { id: "new", header: "New", defaultHidden: true, cell: (f) => (f.is_new ? "yes" : "no"), csv: (f) => (f.is_new ? "yes" : "no") },
  {
    id: "remediation",
    header: "Remediation",
    cell: (f) =>
      f.fixed_version ? (
        <span className="text-[12px]">Upgrade to <span className="font-mono">{f.fixed_version}</span></span>
      ) : f.description ? (
        <span className="line-clamp-2 max-w-sm text-[12px] text-muted-foreground" title={f.description}>{f.description}</span>
      ) : (
        <span className="text-muted-foreground">—</span>
      ),
    csv: (f) => f.fixed_version || f.description,
  },
  { id: "status", header: "Status", defaultHidden: true, className: "text-[12px]", cell: (f) => f.status, csv: (f) => f.status },
];

export function FindingsTab({ job }: { job: ScanJob }) {
  const { can } = useSession();
  const navigate = useNavigate();
  const [f, setF] = useState<{ severity?: string; scanner?: string; new?: string }>({});
  const allowed = can("findings.read");
  const findings = useScanFindings(job.id, { severity: f.severity, scanner: f.scanner }, allowed);
  if (!allowed) return <Alert tone="warning">You need the findings.read permission on this repository to see its findings.</Alert>;
  const rows = (findings.data ?? []).filter((x) => !f.new || x.is_new);
  const scanners = (job.results ?? []).map((r) => r.scanner_key);
  return (
    <Card>
      <DataTable
        tableId="scan-findings"
        exportName={`pathos-${job.scan_key}-findings`}
        columns={columns}
        rows={rows}
        rowKey={(x) => x.id}
        isPending={findings.isPending}
        error={findings.error}
        onRowClick={(x) => void navigate({ to: "/findings", search: { finding: x.id } as never })}
        empty={
          <EmptyState icon={<ShieldCheck />} title={job.finished_at ? "No findings" : "No findings yet"}>
            {job.finished_at ? "This execution reported no findings for the selected filters." : "Findings appear when the scanner engines finish."}
          </EmptyState>
        }
        toolbar={
          <FilterBar
            filters={[
              { key: "severity", label: "Severity", allLabel: "All severities", options: severities.map((s) => ({ value: s, label: s[0]!.toUpperCase() + s.slice(1) })) },
              { key: "scanner", label: "Engine", allLabel: "All engines", options: scanners.map((s) => ({ value: s, label: s })) },
              { key: "new", label: "New findings", allLabel: "New and existing", options: [{ value: "1", label: "New in this scan" }] },
            ]}
            values={f}
            onChange={(k, v) => setF({ ...f, [k]: v })}
            onReset={() => setF({})}
          />
        }
      />
    </Card>
  );
}

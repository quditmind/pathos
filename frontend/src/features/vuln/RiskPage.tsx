import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { ShieldOff } from "lucide-react";
import { api } from "@/api/client";
import type { RiskAcceptance } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, EmptyState, Input, PageHeader, Select } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { SeverityBadge } from "@/components/data/Severity";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { useAcceptances, useVulnMutation } from "./api";

export function RiskPage() {
  const { can } = useSession();
  const [status, setStatus] = useState("pending");
  const [note, setNote] = useState("");
  const list = useAcceptances({ status });
  const decide = useVulnMutation(({ id, action }: { id: string; action: string }) => api(`/api/v1/risk-acceptances/${id}/${action}`, { method: "POST", body: { note } }));
  const columns: Column<RiskAcceptance>[] = [
    { id: "sev", header: "Severity", cell: (a) => <SeverityBadge value={a.finding_severity} />, csv: (a) => a.finding_severity },
    {
      id: "finding", header: "Finding", required: true,
      cell: (a) => (
        <div className="max-w-md">
          <Link to="/findings" search={{ finding: a.finding_id, status: "all" } as never} className="font-medium hover:underline">{a.finding_title}</Link>
          <div className="text-[12px] text-muted-foreground">{a.repository_name}</div>
        </div>
      ), csv: (a) => a.finding_title,
    },
    { id: "just", header: "Justification", cell: (a) => <p className="max-w-sm text-[12.5px]">{a.justification}</p>, csv: (a) => a.justification },
    { id: "req", header: "Requested by", cell: (a) => <span className="text-[12px]">{a.requested_by}<br /><span className="text-muted-foreground">{formatDateTime(a.created_at)}</span></span>, csv: (a) => a.requested_by },
    { id: "exp", header: "Expires", className: "tabular whitespace-nowrap text-[12px]", cell: (a) => formatDateTime(a.expires_at), csv: (a) => a.expires_at },
    { id: "status", header: "Status", cell: (a) => <Badge tone={a.status === "approved" ? "primary" : a.status === "pending" ? "warning" : "neutral"}>{a.status}</Badge>, csv: (a) => a.status },
    {
      id: "actions", header: "", required: true,
      cell: (a) => can("findings.accept_risk") && (
        <div className="flex gap-1">
          {a.status === "pending" && <>
            <Button size="sm" onClick={() => decide.mutate({ id: a.id, action: "approve" })}>Approve</Button>
            <Button size="sm" variant="secondary" onClick={() => decide.mutate({ id: a.id, action: "reject" })}>Reject</Button>
          </>}
          {a.status === "approved" && <Button size="sm" variant="danger-outline" onClick={() => decide.mutate({ id: a.id, action: "revoke" })}>Revoke</Button>}
        </div>
      ),
    },
  ];
  return (
    <>
      <PageHeader title="Risk acceptances" description="Time-boxed exceptions. A different person with findings.accept_risk must approve; findings reopen automatically at expiry." />
      {decide.isError && <div className="mb-3"><Alert>{decide.error.message}</Alert></div>}
      <Card>
        <DataTable tableId="risk" exportName="pathos-risk-acceptances" columns={columns} rows={list.data ?? []} rowKey={(a) => a.id}
          isPending={list.isPending} error={list.error}
          empty={<EmptyState icon={<ShieldOff />} title={status === "pending" ? "Nothing awaiting approval" : "No risk acceptances"} />}
          toolbar={<>
            <Select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
              {["pending", "approved", "expired", "rejected", "revoked", ""].map((s) => <option key={s} value={s}>{s ? s[0]!.toUpperCase() + s.slice(1) : "All"}</option>)}
            </Select>
            {can("findings.accept_risk") && <Input aria-label="Decision note" placeholder="Decision note (optional)" className="max-w-xs" value={note} onChange={(e) => setNote(e.target.value)} />}
          </>} />
      </Card>
    </>
  );
}

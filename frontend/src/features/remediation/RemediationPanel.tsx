import { Link } from "@tanstack/react-router";
import { ExternalLink, Wrench } from "lucide-react";
import { SeverityBadge } from "@/components/data/Severity";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Card, Table, Td, Th } from "@/components/ui/primitives";
import { EmptyStateCard, FeatureDisabled, LoadingSkeleton, PermissionDenied } from "@/components/ui/states";
import { useSession } from "@/features/auth/session";
import { useFeatureFlags } from "@/features/shell/meta";
import { isFeatureDisabled, useItems, type ItemStatus } from "./api";
import { DueDate, StatusBadge, resultLabel } from "./RemediationPage";
import { FLAG } from "./shared";

const openStatuses: ItemStatus[] = ["open", "planned", "in_progress", "fix_submitted", "verifying"];

/**
 * Application hub tab (PATHOS 3.0 M8): the application's remediation items,
 * soonest due first, with a link to the workspace filtered to the
 * application. Behind the remediation_workspace flag; needs remediation.read.
 */
export function RemediationPanel({ applicationId }: { applicationId: string }) {
  const { flags, isPending } = useFeatureFlags();
  const { can } = useSession();
  const enabled = flags[FLAG] === true;
  const allowed = can("remediation.read");
  const q = useItems({ application_id: applicationId }, undefined, enabled && allowed);
  if (isPending) return <LoadingSkeleton rows={3} label="Loading remediation items" />;
  if (!enabled || isFeatureDisabled(q.error)) return <FeatureDisabled flag={FLAG} feature="The remediation workspace" />;
  if (!allowed) return <PermissionDenied permission="remediation.read" what="Remediation" />;
  if (q.isPending) return <LoadingSkeleton rows={4} label="Loading remediation items" />;
  if (q.isError) return <ErrorPanel error={q.error} title="Remediation items could not be loaded" onVerify={() => q.refetch()} />;
  const items = q.data.items;
  const open = items.filter((i) => openStatuses.includes(i.status));
  const overdue = open.filter((i) => i.overdue).length;
  const unassigned = open.filter((i) => !i.owner_id).length;
  const workspace = (
    <Link to="/remediation" search={{ application_id: applicationId } as never} className="inline-flex items-center gap-1 text-[12.5px] text-primary hover:underline">
      Open in the remediation workspace <ExternalLink className="size-3" aria-hidden />
    </Link>
  );
  if (!items.length) {
    return (
      <EmptyStateCard icon={<Wrench />} title="No remediation items yet" action={workspace}>
        Items appear when someone creates them from this application's findings (Findings → select → Create remediation items). Each item tracks one finding or a group of findings to a verified fix.
      </EmptyStateCard>
    );
  }
  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border p-3">
        <div className="flex flex-wrap items-center gap-4 text-[12.5px]" aria-label="Remediation summary">
          <span>
            <strong>{open.length}</strong> open
          </span>
          <span className={overdue ? "text-danger" : undefined}>
            <strong>{overdue}</strong> overdue
          </span>
          <span>
            <strong>{unassigned}</strong> unassigned
          </span>
          {q.data.next_cursor && <span className="text-muted-foreground">counts of the first 50 items</span>}
        </div>
        {workspace}
      </div>
      <Table>
        <thead>
          <tr>
            <Th>Item</Th>
            <Th>Status</Th>
            <Th>Priority</Th>
            <Th>Owner</Th>
            <Th>Due</Th>
            <Th>Verification</Th>
          </tr>
        </thead>
        <tbody>
          {items.map((i) => (
            <tr key={i.id}>
              <Td className="max-w-md">
                <Link to="/remediation/items/$id" params={{ id: i.id }} className="text-[12.5px] text-primary hover:underline">
                  {i.title}
                </Link>
                <div className="flex flex-wrap items-center gap-1 text-[11.5px] text-muted-foreground">
                  {i.top_severity && <SeverityBadge value={i.top_severity} />}
                  {i.repository_name && <span>{i.repository_name}</span>}
                  <span>· {i.open_finding_count}/{i.finding_count} finding(s) open</span>
                </div>
              </Td>
              <Td>
                <StatusBadge status={i.status} />
              </Td>
              <Td className="text-[12px] capitalize">{i.priority}</Td>
              <Td className="text-[12px]">{i.owner_email || <span className="text-muted-foreground">Unassigned</span>}</Td>
              <Td className="whitespace-nowrap text-[12px]">
                <DueDate item={i} />
              </Td>
              <Td className="text-[12px]">
                {i.last_verification ? (
                  <span>{i.last_verification.result ? resultLabel[i.last_verification.result] : i.last_verification.status}</span>
                ) : (
                  <span className="text-muted-foreground">Not verified</span>
                )}
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
      {q.data.next_cursor && <p className="p-3 text-[12px] text-muted-foreground">Showing the first 50; open the remediation workspace for all of them.</p>}
    </Card>
  );
}

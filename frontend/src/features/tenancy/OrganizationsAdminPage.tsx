import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, Plus } from "lucide-react";
import { api, ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useMyOrganizations, type InstallationAuditEntry, type InstallationOrganization } from "./api";

function errText(e: unknown) {
  return e instanceof ApiError || e instanceof Error ? e.message : "request failed";
}

/**
 * Installation administration: the organizations of a multi-tenant
 * installation. installation administrators manage organizations only; they
 * see an organization's data only through an ordinary membership in it.
 */
export function OrganizationsAdminPage() {
  const mine = useMyOrganizations();
  const qc = useQueryClient();
  const allowed = mine.data?.multi_tenant && mine.data.installation_admin;
  const orgs = useQuery({
    queryKey: ["installation", "organizations"],
    queryFn: () => api<{ items: InstallationOrganization[] }>("/api/v1/installation/organizations"),
    enabled: !!allowed,
  });
  const audit = useQuery({
    queryKey: ["installation", "audit"],
    queryFn: () => api<{ items: InstallationAuditEntry[] }>("/api/v1/installation/audit-logs"),
    enabled: !!allowed,
  });
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["installation"] });
  };

  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ name: "", slug: "", admin_email: "" });
  const create = useMutation({
    mutationFn: () => api("/api/v1/installation/organizations", { method: "POST", body: form }),
    onSuccess: () => {
      setCreateOpen(false);
      setForm({ name: "", slug: "", admin_email: "" });
      refresh();
    },
  });

  const [suspend, setSuspend] = useState<InstallationOrganization | null>(null);
  const [reason, setReason] = useState("");
  const doSuspend = useMutation({
    mutationFn: (o: InstallationOrganization) => api(`/api/v1/installation/organizations/${o.id}/suspend`, { method: "POST", body: { reason } }),
    onSuccess: () => {
      setSuspend(null);
      setReason("");
      refresh();
    },
  });
  const resume = useMutation({
    mutationFn: (o: InstallationOrganization) => api(`/api/v1/installation/organizations/${o.id}/resume`, { method: "POST" }),
    onSuccess: refresh,
  });

  const [del, setDel] = useState<InstallationOrganization | null>(null);
  const [confirmSlug, setConfirmSlug] = useState("");
  const doDelete = useMutation({
    mutationFn: (o: InstallationOrganization) =>
      api(`/api/v1/installation/organizations/${o.id}`, { method: "DELETE", body: { confirm_slug: confirmSlug } }),
    onSuccess: () => {
      setDel(null);
      setConfirmSlug("");
      refresh();
    },
  });

  if (mine.isPending) return <Skeleton className="h-40" />;
  if (!allowed) {
    return (
      <>
        <PageHeader title="Organizations" />
        <EmptyState icon={<Building2 />} title="Installation administration is not available">
          {mine.data?.multi_tenant
            ? "Only installation administrators manage organizations."
            : "This installation serves a single organization. An operator enables multi-tenancy with pathosctl multi-tenancy enable."}
        </EmptyState>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Organizations"
        description="Every organization on this installation is isolated from the others. installation administrators create, suspend and delete organizations; they see an organization's data only as a member of it."
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus /> New organization
          </Button>
        }
      />
      {(resume.isError || orgs.isError) && <Alert>{errText(resume.error ?? orgs.error)}</Alert>}
      <Card>
        {orgs.isPending ? (
          <Skeleton className="m-4 h-24" />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Name</Th>
                <Th>Slug</Th>
                <Th>Status</Th>
                <Th className="text-right">Users</Th>
                <Th className="text-right">Repositories</Th>
                <Th>Created</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {(orgs.data?.items ?? []).map((o) => (
                <tr key={o.id}>
                  <Td className="font-medium">{o.name}</Td>
                  <Td className="font-mono text-[12px]">{o.slug}</Td>
                  <Td>
                    {o.status === "active" ? (
                      <Badge tone="success">active</Badge>
                    ) : (
                      <span title={o.suspended_reason}>
                        <Badge tone="warning">suspended</Badge>
                      </span>
                    )}
                  </Td>
                  <Td className="tabular text-right">{o.users}</Td>
                  <Td className="tabular text-right">{o.repositories}</Td>
                  <Td className="text-[12px] text-muted-foreground">{new Date(o.created_at).toLocaleDateString()}</Td>
                  <Td className="text-right">
                    {o.status === "active" ? (
                      <Button size="sm" variant="secondary" onClick={() => setSuspend(o)}>
                        Suspend
                      </Button>
                    ) : (
                      <span className="inline-flex gap-1.5">
                        <Button size="sm" variant="secondary" onClick={() => resume.mutate(o)} disabled={resume.isPending}>
                          Resume
                        </Button>
                        <Button size="sm" variant="danger-outline" onClick={() => setDel(o)}>
                          Delete
                        </Button>
                      </span>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <h2 className="mb-2 mt-6 text-[13px] font-semibold">Installation audit log</h2>
      <Card>
        {audit.isPending ? (
          <Skeleton className="m-4 h-16" />
        ) : (audit.data?.items ?? []).length === 0 ? (
          <p className="p-4 text-[13px] text-muted-foreground">No installation actions yet.</p>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>When</Th>
                <Th>Who</Th>
                <Th>Action</Th>
                <Th>Outcome</Th>
                <Th>Details</Th>
              </tr>
            </thead>
            <tbody>
              {(audit.data?.items ?? []).map((e) => (
                <tr key={e.id}>
                  <Td className="text-[12px] text-muted-foreground">{new Date(e.created_at).toLocaleString()}</Td>
                  <Td>{e.actor_email || "system"}</Td>
                  <Td className="font-mono text-[12px]">{e.action}</Td>
                  <Td>{e.outcome}</Td>
                  <Td className="text-[12px] text-muted-foreground">
                    {String(e.metadata?.slug ?? e.metadata?.email ?? "")}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <Dialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        title="New organization"
        description="Creates the organization with default regions, scan profile, policies and notification rules. The administrator email is invited as the organization's super administrator and linked at their first sign-in with a verified email."
        footer={
          <>
            <Button variant="secondary" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" form="create-org" disabled={create.isPending || !form.name.trim() || !form.slug.trim()}>
              Create
            </Button>
          </>
        }
      >
        <form
          id="create-org"
          className="space-y-3"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          {create.isError && <Alert>{errText(create.error)}</Alert>}
          <div>
            <Label htmlFor="org-name">Name</Label>
            <Input id="org-name" value={form.name} maxLength={200} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <div>
            <Label htmlFor="org-slug" hint="Lowercase letters, digits and hyphens. Used in the identity-provider group /pathos/<slug> and by workers.">
              Slug
            </Label>
            <Input
              id="org-slug"
              value={form.slug}
              maxLength={63}
              pattern="[a-z0-9-]{1,63}"
              onChange={(e) => setForm({ ...form, slug: e.target.value.toLowerCase() })}
            />
          </div>
          <div>
            <Label htmlFor="org-admin" hint="Optional.">
              Administrator email
            </Label>
            <Input id="org-admin" type="email" value={form.admin_email} onChange={(e) => setForm({ ...form, admin_email: e.target.value })} />
          </div>
        </form>
      </Dialog>

      <Dialog
        open={!!suspend}
        onOpenChange={(o) => !o && setSuspend(null)}
        title={`Suspend ${suspend?.name ?? ""}`}
        description="Members can no longer sign in to it, its API tokens, MCP tokens and workers stop working, and its scheduled scans pause. No data is removed."
        footer={
          <>
            <Button variant="secondary" onClick={() => setSuspend(null)}>
              Cancel
            </Button>
            <Button variant="danger" disabled={doSuspend.isPending} onClick={() => suspend && doSuspend.mutate(suspend)}>
              Suspend
            </Button>
          </>
        }
      >
        {doSuspend.isError && <Alert>{errText(doSuspend.error)}</Alert>}
        <Label htmlFor="suspend-reason">Reason (shown to installation administrators)</Label>
        <Input id="suspend-reason" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} />
      </Dialog>

      <Dialog
        open={!!del}
        onOpenChange={(o) => !o && setDel(null)}
        title={`Delete ${del?.name ?? ""}`}
        description="Permanently deletes every record of this organization, including its audit log and stored scan artifacts and source snapshots. This cannot be undone."
        footer={
          <>
            <Button variant="secondary" onClick={() => setDel(null)}>
              Cancel
            </Button>
            <Button variant="danger" disabled={doDelete.isPending || confirmSlug !== del?.slug} onClick={() => del && doDelete.mutate(del)}>
              Delete permanently
            </Button>
          </>
        }
      >
        {doDelete.isError && <Alert>{errText(doDelete.error)}</Alert>}
        <Label htmlFor="confirm-slug">
          Type the slug <span className="font-mono">{del?.slug}</span> to confirm
        </Label>
        <Input id="confirm-slug" value={confirmSlug} onChange={(e) => setConfirmSlug(e.target.value)} />
      </Dialog>
    </>
  );
}

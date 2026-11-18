import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Boxes, Plus } from "lucide-react";
import { api } from "@/api/client";
import type { Application, User } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Card, EmptyState, Input, Label, PageHeader, Select } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { CriticalityBadge } from "@/components/data/TagChip";
import { useSession } from "@/features/auth/session";
import { useBusinessUnits, useUsers } from "@/features/users/api";
import { useApplications, useRepoMutation } from "./api";

const columns: Column<Application>[] = [
  {
    id: "name",
    header: "Application",
    required: true,
    cell: (a) => (
      <div>
        <div className="font-medium">{a.name}</div>
        {a.description && <div className="max-w-md truncate text-[12px] text-muted-foreground">{a.description}</div>}
      </div>
    ),
    csv: (a) => a.name,
  },
  { id: "key", header: "Application ID", required: true, className: "whitespace-nowrap font-mono text-[12px]", cell: (a) => a.application_key, csv: (a) => a.application_key },
  { id: "ref", header: "External ID", defaultHidden: true, exportAlways: true, className: "font-mono text-[12px]", cell: (a) => a.external_ref || <span className="text-muted-foreground">—</span>, csv: (a) => a.external_ref },
  { id: "lifecycle", header: "Lifecycle", className: "text-[12px] capitalize", cell: (a) => a.lifecycle, csv: (a) => a.lifecycle },
  { id: "environment", header: "Environment", defaultHidden: true, exportAlways: true, className: "text-[12px] capitalize", cell: (a) => a.environment, csv: (a) => a.environment },
  { id: "criticality", header: "Criticality", cell: (a) => <CriticalityBadge value={a.criticality} />, csv: (a) => a.criticality },
  { id: "bu", header: "Business unit", cell: (a) => a.business_unit?.name ?? "—", csv: (a) => a.business_unit?.name },
  { id: "owner", header: "Owner", cell: (a) => a.owner?.name ?? <span className="text-muted-foreground">Unassigned</span>, csv: (a) => a.owner?.email },
  { id: "techowner", header: "Technical owner", defaultHidden: true, exportAlways: true, cell: (a) => a.technical_owner?.name ?? <span className="text-muted-foreground">Unassigned</span>, csv: (a) => a.technical_owner?.email },
  { id: "secowner", header: "Security owner", cell: (a) => a.security_owner?.name ?? <span className="text-muted-foreground">Unassigned</span>, csv: (a) => a.security_owner?.email },
  {
    id: "repos",
    header: "Repositories",
    className: "tabular",
    cell: (a) => (
      <Link to="/repositories" search={{ application_id: a.id } as never} onClick={(e) => e.stopPropagation()} className="text-primary hover:underline">
        {a.repository_count}
      </Link>
    ),
    csv: (a) => a.repository_count,
  },
  {
    id: "versions",
    header: "Versions",
    cell: (a) => (
      <Link to="/applications/$id/versions" params={{ id: a.id }} onClick={(e) => e.stopPropagation()} className="text-primary hover:underline">
        Versions
      </Link>
    ),
  },
];

export function ApplicationsPage() {
  const { can, canOrgWide } = useSession();
  const search = useSearch({ strict: false }) as { app?: string };
  const navigate = useNavigate();
  const apps = useApplications();
  const [editing, setEditing] = useState<Application | "new" | null>(null);
  useEffect(() => {
    if (search.app && apps.data) {
      const a = apps.data.find((x) => x.id === search.app);
      if (a) setEditing(a);
    }
  }, [search.app, apps.data]);

  return (
    <>
      <PageHeader
        title="Applications"
        description="Business applications (assets) that group repositories and carry ownership."
        actions={can("repos.manage") && <Button onClick={() => setEditing("new")}><Plus /> New application</Button>}
      />
      <Card>
        <DataTable
          tableId="applications"
          exportName="pathos-applications"
          columns={columns}
          rows={apps.data ?? []}
          rowKey={(a) => a.id}
          isPending={apps.isPending}
          error={apps.error}
          onRowClick={can("repos.manage") ? (a) => setEditing(a) : undefined}
          empty={<EmptyState icon={<Boxes />} title="No applications yet">Group repositories into applications to track ownership and posture per business asset.</EmptyState>}
        />
      </Card>
      <AppDialog
        app={editing}
        canPickUsers={canOrgWide("users.read")}
        onClose={() => {
          setEditing(null);
          if (search.app) void navigate({ to: "/applications", search: {} as never, replace: true });
        }}
      />
    </>
  );
}

function AppDialog({ app, onClose, canPickUsers }: { app: Application | "new" | null; onClose: () => void; canPickUsers: boolean }) {
  const isNew = app === "new";
  const existing = app && app !== "new" ? app : null;
  const bus = useBusinessUnits();
  const users = useUsers("", "active");
  const userList: User[] = users.data?.pages.flatMap((p) => p.items) ?? [];
  const [f, setF] = useState({ name: "", external_ref: "", description: "", business_unit_id: "", owner_user_id: "", security_owner_user_id: "", technical_owner_user_id: "", criticality: "medium", lifecycle: "active", environment: "production" });
  useEffect(() => {
    setF({
      name: existing?.name ?? "",
      description: existing?.description ?? "",
      external_ref: existing?.external_ref ?? "",
      business_unit_id: existing?.business_unit?.id ?? "",
      owner_user_id: existing?.owner?.id ?? "",
      security_owner_user_id: existing?.security_owner?.id ?? "",
      technical_owner_user_id: existing?.technical_owner?.id ?? "",
      lifecycle: existing?.lifecycle ?? "active",
      environment: existing?.environment ?? "production",
      criticality: existing?.criticality ?? "medium",
    });
  }, [app]); // eslint-disable-line react-hooks/exhaustive-deps

  const save = useRepoMutation((body: unknown) =>
    isNew ? api<Application>("/api/v1/applications", { method: "POST", body }) : api<Application>(`/api/v1/applications/${existing!.id}`, { method: "PATCH", body }),
  );
  const archive = useRepoMutation(() => api(`/api/v1/applications/${existing!.id}/archive`, { method: "POST" }));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const nul = (v: string) => v || null;
    save.mutate(
      { name: f.name.trim(), external_ref: f.external_ref.trim(), description: f.description, business_unit_id: nul(f.business_unit_id), criticality: f.criticality,
        lifecycle: f.lifecycle, environment: f.environment,
        ...(canPickUsers ? { owner_user_id: nul(f.owner_user_id), security_owner_user_id: nul(f.security_owner_user_id), technical_owner_user_id: nul(f.technical_owner_user_id) } : {}) },
      { onSuccess: () => { save.reset(); onClose(); } },
    );
  };
  const userOptions = (
    <>
      <option value="">Unassigned</option>
      {userList.map((u) => <option key={u.id} value={u.id}>{u.display_name || u.email}</option>)}
    </>
  );
  return (
    <Dialog
      open={!!app}
      onOpenChange={(o) => !o && onClose()}
      title={isNew ? "New application" : `Edit ${existing?.name ?? ""}`}
      footer={
        <>
          {existing && (
            <Button variant="danger-outline" className="mr-auto" disabled={archive.isPending}
              onClick={() => archive.mutate(undefined, { onSuccess: onClose })} title="Repositories are unlinked, not deleted">
              Archive
            </Button>
          )}
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button type="submit" form="app-form" disabled={save.isPending || !f.name.trim()}>{isNew ? "Create" : "Save"}</Button>
        </>
      }
    >
      <form id="app-form" onSubmit={submit} className="space-y-3">
        {(save.error ?? archive.error) && <Alert>{(save.error ?? archive.error)!.message}</Alert>}
        <div>
          <Label htmlFor="app-name">Name</Label>
          <Input id="app-name" required maxLength={200} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} autoFocus />
        </div>
        <div>
          <Label htmlFor="app-ref" hint="(optional, e.g. CMDB ID)">External ID</Label>
          <Input id="app-ref" maxLength={100} value={f.external_ref} onChange={(e) => setF({ ...f, external_ref: e.target.value })} />
        </div>
        <div>
          <Label htmlFor="app-desc" hint="(optional)">Description</Label>
          <Input id="app-desc" maxLength={2000} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <Label htmlFor="app-bu">Business unit</Label>
            <Select id="app-bu" className="w-full" value={f.business_unit_id} onChange={(e) => setF({ ...f, business_unit_id: e.target.value })}>
              <option value="">None (organization)</option>
              {(bus.data ?? []).map((b) => <option key={b.id} value={b.id}>{b.name}</option>)}
            </Select>
          </div>
          <div>
            <Label htmlFor="app-crit">Criticality</Label>
            <Select id="app-crit" className="w-full capitalize" value={f.criticality} onChange={(e) => setF({ ...f, criticality: e.target.value })}>
              {["critical", "high", "medium", "low"].map((v) => <option key={v} value={v}>{v}</option>)}
            </Select>
          </div>
          <div>
            <Label htmlFor="app-life">Lifecycle</Label>
            <Select id="app-life" className="w-full capitalize" value={f.lifecycle} onChange={(e) => setF({ ...f, lifecycle: e.target.value })}>
              {["planned", "development", "active", "maintenance", "deprecated", "retired"].map((v) => <option key={v} value={v}>{v}</option>)}
            </Select>
          </div>
          <div>
            <Label htmlFor="app-env">Environment</Label>
            <Select id="app-env" className="w-full capitalize" value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })}>
              {["production", "staging", "development", "test", "other"].map((v) => <option key={v} value={v}>{v}</option>)}
            </Select>
          </div>
          {canPickUsers && (
            <>
              <div>
                <Label htmlFor="app-owner">Owner</Label>
                <Select id="app-owner" className="w-full" value={f.owner_user_id} onChange={(e) => setF({ ...f, owner_user_id: e.target.value })}>{userOptions}</Select>
              </div>
              <div>
                <Label htmlFor="app-sec">Security owner</Label>
                <Select id="app-sec" className="w-full" value={f.security_owner_user_id} onChange={(e) => setF({ ...f, security_owner_user_id: e.target.value })}>{userOptions}</Select>
              </div>
              <div>
                <Label htmlFor="app-tech">Technical owner</Label>
                <Select id="app-tech" className="w-full" value={f.technical_owner_user_id} onChange={(e) => setF({ ...f, technical_owner_user_id: e.target.value })}>{userOptions}</Select>
              </div>
            </>
          )}
        </div>
      </form>
    </Dialog>
  );
}

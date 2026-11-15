import { useDeferredValue, useState } from "react";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { Search, UserPlus, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge, Card, EmptyState, Input, PageHeader, Select } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import type { User, UserStatus } from "@/api/types";
import { useSession } from "@/features/auth/session";
import { formatDateTime, initials } from "@/lib/utils";
import { useUsers } from "./api";
import { InviteUserDialog } from "./InviteUserDialog";
import { UserDrawer } from "./UserDrawer";

export const statusTone = { active: "success", invited: "primary", deactivated: "neutral" } as const;

const columns: Column<User>[] = [
  {
    id: "user",
    header: "User",
    required: true,
    cell: (u) => (
      <div className="flex items-center gap-2.5">
        <span className="flex size-7 shrink-0 items-center justify-center rounded-full bg-primary/10 text-[11px] font-semibold text-primary">
          {initials(u.display_name || u.email)}
        </span>
        <div className="min-w-0">
          <div className="truncate font-medium">{u.display_name || "—"}</div>
          <div className="truncate text-[12px] text-muted-foreground">{u.email}</div>
        </div>
      </div>
    ),
    csv: (u) => u.display_name,
  },
  { id: "email", header: "Email", cell: (u) => u.email, csv: (u) => u.email, defaultHidden: true },
  { id: "status", header: "Status", cell: (u) => <Badge tone={statusTone[u.status]}>{u.status}</Badge>, csv: (u) => u.status },
  {
    id: "last_login",
    header: "Last sign-in",
    className: "tabular text-muted-foreground",
    cell: (u) => formatDateTime(u.last_login_at),
    csv: (u) => u.last_login_at,
  },
  { id: "created", header: "Added", className: "tabular text-muted-foreground", cell: (u) => formatDateTime(u.created_at), csv: (u) => u.created_at },
];

export function UsersPage() {
  const { canOrgWide } = useSession();
  const search = useSearch({ strict: false }) as { status?: UserStatus; user?: string };
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const status = search.status ?? "";
  const deferredQ = useDeferredValue(q.trim());
  const users = useUsers(deferredQ, status);
  const [inviteOpen, setInviteOpen] = useState(false);

  const setSearch = (next: { status?: UserStatus; user?: string }) =>
    void navigate({ to: "/admin/users", search: { ...search, ...next } as never, replace: true });

  const rows = users.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <>
      <PageHeader
        title="Users"
        description="People with access to PATHOS and the roles they hold."
        actions={
          canOrgWide("users.manage") && (
            <Button onClick={() => setInviteOpen(true)}>
              <UserPlus /> Invite user
            </Button>
          )
        }
      />
      <Card>
        <DataTable
          tableId="users"
          exportName="pathos-users"
          columns={columns}
          rows={rows}
          rowKey={(u) => u.id}
          isPending={users.isPending}
          error={users.error}
          onRowClick={(u) => setSearch({ user: u.id })}
          hasMore={users.hasNextPage}
          loadingMore={users.isFetchingNextPage}
          onLoadMore={() => void users.fetchNextPage()}
          empty={<EmptyState icon={<Users />} title={q || status ? "No users match these filters" : "No users yet"} />}
          toolbar={
            <>
              <div className="relative w-full max-w-xs">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input aria-label="Search users" placeholder="Search by name or email" className="pl-8" value={q} onChange={(e) => setQ(e.target.value)} />
              </div>
              <Select
                aria-label="Filter by status"
                value={status}
                onChange={(e) => setSearch({ status: (e.target.value || undefined) as UserStatus | undefined })}
              >
                <option value="">All statuses</option>
                <option value="active">Active</option>
                <option value="invited">Invited</option>
                <option value="deactivated">Deactivated</option>
              </Select>
            </>
          }
        />
      </Card>

      <InviteUserDialog open={inviteOpen} onOpenChange={setInviteOpen} onCreated={(id) => setSearch({ user: id })} />
      <UserDrawer userId={search.user ?? null} onClose={() => setSearch({ user: undefined })} />
    </>
  );
}

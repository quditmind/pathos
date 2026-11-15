import { useDeferredValue, useState } from "react";
import { Search, UserPlus, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge, Card, EmptyState, Input, PageHeader, Select, Skeleton, Table, Td, Th, Alert } from "@/components/ui/primitives";
import type { UserStatus } from "@/api/types";
import { useSession } from "@/features/auth/session";
import { formatDateTime, initials } from "@/lib/utils";
import { useUsers } from "./api";
import { InviteUserDialog } from "./InviteUserDialog";
import { UserDrawer } from "./UserDrawer";

export const statusTone = { active: "success", invited: "primary", deactivated: "neutral" } as const;

export function UsersPage() {
  const { canOrgWide } = useSession();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<UserStatus | "">("");
  const deferredQ = useDeferredValue(q.trim());
  const users = useUsers(deferredQ, status);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  const rows = users.data?.pages.flatMap((p) => p.items) ?? [];
  const canManage = canOrgWide("users.manage");

  return (
    <>
      <PageHeader
        title="Users"
        description="People with access to PATHOS and the roles they hold."
        actions={
          canManage && (
            <Button onClick={() => setInviteOpen(true)}>
              <UserPlus /> Invite user
            </Button>
          )
        }
      />
      <Card>
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          <div className="relative w-full max-w-xs">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              aria-label="Search users"
              placeholder="Search by name or email"
              className="pl-8"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <Select aria-label="Filter by status" value={status} onChange={(e) => setStatus(e.target.value as UserStatus | "")}>
            <option value="">All statuses</option>
            <option value="active">Active</option>
            <option value="invited">Invited</option>
            <option value="deactivated">Deactivated</option>
          </Select>
        </div>

        {users.isError ? (
          <div className="p-4">
            <Alert>Could not load users: {users.error.message}</Alert>
          </div>
        ) : users.isPending ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 5 }, (_, i) => (
              <Skeleton key={i} className="h-9" />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <EmptyState icon={<Users />} title={q || status ? "No users match these filters" : "No users yet"} />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>User</Th>
                <Th>Status</Th>
                <Th>Last sign-in</Th>
                <Th>Added</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((u) => (
                <tr
                  key={u.id}
                  className="cursor-pointer hover:bg-surface-muted/60"
                  onClick={() => setSelected(u.id)}
                  onKeyDown={(e) => e.key === "Enter" && setSelected(u.id)}
                  tabIndex={0}
                >
                  <Td>
                    <div className="flex items-center gap-2.5">
                      <span className="flex size-7 shrink-0 items-center justify-center rounded-full bg-primary/10 text-[11px] font-semibold text-primary">
                        {initials(u.display_name || u.email)}
                      </span>
                      <div className="min-w-0">
                        <div className="truncate font-medium">{u.display_name || "—"}</div>
                        <div className="truncate text-[12px] text-muted-foreground">{u.email}</div>
                      </div>
                    </div>
                  </Td>
                  <Td>
                    <Badge tone={statusTone[u.status]}>{u.status}</Badge>
                  </Td>
                  <Td className="tabular text-muted-foreground">{formatDateTime(u.last_login_at)}</Td>
                  <Td className="tabular text-muted-foreground">{formatDateTime(u.created_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        {users.hasNextPage && (
          <div className="flex justify-center p-3">
            <Button variant="secondary" onClick={() => void users.fetchNextPage()} disabled={users.isFetchingNextPage}>
              {users.isFetchingNextPage ? "Loading…" : "Load more"}
            </Button>
          </div>
        )}
      </Card>

      <InviteUserDialog open={inviteOpen} onOpenChange={setInviteOpen} onCreated={(id) => setSelected(id)} />
      <UserDrawer userId={selected} onClose={() => setSelected(null)} />
    </>
  );
}

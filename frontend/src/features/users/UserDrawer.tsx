import { useState } from "react";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { useAssignments, useGrantRole, useRequireMFA, useRevokeRole, useSetUserStatus, useUser, useUserMFA, type RoleGrant } from "./api";
import { RoleScopePicker, grantIsComplete, scopeLabels } from "./RoleScopePicker";
import { statusTone } from "./UsersPage";

export function UserDrawer({ userId, onClose }: { userId: string | null; onClose: () => void }) {
  const { me, canOrgWide, can } = useSession();
  const user = useUser(userId);
  const assignments = useAssignments(userId);
  const setStatus = useSetUserStatus();
  const grant = useGrantRole(userId ?? "");
  const revoke = useRevokeRole(userId ?? "");
  const [newGrant, setNewGrant] = useState<RoleGrant>({ role_key: "", scope_type: "organization" });
  const [confirmDeactivate, setConfirmDeactivate] = useState(false);
  const mfa = useUserMFA(userId);
  const requireMFA = useRequireMFA();

  const u = user.data;
  const isSelf = u?.id === me.user.id;
  const canManage = canOrgWide("users.manage");
  const canAssign = can("roles.assign");
  const error = setStatus.error ?? grant.error ?? revoke.error ?? requireMFA.error;

  return (
    <Dialog
      side
      open={!!userId}
      onOpenChange={(o) => {
        if (!o) {
          setConfirmDeactivate(false);
          setStatus.reset();
          grant.reset();
          revoke.reset();
          onClose();
        }
      }}
      title={u?.display_name || u?.email || "User"}
      description={u?.display_name ? u.email : undefined}
    >
      {!u ? (
        <div className="space-y-3">
          <Skeleton className="h-6 w-1/2" />
          <Skeleton className="h-24" />
        </div>
      ) : (
        <div className="space-y-6">
          {error && <Alert>{error.message}</Alert>}

          <section>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-[13px]">
              <div>
                <dt className="text-[12px] text-muted-foreground">Status</dt>
                <dd className="mt-0.5">
                  <Badge tone={statusTone[u.status]}>{u.status}</Badge>
                </dd>
              </div>
              <div>
                <dt className="text-[12px] text-muted-foreground">Last sign-in</dt>
                <dd className="tabular mt-0.5">{formatDateTime(u.last_login_at)}</dd>
              </div>
              <div>
                <dt className="text-[12px] text-muted-foreground">Added</dt>
                <dd className="tabular mt-0.5">{formatDateTime(u.created_at)}</dd>
              </div>
              <div>
                <dt className="text-[12px] text-muted-foreground">Two-factor (TOTP)</dt>
                <dd className="mt-0.5 flex flex-wrap items-center gap-2">
                  {mfa.isPending ? <span className="text-muted-foreground">…</span>
                    : mfa.isError ? <span className="text-[12px] text-muted-foreground">{mfa.error.message}</span>
                    : mfa.data?.configured ? <Badge tone="success">enabled</Badge>
                    : mfa.data?.pending ? <Badge tone="warning">enrolment at next sign-in</Badge>
                    : <Badge tone="neutral">not set up</Badge>}
                  {canManage && mfa.data && !mfa.data.configured && !mfa.data.pending && u.status !== "deactivated" && (
                    <Button size="sm" variant="secondary" disabled={requireMFA.isPending} onClick={() => requireMFA.mutate(u.id)}>Require MFA</Button>
                  )}
                </dd>
              </div>
              {u.deactivated_at && (
                <div>
                  <dt className="text-[12px] text-muted-foreground">Deactivated</dt>
                  <dd className="tabular mt-0.5">{formatDateTime(u.deactivated_at)}</dd>
                </div>
              )}
            </dl>
            {canManage && !isSelf && (
              <div className="mt-4 flex items-center gap-2">
                {u.status === "deactivated" ? (
                  <Button variant="secondary" disabled={setStatus.isPending} onClick={() => setStatus.mutate({ id: u.id, action: "reactivate" })}>
                    Reactivate user
                  </Button>
                ) : confirmDeactivate ? (
                  <>
                    <span className="text-[12px] text-muted-foreground">Signs the user out everywhere immediately.</span>
                    <Button
                      variant="danger"
                      disabled={setStatus.isPending}
                      onClick={() => setStatus.mutate({ id: u.id, action: "deactivate" }, { onSettled: () => setConfirmDeactivate(false) })}
                    >
                      Confirm deactivation
                    </Button>
                    <Button variant="ghost" onClick={() => setConfirmDeactivate(false)}>
                      Cancel
                    </Button>
                  </>
                ) : (
                  <Button variant="danger-outline" onClick={() => setConfirmDeactivate(true)}>
                    Deactivate user
                  </Button>
                )}
              </div>
            )}
          </section>

          <section>
            <h3 className="mb-2 text-[13px] font-semibold">Role assignments</h3>
            {assignments.isPending ? (
              <Skeleton className="h-16" />
            ) : assignments.data?.length ? (
              <ul className="divide-y divide-border rounded-md border border-border">
                {assignments.data.map((a) => (
                  <li key={a.id} className="flex items-center justify-between gap-3 px-3 py-2">
                    <div className="min-w-0">
                      <div className="text-[13px] font-medium">{a.role_name}</div>
                      <div className="truncate text-[12px] text-muted-foreground">
                        {a.scope_type === "organization" ? scopeLabels.organization : `${scopeLabels[a.scope_type]}: ${a.scope_name || a.scope_id}`}
                      </div>
                    </div>
                    {canAssign && (
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={`Remove ${a.role_name}`}
                        disabled={revoke.isPending}
                        onClick={() => revoke.mutate(a.id)}
                      >
                        <Trash2 />
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-[13px] text-muted-foreground">No roles. This user can sign in but cannot see any data.</p>
            )}
          </section>

          {canAssign && u.status !== "deactivated" && (
            <section className="rounded-md border border-border bg-surface-muted/40 p-3">
              <h3 className="mb-3 text-[13px] font-semibold">Grant a role</h3>
              <RoleScopePicker idPrefix="grant" value={newGrant} onChange={setNewGrant} />
              <div className="mt-3 flex justify-end">
                <Button
                  disabled={!grantIsComplete(newGrant) || grant.isPending}
                  onClick={() =>
                    grant.mutate(newGrant, { onSuccess: () => setNewGrant({ role_key: "", scope_type: "organization" }) })
                  }
                >
                  Grant role
                </Button>
              </div>
            </section>
          )}
        </div>
      )}
    </Dialog>
  );
}

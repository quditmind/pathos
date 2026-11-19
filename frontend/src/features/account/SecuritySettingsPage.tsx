import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, LogOut, ShieldCheck } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, PageHeader, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import type { MFAStatus } from "@/features/users/api";
import { ErrorPanel } from "@/components/ui/error-panel";

/** The signed-in user's own sign-in security: two-factor status and recovery codes. */
export function SecuritySettingsPage() {
  const qc = useQueryClient();
  const { logout } = useSession();
  const st = useQuery({ queryKey: ["my-mfa"], queryFn: () => api<MFAStatus>("/api/v1/me/mfa"), retry: false });
  const codes = useMutation({
    mutationFn: () => api<{ changed: boolean; mfa: MFAStatus }>("/api/v1/me/recovery-codes", { method: "POST" }),
    onSuccess: (r) => qc.setQueryData(["my-mfa"], r.mfa),
  });
  const m = st.data;
  return (
    <>
      <PageHeader title="Sign-in security" description="Your two-factor authentication and recovery codes. Sign-in itself is handled by the PATHOS identity provider (Keycloak)." />
      <Card className="max-w-2xl p-4 text-[13px]">
        {st.isError ? <ErrorPanel error={st.error} /> : st.isPending ? <Skeleton className="h-24" /> : (
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-muted-foreground" aria-hidden />
              <span className="font-medium">Authenticator app (TOTP)</span>
              {m!.configured ? <Badge tone="success">enabled</Badge> : m!.pending ? <Badge tone="warning">set up at next sign-in</Badge> : <Badge>not set up</Badge>}
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <KeyRound className="size-4 text-muted-foreground" aria-hidden />
                <span className="font-medium">Recovery codes</span>
                {m!.recovery_pending ? <Badge tone="warning">shown at next sign-in</Badge> : m!.recovery_codes ? <Badge tone="success">set up</Badge> : <Badge>not set up</Badge>}
              </div>
              <p className="text-muted-foreground">
                One-time codes to sign in if you lose your authenticator. Keep them somewhere safe, such as a password manager. Each code works once;
                generating new codes replaces the old ones.
              </p>
              {m!.recovery_pending ? (
                <Alert tone="warning">
                  Sign out and sign in again: your new codes are shown once, right after you sign in.
                  <div className="mt-2"><Button size="sm" variant="secondary" onClick={() => void logout()}><LogOut /> Sign out now</Button></div>
                </Alert>
              ) : (
                <Button onClick={() => codes.mutate()} disabled={codes.isPending}>
                  <KeyRound /> {m!.recovery_codes ? "Generate new recovery codes" : "Set up recovery codes"}
                </Button>
              )}
              {codes.error && <ErrorPanel error={codes.error} />}
            </div>
          </div>
        )}
      </Card>
    </>
  );
}

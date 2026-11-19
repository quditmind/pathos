import { Alert, Spinner } from "@/components/ui/primitives";
import { Button } from "@/components/ui/button";
import { switchOrganization, useMyOrganizations } from "./api";

/**
 * Shown when the session's organization is suspended: the person can
 * switch to another organization they belong to, or sign out.
 */
export function SuspendedOrganization() {
  const orgs = useMyOrganizations();
  const others = (orgs.data?.items ?? []).filter((m) => m.status === "active" && m.organization_id !== orgs.data?.active_organization_id);
  return (
    <div className="mx-auto mt-20 max-w-md space-y-4 px-4">
      <Alert tone="warning">This organization is suspended. Contact your installation administrator.</Alert>
      {orgs.isPending && <Spinner className="size-5" />}
      {others.length > 0 && (
        <div className="space-y-2">
          <p className="text-[13px] text-muted-foreground">Continue in another organization:</p>
          {others.map((m) => (
            <Button key={m.organization_id} variant="secondary" className="w-full justify-start" onClick={() => void switchOrganization(m.organization_id)}>
              {m.name}
            </Button>
          ))}
        </div>
      )}
      <a className="text-[13px] underline" href="/login">
        Back to sign-in
      </a>
    </div>
  );
}

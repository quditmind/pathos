import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Input, Label } from "@/components/ui/primitives";
import { useInviteUser, type RoleGrant } from "./api";
import { RoleScopePicker, grantIsComplete } from "./RoleScopePicker";

const emptyGrant: RoleGrant = { role_key: "viewer", scope_type: "organization" };

export function InviteUserDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onCreated: (userId: string) => void;
}) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [grant, setGrant] = useState<RoleGrant>(emptyGrant);
  const invite = useInviteUser();
  const [notice, setNotice] = useState<string | null>(null);

  const reset = () => {
    setEmail("");
    setName("");
    setGrant(emptyGrant);
    invite.reset();
    setNotice(null);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const res = await invite.mutateAsync({
      email: email.trim(),
      display_name: name.trim(),
      roles: grantIsComplete(grant) ? [grant] : [],
    });
    if (res.provisioning.status === "failed" || res.provisioning.message?.includes("could not")) {
      setNotice(`User created in PATHOS. ${res.provisioning.message ?? ""}`);
      return;
    }
    reset();
    onOpenChange(false);
    onCreated(res.user.id);
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) reset();
        onOpenChange(o);
      }}
      title="Invite user"
      description="Creates the PATHOS user and a Keycloak account. The user receives an email to set a password."
      footer={
        notice ? (
          <Button onClick={() => { reset(); onOpenChange(false); }}>Close</Button>
        ) : (
          <>
            <Button variant="secondary" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" form="invite-form" disabled={invite.isPending || !email.trim()}>
              {invite.isPending ? "Inviting…" : "Send invitation"}
            </Button>
          </>
        )
      }
    >
      {notice ? (
        <Alert tone="warning">{notice}</Alert>
      ) : (
        <form id="invite-form" onSubmit={(e) => void submit(e).catch(() => {})} className="space-y-4">
          {invite.isError && <Alert>{invite.error.message}</Alert>}
          <div>
            <Label htmlFor="invite-email">Email</Label>
            <Input id="invite-email" type="email" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="invite-name" hint="(optional)">
              Display name
            </Label>
            <Input id="invite-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={200} />
          </div>
          <div>
            <div className="mb-2 text-[12px] font-medium">Initial role</div>
            <RoleScopePicker idPrefix="invite" value={grant} onChange={setGrant} />
            <p className="mt-2 text-[12px] text-muted-foreground">
              You can only grant roles whose permissions you hold yourself at the chosen scope.
            </p>
          </div>
        </form>
      )}
    </Dialog>
  );
}

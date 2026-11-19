import { useState } from "react";
import { Link2, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Combobox, type ComboOption } from "@/components/ui/combobox";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Alert, Card, EmptyState, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { directoryUsers } from "@/features/assets/api";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { useIdentities, useIdentityMutations, useInsightSettings, useSetAttribution } from "./api";
import { ErrorPanel } from "@/components/ui/error-panel";

/** Administration → Developer attribution: the privacy switch and git author links. */
export function AttributionSettingsPage() {
  const { canOrgWide } = useSession();
  const allowed = canOrgWide("settings.manage") || canOrgWide("users.manage") || canOrgWide("insights.people");
  const settings = useInsightSettings(allowed);
  const setAttribution = useSetAttribution();
  const [confirmOff, setConfirmOff] = useState(false);
  const s = settings.data;

  return (
    <>
      <PageHeader title="Developer attribution" description="Opt-in attribution of findings to the git authors who introduced and fixed them." />
      {!allowed ? (
        <Alert tone="warning">You need settings.manage, users.manage or insights.people at organization scope.</Alert>
      ) : settings.isError ? (
        <ErrorPanel error={settings.error} title="Could not load the settings" />
      ) : !s ? (
        <Skeleton className="h-40" />
      ) : (
        <div className="space-y-4">
          <Card className="space-y-3 p-4 text-[13px]">
            <h2 className="text-[14px] font-semibold">Privacy switch</h2>
            <p>
              Attribution is <strong>{s.attribution_enabled ? "on" : "off"}</strong>
              {s.updated_at ? ` (changed ${formatDateTime(s.updated_at)})` : " (default)"}.
            </p>
            <ul className="list-disc space-y-1 pl-5 text-[12.5px] text-muted-foreground">
              <li>It is off by default: data about people needs a deliberate decision and, in many places, an information duty towards employees.</li>
              <li>While it is on, workers send the commit author <em>names</em> of the commits between two scans; PATHOS never stores author e-mail addresses.</li>
              <li>Results are visible only to users with the organization-wide insights.people permission.</li>
              <li>Turning it off erases every stored author name, attribution and identity link immediately.</li>
            </ul>
            {setAttribution.error && <ErrorPanel error={setAttribution.error} />}
            {s.can_manage ? (
              s.attribution_enabled ? (
                <Button variant="danger-outline" onClick={() => setConfirmOff(true)}>Turn off and erase attribution data</Button>
              ) : (
                <Button disabled={setAttribution.isPending} onClick={() => setAttribution.mutate(true)}>Turn on developer attribution</Button>
              )
            ) : (
              <p className="text-[12.5px] text-muted-foreground">Only users with settings.manage can change this.</p>
            )}
          </Card>
          {s.attribution_enabled && s.can_link_identities && <IdentityLinks />}
          {s.attribution_enabled && !s.can_link_identities && (
            <Alert tone="warning">Linking git author names to users needs the users.manage permission.</Alert>
          )}
        </div>
      )}
      <ConfirmDialog
        open={confirmOff}
        onOpenChange={setConfirmOff}
        title="Turn off developer attribution?"
        confirmLabel="Turn off and erase"
        pending={setAttribution.isPending}
        error={setAttribution.error?.message}
        onConfirm={() => setAttribution.mutate(false, { onSuccess: () => setConfirmOff(false) })}
      >
        All stored author names, finding attributions and identity links are deleted. This cannot be undone; attribution restarts from the next
        scans if you turn it on again.
      </ConfirmDialog>
    </>
  );
}

function IdentityLinks() {
  const q = useIdentities();
  const { link, unlink } = useIdentityMutations();
  const [author, setAuthor] = useState("");
  const [user, setUser] = useState<ComboOption | null>(null);
  const loadUsers = (term: string, signal?: AbortSignal) =>
    directoryUsers(term, signal).then((us) => us.map((u) => ({ value: u.id, label: u.name || u.email, description: u.email })));

  return (
    <Card className="space-y-3 p-4 text-[13px]">
      <h2 className="text-[14px] font-semibold">Git authors and PATHOS users</h2>
      <p className="text-[12.5px] text-muted-foreground">
        Link a git author name to a PATHOS user to group attribution per user and team. Names are matched case-insensitively. Nothing is linked
        automatically.
      </p>
      {q.isError ? (
        <ErrorPanel error={q.error} title="Could not load identities" />
      ) : !q.data ? (
        <Skeleton className="h-24" />
      ) : (
        <>
          <form
            className="grid gap-3 md:grid-cols-[1fr_1fr_auto] md:items-end"
            onSubmit={(e) => {
              e.preventDefault();
              if (!author || !user) return;
              link.mutate({ author_name: author, user_id: user.value }, { onSuccess: () => { setAuthor(""); setUser(null); } });
            }}
          >
            <div>
              <Label htmlFor="ident-author">Git author name</Label>
              <Select id="ident-author" value={author} onChange={(e) => setAuthor(e.target.value)}>
                <option value="">{q.data.unlinked_authors.length ? "Choose an author seen in scans…" : "No unlinked authors seen yet"}</option>
                {q.data.unlinked_authors.map((a) => (
                  <option key={a} value={a}>{a}</option>
                ))}
              </Select>
            </div>
            <div>
              <Label htmlFor="ident-user">PATHOS user</Label>
              <Combobox id="ident-user" value={user} onChange={setUser} load={loadUsers} queryKey="ident-users" placeholder="Search users…" />
            </div>
            <Button type="submit" disabled={!author || !user || link.isPending}>
              <Link2 /> Link
            </Button>
          </form>
          {(link.error ?? unlink.error) && <Alert>{(link.error ?? unlink.error)!.message}</Alert>}
          {q.data.items.length === 0 ? (
            <EmptyState title="No links yet" />
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Git author name</Th>
                  <Th>PATHOS user</Th>
                  <Th>Linked</Th>
                  <Th><span className="sr-only">Actions</span></Th>
                </tr>
              </thead>
              <tbody>
                {q.data.items.map((i) => (
                  <tr key={i.id}>
                    <Td className="font-medium">{i.author_name}</Td>
                    <Td>{i.user_name}</Td>
                    <Td className="text-[12px] text-muted-foreground">{formatDateTime(i.created_at)}</Td>
                    <Td className="text-right">
                      <Button variant="ghost" size="sm" aria-label={`Unlink ${i.author_name}`} disabled={unlink.isPending} onClick={() => unlink.mutate(i.id)}>
                        <Trash2 /> Unlink
                      </Button>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </>
      )}
    </Card>
  );
}

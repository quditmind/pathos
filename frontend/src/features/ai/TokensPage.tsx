import { useState, type FormEvent } from "react";
import { Copy, KeyRound, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import type { ApiToken } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { useAIMutation, useTokens } from "./api";

export function TokensPage() {
  const tokens = useTokens();
  const [name, setName] = useState("");
  const [days, setDays] = useState("30");
  const [created, setCreated] = useState<{ secret: string; url: string } | null>(null);
  const create = useAIMutation((body: unknown) => api<{ secret: string; mcp_url: string; token: ApiToken }>("/api/v1/me/tokens", { method: "POST", body }));
  const revoke = useAIMutation((id: string) => api(`/api/v1/me/tokens/${id}`, { method: "DELETE" }));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate({ name: name.trim(), days: Number(days) }, { onSuccess: (r) => { setCreated({ secret: r.secret, url: r.mcp_url }); setName(""); } });
  };
  const now = Date.now();
  const command = created ? `claude mcp add --transport http pathos ${created.url} --header "Authorization: Bearer ${created.secret}"` : "";

  return (
    <>
      <PageHeader title="API tokens" description="Personal tokens for the PATHOS MCP server: review findings interactively from your own AI assistant (for example Claude Code with your own subscription). Tokens act with your current permissions." />
      <Card className="mb-4 p-4">
        <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
          {create.isError && <div className="w-full"><Alert>{create.error.message}</Alert></div>}
          <div><Label htmlFor="t-name">Name</Label><Input id="t-name" required maxLength={100} placeholder="Claude Code on laptop" value={name} onChange={(e) => setName(e.target.value)} className="w-64" /></div>
          <div><Label htmlFor="t-days">Expires in</Label>
            <Select id="t-days" value={days} onChange={(e) => setDays(e.target.value)}>{["7", "30", "90"].map((d) => <option key={d} value={d}>{d} days</option>)}</Select></div>
          <Button type="submit" disabled={create.isPending || !name.trim()}><KeyRound /> Create token</Button>
        </form>
      </Card>
      <Card>
        {tokens.isPending ? <Skeleton className="m-4 h-16" /> : !tokens.data?.items.length ? <EmptyState icon={<KeyRound />} title="No tokens" /> : (
          <Table>
            <thead><tr><Th>Name</Th><Th>Token</Th><Th>Status</Th><Th>Last used</Th><Th>Expires</Th><Th /></tr></thead>
            <tbody>
              {tokens.data.items.map((t) => {
                const expired = new Date(t.expires_at).getTime() < now;
                return (
                  <tr key={t.id}>
                    <Td className="font-medium">{t.name}</Td>
                    <Td className="font-mono text-[12px]">{t.prefix}…</Td>
                    <Td>{t.revoked_at ? <Badge>revoked</Badge> : expired ? <Badge tone="warning">expired</Badge> : <Badge tone="success">active</Badge>}</Td>
                    <Td className="tabular text-[12px] text-muted-foreground">{formatDateTime(t.last_used_at)}</Td>
                    <Td className="tabular text-[12px] text-muted-foreground">{formatDateTime(t.expires_at)}</Td>
                    <Td>{!t.revoked_at && !expired && <Button size="icon" variant="ghost" aria-label={`Revoke ${t.name}`} onClick={() => revoke.mutate(t.id)}><Trash2 /></Button>}</Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Card>
      <Dialog open={!!created} onOpenChange={(o) => !o && setCreated(null)} title="Token created" description="Copy it now: it is not shown again."
        footer={<Button onClick={() => setCreated(null)}>Done</Button>}>
        {created && (
          <div className="space-y-3 text-[13px]">
            <div className="flex gap-2"><Input readOnly value={created.secret} className="font-mono text-[12px]" onFocus={(e) => e.target.select()} />
              <Button variant="secondary" size="icon" aria-label="Copy token" onClick={() => void navigator.clipboard?.writeText(created.secret)}><Copy /></Button></div>
            <p className="text-muted-foreground">Add PATHOS to Claude Code:</p>
            <pre className="overflow-x-auto rounded-md bg-surface-muted p-2 text-[11.5px]">{command}</pre>
            <p className="text-[12px] text-muted-foreground">Then ask, for example: “List my pending high-severity findings in PATHOS and review them.” Your reviews are attributed to you and follow the approval policy.</p>
            <p className="text-[12px] text-muted-foreground">
              Works with a Claude Pro or Max plan: Claude Code does the review on your subscription; PATHOS only stores the result.
              If PATHOS uses its own local certificate (the default <code>https://localhost</code> install), start Claude Code with
              <code className="mx-1">NODE_EXTRA_CA_CERTS=pathos-local-ca.crt claude</code> after exporting the CA with
              <code className="mx-1">docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt pathos-local-ca.crt</code>.
            </p>
          </div>
        )}
      </Dialog>
    </>
  );
}

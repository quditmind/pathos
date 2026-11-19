import { useState, type FormEvent } from "react";
import { Link } from "@tanstack/react-router";
import { PackageSearch, Search } from "lucide-react";
import { api } from "@/api/client";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Badge, Card, EmptyState, Input, Label, PageHeader, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import type { Portfolio } from "./api";
import { ErrorPanel } from "@/components/ui/error-panel";

type Query = { name: string; version: string; purl: string; cve: string };

/**
 * Portfolio: which application versions (releases) and which repositories
 * today contain a component or a vulnerability.
 */
export function PortfolioPage() {
  const [form, setForm] = useState<Query>({ name: "", version: "", purl: "", cve: "" });
  const [q, setQ] = useState<Query | null>(null);
  const res = useQuery({
    queryKey: ["portfolio", q],
    enabled: !!q,
    queryFn: () => {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(q!)) if (v.trim()) p.set(k, v.trim());
      return api<Portfolio>(`/api/v1/portfolio/component-versions?${p}`);
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setQ({ ...form });
  };
  const empty = !form.name.trim() && !form.purl.trim() && !form.cve.trim();
  return (
    <>
      <PageHeader title="Component portfolio" description="Find which released application versions, and which repositories today, contain a component or a vulnerability." />
      <Card className="mb-4">
        <form onSubmit={submit} className="grid gap-3 sm:grid-cols-5 sm:items-end">
          <div><Label htmlFor="pf-name">Component name</Label><Input id="pf-name" placeholder="log4j-core" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
          <div><Label htmlFor="pf-ver" hint="Optional">Version</Label><Input id="pf-ver" placeholder="2.14.1" value={form.version} onChange={(e) => setForm({ ...form, version: e.target.value })} /></div>
          <div><Label htmlFor="pf-purl">Package URL</Label><Input id="pf-purl" placeholder="pkg:maven/org.apache.logging.log4j/log4j-core" value={form.purl} onChange={(e) => setForm({ ...form, purl: e.target.value })} /></div>
          <div><Label htmlFor="pf-cve">Vulnerability</Label><Input id="pf-cve" placeholder="CVE-2021-44228" value={form.cve} onChange={(e) => setForm({ ...form, cve: e.target.value })} /></div>
          <Button type="submit" disabled={empty}><Search /> Search</Button>
        </form>
      </Card>
      {!q ? (
        <Card><EmptyState icon={<PackageSearch />} title="Search the portfolio">Enter a component name, a package URL or a CVE.</EmptyState></Card>
      ) : res.isError ? <ErrorPanel error={res.error} /> : res.isPending ? <Skeleton className="h-32" /> : (
        <div className="space-y-4">
          <Card>
            <h2 className="mb-2 text-[14px] font-semibold">Application versions ({res.data.versions.length})</h2>
            {!res.data.versions.length ? <p className="text-[13px] text-muted-foreground">No released version contains it.</p> : (
              <Table>
                <thead><tr><Th>Application</Th><Th>Version</Th><Th>Repository</Th><Th>Component</Th><Th>Matched by</Th></tr></thead>
                <tbody>
                  {res.data.versions.map((v, i) => (
                    <tr key={`${v.version_id}-${v.repository}-${v.component}-${v.component_version}-${i}`}>
                      <Td><Link to="/applications/$id/versions" params={{ id: v.application_id }} className="text-primary hover:underline">{v.application_name}</Link></Td>
                      <Td className="font-mono text-[12px]">{v.version}</Td>
                      <Td className="text-[12.5px]">{v.repository}</Td>
                      <Td className="font-mono text-[12px]">{v.component}{v.component_version && `@${v.component_version}`}</Td>
                      <Td><Badge>{v.matched_by}</Badge></Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
          <Card>
            <h2 className="mb-2 text-[14px] font-semibold">Repositories today ({res.data.repositories.length})</h2>
            {!res.data.repositories.length ? <p className="text-[13px] text-muted-foreground">No current inventory contains it.</p> : (
              <Table>
                <thead><tr><Th>Repository</Th><Th>Component</Th><Th>Matched by</Th></tr></thead>
                <tbody>
                  {res.data.repositories.map((r, i) => (
                    <tr key={`${r.repository_id}-${r.component}-${r.component_version}-${i}`}>
                      <Td className="text-[12.5px]">{r.repository}</Td>
                      <Td className="font-mono text-[12px]">{r.component}{r.component_version && `@${r.component_version}`}</Td>
                      <Td><Badge>{r.matched_by}</Badge></Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        </div>
      )}
    </>
  );
}

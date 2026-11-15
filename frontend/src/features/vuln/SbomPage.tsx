import { useDeferredValue, useState } from "react";
import { Link } from "@tanstack/react-router";
import { Package, Search } from "lucide-react";
import type { ComponentGroup } from "@/api/types";
import { Badge, Card, EmptyState, Input, PageHeader, Select } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { useRepositories } from "@/features/repos/api";
import { useComponents } from "./api";

const columns: Column<ComponentGroup>[] = [
  { id: "name", header: "Component", required: true, cell: (c) => <div><div className="font-medium">{c.name}</div><div className="max-w-md truncate font-mono text-[11px] text-muted-foreground">{c.purl}</div></div>, csv: (c) => c.name },
  { id: "version", header: "Version", cell: (c) => <span className="font-mono text-[12px]">{c.version || "—"}</span>, csv: (c) => c.version },
  { id: "type", header: "Type", cell: (c) => <span className="text-[12px]">{c.type}</span>, csv: (c) => c.type },
  {
    id: "licenses", header: "Licenses",
    cell: (c) => <span className="flex flex-wrap items-center gap-1">{c.licenses.length ? c.licenses.map((l) => <span key={l} className="font-mono text-[11.5px]">{l}</span>) : <span className="text-muted-foreground">unknown</span>}
      {c.license_policy && <Badge tone={c.license_policy === "deny" ? "danger" : "warning"}>{c.license_policy === "deny" ? "denied" : "review"}</Badge>}</span>,
    csv: (c) => c.licenses.join(";"),
  },
  {
    id: "vulns", header: "Open vulns", className: "tabular",
    cell: (c) => c.open_vulnerabilities ? <Link to="/findings" search={{ q: c.name, category: "sca" } as never} className="font-medium text-danger hover:underline">{c.open_vulnerabilities}</Link> : <span className="text-muted-foreground">0</span>,
    csv: (c) => c.open_vulnerabilities,
  },
  { id: "repos", header: "Used in", cell: (c) => <span className="text-[12px]" title={c.repositories.join("\n")}>{c.repositories.length === 1 ? c.repositories[0] : `${c.repositories.length} repositories`}</span>, csv: (c) => c.repositories.join(";") },
];

export function SbomPage() {
  const [q, setQ] = useState("");
  const dq = useDeferredValue(q.trim());
  const [repo, setRepo] = useState("");
  const [license, setLicense] = useState("");
  const comps = useComponents({ q: dq || undefined, repository_id: repo || undefined, license: license || undefined });
  const repos = useRepositories({});
  return (
    <>
      <PageHeader title="SBOM inventory" description="Components from the latest Syft SBOM of each repository, with license policy and open vulnerabilities. Download a repository's CycloneDX SBOM from its detail panel." />
      <Card>
        <DataTable tableId="sbom" exportName="pathos-sbom-components" columns={columns} rows={comps.data ?? []} rowKey={(c) => `${c.name}@${c.version}`}
          isPending={comps.isPending} error={comps.error}
          empty={<EmptyState icon={<Package />} title="No components">SBOMs are generated when a scan profile has SBOM enabled.</EmptyState>}
          toolbar={<>
            <div className="relative w-full max-w-xs">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input aria-label="Search components" placeholder="Name or purl (e.g. log4j)" className="pl-8" value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
            <Select aria-label="Repository" value={repo} onChange={(e) => setRepo(e.target.value)}>
              <option value="">All repositories</option>
              {(repos.data?.pages.flatMap((p) => p.items) ?? []).map((r) => <option key={r.id} value={r.id}>{r.full_name}</option>)}
            </Select>
            <Select aria-label="License policy" value={license} onChange={(e) => setLicense(e.target.value)}>
              <option value="">Any license</option><option value="violations">Policy matches</option><option value="deny">Denied</option><option value="review">Needs review</option>
            </Select>
          </>} />
      </Card>
    </>
  );
}

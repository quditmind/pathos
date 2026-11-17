import { useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Crosshair, Search } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, EmptyState, Input, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { KevBadge, RiskBadge } from "@/features/vuln/intel";
import { type BlastRadius, relationLabel } from "./api";
import { GraphLink } from "./shared";

type BlastSearch = { cve?: string; package?: string; version?: string };
export const validateBlastSearch = (s: Record<string, unknown>): BlastSearch => {
  const out: BlastSearch = {};
  for (const k of ["cve", "package", "version"] as const) if (typeof s[k] === "string" && s[k]) out[k] = s[k] as string;
  return out;
};

export function BlastRadiusPage() {
  const search = useSearch({ strict: false }) as BlastSearch;
  const navigate = useNavigate();
  const [mode, setMode] = useState<"cve" | "package">(search.package ? "package" : "cve");
  const [term, setTerm] = useState(search.cve ?? search.package ?? "");
  const [version, setVersion] = useState(search.version ?? "");
  const active = search.cve || search.package;
  const params = new URLSearchParams();
  if (search.cve) params.set("cve", search.cve);
  if (search.package) params.set("package", search.package);
  if (search.version) params.set("version", search.version);
  const q = useQuery({
    queryKey: ["posture", "blast", search.cve, search.package, search.version],
    queryFn: () => api<BlastRadius>(`/api/v1/posture/blast-radius?${params}`),
    enabled: !!active,
  });
  const submit = () => {
    const t = term.trim();
    if (!t) return;
    void navigate({ to: "/posture/blast-radius", search: (mode === "cve" ? { cve: t.toUpperCase() } : { package: t, version: version.trim() || undefined }) as never });
  };
  return (
    <>
      <PageHeader
        title="Blast radius"
        description="Which repositories, applications, owners and business units a vulnerability or a package affects, whether it is a direct or transitive dependency, and whether the asset is exposed to the internet."
      />
      <Card className="mb-3 p-3">
        <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); submit(); }}>
          <Select aria-label="Search by" value={mode} onChange={(e) => setMode(e.target.value as "cve" | "package")}>
            <option value="cve">Vulnerability (CVE or GHSA)</option>
            <option value="package">Package</option>
          </Select>
          <Input aria-label={mode === "cve" ? "CVE or GHSA identifier" : "Package name"} value={term} onChange={(e) => setTerm(e.target.value)}
            placeholder={mode === "cve" ? "CVE-2021-44228" : "log4j-core"} className="w-64 font-mono text-[12px]" />
          {mode === "package" && (
            <Input aria-label="Version (optional)" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="version (any)" className="w-36 font-mono text-[12px]" />
          )}
          <Button type="submit" disabled={!term.trim()}><Search /> Analyse</Button>
        </form>
      </Card>
      {!active ? (
        <Card><EmptyState icon={<Crosshair />} title="Search for a vulnerability or a package" /></Card>
      ) : q.isError ? (
        <Alert>{q.error.message}</Alert>
      ) : q.isPending ? (
        <Skeleton className="h-40" />
      ) : (
        <>
          <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {(
              [
                ["repositories", "Repositories"],
                ["applications", "Applications"],
                ["business_units", "Business units"],
                ["internet_exposed", "Internet-exposed"],
              ] as const
            ).map(([k, l]) => (
              <Card key={k} className="p-3">
                <div className="text-[11.5px] text-muted-foreground">{l}</div>
                <div className="tabular text-lg font-semibold">{q.data.summary[k]}</div>
              </Card>
            ))}
          </div>
          <Card>
            {!q.data.items.length ? (
              <EmptyState icon={<Crosshair />} title="Nothing affected in your scope">No open finding and no component in the latest SBOMs matches.</EmptyState>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Repository</Th>
                    <Th>Application</Th>
                    <Th>Ownership</Th>
                    <Th>Exposure</Th>
                    <Th>Dependency</Th>
                    <Th>Packages</Th>
                    <Th>Open findings</Th>
                    <Th>Risk</Th>
                  </tr>
                </thead>
                <tbody>
                  {q.data.items.map((a) => (
                    <tr key={a.repository_id}>
                      <Td>
                        <GraphLink node={`repository:${a.repository_id}`}>{a.repository_name}</GraphLink>
                        <div className="text-[11px] text-muted-foreground"><span className="font-mono">{a.repository_key}</span> · <span className="capitalize">{a.criticality}</span></div>
                      </Td>
                      <Td className="text-[12px]">{a.application_id ? <GraphLink node={`application:${a.application_id}`}>{a.application_name}</GraphLink> : <span className="text-muted-foreground">—</span>}</Td>
                      <Td className="text-[12px]">
                        {[a.owner, a.team, a.business_unit].filter(Boolean).join(" · ") || <span className="text-muted-foreground">none</span>}
                      </Td>
                      <Td>{a.public_exposure === "yes" ? <Badge tone="danger">Internet</Badge> : <span className="text-[12px] capitalize text-muted-foreground">{a.public_exposure}</span>}</Td>
                      <Td className="text-[12px]">
                        {relationLabel[a.relation]}
                        {a.targets.length > 0 && <div className="text-[11px] text-muted-foreground">in {a.targets.join(", ")}</div>}
                      </Td>
                      <Td className="max-w-56 font-mono text-[11.5px]">{a.packages.join(", ") || "—"}</Td>
                      <Td className="text-[12px]">
                        {a.open_findings ? (
                          <Link to="/findings" search={{ repository_id: a.repository_id, q: q.data.query.cve || q.data.query.package } as never} className="text-primary hover:underline">{a.open_findings}</Link>
                        ) : "0"}
                      </Td>
                      <Td><span className="flex items-center gap-1"><RiskBadge score={a.max_risk} />{a.kev && <KevBadge />}</span></Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        </>
      )}
    </>
  );
}

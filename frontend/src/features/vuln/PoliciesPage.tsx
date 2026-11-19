import { useEffect, useState } from "react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Alert, Card, Input, Label, PageHeader, Skeleton } from "@/components/ui/primitives";
import { SeverityBadge } from "@/components/data/Severity";
import type { Severity } from "@/api/types";
import { useLicensePolicy, useSLA, useVulnMutation } from "./api";
import { SecurityPolicies } from "@/features/policies/SecurityPolicies";
import { ErrorPanel } from "@/components/ui/error-panel";

const sevs: Severity[] = ["critical", "high", "medium", "low", "info"];

export function PoliciesPage() {
  const sla = useSLA();
  const lic = useLicensePolicy();
  const [days, setDays] = useState<Record<string, string>>({});
  const [licText, setLicText] = useState("");
  useEffect(() => { if (sla.data) setDays(Object.fromEntries(sevs.map((s) => [s, sla.data[s] ? String(sla.data[s]) : ""]))); }, [sla.data]);
  useEffect(() => { if (lic.data) setLicText(lic.data.map((l) => `${l.spdx_id} ${l.decision}`).join("\n")); }, [lic.data]);
  const saveSLA = useVulnMutation((body: unknown) => api("/api/v1/sla-policies", { method: "PUT", body }));
  const saveLic = useVulnMutation((body: unknown) => api("/api/v1/license-policies", { method: "PUT", body }));

  return (
    <>
      <PageHeader title="Policies" description="Remediation SLAs, the license policy applied to SBOM components, and security policies on findings." />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-4">
          <h2 className="mb-1 text-[13px] font-semibold">Remediation SLAs</h2>
          <p className="mb-3 text-[12px] text-muted-foreground">Days from first detection. Leave empty for no SLA. Changes recompute deadlines of existing findings.</p>
          {saveSLA.isError && <ErrorPanel error={saveSLA.error} />}
          {saveSLA.isSuccess && <Alert tone="success">Saved.</Alert>}
          {!sla.data ? <Skeleton className="h-40" /> : (
            <div className="space-y-2">
              {sevs.map((s) => (
                <div key={s} className="flex items-center gap-3">
                  <div className="w-24"><SeverityBadge value={s} /></div>
                  <Input aria-label={`${s} SLA days`} type="number" min={1} max={3650} className="w-28" value={days[s] ?? ""} onChange={(e) => setDays({ ...days, [s]: e.target.value })} />
                  <span className="text-[12px] text-muted-foreground">days</span>
                </div>
              ))}
              <Button className="mt-2" disabled={saveSLA.isPending}
                onClick={() => saveSLA.mutate(Object.fromEntries(sevs.map((s) => [s, days[s] ? Number(days[s]) : null])))}>Save SLAs</Button>
            </div>
          )}
        </Card>
        <Card className="p-4">
          <h2 className="mb-1 text-[13px] font-semibold">License policy</h2>
          <p className="mb-3 text-[12px] text-muted-foreground">One SPDX identifier per line followed by <code>deny</code> or <code>review</code>. Components with a denied license count as violations.</p>
          {saveLic.isError && <ErrorPanel error={saveLic.error} />}
          {saveLic.isSuccess && <Alert tone="success">Saved.</Alert>}
          <Label htmlFor="lic">Rules</Label>
          <textarea id="lic" rows={12} value={licText} onChange={(e) => setLicText(e.target.value)} className="w-full rounded-md border border-border bg-surface p-2 font-mono text-[12px] focus-visible:outline-2 focus-visible:outline-ring" />
          <Button className="mt-2" disabled={saveLic.isPending} onClick={() => saveLic.mutate({
            items: licText.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => { const [spdx_id, decision] = l.split(/\s+/); return { spdx_id, decision: decision === "deny" ? "deny" : "review" }; }),
          })}>Save license policy</Button>
        </Card>
      </div>
      <SecurityPolicies />
    </>
  );
}

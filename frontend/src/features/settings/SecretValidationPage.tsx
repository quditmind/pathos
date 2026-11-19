import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { SecretValidationSettings } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Card, Input, Label, PageHeader, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";

const path = "/api/v1/settings/secret-validation";

/**
 * Administration → Secret validation: which providers workers may ask
 * whether a detected credential is still active. Off by default; each
 * provider's host must also be on the egress allowlist.
 */
export function SecretValidationPage() {
  const { canOrgWide } = useSession();
  const allowed = canOrgWide("settings.manage");
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["secret-validation-settings"], queryFn: () => api<SecretValidationSettings>(path), enabled: allowed });
  const [enabled, setEnabled] = useState<string[]>([]);
  const [rate, setRate] = useState("1");
  const [max, setMax] = useState("50");
  useEffect(() => {
    if (!q.data) return;
    setEnabled(q.data.providers.filter((p) => p.enabled).map((p) => p.id));
    setRate(String(q.data.rate_per_second));
    setMax(String(q.data.max_checks_per_scan));
  }, [q.data]);
  const save = useMutation({
    mutationFn: () => api<SecretValidationSettings>(path, { method: "PUT", body: { providers: enabled, rate_per_second: Number(rate), max_checks_per_scan: Number(max) } }),
    onSuccess: (d) => qc.setQueryData(["secret-validation-settings"], d),
  });
  const s = q.data;
  const toggle = (id: string, on: boolean) => setEnabled((cur) => (on ? [...cur, id] : cur.filter((x) => x !== id)));
  const hosts = s?.providers.filter((p) => enabled.includes(p.id)).flatMap((p) => p.hosts ?? []) ?? [];

  return (
    <>
      <PageHeader title="Secret validation" description="Optional live check of detected secrets against their provider: still active, revoked, or not checked." />
      {!allowed ? (
        <Alert tone="warning">You need the settings.manage permission at organization scope.</Alert>
      ) : q.isError ? (
        <Alert>Could not load the settings: {q.error.message}</Alert>
      ) : !s ? (
        <Skeleton className="h-40" />
      ) : (
        <div className="space-y-4">
          <Card className="space-y-2 p-4 text-[13px]">
            <p>
              Live validation is <strong>{s.providers.some((p) => p.enabled) ? "on" : "off"}</strong>
              {s.updated_at ? ` (changed ${formatDateTime(s.updated_at)})` : " (default)"}.
            </p>
            <ul className="list-disc space-y-1 pl-5 text-[12.5px] text-muted-foreground">
              <li>
                After a repository scan, the worker reads each detected secret from its checkout and sends it once, through the egress proxy, to that
                provider's read-only “who am I” endpoint. Only the verdict, the HTTP status and a non-secret identity reach PATHOS.
              </li>
              <li>Active secrets become critical findings. Pull request scans, scan targets and offline installations are never validated.</li>
              <li>A provider also needs its host on the egress allowlist (deploy/egress/allowlist.txt); until then its checks fail closed with an error.</li>
              <li>Every validation batch and every change here is recorded in the audit log.</li>
            </ul>
            {s.offline && <Alert tone="warning">This installation runs offline (PATHOS_OFFLINE=true): no secret is validated.</Alert>}
          </Card>
          <Card className="p-0">
            <Table>
              <thead>
                <tr>
                  <Th>Provider</Th>
                  <Th>Request</Th>
                  <Th>Allowlist entry</Th>
                </tr>
              </thead>
              <tbody>
                {s.providers.map((p) => (
                  <tr key={p.id}>
                    <Td>
                      <label className="flex items-start gap-2">
                        <input type="checkbox" className="mt-0.5" aria-label={`Validate ${p.name}`} checked={enabled.includes(p.id)}
                          disabled={!s.can_manage || !p.checkable} onChange={(e) => toggle(p.id, e.target.checked)} />
                        <span>
                          <span className="font-medium">{p.name}</span>
                          {p.note && <span className="block text-[11.5px] text-muted-foreground">{p.note}</span>}
                        </span>
                      </label>
                    </Td>
                    <Td className="break-all font-mono text-[11.5px]">{p.checkable ? p.endpoint : "not checkable"}</Td>
                    <Td className="font-mono text-[11.5px]">{(p.hosts ?? []).join(", ") || "—"}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Card>
          <Card className="space-y-3 p-4 text-[13px]">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <Label htmlFor="sv-rate" hint="1–10; checks are spaced at this rate within a scan">Checks per second</Label>
                <Input id="sv-rate" type="number" min={1} max={10} value={rate} disabled={!s.can_manage} onChange={(e) => setRate(e.target.value)} />
              </div>
              <div>
                <Label htmlFor="sv-max" hint="1–500; further secrets are reported as not checked">Checks per scan</Label>
                <Input id="sv-max" type="number" min={1} max={500} value={max} disabled={!s.can_manage} onChange={(e) => setMax(e.target.value)} />
              </div>
            </div>
            {hosts.length > 0 && (
              <div className="text-[12.5px]">
                Make sure these lines are in <span className="font-mono">deploy/egress/allowlist.txt</span>, then restart the egress service:
                <pre className="mt-1 rounded-md border border-border bg-muted/40 p-2 font-mono text-[11.5px]">{[...new Set(hosts)].join("\n")}</pre>
                {enabled.includes("github") && <span className="text-muted-foreground">api.github.com is already covered by the default .github.com entry.</span>}
              </div>
            )}
            {save.isError && <Alert>{save.error.message}</Alert>}
            {save.isSuccess && <Alert tone="success">Saved. The next scans use these settings.</Alert>}
            {s.can_manage ? (
              <Button disabled={save.isPending} onClick={() => save.mutate()}>Save</Button>
            ) : (
              <p className="text-[12.5px] text-muted-foreground">Only users with settings.manage can change this.</p>
            )}
          </Card>
        </div>
      )}
    </>
  );
}

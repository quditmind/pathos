import { useEffect, useState } from "react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Alert, Card, Skeleton } from "@/components/ui/primitives";
import { fieldLabels, useApplicationSettings, useInventoryMutation, type ApplicationSettings } from "./api";

const groups: { title: string; fields: string[] }[] = [
  { title: "Business", fields: ["owner", "business_unit", "criticality", "security_owner", "technical_owner", "description", "external_ref"] },
  { title: "Technical", fields: ["application_type", "languages", "frameworks", "runtimes"] },
  { title: "Security", fields: ["data_classification", "internet_exposure", "compliance_scopes", "authentication_model"] },
  { title: "Geography", fields: ["hosting_region", "data_residency"] },
  { title: "Environment", fields: ["environment", "lifecycle"] },
];

/**
 * Configurations › Asset settings › Application fields (flag "onboarding"):
 * the fields an application needs before it can be saved to the inventory.
 * Drafts count them as "Onboarding: N of M fields".
 */
export function ApplicationFieldsSettings({ manage }: { manage: boolean }) {
  const s = useApplicationSettings();
  const [req, setReq] = useState<Set<string>>(new Set());
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    if (s.data) setReq(new Set(s.data.required_fields));
  }, [s.data]);
  const save = useInventoryMutation((fields: string[]) => api<ApplicationSettings>("/api/v1/application-settings", { method: "PATCH", body: { required_fields: fields } }));
  if (s.isPending) return <Skeleton className="mt-4 h-40" />;
  if (s.isError) return <div className="mt-4"><ErrorPanel error={s.error} onVerify={() => s.refetch()} /></div>;
  const dirty = [...req].sort().join() !== [...s.data.required_fields].sort().join();
  return (
    <Card className="mt-4 p-4">
      <h2 className="text-[14px] font-semibold">Application fields</h2>
      <p className="mb-3 text-[12px] text-muted-foreground">
        Fields an application needs before it is saved to the inventory. Incomplete applications stay drafts with the status “Onboarding: N of M fields”.
      </p>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        {groups.map((g) => (
          <fieldset key={g.title} disabled={!manage}>
            <legend className="mb-1 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">{g.title}</legend>
            {g.fields.map((f) => (
              <label key={f} className="flex items-center gap-2 text-[13px]">
                <input
                  type="checkbox"
                  className="accent-[var(--primary)]"
                  checked={req.has(f)}
                  onChange={(e) => {
                    const n = new Set(req);
                    if (e.target.checked) n.add(f);
                    else n.delete(f);
                    setReq(n);
                    setSaved(false);
                  }}
                />
                {fieldLabels[f] ?? f}
              </label>
            ))}
          </fieldset>
        ))}
      </div>
      {save.isError && <div className="mt-3"><ErrorPanel error={save.error} /></div>}
      {saved && !dirty && <div className="mt-3"><Alert tone="success">Application fields saved.</Alert></div>}
      {manage && (
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="secondary" disabled={!dirty || save.isPending} onClick={() => setReq(new Set(s.data.required_fields))}>
            Reset
          </Button>
          <Button disabled={!dirty || save.isPending} onClick={() => save.mutate([...req], { onSuccess: () => setSaved(true) })}>
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      )}
    </Card>
  );
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/api/client";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Badge, Card, PageHeader, Table, Td, Th } from "@/components/ui/primitives";
import { LoadingSkeleton, PermissionDenied } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useSession } from "@/features/auth/session";
import { metaQueryKey } from "@/features/shell/meta";

/** GET /api/v1/admin/feature-flags item. */
export interface FeatureFlagView {
  name: string;
  description: string;
  milestone: string;
  enabled: boolean;
  updated_at: string | null;
  updated_by: string | null;
}

const flagsKey = ["admin", "feature-flags"] as const;

/**
 * Administration › Feature flags: per-organization switches for the modules
 * of the PATHOS 3.0 roadmap (all off by default; every change is audited).
 */
export function FeatureFlagsPage() {
  const { canOrgWide } = useSession();
  const qc = useQueryClient();
  const allowed = canOrgWide("settings.manage");
  const q = useQuery({
    queryKey: flagsKey,
    queryFn: () => api<{ items: FeatureFlagView[] }>("/api/v1/admin/feature-flags").then((r) => r.items),
    enabled: allowed,
  });
  const save = useMutation({
    mutationFn: (v: { name: string; enabled: boolean }) =>
      api<{ items?: FeatureFlagView[] }>("/api/v1/admin/feature-flags", { method: "PUT", body: { flags: { [v.name]: v.enabled } } }),
    onSuccess: (_r, v) => {
      void qc.invalidateQueries({ queryKey: flagsKey });
      void qc.invalidateQueries({ queryKey: metaQueryKey });
      toast.success(`Feature flag ${v.name} turned ${v.enabled ? "on" : "off"}.`);
    },
  });

  const header = (
    <PageHeader
      title="Feature flags"
      description="Turn the modules of the PATHOS 3.0 roadmap on or off for this organization. All are off by default; every change is recorded in the audit log."
    />
  );
  if (!allowed || (q.error instanceof ApiError && q.error.status === 403)) {
    return (
      <>
        {header}
        <PermissionDenied permission="settings.manage" what="Managing feature flags" />
      </>
    );
  }
  return (
    <>
      {header}
      {save.isError && (
        <div className="mb-3">
          <ErrorPanel error={save.error} title="Could not change the flag" />
        </div>
      )}
      <Card>
        {q.isPending ? (
          <div className="p-4">
            <LoadingSkeleton rows={8} label="Loading feature flags" />
          </div>
        ) : q.isError ? (
          <div className="p-4">
            <ErrorPanel error={q.error} title="Could not load the feature flags" />
          </div>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Flag</Th>
                <Th>Module</Th>
                <Th>Milestone</Th>
                <Th>Last change</Th>
                <Th className="text-right">Enabled</Th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((f) => (
                <tr key={f.name}>
                  <Td>
                    <code className="font-mono text-[12px]">{f.name}</code>
                  </Td>
                  <Td>{f.description}</Td>
                  <Td>
                    <Badge>{f.milestone}</Badge>
                  </Td>
                  <Td className="text-[12px] text-muted-foreground">
                    {f.updated_at ? `${new Date(f.updated_at).toLocaleString()}${f.updated_by ? ` · ${f.updated_by}` : ""}` : "Never changed"}
                  </Td>
                  <Td className="text-right">
                    <button
                      type="button"
                      role="switch"
                      aria-checked={f.enabled}
                      aria-label={`${f.name}: ${f.enabled ? "on" : "off"}`}
                      disabled={save.isPending}
                      onClick={() => save.mutate({ name: f.name, enabled: !f.enabled })}
                      className={
                        "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-border transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring disabled:opacity-50 motion-reduce:transition-none " +
                        (f.enabled ? "bg-primary" : "bg-surface-muted")
                      }
                    >
                      <span
                        aria-hidden
                        className={
                          "inline-block size-4 rounded-full bg-surface shadow transition-transform motion-reduce:transition-none " + (f.enabled ? "translate-x-4" : "translate-x-0.5")
                        }
                      />
                    </button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <p className="mt-3 text-[12px] text-muted-foreground">
        Turning a flag on opens its module for this organization. While a flag is off, the module's menu item stays disabled and shows "Off".
      </p>
    </>
  );
}

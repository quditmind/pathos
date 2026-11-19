import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Badge, Skeleton } from "@/components/ui/primitives";
import { basisLabel, type FindingRuntimeResponse } from "./api";

const short = (d?: string) => (d ? d.slice(0, 19) : "");

/** Where a finding runs (finding drawer): clusters, namespaces, workloads,
 * the evidence of the link, exposure, security context and alerts. */
export function FindingRuntime({ findingId }: { findingId: string }) {
  const q = useQuery({
    queryKey: ["finding-runtime", findingId],
    queryFn: () => api<FindingRuntimeResponse>(`/api/v1/findings/${findingId}/runtime`),
    retry: false,
  });
  if (q.isPending) return <Skeleton className="h-16" />;
  if (q.isError) return <p className="text-[12px] text-danger">{q.error.message}</p>;
  const r = q.data;
  const ctx = r.context;
  return (
    <div>
      <h3 className="mb-2 text-[13px] font-semibold">Where it runs</h3>
      <div className="space-y-2 rounded-md border border-border p-3 text-[12.5px]">
        {r.clusters_connected === 0 ? (
          <p className="text-muted-foreground">
            No Kubernetes cluster is connected, so PATHOS cannot tell whether this runs in production. An administrator can connect a cluster
            (read-only) under <Link to="/runtime" className="text-primary hover:underline">Runtime</Link>.
          </p>
        ) : r.status === "" ? (
          <p className="text-muted-foreground">
            Unknown: PATHOS does not know which container image ships this finding (no image scan target for it, and no registry image whose
            source label names its repository), or the finding type is not part of an image.
          </p>
        ) : r.status === "not_deployed" ? (
          <>
            <Badge tone="success">Not deployed</Badge>
            <p className="text-muted-foreground">{ctx?.not_deployed_reason}. Its contextual risk is lowered.</p>
          </>
        ) : (
          <>
            <div className="flex flex-wrap gap-1.5">
              <Badge tone="warning">Deployed</Badge>
              {r.internet_exposed && <Badge tone="danger">Internet-exposed</Badge>}
              {r.privileged && <Badge tone="danger">Privileged workload</Badge>}
              {r.runtime_alert && <Badge tone="danger">Runtime alert seen</Badge>}
            </div>
            <ul className="space-y-2">
              {ctx?.deployments.map((d) => (
                <li key={`${d.workload_id}-${d.container}-${d.digest}`} className="border-t border-border pt-2 first:border-0 first:pt-0">
                  <div className="font-medium">
                    {d.cluster} / {d.namespace} / {d.kind} {d.workload}
                    <span className="font-normal text-muted-foreground"> · container {d.container}</span>
                  </div>
                  <div className="break-all font-mono text-[11px] text-muted-foreground">{d.image}{d.digest && !d.image.includes(d.digest) ? ` @ ${short(d.digest)}…` : ""}</div>
                  <div className="text-[11.5px] text-muted-foreground">Linked by {basisLabel[d.basis] ?? d.basis}: {d.basis_detail}</div>
                  {(d.exposure ?? []).map((x, i) => (
                    <div key={i} className="text-[11.5px]">↳ {x.detail}{x.address ? ` (${x.address})` : ""}</div>
                  ))}
                  {(d.privileged || d.host_network || d.host_pid || d.run_as_root === "yes") && (
                    <div className="text-[11.5px] text-danger">
                      {[d.privileged && "privileged container", d.host_network && "hostNetwork", d.host_pid && "hostPID", d.run_as_root === "yes" && "runs as root"]
                        .filter(Boolean).join(", ")}
                    </div>
                  )}
                  {(d.alerts ?? []).map((a) => (
                    <div key={a.finding_id} className="text-[11.5px]">
                      Alert:{" "}
                      <Link to="/findings" search={{ finding: a.finding_id } as never} className="text-primary hover:underline">{a.title}</Link>
                      <span className="text-muted-foreground"> ({a.severity}) at {a.location}, matched by {a.basis === "pod_name" ? "pod name" : "pod name pattern"}</span>
                    </div>
                  ))}
                </li>
              ))}
            </ul>
            {ctx && ctx.total_deployments > ctx.deployments.length && (
              <p className="text-[11.5px] text-muted-foreground">and {ctx.total_deployments - ctx.deployments.length} more workloads</p>
            )}
          </>
        )}
      </div>
    </div>
  );
}

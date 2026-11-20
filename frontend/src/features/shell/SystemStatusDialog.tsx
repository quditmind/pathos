import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { CircleCheck, CircleHelp, CircleX, RotateCw } from "lucide-react";
import { api } from "@/api/client";
import type { AIProvider, Page, Worker } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { useMeta } from "./meta";

type Health = "ok" | "down" | "unknown";

const icon: Record<Health, ReactNode> = {
  ok: <CircleCheck className="size-4 text-success" aria-hidden />,
  down: <CircleX className="size-4 text-danger" aria-hidden />,
  unknown: <CircleHelp className="size-4 text-muted-foreground" aria-hidden />,
};
const word: Record<Health, string> = { ok: "Healthy", down: "Problem", unknown: "Not available" };

const time = (t: number | string | null | undefined) => (t ? new Date(t).toLocaleString() : "—");

function Row({ name, health, detail, checked }: { name: string; health: Health; detail: ReactNode; checked?: string }) {
  return (
    <tr>
      <td className="py-2 pr-3 align-top font-medium">{name}</td>
      <td className="py-2 pr-3 align-top">
        <span className="inline-flex items-center gap-1.5">
          {icon[health]} {word[health]}
        </span>
      </td>
      <td className="py-2 pr-3 align-top text-muted-foreground">{detail}</td>
      <td className="py-2 align-top text-[12px] whitespace-nowrap text-muted-foreground">{checked ?? "—"}</td>
    </tr>
  );
}

/**
 * System status from endpoints the browser can reach: the API itself
 * (/api/v1/meta), worker packs (/api/v1/workers) and AI providers
 * (/api/v1/ai/providers, last connection test). Database, queue, object
 * storage and connector health have no browser-facing endpoint, so they say
 * "Not available" instead of guessing.
 */
export function SystemStatusDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { can, canOrgWide } = useSession();
  const meta = useMeta();
  const canWorkers = can("scans.read");
  const canAI = can("ai.review") || canOrgWide("ai.configure");
  const workers = useQuery({
    queryKey: ["workers"],
    queryFn: () => api<Page<Worker>>("/api/v1/workers").then((r) => r.items),
    enabled: open && canWorkers,
  });
  const providers = useQuery({
    queryKey: ["ai-providers"],
    queryFn: () => api<Page<AIProvider>>("/api/v1/ai/providers").then((r) => r.items),
    enabled: open && canAI,
  });
  const refresh = () => {
    void meta.refetch();
    if (canWorkers) void workers.refetch();
    if (canAI) void providers.refetch();
  };

  const families = new Map<string, Worker[]>();
  for (const w of workers.data ?? []) if (!w.revoked_at) families.set(w.family, [...(families.get(w.family) ?? []), w]);
  const noEndpoint = "No browser-facing health endpoint; operators check GET /readyz on the API container.";

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="xl"
      title="System status"
      description="Live health from the API. Anything without a health endpoint says Not available."
      footer={
        <Button variant="secondary" size="sm" onClick={refresh}>
          <RotateCw /> Check again
        </Button>
      }
    >
      <table className="w-full text-[13px]">
        <thead>
          <tr className="text-left text-[11px] tracking-wide text-muted-foreground uppercase">
            <th className="py-1 pr-3 font-semibold">Component</th>
            <th className="py-1 pr-3 font-semibold">Status</th>
            <th className="py-1 pr-3 font-semibold">Details</th>
            <th className="py-1 font-semibold">Last check</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          <Row
            name="API"
            health={meta.isSuccess ? "ok" : meta.isError ? "down" : "unknown"}
            detail={meta.isError ? meta.error.message : meta.isSuccess ? "Responding" : "Checking…"}
            checked={time(meta.isError ? meta.errorUpdatedAt : meta.dataUpdatedAt)}
          />
          <Row name="Database" health="unknown" detail={noEndpoint} />
          <Row name="Queue" health="unknown" detail={noEndpoint} />
          <Row name="Object storage" health="unknown" detail={noEndpoint} />
          {!canWorkers ? (
            <Row name="Worker packs" health="unknown" detail="Needs the scans.read permission." />
          ) : workers.isPending ? (
            <tr>
              <td colSpan={4} className="py-2">
                <Skeleton className="h-6" />
              </td>
            </tr>
          ) : workers.isError ? (
            <Row name="Worker packs" health="down" detail={workers.error.message} checked={time(workers.errorUpdatedAt)} />
          ) : families.size === 0 ? (
            <Row name="Worker packs" health="down" detail="No worker is registered; scans cannot run." checked={time(workers.dataUpdatedAt)} />
          ) : (
            [...families.entries()]
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([family, ws]) => {
                const online = ws.filter((w) => w.online).length;
                const last = ws.map((w) => w.last_seen_at).filter(Boolean).sort().pop();
                return (
                  <Row
                    key={family}
                    name={`Worker pack: ${family}`}
                    health={online > 0 ? "ok" : "down"}
                    detail={`${online} of ${ws.length} worker${ws.length === 1 ? "" : "s"} online · last seen ${time(last)}`}
                    checked={time(workers.dataUpdatedAt)}
                  />
                );
              })
          )}
          <Row name="Connectors" health="unknown" detail="Not summarised here: the Connectors page (feature flag connectors) shows the health check of each connection." />
          {!canAI ? (
            <Row name="AI providers" health="unknown" detail="Needs the ai.review or ai.configure permission." />
          ) : providers.isPending ? (
            <tr>
              <td colSpan={4} className="py-2">
                <Skeleton className="h-6" />
              </td>
            </tr>
          ) : providers.isError ? (
            <Row name="AI providers" health="down" detail={providers.error.message} checked={time(providers.errorUpdatedAt)} />
          ) : !providers.data.length ? (
            <Row name="AI providers" health="unknown" detail="No AI provider is configured." checked={time(providers.dataUpdatedAt)} />
          ) : (
            providers.data.map((p) => (
              <Row
                key={p.id}
                name={`AI provider: ${p.name}`}
                health={p.status === "ok" ? "ok" : p.status === "error" ? "down" : "unknown"}
                detail={p.status === "untested" ? "Not tested yet (AI settings › Test)" : `Last connection test: ${p.status_message || p.status}`}
                checked={time(providers.dataUpdatedAt)}
              />
            ))
          )}
        </tbody>
      </table>
    </Dialog>
  );
}

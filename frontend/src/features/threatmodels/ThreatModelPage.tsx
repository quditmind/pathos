import { useCallback, useId, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { Download, GitBranchPlus, Plus, RefreshCw, Send, ShieldHalf } from "lucide-react";
import { ApiError } from "@/api/client";
import { GraphExplorer } from "@/components/graph";
import { downloadUrl, exportFileName } from "@/components/graph/export";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Alert, Card, Label, PageHeader, Select, Table, Td, Th } from "@/components/ui/primitives";
import { EmptyStateCard, FeatureDisabled, LoadingSkeleton, PermissionDenied } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useSession } from "@/features/auth/session";
import { useFeatureFlags, useMeta } from "@/features/shell/meta";
import { formatDateTime } from "@/lib/utils";
import {
  approveBlockedReason,
  diagramDetail,
  exportExt,
  exportFormats,
  exportLabel,
  exportUrl,
  useDiagram,
  useModelAction,
  useThreatModel,
  useThreats,
  useVersions,
  type ExportFormat,
  type Threat,
  type ThreatModel,
} from "./api";
import { ModelStatusBadge } from "./badges";
import { AddThreatDialog } from "./dialogs";
import { modelTabs, type ModelTab, type ThreatModelSearch } from "./search";
import { ThreatDetail, ThreatsTable } from "./threats";

const tabLabel: Record<ModelTab, string> = { threats: "Threats", diagram: "Diagram", versions: "Versions" };

/** Summary line: counts by status and evidence. */
function Summary({ m }: { m: ThreatModel }) {
  const c = m.counts;
  if (!c) return null;
  return (
    <dl className="flex flex-wrap gap-x-5 gap-y-1 text-[12px]" aria-label="Threat model summary">
      {(
        [
          ["Threats", c.total],
          ["Open", c.open],
          ["Mitigated", c.mitigated],
          ["Accepted", c.accepted],
          ["Not applicable", c.not_applicable],
          ["Unverified", c.unverified],
          ["Without mitigation", c.without_mitigation],
        ] as const
      ).map(([l, v]) => (
        <div key={l} className="flex gap-1">
          <dt className="text-muted-foreground">{l}</dt>
          <dd className="font-semibold">{v ?? 0}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Approve, reject or request changes; explains why approval is not possible. */
export function ApprovalPanel({ model }: { model: ThreatModel }) {
  const ids = useId();
  const { me, can } = useSession();
  const [note, setNote] = useState("");
  const [noteError, setNoteError] = useState<string>();
  const act = useModelAction(model.id);
  const canPerm = can("threats.approve");
  const blocked = approveBlockedReason(model, me.user.id, canPerm);
  const decide = (action: "approve" | "reject", decision?: "rejected" | "changes_requested") => {
    if (action === "reject" && !note.trim()) return setNoteError("A note is required to reject or request changes.");
    setNoteError(undefined);
    act.mutate(
      { action, body: { note: note.trim(), ...(decision ? { decision } : {}) } },
      { onSuccess: () => (toast.success(action === "approve" ? "Threat model approved." : "Sent back to draft."), setNote("")) },
    );
  };
  return (
    <Card className="space-y-2 p-4" aria-label="Approval">
      <h2 className="text-[13px] font-semibold">Approval</h2>
      {model.status === "approved" ? (
        <p className="text-[13px]">
          Approved by {model.approved_by?.name ?? "—"} {model.approved_at ? `on ${formatDateTime(model.approved_at)}` : ""}.
        </p>
      ) : model.status === "draft" ? (
        <p className="text-[13px] text-muted-foreground">A draft. Submit it for review when every open threat has a mitigation and every manual or imported threat is linked to evidence.</p>
      ) : model.status === "in_review" ? (
        <>
          <p className="text-[13px]">
            Submitted by {model.submitted_by?.name ?? "—"} {model.submitted_at ? `on ${formatDateTime(model.submitted_at)}` : ""}. The approver must be someone else than the author and the submitter.
          </p>
          {blocked && (
            <p className="text-[12px] text-warning" data-testid="approve-blocked">
              {blocked}
            </p>
          )}
          <div>
            <Label htmlFor={`${ids}-note`} hint="(required to reject or request changes)">
              Note
            </Label>
            <textarea id={`${ids}-note`} className="min-h-14 w-full rounded-md border border-border bg-surface px-2 py-1 text-[13px]" value={note} maxLength={4000} onChange={(e) => setNote(e.target.value)} />
          </div>
          {noteError && (
            <p role="alert" className="text-[12px] text-danger">
              {noteError}
            </p>
          )}
          {act.isError && <ErrorPanel error={act.error} title="The decision was not recorded" />}
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => decide("approve")} disabled={!!blocked || act.isPending}>
              Approve
            </Button>
            <Button size="sm" variant="secondary" onClick={() => decide("reject", "changes_requested")} disabled={!!blocked || act.isPending}>
              Request changes
            </Button>
            <Button size="sm" variant="danger-outline" onClick={() => decide("reject", "rejected")} disabled={!!blocked || act.isPending}>
              Reject
            </Button>
          </div>
        </>
      ) : (
        <p className="text-[13px] text-muted-foreground">This version is {model.status}; a newer version replaces it.</p>
      )}
    </Card>
  );
}

function ExportMenu({ model }: { model: ThreatModel }) {
  const ids = useId();
  const meta = useMeta();
  const [format, setFormat] = useState<ExportFormat>("pathos");
  return (
    <div className="flex items-center gap-1">
      <label htmlFor={`${ids}-fmt`} className="sr-only">
        Export format
      </label>
      <Select id={`${ids}-fmt`} value={format} onChange={(e) => setFormat(e.target.value as ExportFormat)} className="h-7 w-auto">
        {exportFormats.map((f) => (
          <option key={f} value={f}>
            {exportLabel[f]}
          </option>
        ))}
      </Select>
      <Button
        size="sm"
        variant="secondary"
        onClick={() => downloadUrl(exportUrl(model.id, format), exportFileName(`threat-model-${model.title}-v${model.version}`, exportExt[format], meta.data?.version))}
      >
        <Download /> Export
      </Button>
    </div>
  );
}

function Diagram({ model, threats }: { model: ThreatModel; threats: Threat[] }) {
  const g = useDiagram(model.id);
  const meta = useMeta();
  const loadDetail = useCallback(async (nid: string) => diagramDetail(g.data!, threats, model.id, nid), [g.data, threats, model.id]);
  if (g.isPending) return <LoadingSkeleton rows={8} label="Loading the diagram" />;
  if (g.isError) return <ErrorPanel error={g.error} title="Could not load the diagram" onVerify={() => g.refetch()} />;
  if (!g.data.nodes.length)
    return (
      <EmptyStateCard icon={<ShieldHalf />} title="No diagram elements yet">
        The diagram shows the processes, data stores, external entities, data flows and trust boundaries the threats are about. Generate the model to fill it.
      </EmptyStateCard>
    );
  return (
    <div className="space-y-1">
      <p className="text-[12px] text-muted-foreground">Badges on an element count its open threats by severity. Select an element to list them. Elements the CodeGraph does not show produce no threats.</p>
      <GraphExplorer
        data={g.data}
        title={`Threat model diagram of ${model.title}, version ${model.version}`}
        loadDetail={loadDetail}
        detailKey={["threat-model-diagram", model.id, threats.length]}
        exportName={`threat-model-${model.title}-v${model.version}`}
        version={meta.data?.version}
        countsNoun="threats"
      />
    </div>
  );
}

function Versions({ model }: { model: ThreatModel }) {
  const v = useVersions(model.id);
  if (v.isPending) return <LoadingSkeleton rows={4} label="Loading versions" />;
  if (v.isError) return <ErrorPanel error={v.error} title="Could not load the versions" onVerify={() => v.refetch()} />;
  return (
    <div className="space-y-4">
      <Table>
        <thead>
          <tr>
            <Th>Version</Th>
            <Th>Status</Th>
            <Th>Author</Th>
            <Th>Created</Th>
            <Th>Approved</Th>
          </tr>
        </thead>
        <tbody>
          {[...v.data.items]
            .sort((a, b) => b.version - a.version)
            .map((m) => (
              <tr key={m.id}>
                <Td>
                  {m.id === model.id ? (
                    <span className="font-semibold">v{m.version} (this page)</span>
                  ) : (
                    <Link to="/threat-models/$modelId" params={{ modelId: m.id }} className="text-primary underline">
                      v{m.version}
                    </Link>
                  )}
                </Td>
                <Td>
                  <ModelStatusBadge status={m.status} />
                </Td>
                <Td>{m.created_by?.name ?? "—"}</Td>
                <Td>{formatDateTime(m.created_at)}</Td>
                <Td>{m.approved_at ? `${m.approved_by?.name ?? ""} ${formatDateTime(m.approved_at)}` : "—"}</Td>
              </tr>
            ))}
        </tbody>
      </Table>
      <section>
        <h3 className="mb-1 text-[13px] font-semibold">Review decisions</h3>
        {v.data.approvals.length ? (
          <ol className="space-y-1 text-[13px]">
            {v.data.approvals.map((a) => (
              <li key={a.id}>
                <span className="text-muted-foreground">{formatDateTime(a.decided_at)}</span> v{a.version} — {a.decision.replaceAll("_", " ")} by {a.actor?.name ?? "—"}
                {a.note && <span className="text-muted-foreground">: {a.note}</span>}
              </li>
            ))}
          </ol>
        ) : (
          <p className="text-[13px] text-muted-foreground">No decisions yet.</p>
        )}
      </section>
    </div>
  );
}

/** The model view: header and actions, threats, diagram, versions, approval. */
export function ThreatModelView({ modelId, tab, threat, onNavigate }: { modelId: string; tab: ModelTab; threat?: string; onNavigate: (s: ThreatModelSearch) => void }) {
  const { can } = useSession();
  const navigate = useNavigate();
  const q = useThreatModel(modelId);
  const threats = useThreats(modelId);
  const act = useModelAction(modelId);
  const [adding, setAdding] = useState(false);
  const m = q.data?.model;
  const sorted = useMemo(() => threats.data ?? [], [threats.data]);
  if (q.isPending) return <LoadingSkeleton rows={6} label="Loading the threat model" />;
  if (q.isError) {
    if (q.error instanceof ApiError && q.error.status === 403) return <PermissionDenied permission="threats.read" what="Viewing threat models" />;
    return <ErrorPanel error={q.error} title="Could not load the threat model" onVerify={() => q.refetch()} />;
  }
  if (!m) return null;
  const manage = can("threats.manage");
  const editable = !!m.can_edit && m.status === "draft";
  const run = (action: "generate" | "versions" | "submit", ok: string) =>
    act.mutate(
      { action },
      {
        onSuccess: (r) => {
          const res = r.result;
          toast.success(res ? `${ok} ${res.new ?? 0} new, ${res.changed ?? 0} changed, ${res.resolved ?? 0} resolved.` : ok);
          if (r.model.id && r.model.id !== m.id) void navigate({ to: "/threat-models/$modelId", params: { modelId: r.model.id } });
        },
      },
    );
  const notes = m.generation?.notes ?? [];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-muted-foreground">
        <ModelStatusBadge status={m.status} />
        <span>Version {m.version}</span>
        <span>
          {m.application_name ?? "Application"}
          {m.repository_name ? ` / ${m.repository_name}` : ""}
        </span>
        {m.generated_at && <span>Generated {formatDateTime(m.generated_at)}</span>}
        {m.method === "imported" && <span>Imported ({m.imported_format?.replaceAll("_", " ")})</span>}
        {m.codegraph_snapshot_ids?.length ? (
          <Link to="/codegraph/$appId" params={{ appId: m.application_id }} search={{ snapshot: m.codegraph_snapshot_ids[0] } as never} className="text-primary underline">
            CodeGraph snapshot
          </Link>
        ) : null}
      </div>
      <Summary m={m} />
      <div className="flex flex-wrap items-center gap-2">
        {manage && (m.status === "draft" || m.status === "approved") && (
          <Button size="sm" onClick={() => run("generate", "Threats generated:")} disabled={act.isPending}>
            <RefreshCw /> {m.status === "approved" ? "Regenerate in a new version" : "Generate"}
          </Button>
        )}
        {manage && m.status === "approved" && (
          <Button size="sm" variant="secondary" onClick={() => run("versions", "New draft version created.")} disabled={act.isPending}>
            <GitBranchPlus /> New version
          </Button>
        )}
        {editable && (
          <>
            <Button size="sm" variant="secondary" onClick={() => setAdding(true)}>
              <Plus /> Add manual threat
            </Button>
            <Button size="sm" variant="secondary" onClick={() => run("submit", "Submitted for review.")} disabled={act.isPending}>
              <Send /> Submit for review
            </Button>
          </>
        )}
        <span className="ml-auto">
          <ExportMenu model={m} />
        </span>
      </div>
      {act.isError && <ErrorPanel error={act.error} title="The action did not complete" />}
      {notes.length > 0 && (
        <Alert tone="warning">
          <ul className="list-disc pl-4">
            {notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </Alert>
      )}
      <div role="tablist" aria-label="Threat model sections" className="flex gap-1 border-b border-border">
        {modelTabs.map((t) => (
          <button
            key={t}
            type="button"
            role="tab"
            id={`tm-tab-${t}`}
            aria-selected={t === tab}
            aria-controls={`tm-panel-${t}`}
            onClick={() => onNavigate({ tab: t === "threats" ? undefined : t })}
            className={"-mb-px border-b-2 px-3 py-1.5 text-[13px] " + (t === tab ? "border-primary font-medium text-foreground" : "border-transparent text-muted-foreground hover:text-foreground")}
          >
            {tabLabel[t]}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`tm-panel-${tab}`} aria-labelledby={`tm-tab-${tab}`} className={tab === "diagram" ? "grid gap-3" : "grid gap-3 lg:grid-cols-[1fr_320px]"}>
        <div className="min-w-0">
          {tab === "threats" &&
            (threats.isPending ? (
              <LoadingSkeleton rows={6} label="Loading threats" />
            ) : threats.isError ? (
              <ErrorPanel error={threats.error} title="Could not load the threats" onVerify={() => threats.refetch()} />
            ) : (
              <ThreatsTable threats={sorted} selected={threat} onOpen={(id) => onNavigate({ threat: id })} />
            ))}
          {tab === "diagram" && <Diagram model={m} threats={sorted} />}
          {tab === "versions" && <Versions model={m} />}
        </div>
        {/* The diagram uses the full width (its inspector is the side panel). */}
        {tab !== "diagram" && <ApprovalPanel model={m} />}
      </div>
      <ThreatDetail threatId={threat} model={m} onClose={() => onNavigate({ threat: undefined })} />
      {editable && <AddThreatDialog open={adding} onOpenChange={setAdding} modelId={m.id} defaultRepo={m.repository_id ?? undefined} />}
    </div>
  );
}

/** /threat-models/$modelId */
export function ThreatModelPage() {
  const { modelId } = useParams({ strict: false }) as { modelId: string };
  const search = useSearch({ strict: false }) as ThreatModelSearch;
  const navigate = useNavigate();
  const { flags, isPending } = useFeatureFlags();
  const q = useThreatModel(modelId, flags.threat_models === true);
  const title = q.data?.model ? `Threat model: ${q.data.model.title}` : "Threat model";
  const tab = search.tab ?? "threats";
  const onNavigate = (s: ThreatModelSearch) =>
    void navigate({
      to: "/threat-models/$modelId",
      params: { modelId },
      search: { tab: "tab" in s ? s.tab : search.tab, threat: "threat" in s ? s.threat : search.threat } as never,
    });
  return (
    <>
      <nav aria-label="Breadcrumb" className="mb-2 text-[12px] text-muted-foreground">
        <ol className="flex flex-wrap items-center gap-1">
          <li>
            <Link to="/threat-models" className="hover:underline">
              Threat models
            </Link>{" "}
            /
          </li>
          <li aria-current="page" className="font-semibold text-foreground">
            {q.data?.model.title ?? "Threat model"}
          </li>
        </ol>
      </nav>
      <PageHeader
        title={title}
        description="Threats generated from the application's CodeGraph by deterministic STRIDE rules and from its attack paths, plus manual and imported threats. Every threat names its evidence, method, severity, confidence and mitigation."
      />
      {isPending ? (
        <LoadingSkeleton rows={4} />
      ) : !flags.threat_models ? (
        <FeatureDisabled flag="threat_models" feature="Threat models" />
      ) : (
        <ThreatModelView modelId={modelId} tab={tab} threat={search.threat} onNavigate={onNavigate} />
      )}
    </>
  );
}

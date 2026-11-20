import { useCallback, useState } from "react";
import { Link } from "@tanstack/react-router";
import { Activity, FileSearch, GitCompareArrows, Waypoints } from "lucide-react";
import { SeverityBadge } from "@/components/data/Severity";
import { GraphExplorer } from "@/components/graph";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Dialog } from "@/components/ui/dialog";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Alert, Badge, Card, Input, Select, Table, Td, Th } from "@/components/ui/primitives";
import { EmptyStateCard, LoadingSkeleton } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useSession } from "@/features/auth/session";
import { useSnapshots } from "@/features/codegraph/api";
import { useMeta } from "@/features/shell/meta";
import { useAddThreat, useThreatModels } from "@/features/threatmodels/api";
import { formatDateTime } from "@/lib/utils";
import {
  binaryViewInfo,
  binaryViews,
  fetchBinaryNode,
  hex,
  hideToolNames,
  kindOf,
  refText,
  threatCategoryFor,
  useAnalyses,
  useBinaryGraph,
  useCreateFinding,
  useDiff,
  useDismissDraft,
  useDrafts,
  useFunctionDetail,
  useFunctions,
  useImports,
  useRecomputeDiff,
  useStrings,
  type Analysis,
  type BinaryView,
  type DiffSide,
  type Draft,
  type FunctionItem,
  type Ref,
} from "./api";
import { AnalysisStatusBadge, EvidenceLabel, MatchBadge } from "./badges";

const PAGE = 50;

function Pager({ total, offset, onOffset, noun }: { total: number; offset: number; onOffset: (o: number) => void; noun: string }) {
  if (total <= PAGE) return <p className="text-[12px] text-muted-foreground">{total} {noun}</p>;
  return (
    <div className="flex items-center gap-2 text-[12px] text-muted-foreground">
      <span>
        {offset + 1}–{Math.min(offset + PAGE, total)} of {total} {noun}
      </span>
      <Button size="sm" variant="secondary" disabled={offset === 0} onClick={() => onOffset(Math.max(0, offset - PAGE))}>
        Previous
      </Button>
      <Button size="sm" variant="secondary" disabled={offset + PAGE >= total} onClick={() => onOffset(offset + PAGE)}>
        Next
      </Button>
    </div>
  );
}

export function RefList({ refs }: { refs: Ref[] }) {
  if (!refs.length) return <p className="text-[12px] text-muted-foreground">No evidence recorded.</p>;
  return (
    <ul className="space-y-1" aria-label="Evidence">
      {refs.map((r, i) => (
        <li key={`${r.kind}:${r.ref}:${i}`} className="flex flex-wrap items-center gap-1.5 text-[12px]">
          <EvidenceLabel evidence={r.evidence} />
          <span className="text-muted-foreground">{r.kind === "binary" ? "Binary" : r.kind === "file_line" ? "Source" : r.kind}</span>
          <code className="break-all">{refText(r)}</code>
        </li>
      ))}
    </ul>
  );
}

// ---------------------------------------------------------------- Functions

const matchFilters: { value: string; label: string }[] = [
  { value: "", label: "All functions" },
  { value: "binary_only", label: "Only in binary" },
  { value: "matched", label: "Matched with source" },
  { value: "library", label: "Library" },
  { value: "sensitive", label: "Sensitive" },
];

function FunctionDetailPane({ analysisId, nodeId, onOpen }: { analysisId: string; nodeId: string; onOpen: (nid: string) => void }) {
  const d = useFunctionDetail(analysisId, nodeId);
  if (d.isPending) return <LoadingSkeleton rows={6} label="Loading the function" />;
  if (d.isError) return <ErrorPanel error={d.error} title="Could not load the function" onVerify={() => d.refetch()} />;
  const { function: f, code, callers, callees, strings, evidence } = d.data;
  const fnLink = (x: FunctionItem) => (
    <li key={x.node_id}>
      <button type="button" className="text-left text-primary underline" onClick={() => onOpen(x.node_id)}>
        {x.name}
      </button>
    </li>
  );
  return (
    <div className="space-y-3" data-testid="function-detail">
      <div>
        <h3 className="text-[14px] font-semibold break-all">{f.name}</h3>
        <p className="text-[12px] text-muted-foreground">
          {f.addr ?? ""} · offset {hex(f.offset)} {f.size ? `· ${f.size} bytes` : ""} {f.section ? `· ${f.section}` : ""}
        </p>
        <div className="mt-1">
          <MatchBadge match={f.match} sensitive={f.sensitive} />
        </div>
        {f.source && (
          <p className="mt-1 text-[12px]">
            Source match: <code>{f.source.file}{f.source.line ? `:${f.source.line}` : ""}</code>
          </p>
        )}
      </div>
      <section aria-label="Code">
        {code ? (
          <>
            <h4 className="text-[12px] font-semibold">
              {code.kind === "pseudo_c" ? "Decompiled (pseudo-C)" : "Disassembly"} · {kindOf(code.tool)} · {hex(f.offset)}
            </h4>
            <pre className="mt-1 max-h-96 overflow-auto rounded-md bg-surface-muted p-2 text-[12px] leading-snug" data-testid="function-code">
              {code.text}
            </pre>
          </>
        ) : (
          <p className="text-[12px] text-muted-foreground">
            {d.data.code_withheld || "No code was kept for this function (code is kept for functions only in the binary, sensitive ones and the main package)."}
          </p>
        )}
      </section>
      <div className="grid gap-3 sm:grid-cols-2">
        <section>
          <h4 className="text-[12px] font-semibold">Called by ({callers.length})</h4>
          <ul className="text-[12px]">{callers.slice(0, 30).map(fnLink)}</ul>
        </section>
        <section>
          <h4 className="text-[12px] font-semibold">Calls ({callees.length})</h4>
          <ul className="text-[12px]">{callees.slice(0, 30).map(fnLink)}</ul>
        </section>
      </div>
      {strings.length > 0 && (
        <section>
          <h4 className="text-[12px] font-semibold">Strings referenced</h4>
          <ul className="text-[12px]">
            {strings.slice(0, 30).map((s) => (
              <li key={s.node_id}>
                <StringValue value={s.value} redacted={s.redacted} />
              </li>
            ))}
          </ul>
        </section>
      )}
      <section>
        <h4 className="text-[12px] font-semibold">Evidence</h4>
        <RefList refs={evidence} />
      </section>
    </div>
  );
}

export function FunctionsTab({ analysis, selected, onSelect }: { analysis: Analysis; selected?: string; onSelect: (nid: string | undefined) => void }) {
  const [q, setQ] = useState("");
  const [match, setMatch] = useState("");
  const [offset, setOffset] = useState(0);
  const list = useFunctions(analysis.id, { q: q || undefined, match: match || undefined, limit: PAGE, offset });
  return (
    <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <Card className="space-y-2 p-3">
        <div className="flex flex-wrap gap-2">
          <Input
            aria-label="Search functions"
            placeholder="Search functions"
            className="h-8 w-56"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setOffset(0);
            }}
          />
          <Select
            aria-label="Match"
            className="h-8 w-auto"
            value={match}
            onChange={(e) => {
              setMatch(e.target.value);
              setOffset(0);
            }}
          >
            {matchFilters.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </Select>
        </div>
        {list.isError ? (
          <ErrorPanel error={list.error} title="Could not load the functions" onVerify={() => list.refetch()} />
        ) : list.isPending ? (
          <LoadingSkeleton rows={8} label="Loading functions" />
        ) : !list.data.items.length ? (
          <p className="text-[13px] text-muted-foreground">No functions match.</p>
        ) : (
          <>
            <ul className="divide-y divide-border" aria-label="Functions">
              {list.data.items.map((f) => (
                <li key={f.node_id} data-testid="function-row">
                  <button
                    type="button"
                    aria-current={selected === f.node_id ? "true" : undefined}
                    onClick={() => onSelect(f.node_id)}
                    className={"flex w-full flex-wrap items-center justify-between gap-2 px-1 py-1.5 text-left text-[13px] hover:bg-surface-muted " + (selected === f.node_id ? "bg-surface-muted" : "")}
                  >
                    <span className="min-w-0 break-all">{f.name}</span>
                    <MatchBadge match={f.match} sensitive={f.sensitive} />
                  </button>
                </li>
              ))}
            </ul>
            <Pager total={list.data.total} offset={offset} onOffset={setOffset} noun="functions" />
          </>
        )}
      </Card>
      <Card className="p-3">
        {selected ? (
          <FunctionDetailPane analysisId={analysis.id} nodeId={selected} onOpen={(nid) => onSelect(nid)} />
        ) : (
          <p className="text-[13px] text-muted-foreground">Select a function to see its code, callers, callees, strings and evidence.</p>
        )}
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------- Call graph

export function CallGraphTab({ analysis, node, onNode }: { analysis: Analysis; node?: string; onNode: (id: string | undefined) => void }) {
  const [view, setView] = useState<BinaryView>("binary_call_graph");
  const [focus, setFocus] = useState<string | undefined>();
  const meta = useMeta();
  const g = useBinaryGraph(analysis.id, view, focus);
  const loadDetail = useCallback((nid: string) => fetchBinaryNode(analysis.id, nid), [analysis.id]);
  return (
    <div className="space-y-2">
      <div className="flex gap-1" role="group" aria-label="Binary graph views">
        {binaryViews.map((v) => (
          <button
            key={v}
            type="button"
            aria-pressed={v === view}
            title={binaryViewInfo[v].description}
            onClick={() => {
              setView(v);
              setFocus(undefined);
            }}
            className={
              "h-7 rounded-md border px-2 text-[12px] " +
              (v === view ? "border-foreground bg-foreground text-background" : "border-border bg-surface text-foreground hover:bg-surface-muted")
            }
          >
            {binaryViewInfo[v].label}
          </button>
        ))}
      </div>
      <p className="text-[12px] text-muted-foreground">{binaryViewInfo[view].description} Every edge is verified from the binary, with its offset.</p>
      {focus && (
        <Button size="sm" variant="ghost" onClick={() => setFocus(undefined)}>
          Back to the full view
        </Button>
      )}
      {g.isError ? (
        <ErrorPanel error={g.error} title="Could not load the binary graph" onVerify={() => g.refetch()} />
      ) : g.isPending ? (
        <Card className="p-4">
          <LoadingSkeleton rows={8} label="Loading the graph" />
        </Card>
      ) : g.data.nodes.length + (g.data.aggregated?.length ?? 0) === 0 ? (
        <EmptyStateCard icon={<Waypoints />} title="Nothing in this view">
          The analysis found no elements for this view.
        </EmptyStateCard>
      ) : (
        <GraphExplorer
          key={`${analysis.id}:${view}:${focus ?? ""}`}
          data={g.data}
          title={`Binary graph of ${analysis.artifact_name}, ${binaryViewInfo[view].label} view`}
          initialSelected={node}
          onSelect={onNode}
          onExpand={setFocus}
          loadDetail={loadDetail}
          detailKey={["rea", analysis.id]}
          exportName={`binary-${analysis.artifact_name}-${view}`}
          version={meta.data?.version}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Strings and imports

export function StringValue({ value, redacted }: { value: string; redacted?: boolean }) {
  if (redacted) return <Badge tone="warning">Redacted secret</Badge>;
  return <code className="break-all">{value}</code>;
}

export function StringsImportsTab({ analysis }: { analysis: Analysis }) {
  const [sq, setSq] = useState("");
  const [kind, setKind] = useState("");
  const [so, setSo] = useState(0);
  const [iq, setIq] = useState("");
  const [io, setIo] = useState(0);
  const strings = useStrings(analysis.id, { q: sq || undefined, kind: kind || undefined, limit: PAGE, offset: so });
  const imports = useImports(analysis.id, { q: iq || undefined, limit: PAGE, offset: io });
  return (
    <div className="grid gap-3 xl:grid-cols-2">
      <Card className="space-y-2 p-3">
        <h3 className="text-[14px] font-semibold">Strings</h3>
        <p className="text-[12px] text-muted-foreground">Secrets found in strings are redacted inside the isolated analysis; their values never reach PATHOS.</p>
        <div className="flex flex-wrap gap-2">
          <Input aria-label="Search strings" placeholder="Search strings" className="h-8 w-48" value={sq} onChange={(e) => { setSq(e.target.value); setSo(0); }} />
          <Select aria-label="String kind" className="h-8 w-auto" value={kind} onChange={(e) => { setKind(e.target.value); setSo(0); }}>
            <option value="">Any kind</option>
            {["url", "route", "path", "secret", "format", "text"].map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </Select>
        </div>
        {strings.isError ? (
          <ErrorPanel error={strings.error} title="Could not load the strings" onVerify={() => strings.refetch()} />
        ) : strings.isPending ? (
          <LoadingSkeleton rows={6} label="Loading strings" />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Value</Th>
                  <Th>Kind</Th>
                  <Th>Offset</Th>
                  <Th>Section</Th>
                </tr>
              </thead>
              <tbody>
                {strings.data.items.map((s) => (
                  <tr key={s.node_id} data-testid="string-row">
                    <Td>
                      <StringValue value={s.value} redacted={s.redacted} />
                    </Td>
                    <Td>{s.kind ?? ""}</Td>
                    <Td>
                      <code>{hex(s.offset)}</code>
                    </Td>
                    <Td>{s.section ?? ""}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pager total={strings.data.total} offset={so} onOffset={setSo} noun="strings" />
          </>
        )}
      </Card>
      <Card className="space-y-2 p-3">
        <h3 className="text-[14px] font-semibold">Imports</h3>
        <Input aria-label="Search imports" placeholder="Search imports" className="h-8 w-48" value={iq} onChange={(e) => { setIq(e.target.value); setIo(0); }} />
        {imports.isError ? (
          <ErrorPanel error={imports.error} title="Could not load the imports" onVerify={() => imports.refetch()} />
        ) : imports.isPending ? (
          <LoadingSkeleton rows={6} label="Loading imports" />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Library or package</Th>
                  <Th>Kind</Th>
                </tr>
              </thead>
              <tbody>
                {imports.data.items.map((i) => (
                  <tr key={i.node_id} data-testid="import-row">
                    <Td>
                      <span className="break-all">{i.name}</span> {i.sensitive && <Badge tone="warning">Sensitive</Badge>}
                    </Td>
                    <Td>{i.library ?? ""}</Td>
                    <Td>{i.kind ?? ""}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pager total={imports.data.total} offset={io} onOffset={setIo} noun="imports" />
          </>
        )}
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------- Runtime behaviour

export function RuntimeTab() {
  return (
    <EmptyStateCard icon={<Activity />} title="Sandbox tier arrives after 3.0">
      Runtime behaviour (function traces, system calls, files, network and processes observed while the program runs) needs the dynamic sandbox tier.
      It runs only in a throwaway virtual machine, never on the PATHOS host, and needs its own approval. This release analyses binaries statically
      and never runs them, so there is no runtime data to show.
    </EmptyStateCard>
  );
}

// ---------------------------------------------------------------- Source ↔ binary

const sideLabel: Record<DiffSide, string> = { binary_only: "Only in binary", source_only: "Only in source", matched: "Matched" };

function DraftCard({ draft, analysis }: { draft: Draft; analysis: Analysis }) {
  const { can } = useSession();
  const create = useCreateFinding(analysis.id);
  const dismiss = useDismissDraft(analysis.id);
  const [confirming, setConfirming] = useState(false);
  const [dismissing, setDismissing] = useState(false);
  const [reason, setReason] = useState("");
  const [toModel, setToModel] = useState(false);
  const triage = can("findings.triage");
  return (
    <Card className="space-y-2 p-3" data-testid="draft-card">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="primary">Proposal · needs human review</Badge>
        <SeverityBadge value={draft.severity} />
        {draft.status !== "proposed" && <Badge>{draft.status === "created" ? "Finding created" : "Dismissed"}</Badge>}
      </div>
      <h4 className="text-[14px] font-semibold">{draft.title}</h4>
      <p className="text-[13px] whitespace-pre-line">{hideToolNames(draft.description)}</p>
      <RefList refs={draft.evidence} />
      {draft.status === "created" && draft.finding_id && (
        <Link to="/findings" search={{ finding: draft.finding_id } as never} className="text-[13px] text-primary underline">
          Open the finding
        </Link>
      )}
      {draft.status === "proposed" && (
        <div className="flex flex-wrap gap-2">
          {triage && (
            <Button size="sm" onClick={() => setConfirming(true)}>
              Create finding
            </Button>
          )}
          {can("threats.manage") && (
            <Button size="sm" variant="secondary" onClick={() => setToModel(true)}>
              Add to threat model
            </Button>
          )}
          {triage && (
            <Button size="sm" variant="ghost" onClick={() => setDismissing(true)}>
              Dismiss
            </Button>
          )}
        </div>
      )}
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Create a finding from this proposal?"
        confirmLabel="Create finding"
        destructive={false}
        pending={create.isPending}
        error={create.isError ? (create.error as Error).message : null}
        onConfirm={() =>
          create.mutate(draft.id, {
            onSuccess: () => {
              setConfirming(false);
              toast.success("Finding created with status Needs review.");
            },
          })
        }
      >
        <p>
          The finding is created with status <strong>Needs review</strong>, never as confirmed. It keeps this proposal's evidence (binary offsets and source
          lines).
        </p>
      </ConfirmDialog>
      <Dialog
        open={dismissing}
        onOpenChange={setDismissing}
        title="Dismiss this proposal"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDismissing(false)}>
              Cancel
            </Button>
            <Button
              disabled={!reason.trim() || dismiss.isPending}
              onClick={() =>
                dismiss.mutate(
                  { id: draft.id, reason: reason.trim() },
                  {
                    onSuccess: () => {
                      setDismissing(false);
                      toast.success("Proposal dismissed.");
                    },
                  },
                )
              }
            >
              Dismiss
            </Button>
          </>
        }
      >
        {dismiss.isError && <ErrorPanel error={dismiss.error} title="Could not dismiss the proposal" />}
        <label className="block space-y-1 text-[13px]">
          <span>Reason (required)</span>
          <textarea aria-label="Dismiss reason" className="min-h-16 w-full rounded-md border border-border bg-surface px-2 py-1" value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
      </Dialog>
      {toModel && <AddToThreatModelDialog draft={draft} analysis={analysis} onClose={() => setToModel(false)} />}
    </Card>
  );
}

function AddToThreatModelDialog({ draft, analysis, onClose }: { draft: Draft; analysis: Analysis; onClose: () => void }) {
  const appId = draft.application_id ?? analysis.application_id ?? undefined;
  const models = useThreatModels({ application_id: appId }, !!appId);
  const editable = (models.data ?? []).filter((m) => m.status === "draft" || m.status === "in_review" || m.status === "approved");
  const [modelId, setModelId] = useState("");
  const chosen = modelId || editable[0]?.id || "";
  const add = useAddThreat(chosen);
  const description = [
    hideToolNames(draft.description),
    "",
    "Evidence (reverse engineering, static analysis of the shipped binary):",
    ...draft.evidence.map((r) => `- ${r.evidence}: ${refText(r)}`),
    `Analysis: ${analysis.artifact_name} (${analysis.artifact_sha256.slice(0, 12)})`,
  ].join("\n");
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Add to threat model"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={!chosen || add.isPending}
            onClick={() =>
              add.mutate(
                { title: draft.title.slice(0, 300), description: description.slice(0, 8000), category: threatCategoryFor(draft), severity: draft.severity },
                {
                  onSuccess: () => {
                    toast.success("Threat added to the threat model as a manual threat.");
                    onClose();
                  },
                },
              )
            }
          >
            Add threat
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-[13px]">
        {!appId ? (
          <p>
            The artifact's repository belongs to no application, so it has no threat model. Assign the repository to an application, or open{" "}
            <Link to="/threat-models" className="text-primary underline">
              Threat models
            </Link>
            .
          </p>
        ) : models.isPending ? (
          <LoadingSkeleton rows={2} label="Loading threat models" />
        ) : models.isError ? (
          <ErrorPanel error={models.error} title="Could not load the threat models" />
        ) : !editable.length ? (
          <p>
            The application has no threat model yet.{" "}
            <Link to="/threat-models" search={{ application: appId } as never} className="text-primary underline">
              Create one in Threat models
            </Link>
            , then add this proposal.
          </p>
        ) : (
          <>
            <label className="flex items-center gap-2">
              Threat model
              <Select aria-label="Threat model" value={chosen} onChange={(e) => setModelId(e.target.value)} className="h-8 w-auto">
                {editable.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.title} (v{m.version}, {m.status})
                  </option>
                ))}
              </Select>
            </label>
            <p className="text-muted-foreground">
              The threat is added to the model's draft as a manual threat ({threatCategoryFor(draft).replaceAll("_", " ")}, severity {draft.severity}), with
              the binary evidence in its description.
            </p>
            {add.isError && <ErrorPanel error={add.error} title="Could not add the threat" />}
          </>
        )}
      </div>
    </Dialog>
  );
}

function DiffStatusNotice({ analysis, status, commit }: { analysis: Analysis; status: string; commit?: string }) {
  const { can } = useSession();
  const appId = analysis.application_id ?? "";
  const snaps = useSnapshots(appId, !!appId && status !== "ready");
  const recompute = useRecomputeDiff(analysis.id);
  const [sid, setSid] = useState("");
  const usable = (snaps.data ?? []).filter((s) => (s.status === "ready" || s.status === "partial") && (!analysis.repository_id || s.repository_id === analysis.repository_id));
  if (status === "ready") return null;
  const message =
    status === "pending"
      ? "The comparison is computed when the analysis finishes."
      : status === "no_commit"
        ? "PATHOS does not know which commit this artifact was built from: it has no verified provenance and no build information. Choose a CodeGraph snapshot to compare with; the comparison is then labelled as chosen by you."
        : `There is no CodeGraph snapshot of commit ${commit ? commit.slice(0, 12) : "(unknown)"} for this repository. Build the CodeGraph at that commit, or choose another snapshot (labelled as chosen by you).`;
  return (
    <Alert tone="warning">
      <p>{message}</p>
      {status !== "pending" && can("rea.run") && appId && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Select aria-label="CodeGraph snapshot" className="h-8 w-auto" value={sid} onChange={(e) => setSid(e.target.value)}>
            <option value="">Choose a snapshot…</option>
            {usable.map((s) => (
              <option key={s.id} value={s.id}>
                {(s.repository_name ? `${s.repository_name} · ` : "") + (s.commit_sha ? s.commit_sha.slice(0, 12) : "no commit") + " · " + formatDateTime(s.created_at)}
              </option>
            ))}
          </Select>
          <Button
            size="sm"
            disabled={!sid || recompute.isPending}
            onClick={() => recompute.mutate(sid, { onSuccess: () => toast.success("Comparing the binary with the chosen snapshot.") })}
          >
            Compare
          </Button>
          {recompute.isError && <ErrorPanel error={recompute.error} title="Could not compare" />}
        </div>
      )}
      {status !== "pending" && !appId && <p className="mt-1">The repository belongs to no application, so it has no CodeGraph.</p>}
    </Alert>
  );
}

export function DiffTab({ analysis }: { analysis: Analysis }) {
  const [side, setSide] = useState<DiffSide | "">("binary_only");
  const [offset, setOffset] = useState(0);
  const diff = useDiff(analysis.id, { side: side || undefined, limit: PAGE, offset });
  const drafts = useDrafts(analysis.id);
  const sourceLabel: Record<string, string> = { provenance: "verified provenance", binary: "build information in the binary", user: "chosen by a person" };
  return (
    <div className="space-y-3">
      {diff.isError ? (
        <ErrorPanel error={diff.error} title="Could not load the comparison" onVerify={() => diff.refetch()} />
      ) : diff.isPending ? (
        <LoadingSkeleton rows={6} label="Loading the comparison" />
      ) : (
        <>
          {diff.data.commit_sha && (
            <p className="text-[12px] text-muted-foreground" data-testid="diff-commit">
              Compared with source at <code>{diff.data.commit_sha.slice(0, 12)}</code>
              {diff.data.commit_source ? ` (commit from ${sourceLabel[diff.data.commit_source] ?? diff.data.commit_source})` : ""}.
            </p>
          )}
          <DiffStatusNotice analysis={analysis} status={diff.data.status} commit={diff.data.commit_sha} />
          <div className="flex flex-wrap gap-2" role="group" aria-label="Comparison side">
            {(["binary_only", "source_only", "matched"] as DiffSide[]).map((s) => (
              <button
                key={s}
                type="button"
                aria-pressed={side === s}
                onClick={() => {
                  setSide(s);
                  setOffset(0);
                }}
                className={"rounded-md border px-2 py-1 text-[12px] " + (side === s ? "border-foreground bg-foreground text-background" : "border-border bg-surface")}
              >
                {sideLabel[s]} · {diff.data.counts[s]}
              </button>
            ))}
          </div>
          {!diff.data.items.length ? (
            diff.data.status === "ready" && <p className="text-[13px] text-muted-foreground">Nothing on this side.</p>
          ) : (
            <Card className="overflow-x-auto">
              <Table>
                <thead>
                  <tr>
                    <Th>Item</Th>
                    <Th>Kind</Th>
                    <Th>Evidence</Th>
                  </tr>
                </thead>
                <tbody>
                  {diff.data.items.map((it) => (
                    <tr key={it.id} data-testid="diff-row">
                      <Td>
                        <div className="break-all">{it.name}</div>
                        <div className="mt-1 flex gap-1">
                          <Badge tone={it.side === "matched" ? "success" : it.side === "binary_only" ? "danger" : "neutral"}>{sideLabel[it.side]}</Badge>
                          {it.sensitive && <Badge tone="warning">Sensitive</Badge>}
                        </div>
                        {it.sensitive_reason && <div className="mt-1 text-[12px] text-muted-foreground">{it.sensitive_reason}</div>}
                      </Td>
                      <Td>{it.kind}</Td>
                      <Td>
                        <RefList refs={it.evidence} />
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              <div className="p-2">
                <Pager total={diff.data.total} offset={offset} onOffset={setOffset} noun="items" />
              </div>
            </Card>
          )}
        </>
      )}
      <section className="space-y-2" aria-label="Finding proposals">
        <h3 className="text-[14px] font-semibold">Finding proposals</h3>
        <p className="text-[12px] text-muted-foreground">
          Sensitive items found only in the binary become proposals. They are never created as confirmed findings: a person reviews each one.
        </p>
        {drafts.isError ? (
          <ErrorPanel error={drafts.error} title="Could not load the proposals" onVerify={() => drafts.refetch()} />
        ) : drafts.isPending ? (
          <LoadingSkeleton rows={2} label="Loading proposals" />
        ) : !drafts.data.length ? (
          <p className="text-[13px] text-muted-foreground">No proposals: nothing sensitive was found only in the binary.</p>
        ) : (
          drafts.data.map((d) => <DraftCard key={d.id} draft={d} analysis={analysis} />)
        )}
      </section>
    </div>
  );
}

// ---------------------------------------------------------------- History

export function HistoryTab({ analysis }: { analysis: Analysis }) {
  const list = useAnalyses(analysis.target_id);
  if (list.isError) return <ErrorPanel error={list.error} title="Could not load the history" onVerify={() => list.refetch()} />;
  if (list.isPending) return <LoadingSkeleton rows={4} label="Loading the history" />;
  if (!list.data.length) return <EmptyStateCard icon={<FileSearch />} title="No analyses yet" />;
  return (
    <Card className="overflow-x-auto">
      <Table>
        <thead>
          <tr>
            <Th>Started</Th>
            <Th>Status</Th>
            <Th>Commit</Th>
            <Th>Analysis</Th>
          </tr>
        </thead>
        <tbody>
          {list.data.map((a) => (
            <tr key={a.id} data-testid="history-row">
              <Td>{formatDateTime(a.created_at)}</Td>
              <Td>
                <AnalysisStatusBadge status={a.status} />
              </Td>
              <Td>{a.commit_sha ? <code>{a.commit_sha.slice(0, 12)}</code> : "—"}</Td>
              <Td>
                {a.id === analysis.id ? (
                  <span className="text-muted-foreground">This analysis</span>
                ) : (
                  <Link to="/reverse-engineering/analyses/$analysisId" params={{ analysisId: a.id }} className="text-primary underline">
                    <GitCompareArrows className="inline size-3.5" /> Open
                  </Link>
                )}
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}

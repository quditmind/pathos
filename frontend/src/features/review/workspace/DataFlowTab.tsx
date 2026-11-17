import { useState } from "react";
import { ArrowDown, CircleDot, Crosshair, GitFork, Info, Target } from "lucide-react";
import { Alert, Badge, Card, Label, Skeleton } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import { useDataFlow } from "../api";
import type { FlowNode, ReviewDetail } from "../types";
import { textareaCls } from "./actions";
import { Panel, SaveBar, useSections } from "./section";

const statusInfo = {
  confirmed: { tone: "success" as const, label: "Confirmed data flow", text: "Source-to-sink paths reported by the scanner." },
  incomplete: { tone: "warning" as const, label: "Incomplete data flow", text: "The scanner reported a path without a distinct source or sink." },
  inferred: { tone: "warning" as const, label: "Inferred (unverified)", text: "Related locations only; the scanner did not establish a flow between them." },
  unavailable: { tone: "neutral" as const, label: "Data flow unavailable", text: "" },
};

const roleStyle: Record<FlowNode["role"], { label: string; icon: React.ReactNode; cls: string }> = {
  source: { label: "Source / entry point", icon: <Crosshair className="size-3.5" />, cls: "border-primary" },
  intermediate: { label: "Intermediate step", icon: <CircleDot className="size-3.5" />, cls: "border-border" },
  sink: { label: "Sink / vulnerable operation", icon: <Target className="size-3.5" />, cls: "border-danger" },
  related: { label: "Related location", icon: <GitFork className="size-3.5" />, cls: "border-dashed border-border" },
};

/** Step-level annotations reviewers record (validation, sanitization, auth). */
const annotations = [
  ["validation", "Input validation at this step"],
  ["sanitization", "Sanitization / encoding"],
  ["authz", "Authentication / authorization checks"],
  ["transformation", "Data transformation"],
] as const;

export function DataFlowTab({ d, openSource }: { d: ReviewDetail; openSource: (path: string, line?: number) => void }) {
  const q = useDataFlow(d.id);
  const s = useSections(d, ["dataflow_notes"]);
  const [sel, setSel] = useState<string | null>(null);
  const df = q.data;
  if (q.isError) return <Alert>{q.error.message}</Alert>;
  if (!df) return <Skeleton className="h-64" />;
  const info = statusInfo[df.status];
  const nodes: [string, FlowNode][] = [
    ...df.paths.flatMap((p, i) => p.nodes.map((n, j) => [`p${i}n${j}`, n] as [string, FlowNode])),
    ...df.related.map((n, j) => [`r${j}`, n] as [string, FlowNode]),
  ];
  const selected = nodes.find(([k]) => k === sel);
  const notes = s.draft.dataflow_notes ?? {};
  const editable = d.can.assess;

  const NodeCard = ({ k, n, dashed }: { k: string; n: FlowNode; dashed?: boolean }) => {
    const r = roleStyle[n.role];
    const annotated = annotations.some(([a]) => notes[`${k}.${a}`]);
    return (
      <button
        type="button"
        onClick={() => setSel(k)}
        aria-pressed={sel === k}
        className={cn(
          "w-full rounded-md border-2 bg-surface p-2 text-left text-[12px] hover:bg-surface-muted/60 focus-visible:outline-2 focus-visible:outline-ring",
          r.cls,
          dashed && "border-dashed",
          sel === k && "ring-2 ring-primary/40",
        )}
      >
        <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          {r.icon} {r.label}
          {n.kinds?.length ? <span className="font-normal normal-case">({n.kinds.join(", ")})</span> : null}
          {annotated && <Badge tone="primary" className="ml-auto">annotated</Badge>}
        </div>
        <div className="mt-1 font-mono">{n.file_path}{n.line ? `:${n.line}` : ""}</div>
        {n.function && <div className="font-mono text-[11.5px] text-muted-foreground">in {n.function}()</div>}
        {n.message && <div className="mt-0.5">{n.message}</div>}
        {n.snippet && <pre className="mt-1 overflow-x-auto rounded bg-surface-muted px-2 py-1 font-mono text-[11.5px]">{n.snippet}</pre>}
      </button>
    );
  };

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
      <div className="min-w-0 space-y-4">
        <Alert tone={info.tone === "neutral" ? "warning" : info.tone}>
          <strong>{info.label}.</strong> {df.reason || info.text}
        </Alert>
        <div className="flex flex-wrap gap-3 text-[11.5px] text-muted-foreground" aria-label="Legend">
          <span className="flex items-center gap-1"><span className="inline-block h-3 w-5 rounded border-2 border-primary" /> source</span>
          <span className="flex items-center gap-1"><span className="inline-block h-3 w-5 rounded border-2 border-border" /> intermediate</span>
          <span className="flex items-center gap-1"><span className="inline-block h-3 w-5 rounded border-2 border-danger" /> sink</span>
          <span className="flex items-center gap-1"><span className="inline-block h-3 w-5 rounded border-2 border-dashed border-border" /> incomplete / related (not a proven flow)</span>
        </div>
        {df.paths.map((p, i) => (
          <Card key={i} className="p-3">
            <div className="mb-2 flex items-center gap-2 text-[12.5px]">
              <span className="font-semibold">Path {i + 1}</span>
              <Badge tone={p.status === "confirmed" ? "success" : "warning"}>{p.status === "confirmed" ? "confirmed" : "incomplete"}</Badge>
              {p.message && <span className="text-muted-foreground">{p.message}</span>}
            </div>
            <ol className="space-y-1" aria-label={`Data flow path ${i + 1}`}>
              {p.nodes.map((n, j) => (
                <li key={j}>
                  <NodeCard k={`p${i}n${j}`} n={n} dashed={p.status === "incomplete"} />
                  {j < p.nodes.length - 1 && <ArrowDown className={cn("mx-auto my-0.5 size-4 text-muted-foreground", p.status === "incomplete" && "opacity-50")} aria-hidden />}
                </li>
              ))}
            </ol>
          </Card>
        ))}
        {df.related.length > 0 && (
          <Card className="p-3">
            <div className="mb-2 text-[12.5px] font-semibold">Related locations reported by the scanner</div>
            <div className="grid gap-2 md:grid-cols-2">
              {df.related.map((n, j) => <NodeCard key={j} k={`r${j}`} n={n} dashed />)}
            </div>
            {df.sink && (
              <p className="mt-2 text-[12px] text-muted-foreground">
                Reported location: <span className="font-mono">{df.sink.file_path}{df.sink.line ? `:${df.sink.line}` : ""}</span>
              </p>
            )}
          </Card>
        )}
        <Panel title="Analyst-traced data flow">
          <p className="mb-2 text-[12px] text-muted-foreground">
            Record the flow you traced manually (entry point → controller → service → sink), including validation, sanitization and authorization you found.
            This is your assessment, kept apart from what the scanner reported.
          </p>
          <textarea
            aria-label="Analyst-traced data flow"
            rows={5}
            className={textareaCls}
            disabled={!editable}
            value={notes["manual_flow"] ?? ""}
            onChange={(e) => s.set("dataflow_notes", "manual_flow", e.target.value)}
            placeholder="e.g. GET /search?q= (UserController.search) → SearchService.find(q) → OrderRepository.query(sql) — no parameter binding; no authorization check"
          />
        </Panel>
        <SaveBar s={s} editable={editable} d={d} />
      </div>
      <aside className="space-y-3">
        {selected ? (
          <Card className="p-3 text-[12.5px]">
            <div className="mb-1 font-semibold">{roleStyle[selected[1].role].label}</div>
            <button type="button" className="font-mono text-primary hover:underline" onClick={() => openSource(selected[1].file_path, selected[1].line)}>
              Open {selected[1].file_path}{selected[1].line ? `:${selected[1].line}` : ""} at the scanned commit
            </button>
            <div className="mt-3 space-y-2">
              {annotations.map(([a, label]) => (
                <div key={a}>
                  <Label htmlFor={`ann-${a}`}>{label}</Label>
                  <textarea
                    id={`ann-${a}`}
                    rows={2}
                    className={textareaCls}
                    disabled={!editable}
                    value={notes[`${selected[0]}.${a}`] ?? ""}
                    onChange={(e) => s.set("dataflow_notes", `${selected[0]}.${a}`, e.target.value)}
                  />
                </div>
              ))}
            </div>
          </Card>
        ) : (
          <Card className="flex gap-2 p-3 text-[12.5px] text-muted-foreground">
            <Info className="size-4 shrink-0" />
            {nodes.length ? "Select a step to open its code and record validation, sanitization or authorization checks." : "No steps were reported. Use the source code tab to trace the flow."}
          </Card>
        )}
      </aside>
    </div>
  );
}

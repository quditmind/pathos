import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { FileCode2, GitCommitHorizontal, Lock, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, EmptyState, Input, Select, Skeleton } from "@/components/ui/primitives";
import { cn, formatDateTime } from "@/lib/utils";
import { useSource, useSourceCommits } from "../api";
import { diffLines, hunks } from "../lib/diff";
import { findReferences, findSymbols, highlightLines, type Token } from "../lib/highlight";
import type { ReviewDetail } from "../types";

const tokenClass: Record<Token["kind"], string> = {
  kw: "text-[var(--code-keyword,#7c3aed)] font-medium",
  str: "text-[var(--code-string,#15803d)]",
  com: "text-muted-foreground italic",
  num: "text-[var(--code-number,#b45309)]",
  fn: "text-[var(--code-function,#1d4ed8)]",
  type: "text-[var(--code-type,#0e7490)]",
  plain: "",
};

function Line({ tokens, onIdent }: { tokens: Token[]; onIdent?: (w: string) => void }) {
  return (
    <>
      {tokens.map((t, i) =>
        (t.kind === "fn" || t.kind === "plain" || t.kind === "type") && onIdent && /^[A-Za-z_$][\w$]*$/.test(t.text) ? (
          <span key={i} className={cn(tokenClass[t.kind], "cursor-pointer hover:underline")} onClick={() => onIdent(t.text)}>
            {t.text}
          </span>
        ) : (
          <span key={i} className={tokenClass[t.kind]}>{t.text}</span>
        ),
      )}
    </>
  );
}

const shortSha = (s: string) => (s ? s.slice(0, 10) : "—");

/** Source code at the scanned commit, with navigation and comparison. */
export function SourceTab({ d, path, line }: { d: ReviewDetail; path?: string; line?: number }) {
  const navigate = useNavigate();
  const file = path || d.file_path;
  const isFindingFile = file === d.file_path;
  const focus = line ?? (isFindingFile ? d.start_line ?? undefined : undefined);
  const [context, setContext] = useState<number | "all">(30);
  const [compare, setCompare] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [goto, setGoto] = useState(file);
  useEffect(() => setGoto(file), [file]);
  const src = useSource(d.id, file, d.commit_sha, !!file);
  const commits = useSourceCommits(d.id, file, !!file && d.source_type === "scm");
  const other = useSource(d.id, file, compare, !!compare);
  const s = src.data;
  const tokens = useMemo(() => (s?.available ? highlightLines(s.lines, s.language) : []), [s]);
  const symbols = useMemo(() => (s?.available ? findSymbols(s.lines) : []), [s]);
  const refs = useMemo(() => (selected && s?.available ? findReferences(s.lines, selected) : []), [selected, s]);
  const focusRef = useRef<HTMLTableRowElement>(null);
  useEffect(() => focusRef.current?.scrollIntoView?.({ block: "center" }), [s, focus, context]);

  const setPath = (p: string, l?: number) => void navigate({ to: ".", search: { tab: "source", path: p, ...(l ? { line: l } : {}) } as never, replace: true });
  const jump = (l: number) => setPath(file, l);

  if (!file) return <EmptyState icon={<FileCode2 />} title="The scanner did not report a file for this finding" />;

  const total = s?.lines.length ?? 0;
  const center = focus ?? 1;
  const from = context === "all" ? 1 : Math.max(1, center - context);
  const to = context === "all" ? total : Math.min(total, center + context);

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_240px]">
      <Card className="min-w-0">
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2 text-[12px]">
          <form
            className="relative flex-1"
            onSubmit={(e) => {
              e.preventDefault();
              if (goto.trim()) setPath(goto.trim());
            }}
          >
            <FileCode2 className="pointer-events-none absolute left-2 top-2 size-4 text-muted-foreground" aria-hidden />
            <Input aria-label="File path in the repository" value={goto} onChange={(e) => setGoto(e.target.value)} className="pl-7 font-mono text-[12px]" />
          </form>
          {!isFindingFile && (
            <Button size="sm" variant="ghost" onClick={() => setPath(d.file_path, d.start_line ?? undefined)}>Back to finding</Button>
          )}
          <Select aria-label="Surrounding lines" value={String(context)} onChange={(e) => setContext(e.target.value === "all" ? "all" : Number(e.target.value))}>
            {[20, 30, 50].map((n) => <option key={n} value={n}>±{n} lines</option>)}
            <option value="all">Whole file</option>
          </Select>
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border bg-surface-muted/40 px-3 py-1.5 text-[11.5px] text-muted-foreground">
          <span>{d.repository_name}</span>
          <span>branch <span className="font-mono">{d.branch || "—"}</span></span>
          <span className="flex items-center gap-1">
            <GitCommitHorizontal className="size-3.5" />
            {d.source_type === "upload" ? "uploaded snapshot (as scanned)" : <span className="font-mono">{d.commit_sha || "commit not recorded"}</span>}
          </span>
          <Badge tone="primary">Scanned version</Badge>
          {s?.origin && <span>source: {s.origin === "scm" ? "SCM provider" : "encrypted snapshot"}</span>}
          {s?.redacted && (
            <span className="flex items-center gap-1 text-warning"><Lock className="size-3" /> secret values redacted</span>
          )}
        </div>
        {s?.available && !d.start_line && (
          <p className="border-b border-border px-3 py-1.5 text-[12px] text-muted-foreground">
            The scanner did not report a line for this finding (typical for dependency findings in a manifest or lockfile); the whole file is shown.
          </p>
        )}
        {src.isError ? (
          <div className="p-4"><Alert>{src.error.message}</Alert></div>
        ) : src.isPending ? (
          <Skeleton className="m-3 h-96" />
        ) : s && !s.available ? (
          <div className="space-y-3 p-4">
            <Alert tone="warning">Source code unavailable: {s.unavailable_message}</Alert>
            {s.scanner_context ? (
              <>
                <p className="text-[12px] text-muted-foreground">Code context captured by the scanner at scan time (redacted, may be partial):</p>
                <pre className="overflow-auto rounded-md bg-surface-muted p-3 font-mono text-[12px] leading-relaxed">
                  {s.scanner_context.split("\n").map((l, i) => {
                    const n = (s.scanner_context_start ?? 1) + i;
                    return (
                      <div key={i} className={cn(n === d.start_line && "bg-danger-soft")}>
                        <span className="mr-3 inline-block w-10 select-none text-right text-muted-foreground">{n}</span>
                        {l}
                      </div>
                    );
                  })}
                </pre>
              </>
            ) : (
              <p className="text-[12px] text-muted-foreground">No scanner-captured context is available either.</p>
            )}
          </div>
        ) : s ? (
          <div className="max-h-[70vh] overflow-auto">
            <table className="w-full border-collapse font-mono text-[12px] leading-[1.55]">
              <tbody>
                {from > 1 && (
                  <tr>
                    <td colSpan={2} className="bg-surface-muted/50 px-3 py-0.5 text-[11px] text-muted-foreground">
                      <button type="button" className="hover:underline" onClick={() => setContext("all")}>… {from - 1} lines above</button>
                    </td>
                  </tr>
                )}
                {tokens.slice(from - 1, to).map((tk, i) => {
                  const n = from + i;
                  const hit = n === focus;
                  const ref = refs.includes(n);
                  return (
                    <tr key={n} ref={hit ? focusRef : undefined} className={cn(hit ? "bg-danger-soft" : ref ? "bg-warning-soft/60" : "hover:bg-surface-muted/40")}>
                      <td className={cn("w-12 select-none border-r border-border px-2 text-right align-top text-muted-foreground", hit && "font-bold text-danger")}>
                        <button type="button" onClick={() => jump(n)} aria-label={`Line ${n}`} className="w-full text-right">{n}</button>
                      </td>
                      <td className="whitespace-pre px-3">
                        <Line tokens={tk} onIdent={setSelected} />
                        {hit && <span className="sr-only"> (vulnerable line)</span>}
                      </td>
                    </tr>
                  );
                })}
                {to < total && (
                  <tr>
                    <td colSpan={2} className="bg-surface-muted/50 px-3 py-0.5 text-[11px] text-muted-foreground">
                      <button type="button" className="hover:underline" onClick={() => setContext("all")}>… {total - to} lines below</button>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            {s.truncated && <p className="p-2 text-[11.5px] text-muted-foreground">Only the first 20,000 lines are shown.</p>}
          </div>
        ) : null}

        {compare && (
          <div className="border-t border-border">
            <div className="flex items-center justify-between px-3 py-2 text-[12px]">
              <span>
                Changes from the scanned commit <span className="font-mono">{shortSha(d.commit_sha)}</span> to <span className="font-mono">{shortSha(compare)}</span>
              </span>
              <Button size="sm" variant="ghost" onClick={() => setCompare("")}>Close comparison</Button>
            </div>
            <CompareView base={s?.available ? s.lines : null} other={other.data} pending={other.isPending} error={other.error} />
          </div>
        )}
      </Card>

      <div className="space-y-4">
        <Card className="p-3">
          <h3 className="mb-2 text-[12px] font-semibold">Symbols in this file</h3>
          {symbols.length ? (
            <ul className="max-h-60 space-y-0.5 overflow-auto text-[12px]">
              {symbols.map((sym) => (
                <li key={`${sym.name}-${sym.line}`}>
                  <button type="button" className="flex w-full justify-between gap-2 rounded px-1 hover:bg-surface-muted" onClick={() => { jump(sym.line); setSelected(sym.name); }}>
                    <span className="truncate font-mono">{sym.name}</span>
                    <span className="tabular text-muted-foreground">{sym.line}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[12px] text-muted-foreground">No function definitions recognised.</p>
          )}
        </Card>
        <Card className="p-3">
          <h3 className="mb-1 flex items-center gap-1 text-[12px] font-semibold"><Search className="size-3.5" /> References</h3>
          {selected ? (
            <>
              <p className="mb-1 text-[12px]">
                <span className="font-mono">{selected}</span> appears on {refs.length} line{refs.length === 1 ? "" : "s"} of this file:
              </p>
              <div className="flex max-h-40 flex-wrap gap-1 overflow-auto">
                {refs.map((n) => (
                  <button key={n} type="button" className="tabular rounded bg-surface-muted px-1.5 text-[11.5px] hover:bg-primary/10" onClick={() => jump(n)}>{n}</button>
                ))}
              </div>
              <p className="mt-2 text-[11px] text-muted-foreground">References in other files: open the file by path above.</p>
            </>
          ) : (
            <p className="text-[12px] text-muted-foreground">Click an identifier in the code to find its references.</p>
          )}
        </Card>
        {d.source_type === "scm" && (
          <Card className="p-3">
            <h3 className="mb-2 text-[12px] font-semibold">Commit history & comparison</h3>
            {commits.isPending ? (
              <Skeleton className="h-20" />
            ) : commits.data ? (
              <div className="space-y-2 text-[12px]">
                {commits.data.history_unavailable && <p className="text-muted-foreground">{commits.data.history_unavailable}</p>}
                {[...(commits.data.head ? [commits.data.head] : []), ...commits.data.occurrences, ...commits.data.history]
                  .filter((c, i, all) => c.sha && c.sha !== d.commit_sha && all.findIndex((x) => x.sha === c.sha) === i)
                  .slice(0, 30)
                  .map((c) => (
                    <div key={c.sha} className={cn("rounded border border-border p-1.5", compare === c.sha && "border-primary bg-primary/5")}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono">{shortSha(c.sha)}</span>
                        <Button size="sm" variant="ghost" onClick={() => setCompare(c.sha)} aria-label={`Compare with ${c.sha}`}>Compare</Button>
                      </div>
                      <div className="truncate" title={c.message || c.label}>{c.label}</div>
                      <div className="text-[11px] text-muted-foreground">{[c.author, formatDateTime(c.committed_at)].filter(Boolean).join(" · ")}</div>
                    </div>
                  ))}
              </div>
            ) : commits.error ? (
              <p className="text-danger">{commits.error.message}</p>
            ) : null}
          </Card>
        )}
      </div>
    </div>
  );
}

function CompareView({ base, other, pending, error }: { base: string[] | null; other?: { available: boolean; lines: string[]; unavailable_message?: string }; pending: boolean; error: Error | null }) {
  const result = useMemo(() => (base && other?.available ? diffLines(base, other.lines) : null), [base, other]);
  if (error) return <div className="p-3"><Alert>{error.message}</Alert></div>;
  if (pending) return <Skeleton className="m-3 h-40" />;
  if (!other?.available) return <p className="p-3 text-[12px] text-muted-foreground">The other version is unavailable: {other?.unavailable_message}</p>;
  if (!base) return <p className="p-3 text-[12px] text-muted-foreground">The scanned version is unavailable.</p>;
  if (!result) return <p className="p-3 text-[12px] text-muted-foreground">The versions differ too much to compare here.</p>;
  if (result.every((l) => l.op === "equal")) return <p className="p-3 text-[12px] text-muted-foreground">No changes to this file.</p>;
  return (
    <div className="max-h-[50vh] overflow-auto">
      <table className="w-full border-collapse font-mono text-[12px] leading-[1.5]">
        <tbody>
          {hunks(result).map((l, i) =>
            l === null ? (
              <tr key={i}><td colSpan={3} className="bg-surface-muted/50 px-3 text-[11px] text-muted-foreground">⋯</td></tr>
            ) : (
              <tr key={i} className={l.op === "insert" ? "bg-success-soft" : l.op === "delete" ? "bg-danger-soft" : ""}>
                <td className="w-10 select-none px-1 text-right text-muted-foreground">{l.op !== "insert" ? l.a : ""}</td>
                <td className="w-10 select-none border-r border-border px-1 text-right text-muted-foreground">{l.op !== "delete" ? l.b : ""}</td>
                <td className="whitespace-pre px-3">
                  <span aria-hidden>{l.op === "insert" ? "+ " : l.op === "delete" ? "- " : "  "}</span>
                  <span className="sr-only">{l.op === "insert" ? "added" : l.op === "delete" ? "removed" : ""}</span>
                  {l.text}
                </td>
              </tr>
            ),
          )}
        </tbody>
      </table>
    </div>
  );
}

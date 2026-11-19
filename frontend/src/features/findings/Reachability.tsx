import { Link } from "@tanstack/react-router";
import type { Finding, ReachFrame, ReachabilityMethod } from "@/api/types";
import { formatDateTime } from "@/lib/utils";

export const reachabilityLabel: Record<string, string> = { reachable: "Reachable", not_reachable: "Not reachable", unknown: "Unknown" };

/** How the answer was decided, in words. */
export const reachabilityMethodLabel: Record<ReachabilityMethod, string> = {
  "": "not analysed",
  import: "package level: the code's imports",
  call_graph: "function level: call graph (govulncheck)",
  symbol_calls: "function level: calls in the code (pathos-reach)",
};

function frameText(f: ReachFrame) {
  return f.file ? `${f.file}:${f.line}` : f.function;
}

/**
 * Reachability of a dependency finding: the answer, how it was decided and
 * why, and for a function-level answer its evidence: the vulnerable
 * functions checked, the call paths (outermost caller first, ending at the
 * vulnerable call) and what made it unknown.
 */
export function ReachabilitySection({ f }: { f: Pick<Finding, "reachability" | "reachability_basis" | "reachability_method" | "reachability_evidence"> }) {
  if (!f.reachability) return null;
  const ev = f.reachability_evidence;
  const method = f.reachability_method ?? "";
  return (
    <div className="col-span-2" data-testid="reachability">
      <dt className="text-[12px] text-muted-foreground">Reachability</dt>
      <dd>
        {reachabilityLabel[f.reachability] ?? f.reachability}
        {f.reachability_basis && <span className="text-muted-foreground"> — {f.reachability_basis}</span>}
        <div className="text-[11.5px] text-muted-foreground">Decided by: {reachabilityMethodLabel[method] ?? method}</div>
        {ev && (
          <div className="mt-2 space-y-2 text-[12px]">
            {ev.symbols.length > 0 && (
              <div>
                <span className="text-muted-foreground">Vulnerable functions checked: </span>
                <span className="break-all font-mono text-[11.5px]">{ev.symbols.join(", ")}</span>
              </div>
            )}
            {ev.paths.length > 0 && (
              <div>
                <div className="text-muted-foreground">{ev.paths.length === 1 ? "Call path" : `Call paths (${ev.paths.length})`}</div>
                {ev.paths.map((p, i) => (
                  <ol key={i} aria-label={`Call path ${i + 1}`} className="mt-1 space-y-0.5 rounded-md border border-border bg-muted/40 p-2 font-mono text-[11.5px]">
                    {p.map((fr, j) => (
                      <li key={j} className="flex gap-2" style={{ paddingLeft: `${Math.min(j, 8) * 10}px` }}>
                        <span aria-hidden className="select-none text-muted-foreground">{j === 0 ? "•" : "↳"}</span>
                        <span className="break-all">{frameText(fr)}</span>
                        {fr.function && fr.file && <span className="break-all text-muted-foreground">{fr.function}</span>}
                      </li>
                    ))}
                  </ol>
                ))}
              </div>
            )}
            {(ev.dynamic ?? []).length > 0 && (
              <div>
                <div className="text-muted-foreground">Dynamic use the analysis cannot follow</div>
                <ul className="mt-1 list-disc pl-5">
                  {ev.dynamic!.map((d, i) => (
                    <li key={i}>
                      {d.reason} {d.module ? <span className="font-mono text-[11.5px]">({d.module})</span> : "(any module)"} at{" "}
                      <span className="font-mono text-[11.5px]">{d.file}:{d.line}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {(ev.unresolved ?? []).length > 0 && (
              <div>
                <div className="text-muted-foreground">Calls on values of unknown type</div>
                <ul className="mt-1 list-disc pl-5 font-mono text-[11.5px]">
                  {ev.unresolved!.map((fr, i) => <li key={i}>{frameText(fr)} {fr.function}</li>)}
                </ul>
              </div>
            )}
            <div className="text-[11.5px] text-muted-foreground">
              {ev.tool}
              {ev.analysed_at && <> · analysed {formatDateTime(ev.analysed_at)}</>}
              {ev.scan_job_id && <> · <Link to="/scans" search={{ job: ev.scan_job_id } as never} className="text-primary hover:underline">scan</Link></>}
              {ev.limits && <div className="mt-1">Limits: {ev.limits}</div>}
            </div>
          </div>
        )}
      </dd>
    </div>
  );
}

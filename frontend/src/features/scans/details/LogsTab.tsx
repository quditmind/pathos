import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { CATALOG_TOOLS, redactToolNames, toolCheckLabel } from "@/lib/checkKinds";
import { Download, ScrollText } from "lucide-react";
import type { ScanJob, ScanLogLine } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Card, EmptyState, Select, Spinner } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import { fetchScanLogs, isActive } from "../api";

const ROW = 20;
const VIEWPORT = 480;
/** Pages of 1000 lines fetched in one go before asking the user to continue. */
const MAX_PAGES = 20;

const levelTone: Record<ScanLogLine["level"], string> = {
  debug: "bg-surface-muted text-muted-foreground",
  info: "bg-primary/10 text-primary",
  warn: "bg-warning-soft text-warning",
  error: "bg-danger-soft text-danger",
};

function time(iso: string) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString(undefined, { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

/** Log sources that are engines are shown as their kind of check (rule 3); platform sources keep their name. */
function sourceLabel(source: string): string {
  return CATALOG_TOOLS.some((t) => t.key === source) || /^import-/.test(source) ? toolCheckLabel(source) : redactToolNames(source);
}

export function logsAsText(lines: ScanLogLine[]): string {
  return lines.map((l) => `${l.at}\t${l.level.toUpperCase()}\t${l.source}\t${l.message}`).join("\n") + "\n";
}

/**
 * Execution logs: loads all lines for the filters, then tails new ones with
 * after_id every `pollMs` while the execution is queued or running.
 */
export function LogsTab({ job, pollMs = 3000 }: { job: ScanJob; pollMs?: number }) {
  const [source, setSource] = useState("");
  const [level, setLevel] = useState("");
  const [lines, setLines] = useState<ScanLogLine[]>([]);
  const [sources, setSources] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [truncated, setTruncated] = useState(false);
  const [follow, setFollow] = useState(true);
  const [scrollTop, setScrollTop] = useState(0);
  const lastId = useRef(0);
  const gen = useRef(0);
  const busy = useRef(false);
  const box = useRef<HTMLDivElement>(null);
  const live = isActive(job);

  /** Fetches lines after lastId (up to `pages` pages) for generation g. */
  const fetchAfter = useCallback(
    async (g: number, pages: number) => {
      if (busy.current) return;
      busy.current = true;
      try {
        for (let i = 0; i < pages; i++) {
          const r = await fetchScanLogs(job.id, { source: source || undefined, level: level || undefined, after_id: lastId.current || undefined });
          if (g !== gen.current) return;
          setSources(r.sources ?? []);
          if (r.items.length) {
            lastId.current = Math.max(lastId.current, r.items[r.items.length - 1]!.id);
            setLines((prev) => {
              const last = prev.length ? prev[prev.length - 1]!.id : 0;
              return [...prev, ...r.items.filter((x) => x.id > last)];
            });
          }
          setError("");
          if (r.next_after_id == null) {
            setTruncated(false);
            return;
          }
          if (i === pages - 1) setTruncated(true);
        }
      } catch (e) {
        if (g === gen.current) setError((e as Error).message);
      } finally {
        busy.current = false;
      }
    },
    [job.id, source, level],
  );

  // Reload from the start whenever the filters change.
  useEffect(() => {
    const g = ++gen.current;
    lastId.current = 0;
    busy.current = false;
    setLines([]);
    setLoading(true);
    void fetchAfter(g, MAX_PAGES).finally(() => g === gen.current && setLoading(false));
  }, [fetchAfter]);

  // Live tail while the execution is active, plus one last fetch when it ends.
  useEffect(() => {
    if (!live) return;
    const t = setInterval(() => void fetchAfter(gen.current, 1), pollMs);
    return () => {
      clearInterval(t);
      void fetchAfter(gen.current, MAX_PAGES);
    };
  }, [live, pollMs, fetchAfter]);

  useLayoutEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [lines, follow]);

  const height = box.current?.clientHeight || VIEWPORT;
  const start = Math.max(0, Math.floor(scrollTop / ROW) - 20);
  const end = Math.min(lines.length, Math.ceil((scrollTop + height) / ROW) + 20);
  const visible = lines.slice(start, end);

  const download = () => {
    const url = URL.createObjectURL(new Blob([logsAsText(lines)], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${job.scan_key || job.id}-logs.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2 border-b border-border p-3" role="group" aria-label="Log filters">
        <Select aria-label="Log source" value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="">All sources</option>
          {[...new Set([...sources, ...(source ? [source] : [])])].map((s) => (
            <option key={s} value={s}>{sourceLabel(s)}</option>
          ))}
        </Select>
        <Select aria-label="Minimum level" value={level} onChange={(e) => setLevel(e.target.value)}>
          <option value="">All levels</option>
          <option value="info">Info and above</option>
          <option value="warn">Warnings and errors</option>
          <option value="error">Errors only</option>
        </Select>
        {live && (
          <span className="flex items-center gap-1.5 text-[12px] text-primary">
            <span className="size-2 animate-pulse rounded-full bg-primary" aria-hidden /> Live
          </span>
        )}
        <label className="flex items-center gap-1.5 text-[12px] text-muted-foreground">
          <input type="checkbox" className="size-3.5 accent-[var(--primary)]" checked={follow} onChange={(e) => setFollow(e.target.checked)} /> Follow
        </label>
        <div className="ml-auto flex items-center gap-2">
          <span className="tabular text-[12px] text-muted-foreground">{lines.length} lines</span>
          <Button variant="ghost" size="sm" disabled={!lines.length} onClick={download}>
            <Download /> Download .txt
          </Button>
        </div>
      </div>
      {error && <div className="p-3"><Alert>Could not load logs: {error}</Alert></div>}
      {loading && !lines.length ? (
        <div className="flex items-center gap-2 p-4 text-[13px] text-muted-foreground"><Spinner /> Loading logs…</div>
      ) : !lines.length ? (
        <EmptyState icon={<ScrollText />} title="No log lines">{live ? "Lines appear here while the execution runs." : "No lines match these filters."}</EmptyState>
      ) : (
        <div
          ref={box}
          role="log"
          aria-label="Execution log"
          aria-live={live ? "polite" : "off"}
          className="overflow-auto bg-surface-muted/30 font-mono text-[12px]"
          style={{ height: Math.min(VIEWPORT, lines.length * ROW + 8) }}
          onScroll={(e) => {
            const el = e.currentTarget;
            setScrollTop(el.scrollTop);
            const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < ROW * 2;
            if (follow !== atBottom) setFollow(atBottom);
          }}
        >
          <ol style={{ height: lines.length * ROW, position: "relative" }} className="min-w-max">
            {visible.map((l, i) => (
              <li key={l.id} data-testid="log-line" className="absolute left-0 flex items-center gap-2 whitespace-pre px-3" style={{ top: (start + i) * ROW, height: ROW }}>
                <time className="tabular text-muted-foreground" dateTime={l.at}>{time(l.at)}</time>
                <span className={cn("w-12 rounded px-1 text-center text-[10.5px] font-semibold uppercase", levelTone[l.level])}>{l.level}</span>
                <span className="w-24 truncate text-muted-foreground" title={sourceLabel(l.source)}>{sourceLabel(l.source)}</span>
                <span>{redactToolNames(l.message)}</span>
              </li>
            ))}
          </ol>
        </div>
      )}
      {truncated && (
        <div className="flex items-center justify-between border-t border-border px-3 py-2 text-[12px] text-muted-foreground">
          More lines are available.
          <Button size="sm" variant="secondary" onClick={() => void fetchAfter(gen.current, MAX_PAGES)}>Load more</Button>
        </div>
      )}
    </Card>
  );
}

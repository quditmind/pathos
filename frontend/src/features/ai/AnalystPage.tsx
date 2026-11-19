import { useEffect, useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, MessageSquarePlus, Send, Trash2, User } from "lucide-react";
import { api } from "@/api/client";
import { SeverityBadge } from "@/components/data/Severity";
import type { Severity } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Card, EmptyState, PageHeader, Skeleton } from "@/components/ui/primitives";
import { cn, formatDateTime } from "@/lib/utils";
import { ErrorPanel } from "@/components/ui/error-panel";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  citations: { id: string; title: string; severity: Severity }[];
  follow_ups: string[];
  context_findings: number;
  model?: string;
  input_tokens: number;
  output_tokens: number;
  created_at: string;
}
interface Conversation {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  messages?: Message[];
}

/** Minimal, safe Markdown: paragraphs, bullet lists, **bold** and `code` (no HTML is ever injected). */
function Markdown({ text }: { text: string }) {
  const inline = (s: string) =>
    s.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, i) =>
      part.startsWith("**") && part.endsWith("**") ? <strong key={i}>{part.slice(2, -2)}</strong>
        : part.startsWith("`") && part.endsWith("`") ? <code key={i} className="rounded bg-surface-muted px-1 font-mono text-[12px]">{part.slice(1, -1)}</code>
        : part,
    );
  const blocks = text.split(/\n{2,}/);
  return (
    <div className="space-y-2">
      {blocks.map((b, i) => {
        const lines = b.split("\n");
        if (lines.every((l) => /^\s*([-*]|\d+\.)\s/.test(l))) {
          return <ul key={i} className="list-disc space-y-0.5 pl-5">{lines.map((l, j) => <li key={j}>{inline(l.replace(/^\s*([-*]|\d+\.)\s/, ""))}</li>)}</ul>;
        }
        if (/^#{1,4}\s/.test(b)) return <p key={i} className="font-semibold">{inline(b.replace(/^#{1,4}\s/, ""))}</p>;
        return <p key={i} className="whitespace-pre-wrap">{inline(b)}</p>;
      })}
    </div>
  );
}

const starters = [
  "What should we fix first this week?",
  "Which actively exploited vulnerabilities (KEV) are open?",
  "Which applications have the highest risk, and why?",
  "Summarize our SQL injection findings.",
];

function Thread({ id }: { id: string }) {
  const qc = useQueryClient();
  const conv = useQuery({ queryKey: ["analyst", "conversation", id], queryFn: () => api<Conversation>(`/api/v1/ai/analyst/conversations/${id}`) });
  const [q, setQ] = useState("");
  const end = useRef<HTMLDivElement>(null);
  const ask = useMutation({
    mutationFn: (question: string) => api<{ messages: Message[] }>(`/api/v1/ai/analyst/conversations/${id}/messages`, { method: "POST", body: { question } }),
    onSuccess: (r) => {
      qc.setQueryData(["analyst", "conversation", id], (c: Conversation | undefined) => (c ? { ...c, messages: r.messages } : c));
      void qc.invalidateQueries({ queryKey: ["analyst", "conversations"] });
      setQ("");
    },
  });
  useEffect(() => end.current?.scrollIntoView?.({ block: "end" }), [conv.data?.messages?.length, ask.isPending]);
  const send = (text: string) => {
    const t = text.trim();
    if (t.length >= 3 && !ask.isPending) ask.mutate(t);
  };
  if (conv.isError) return <ErrorPanel error={conv.error} />;
  if (conv.isPending) return <Skeleton className="h-64" />;
  const msgs = conv.data.messages ?? [];
  return (
    <Card className="flex min-h-[60vh] flex-col">
      <div className="flex-1 space-y-3 overflow-auto p-4" aria-live="polite">
        {!msgs.length && (
          <div className="space-y-2">
            <p className="text-[13px] text-muted-foreground">Ask about your findings, applications and risks. Answers use only the data you can see in PATHOS and cite the findings they rely on.</p>
            <div className="flex flex-wrap gap-2">
              {starters.map((s) => <Button key={s} size="sm" variant="secondary" onClick={() => send(s)} disabled={ask.isPending}>{s}</Button>)}
            </div>
          </div>
        )}
        {msgs.map((m) => (
          <div key={m.id} className={cn("flex gap-2", m.role === "user" && "justify-end")}>
            {m.role === "assistant" && <Bot className="mt-1 size-4 shrink-0 text-primary" aria-label="AI Security Analyst" />}
            <div className={cn("max-w-[80%] rounded-lg px-3 py-2 text-[13px]", m.role === "user" ? "bg-primary/10" : "border border-border bg-surface")}>
              {m.role === "assistant" ? <Markdown text={m.content} /> : <p className="whitespace-pre-wrap">{m.content}</p>}
              {m.citations.length > 0 && (
                <div className="mt-2 border-t border-border pt-1.5">
                  <div className="text-[11px] font-medium text-muted-foreground">Findings cited</div>
                  <ul className="space-y-0.5 text-[12px]">
                    {m.citations.map((c) => (
                      <li key={c.id} className="flex items-center gap-1.5">
                        <SeverityBadge value={c.severity} />
                        <Link to="/findings" search={{ finding: c.id } as never} className="truncate text-primary hover:underline">{c.title}</Link>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {m.role === "assistant" && (
                <div className="mt-1.5 text-[10.5px] text-muted-foreground">
                  {m.model} · answered from {m.context_findings} findings · {formatDateTime(m.created_at)} · AI-generated; check before acting
                </div>
              )}
              {m.follow_ups.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {m.follow_ups.map((f) => <Button key={f} size="sm" variant="ghost" className="h-auto py-0.5 text-left text-[11.5px]" onClick={() => send(f)} disabled={ask.isPending}>{f}</Button>)}
                </div>
              )}
            </div>
            {m.role === "user" && <User className="mt-1 size-4 shrink-0 text-muted-foreground" aria-hidden />}
          </div>
        ))}
        {ask.isPending && <p className="text-[12px] text-muted-foreground">The analyst is reading your data…</p>}
        <div ref={end} />
      </div>
      {ask.error && <div className="px-4"><ErrorPanel error={ask.error} /></div>}
      <form className="flex gap-2 border-t border-border p-3" onSubmit={(e) => { e.preventDefault(); send(q); }}>
        <textarea aria-label="Your question" value={q} maxLength={2000} rows={2} onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(q); } }}
          placeholder="Ask about findings, applications, CVEs…" className="min-w-0 flex-1 resize-none rounded-md border border-border bg-surface px-3 py-2 text-[13px] focus-visible:outline-2 focus-visible:outline-ring" />
        <Button type="submit" disabled={q.trim().length < 3 || ask.isPending}><Send /> Ask</Button>
      </form>
    </Card>
  );
}

export function AnalystPage() {
  const qc = useQueryClient();
  const [active, setActive] = useState<string | null>(null);
  const list = useQuery({ queryKey: ["analyst", "conversations"], queryFn: () => api<{ items: Conversation[] }>("/api/v1/ai/analyst/conversations").then((r) => r.items) });
  const create = useMutation({
    mutationFn: () => api<Conversation>("/api/v1/ai/analyst/conversations", { method: "POST", body: {} }),
    onSuccess: (c) => {
      void qc.invalidateQueries({ queryKey: ["analyst", "conversations"] });
      setActive(c.id);
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/api/v1/ai/analyst/conversations/${id}`, { method: "DELETE" }),
    onSuccess: (_r, id) => {
      if (active === id) setActive(null);
      void qc.invalidateQueries({ queryKey: ["analyst", "conversations"] });
    },
  });
  useEffect(() => {
    if (!active && list.data?.length) setActive(list.data[0]!.id);
  }, [list.data, active]);
  return (
    <>
      <PageHeader
        title="AI Security Analyst"
        description="Ask questions about your security posture. Answers come only from data you can access, cite the findings they use, never include source code or secret values, and never change anything. Each question is recorded with the model and tokens used."
        actions={<Button onClick={() => create.mutate()} disabled={create.isPending}><MessageSquarePlus /> New conversation</Button>}
      />
      {create.error && <div className="mb-3"><ErrorPanel error={create.error} /></div>}
      <div className="grid gap-4 lg:grid-cols-[260px_minmax(0,1fr)]">
        <Card>
          {list.isError ? (
            <div className="p-3"><ErrorPanel error={list.error} /></div>
          ) : list.isPending ? (
            <Skeleton className="m-3 h-24" />
          ) : !list.data.length ? (
            <EmptyState icon={<Bot />} title="No conversations yet" />
          ) : (
            <ul className="divide-y divide-border">
              {list.data.map((c) => (
                <li key={c.id} className={cn("flex items-center gap-1 px-2 py-1.5", active === c.id && "bg-primary/5")}>
                  <button type="button" className="min-w-0 flex-1 text-left" onClick={() => setActive(c.id)}>
                    <div className="truncate text-[13px] font-medium">{c.title}</div>
                    <div className="text-[11px] text-muted-foreground">{formatDateTime(c.updated_at)}</div>
                  </button>
                  <Button size="icon" variant="ghost" aria-label={`Delete ${c.title}`} onClick={() => remove.mutate(c.id)}><Trash2 /></Button>
                </li>
              ))}
            </ul>
          )}
        </Card>
        {active ? <Thread key={active} id={active} /> : (
          <Card><EmptyState icon={<Bot />} title="Start a conversation">Select <strong>New conversation</strong> and ask a question.</EmptyState></Card>
        )}
      </div>
    </>
  );
}

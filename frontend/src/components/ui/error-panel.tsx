import { useState, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { BookOpen, Bot, Check, Copy, LifeBuoy, RotateCw, TriangleAlert } from "lucide-react";
import { api, ApiError, isCatalogueCode, maskPath, parseEnvelope, type EnvelopeStep, type ErrorEnvelope } from "@/api/client";
import { redactText } from "@/features/shell/diagnostics";
import { Button } from "./button";
import { Alert, Badge } from "./primitives";

/** POST /api/v1/diagnostics/troubleshoot: the envelope plus where the answer came from. */
export type TroubleshootAnswer = ErrorEnvelope & { source: "ai" | "catalogue"; model?: string; ai_unavailable?: string };

/** Reads a troubleshoot response (flat or wrapped in "error"). */
export function parseTroubleshoot(resp: unknown, requested: string): TroubleshootAnswer | undefined {
  if (!resp || typeof resp !== "object") return undefined;
  const r = resp as Record<string, unknown>;
  const body = (r.error && typeof r.error === "object" ? r.error : r) as Record<string, unknown>;
  const errorCode = typeof body.error_code === "string" ? body.error_code : typeof body.code === "string" && isCatalogueCode(body.code) ? body.code : requested;
  const env = parseEnvelope({ ...body, error_code: errorCode });
  if (!env) return undefined;
  const source = (r.source ?? body.source) === "ai" ? "ai" : "catalogue";
  const opt = (k: string) => (typeof r[k] === "string" && r[k] ? (r[k] as string) : undefined);
  return { ...env, source, model: opt("model"), ai_unavailable: opt("ai_unavailable") };
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "Something went wrong";
}

function CopyValue({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="inline-flex items-center gap-1">
      <span className="text-muted-foreground">{label}</span>
      <code className="rounded bg-surface-muted px-1 font-mono text-[12px] text-foreground">{value}</code>
      <button
        type="button"
        className="rounded p-0.5 text-muted-foreground hover:bg-surface-muted hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring"
        aria-label={`Copy ${label.toLowerCase()} ${value}`}
        onClick={() => {
          void navigator.clipboard?.writeText(value).then(
            () => setCopied(true),
            () => setCopied(false),
          );
          setTimeout(() => setCopied(false), 2000);
        }}
      >
        {copied ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />}
      </button>
      <span className="sr-only" aria-live="polite">
        {copied ? "Copied" : ""}
      </span>
    </span>
  );
}

function StepText({ step }: { step: EnvelopeStep }) {
  if (typeof step === "string") return <>{step}</>;
  if (!step.href) return <>{step.text}</>;
  return (
    <Link to={step.href as never} className="text-primary underline underline-offset-2">
      {step.text}
    </Link>
  );
}

function splitUrl(u: string): { to: string; hash?: string } {
  const [to, hash] = u.split("#");
  return { to: to || "/help/troubleshooting", hash };
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h3 className="mb-1 text-[12px] font-semibold tracking-wide text-muted-foreground uppercase">{title}</h3>
      {children}
    </div>
  );
}

/** The explanation part of an envelope (also used for the AI answer). */
export function EnvelopeBody({ env }: { env: ErrorEnvelope }) {
  const probable = env.cause && !env.cause.confirmed ? [env.cause.text, ...env.probable_causes] : env.probable_causes;
  return (
    <div className="space-y-3 text-[13px]">
      {env.cause?.confirmed && (
        <Section title="Confirmed cause">
          <p>
            <Badge tone="danger" className="mr-1.5">
              Confirmed
            </Badge>
            {env.cause.text}
          </p>
        </Section>
      )}
      {probable.length > 0 && (
        <Section title={env.cause?.confirmed ? "Other possible causes" : "Probable causes (not confirmed)"}>
          <ul className="list-disc space-y-0.5 pl-5">
            {probable.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </Section>
      )}
      {env.impact && (
        <Section title="Impact">
          <p>{env.impact}</p>
        </Section>
      )}
      {env.actions.length > 0 && (
        <Section title="How to fix it">
          <ol className="list-decimal space-y-0.5 pl-5">
            {env.actions.map((a, i) => (
              <li key={i}>
                <StepText step={a} />
              </li>
            ))}
          </ol>
        </Section>
      )}
      {env.verify.length > 0 && (
        <Section title="How to verify">
          <ol className="list-decimal space-y-0.5 pl-5">
            {env.verify.map((a, i) => (
              <li key={i}>
                <StepText step={a} />
              </li>
            ))}
          </ol>
        </Section>
      )}
    </div>
  );
}

/**
 * Renders an API error. Errors with a diagnostic envelope (error.error_code
 * PTH-…) get the full panel: copyable code and request ID, confirmed versus
 * probable cause, impact, numbered fixes, Verify, docs links and
 * "Troubleshoot with AI". Older errors keep the one-line alert they always
 * had (`title: message`).
 */
export function ErrorPanel({ error, title, onVerify }: { error: unknown; title?: string; onVerify?: () => unknown }) {
  const qc = useQueryClient();
  const [verifying, setVerifying] = useState(false);
  const env = error instanceof ApiError ? error.envelope : undefined;
  const ai = useMutation({
    mutationFn: async () => {
      const resp = await api<unknown>("/api/v1/diagnostics/troubleshoot", {
        method: "POST",
        body: {
          code: env!.error_code,
          ...(env!.request_id ? { request_id: env!.request_id } : {}),
          message: redactText(env!.message),
          context: { route: maskPath(window.location.pathname) },
        },
      });
      const parsed = parseTroubleshoot(resp, env!.error_code);
      if (!parsed) throw new Error("The troubleshooting answer could not be read.");
      return parsed;
    },
  });

  if (!env) {
    return (
      <Alert>
        {title ? `${title}: ` : null}
        {errorMessage(error)}
      </Alert>
    );
  }

  const verify = async () => {
    setVerifying(true);
    try {
      // Default: re-run the queries that failed.
      await (onVerify ? onVerify() : qc.refetchQueries({ type: "active", predicate: (q) => q.state.status === "error" }));
    } finally {
      setVerifying(false);
    }
  };
  const docs = env.docs_url ? splitUrl(env.docs_url) : undefined;
  const heading = env.title || title || "Something went wrong";

  return (
    <section role="alert" aria-label={heading} className="rounded-lg border border-danger/40 bg-surface text-[13px]">
      <div className="flex items-start gap-2.5 rounded-t-lg bg-danger-soft px-4 py-3 text-danger">
        <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
        <div className="min-w-0 flex-1">
          <h2 className="text-[14px] font-semibold">{heading}</h2>
          {env.message && env.message !== heading && <p className="mt-0.5 break-words text-foreground">{env.message}</p>}
        </div>
      </div>
      <div className="space-y-3 px-4 py-3">
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-[12px]">
          <CopyValue label="Code" value={env.error_code} />
          {env.request_id && <CopyValue label="Request ID" value={env.request_id} />}
        </div>
        <EnvelopeBody env={env} />
        <div className="flex flex-wrap items-center gap-2 border-t border-border pt-3">
          <Button size="sm" onClick={() => void verify()} disabled={verifying}>
            <RotateCw className={verifying ? "motion-safe:animate-spin" : undefined} /> {verifying ? "Verifying…" : "Verify"}
          </Button>
          {env.ai_help && (
            <Button size="sm" variant="secondary" onClick={() => ai.mutate()} disabled={ai.isPending}>
              <Bot /> {ai.isPending ? "Asking…" : "Troubleshoot with AI"}
            </Button>
          )}
          {docs && (
            <Button size="sm" variant="ghost" asChild>
              <Link to={docs.to as never} hash={docs.hash}>
                <BookOpen /> Read the docs
              </Link>
            </Button>
          )}
          <Button size="sm" variant="ghost" asChild>
            <Link to="/help/troubleshooting" search={{ q: env.error_code } as never}>
              <LifeBuoy /> Troubleshooting centre
            </Link>
          </Button>
        </div>
        {ai.isError && <Alert>Troubleshooting is unavailable: {errorMessage(ai.error)}. The steps above still apply.</Alert>}
        {ai.data && (
          <div className="rounded-md border border-border bg-surface-muted/50 p-3" aria-live="polite">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-[12px] font-semibold">Troubleshooting answer</span>
              {ai.data.source === "ai" ? (
                <Badge tone="warning">AI-inferred: check before acting</Badge>
              ) : (
                <Badge tone="neutral">From the error catalogue (AI not used)</Badge>
              )}
              {ai.data.source === "ai" && ai.data.model && <span className="text-[11px] text-muted-foreground">Model: {ai.data.model}</span>}
            </div>
            {ai.data.source === "catalogue" && ai.data.ai_unavailable && (
              <p className="mb-2 text-[12px] text-muted-foreground">AI was not used: {ai.data.ai_unavailable}</p>
            )}
            <EnvelopeBody env={ai.data} />
          </div>
        )}
      </div>
    </section>
  );
}

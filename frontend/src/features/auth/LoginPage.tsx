import { Button } from "@/components/ui/button";
import { Alert } from "@/components/ui/primitives";
import { useEffect, useState } from "react";
import { Wordmark } from "@/components/layout/Logo";
import { api, loginUrl } from "@/api/client";
import { displayVersion, isPreRelease, type Meta } from "@/features/shell/meta";
import { PreReleaseTag } from "@/features/shell/Brand";
import { renderDoc } from "@/features/help/content";
import { catalogueSection } from "@/features/help/troubleshooting";

/** The bundled catalogue entry of a sign-in error code (?code=PTH-AUTH-…), shown without the API. */
function SignInCode({ code }: { code: string }) {
  const entry = catalogueSection(code);
  return (
    <div className="mt-3 rounded-md border border-border p-3 text-[13px]" data-testid="login-error-code">
      <div className="flex flex-wrap items-center gap-2">
        <code className="rounded bg-surface-muted px-1 font-mono text-[12px]">{code}</code>
        {entry && <span className="font-medium">{entry.title}</span>}
      </div>
      {entry ? (
        <details className="mt-2">
          <summary className="cursor-pointer text-primary">Causes and fixes</summary>
          <article className="help-prose mt-2 text-[13px]" dangerouslySetInnerHTML={{ __html: renderDoc({ section: "troubleshooting", body: entry.body, headings: [] }) }} />
        </details>
      ) : (
        <p className="mt-1 text-muted-foreground">Give this code to your PATHOS administrator.</p>
      )}
    </div>
  );
}

/**
 * Backend version for the sign-in page (unauthenticated /api/v1/meta). The
 * page renders outside the query client, so this is a plain fetch; any
 * failure just hides the version.
 */
function useLoginVersion(): string {
  const [v, setV] = useState("");
  useEffect(() => {
    let live = true;
    api<Meta>("/api/v1/meta")
      .then((m) => live && typeof m?.version === "string" && setV(m.version))
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, []);
  return v;
}

const errors: Record<string, string> = {
  deactivated: "Your account is deactivated. Contact your PATHOS administrator.",
  idp_unavailable: "The identity provider is not reachable. Try again in a moment.",
  expired: "The sign-in attempt expired. Please try again.",
  invalid_state: "The sign-in attempt could not be verified. Please try again.",
  provisioning_failed: "Your account could not be set up. Contact your PATHOS administrator.",
};

export function LoginPage() {
  const params = new URLSearchParams(window.location.search);
  const error = params.get("error");
  const code = params.get("code") ?? "";
  const loggedOut = params.has("logged_out");
  const returnTo = params.get("return_to") ?? "/";
  const version = useLoginVersion();

  return (
    <div className="flex min-h-full items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <h1 className="flex flex-col items-center gap-3">
            <Wordmark size="lg" />
          </h1>
          <p className="mt-1 text-[13px] text-muted-foreground">Application Security Posture Management</p>
          {version && (
            <p className="mt-2 flex items-center gap-1.5 text-[12px] text-muted-foreground" data-testid="login-version">
              {displayVersion(version)}
              {isPreRelease(version) && <PreReleaseTag />}
            </p>
          )}
        </div>
        <div className="rounded-lg border border-border bg-surface p-6 shadow-sm">
          {error && (
            <div className="mb-4">
              <Alert>{errors[error] ?? "Sign-in failed. Please try again."}</Alert>
              {/^PTH-[A-Z]+-\d{4}$/.test(code) && <SignInCode code={code} />}
            </div>
          )}
          {loggedOut && !error && (
            <div className="mb-4">
              <Alert tone="success">You have been signed out.</Alert>
            </div>
          )}
          <Button size="lg" className="w-full" asChild>
            <a href={loginUrl(returnTo)}>Sign in</a>
          </Button>
          <p className="mt-4 text-center text-[12px] text-muted-foreground">
            Single sign-on through your organization&apos;s identity provider.
          </p>
        </div>
      </div>
    </div>
  );
}

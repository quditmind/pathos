import { Button } from "@/components/ui/button";
import { Alert } from "@/components/ui/primitives";
import { LogoMark } from "@/components/layout/Logo";
import { loginUrl } from "@/api/client";

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
  const loggedOut = params.has("logged_out");
  const returnTo = params.get("return_to") ?? "/";

  return (
    <div className="flex min-h-full items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <LogoMark className="size-12" />
          <h1 className="mt-4 text-xl font-semibold tracking-[0.14em]">PATHOS</h1>
          <p className="mt-1 text-[13px] text-muted-foreground">Application Security Posture Management</p>
        </div>
        <div className="rounded-lg border border-border bg-surface p-6 shadow-sm">
          {error && (
            <div className="mb-4">
              <Alert>{errors[error] ?? "Sign-in failed. Please try again."}</Alert>
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

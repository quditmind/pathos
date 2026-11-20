import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Globe } from "lucide-react";
import { api, ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, Input } from "@/components/ui/primitives";

export interface PublicRepoProbe {
  provider: string;
  full_name: string;
  url: string;
  clone_url: string;
  default_branch: string;
  description: string;
}

export interface AnonymousImportResult {
  status: "imported" | "would_import";
  repository_id?: string;
  anonymous: boolean;
  visibility: string;
  scan_queued: boolean;
  scan_error?: string;
  repository: PublicRepoProbe;
}

const providerLabels: Record<string, string> = {
  github: "GitHub",
  gitlab: "GitLab.com",
  bitbucket: "Bitbucket Cloud",
  azure_devops: "Azure DevOps",
  git: "Git over HTTPS",
};

function errorText(e: unknown): string {
  if (e instanceof ApiError) {
    const code = typeof e.details?.error_code === "string" ? ` (${e.details.error_code})` : "";
    return e.message + code;
  }
  return String(e);
}

/** Anonymous (token-less) import of a public repository by URL. */
export function PublicUrlImport({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const [url, setUrl] = useState("");
  const [checked, setChecked] = useState<AnonymousImportResult | null>(null);
  const run = useMutation({
    mutationFn: (dryRun: boolean) =>
      api<AnonymousImportResult>("/api/v1/repositories/import-url", { method: "POST", body: { url: url.trim(), dry_run: dryRun, start_scan: !dryRun } }),
    onSuccess: (res) => {
      setChecked(res);
      if (res.status === "imported") void qc.invalidateQueries({ queryKey: ["repositories"] });
    },
  });
  const imported = checked?.status === "imported" ? checked : null;

  return (
    <Card className="mt-6 p-4">
      <div className="flex items-start gap-3">
        <Globe className="mt-0.5 size-5 text-muted-foreground" aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 text-[13px] font-medium">
            Public repository by URL <Badge tone="warning">Anonymous · no token</Badge>
          </div>
          <div className="text-[12px] text-muted-foreground">
            GitHub, GitLab.com, Bitbucket Cloud, Azure DevOps public projects or any HTTPS git URL. Read-only: PATHOS clones it without credentials,
            so private repositories are refused. Pull request checks, fix pull requests and the source view need an SCM connection.
          </div>
          <form
            className="mt-3 flex flex-wrap gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              setChecked(null);
              run.mutate(true);
            }}
          >
            <Input
              aria-label="Public repository URL"
              className="min-w-[280px] flex-1"
              placeholder="https://github.com/owner/repository"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                setChecked(null);
                run.reset();
              }}
            />
            <Button type="submit" variant="secondary" disabled={!url.trim() || run.isPending || !canManage}>
              Check
            </Button>
            <Button type="button" disabled={checked?.status !== "would_import" || run.isPending || !canManage} onClick={() => run.mutate(false)}>
              Import and scan
            </Button>
          </form>
          {run.isError && (
            <div className="mt-3">
              <Alert>{errorText(run.error)}</Alert>
            </div>
          )}
          {checked && !imported && (
            <div className="mt-3 text-[12px]">
              <Badge tone="success">public</Badge> {providerLabels[checked.repository.provider] ?? checked.repository.provider} ·{" "}
              <span className="font-medium">{checked.repository.full_name}</span> · default branch {checked.repository.default_branch || "unknown"}
            </div>
          )}
          {imported && (
            <div className="mt-3">
              <Alert tone="success">
                Imported {imported.repository.full_name} anonymously.{" "}
                {imported.scan_queued ? "The first scan is queued." : imported.scan_error ? `The first scan was not queued: ${imported.scan_error}` : ""}{" "}
                <Link className="underline" to="/repositories">
                  Open repositories
                </Link>
              </Alert>
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}

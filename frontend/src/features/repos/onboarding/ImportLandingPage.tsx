import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { ArrowLeft, ArrowRight, FileSpreadsheet, GitBranch, History, MonitorUp, Workflow } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Alert, Card, PageHeader } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { providerCategory, useProviders } from "@/features/settings/scmApi";
import { cn } from "@/lib/utils";
import { useConnections } from "../api";
import { PublicUrlImport } from "./PublicUrlImport";

function SourceCard({
  to,
  icon,
  title,
  description,
  providers,
  status,
  accent,
}: {
  to: string;
  icon: ReactNode;
  title: string;
  description: string;
  providers: string;
  status: ReactNode;
  accent: string;
}) {
  return (
    <Link
      to={to as never}
      className="group flex h-full flex-col rounded-lg border border-border bg-surface p-5 transition-colors hover:border-primary/50 hover:bg-primary/[0.03] focus-visible:outline-2 focus-visible:outline-ring"
    >
      <span className={cn("mb-4 flex size-12 items-center justify-center rounded-lg [&_svg]:size-6", accent)} aria-hidden>
        {icon}
      </span>
      <span className="text-[15px] font-semibold">{title}</span>
      <span className="mt-1 text-[13px] text-muted-foreground">{description}</span>
      <span className="mt-3 text-[12px] font-medium text-foreground/80">{providers}</span>
      <span className="mt-auto flex items-center justify-between pt-5 text-[12px]">
        <span className="text-muted-foreground">{status}</span>
        <span className="flex items-center gap-1 font-medium text-primary">
          Start <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
        </span>
      </span>
    </Link>
  );
}

export function ImportLandingPage() {
  const { can } = useSession();
  const conns = useConnections();
  const providers = useProviders();
  const count = (cat: "git" | "devops") => (conns.data ?? []).filter((c) => providerCategory(c.provider, providers.data) === cat).length;
  const status = (cat: "git" | "devops") => {
    if (conns.isPending) return "Checking connections…";
    if (conns.isError) return "Connections unavailable";
    const n = count(cat);
    return n ? `${n} connection${n === 1 ? "" : "s"} available` : "No provider connected yet";
  };

  return (
    <>
      <PageHeader
        title="Import repositories"
        description="Bring source code under management. Every method uses the same registration wizard and runs in the background."
        actions={
          <>
            <Button variant="ghost" asChild>
              <Link to="/repositories/imports">
                <History /> Import history
              </Link>
            </Button>
            <Button variant="ghost" asChild>
              <Link to="/repositories">
                <ArrowLeft /> Repositories
              </Link>
            </Button>
          </>
        }
      />
      {!can("repos.manage") && (
        <div className="mb-4">
          <Alert tone="warning">Importing requires the repository management permission for the target business unit. You can still view the options.</Alert>
        </div>
      )}
      <div className="grid gap-4 md:grid-cols-3">
        <SourceCard
          to="/repositories/import/local"
          icon={<MonitorUp />}
          title="Import from Local PC"
          description="Upload source code directly from a local computer."
          providers="ZIP, TAR, TAR.GZ archives or a folder"
          status="Resumable chunked upload"
          accent="bg-primary/10 text-primary"
        />
        <SourceCard
          to="/repositories/import/git"
          icon={<GitBranch />}
          title="Import from Git"
          description="Connect to external Git repositories."
          providers="GitHub · GitLab · Bitbucket"
          status={status("git")}
          accent="bg-success-soft text-success"
        />
        <SourceCard
          to="/repositories/import/devops"
          icon={<Workflow />}
          title="Import from DevOps Project"
          description="Import source code from enterprise DevOps projects."
          providers="Azure DevOps Services · Azure DevOps Server"
          status={status("devops")}
          accent="bg-warning-soft text-warning"
        />
      </div>
      <PublicUrlImport canManage={can("repos.manage")} />
      <Card className="mt-6 flex flex-wrap items-center justify-between gap-3 p-4">
        <div className="flex items-start gap-3">
          <FileSpreadsheet className="mt-0.5 size-5 text-muted-foreground" aria-hidden />
          <div>
            <div className="text-[13px] font-medium">Bulk CSV import</div>
            <div className="text-[12px] text-muted-foreground">Import many repositories from an existing SCM connection with a CSV of placements and tags.</div>
          </div>
        </div>
        <Button variant="secondary" asChild>
          <Link to="/repositories/import/csv">Open bulk import</Link>
        </Button>
      </Card>
    </>
  );
}

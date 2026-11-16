import { Link, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/primitives";
import { useRepository } from "../api";
import { OnboardingWizard, type WizardSource } from "./OnboardingWizard";

const titles: Record<WizardSource, { title: string; description: string }> = {
  local: { title: "Import from Local PC", description: "Upload source code directly from a local computer." },
  git: { title: "Import from Git", description: "Connect to external Git repositories (GitHub, GitLab, Bitbucket)." },
  devops: { title: "Import from DevOps Project", description: "Import source code from enterprise DevOps projects (Azure DevOps)." },
};

export function validateOnboardingSearch(s: Record<string, unknown>): { target?: string } {
  return { target: typeof s.target === "string" && /^[0-9a-f-]{8,64}$/i.test(s.target) ? s.target : undefined };
}

export function OnboardingPage() {
  const { source } = useParams({ strict: false }) as { source: string };
  const { target } = useSearch({ strict: false }) as { target?: string };
  const navigate = useNavigate();
  const target_repo = useRepository(target);
  if (source !== "local" && source !== "git" && source !== "devops") {
    return <p className="text-[13px] text-muted-foreground">Unknown import source.</p>;
  }
  const t = titles[source];
  const forTarget = source === "local" && target;
  return (
    <>
      <PageHeader
        title={forTarget ? `Upload new version${target_repo.data ? ` of ${target_repo.data.display_name || target_repo.data.full_name}` : ""}` : t.title}
        description={forTarget ? "Add a new source snapshot to an uploaded repository." : t.description}
        actions={
          <Button variant="ghost" asChild>
            <Link to="/repositories/import">
              <ArrowLeft /> All import methods
            </Link>
          </Button>
        }
      />
      <OnboardingWizard
        key={`${source}-${target ?? ""}`}
        source={source}
        targetRepositoryId={forTarget ? target : undefined}
        onSubmitted={(id) => void navigate({ to: "/repositories/imports/$id", params: { id } })}
      />
    </>
  );
}

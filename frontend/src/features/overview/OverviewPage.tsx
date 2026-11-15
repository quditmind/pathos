import { CheckCircle2, Circle } from "lucide-react";
import { Card, PageHeader } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";

const phases = [
  { n: 1, title: "Foundation", detail: "Identity, RBAC, audit, encrypted secrets, deployment", done: true },
  { n: 2, title: "Dashboard", detail: "Posture KPIs, charts, global search" },
  { n: 3, title: "Repositories & assets", detail: "GitHub / Azure DevOps import, tagging, applications" },
  { n: 4, title: "Scanning engine", detail: "Isolated workers, Gitleaks, Opengrep, Trivy and more" },
  { n: 5, title: "AI review & MCP", detail: "Provider-agnostic AI triage, PATHOS MCP server" },
  { n: 6, title: "Vulnerability management", detail: "Finding lifecycle, SLAs, accepted risk, SBOM" },
];

export function OverviewPage() {
  const { me } = useSession();
  return (
    <>
      <PageHeader
        title={`Welcome${me.user.display_name ? `, ${me.user.display_name.split(" ")[0]}` : ""}`}
        description="Security posture dashboards appear here once repositories are onboarded and scanned."
      />
      <Card className="p-5">
        <h2 className="text-[13px] font-semibold">Platform roadmap</h2>
        <ol className="mt-3 divide-y divide-border">
          {phases.map((p) => (
            <li key={p.n} className="flex items-start gap-3 py-2.5">
              {p.done ? (
                <CheckCircle2 className="mt-0.5 size-4 text-success" aria-label="Available" />
              ) : (
                <Circle className="mt-0.5 size-4 text-muted-foreground" aria-label="Planned" />
              )}
              <div>
                <div className="text-[13px] font-medium">
                  Phase {p.n}: {p.title}
                </div>
                <div className="text-[12px] text-muted-foreground">{p.detail}</div>
              </div>
            </li>
          ))}
        </ol>
      </Card>
    </>
  );
}

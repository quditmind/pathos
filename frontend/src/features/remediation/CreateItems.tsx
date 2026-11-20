import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { Wrench } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Select } from "@/components/ui/primitives";
import { toast } from "@/components/ui/toast";
import { useSession } from "@/features/auth/session";
import { useFeatureFlag } from "@/features/shell/meta";
import { useCreateItems } from "./api";
import { FLAG } from "./shared";

/**
 * Findings bulk action: create remediation items from the selected
 * findings, one per finding or one group. Shown only while the
 * remediation_workspace flag is on and the user has remediation.manage.
 */
export function CreateRemediationItems({ findingIds, onDone }: { findingIds: string[]; onDone: () => void }) {
  const on = useFeatureFlag(FLAG);
  const { can } = useSession();
  const create = useCreateItems();
  const [mode, setMode] = useState<"per_finding" | "group">("per_finding");
  if (!on || !can("remediation.manage")) return null;
  return (
    <>
      <span className="mx-1 h-5 w-px bg-border" />
      <Select aria-label="Remediation item grouping" value={mode} onChange={(e) => setMode(e.target.value as "per_finding" | "group")}>
        <option value="per_finding">One item per finding</option>
        <option value="group">One item for all selected</option>
      </Select>
      <Button
        size="sm"
        variant="secondary"
        disabled={create.isPending}
        onClick={() =>
          create.mutate(
            { finding_ids: findingIds, mode },
            {
              onSuccess: (r) => {
                toast.success(`${r?.items?.length ?? 0} remediation item(s) created`);
                onDone();
              },
            },
          )
        }
      >
        <Wrench /> Create remediation items
      </Button>
      {create.isSuccess && (
        <Link to="/remediation" className="text-[12px] text-primary hover:underline">
          Open the workspace
        </Link>
      )}
      {create.isError && (
        <div className="w-full">
          <ErrorPanel error={create.error} />
        </div>
      )}
    </>
  );
}

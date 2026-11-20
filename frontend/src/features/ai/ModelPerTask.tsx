import { useEffect, useState } from "react";
import { Code2 } from "lucide-react";
import type { AIConfiguration } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Alert, Badge, Card, Input, Label, Select, Table, Td, Th } from "@/components/ui/primitives";
import { LoadingSkeleton } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useSession } from "@/features/auth/session";
import { useFeatureFlag } from "@/features/shell/meta";
import { LocationBadge } from "./AIEvidencePanel";
import { useSaveEvidenceSettings, useSaveTaskAssignments, useTaskAssignments } from "./evidence";

const sourceLabel: Record<string, string> = {
  assignment: "assigned",
  local_default: "automatic: local model for code",
  default: "automatic: default configuration",
  troubleshooting_local: "automatic: local model",
};

/**
 * AI settings → Model per task and AI evidence retention (PATHOS 3.0 M7,
 * flag ai_intelligence, ai.configure). Tasks that carry code use a local
 * model by default; a cloud model only receives code when its configuration
 * allows it.
 */
export function ModelPerTask({ configs }: { configs: AIConfiguration[] }) {
  const on = useFeatureFlag("ai_intelligence");
  const { canOrgWide } = useSession();
  const visible = on && canOrgWide("ai.configure");
  const q = useTaskAssignments(visible);
  const save = useSaveTaskAssignments();
  const saveEv = useSaveEvidenceSettings();
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [days, setDays] = useState(180);
  const [store, setStore] = useState(true);
  useEffect(() => {
    if (!q.data) return;
    setDraft(Object.fromEntries(q.data.items.map((t) => [t.task, t.configuration_id ?? ""])));
    setDays(q.data.evidence.retention_days);
    setStore(q.data.evidence.store_payloads);
  }, [q.data]);
  if (!visible) return null;
  const changed = q.data?.items.filter((t) => (t.configuration_id ?? "") !== (draft[t.task] ?? "")) ?? [];
  return (
    <section aria-label="Model per task" className="mt-6 space-y-3">
      <h2 className="text-[13px] font-semibold">Model per task</h2>
      <p className="text-[12px] text-muted-foreground">
        Each AI task can use its own configuration. Automatic uses a self-hosted (local) model for tasks that carry code, when one exists, and the default
        configuration otherwise. Source code is sent only where the configuration allows it.
      </p>
      {q.isPending ? (
        <LoadingSkeleton rows={4} label="Loading the task assignments" />
      ) : q.isError ? (
        <ErrorPanel error={q.error} title="Could not load the task assignments" onVerify={() => q.refetch()} />
      ) : (
        <Card className="p-3">
          {save.isError && <ErrorPanel error={save.error} title="The assignments were not saved" />}
          <Table>
            <thead>
              <tr>
                <Th>Task</Th>
                <Th>Configuration</Th>
                <Th>Effective</Th>
              </tr>
            </thead>
            <tbody>
              {q.data.items.map((t) => (
                <tr key={t.task}>
                  <Td>
                    <div className="flex items-center gap-1 font-medium">
                      {t.label}
                      {t.code_bearing && (
                        <Badge>
                          <Code2 className="size-3" aria-hidden /> carries code
                        </Badge>
                      )}
                    </div>
                    <div className="text-[12px] text-muted-foreground">{t.description}</div>
                  </Td>
                  <Td>
                    <Select aria-label={`Configuration for ${t.label}`} value={draft[t.task] ?? ""} onChange={(e) => setDraft({ ...draft, [t.task]: e.target.value })}>
                      <option value="">Automatic</option>
                      {configs.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name} ({c.current.model})
                        </option>
                      ))}
                    </Select>
                  </Td>
                  <Td>
                    {t.effective ? (
                      <div className="space-y-0.5 text-[12px]">
                        <div className="flex flex-wrap items-center gap-1">
                          <LocationBadge location={t.effective.location} />
                          <span>{t.effective.configuration_name}</span>
                          <span className="font-mono text-[11px] text-muted-foreground">{t.effective.model}</span>
                        </div>
                        <div className="text-muted-foreground">
                          {sourceLabel[t.effective.source] ?? t.effective.source} · code {t.effective.send_code_context ? "allowed" : "not sent"}
                        </div>
                        {t.warning && <div className="text-warning">{t.warning}</div>}
                      </div>
                    ) : (
                      <span className="text-[12px] text-muted-foreground">No configuration: AI is off for this task.</span>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <div className="mt-3 flex justify-end">
            <Button
              disabled={!changed.length || save.isPending}
              onClick={() =>
                save.mutate(Object.fromEntries(changed.map((t) => [t.task, draft[t.task] || null])), { onSuccess: () => toast.success("Model per task saved.") })
              }
            >
              Save assignments
            </Button>
          </div>
        </Card>
      )}
      <h2 className="pt-2 text-[13px] font-semibold">AI evidence retention</h2>
      <Card className="space-y-3 p-3 text-[13px]">
        <p className="text-[12px] text-muted-foreground">
          Every AI call is recorded. The redacted prompt and response are kept for the retention period and then deleted; the record keeps its hashes,
          model, reasoning, conclusion and review. A record is deleted with its finding.
        </p>
        {saveEv.isError && <ErrorPanel error={saveEv.error} title="The retention was not saved" />}
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <Label htmlFor="ev-days" hint="(1 to 3650; default 180)">
              Keep prompts and responses for (days)
            </Label>
            <Input id="ev-days" type="number" min={1} max={3650} value={days} onChange={(e) => setDays(Number(e.target.value))} className="w-32" />
          </div>
          <label className="flex items-center gap-2">
            <input type="checkbox" className="accent-[var(--primary)]" checked={store} onChange={(e) => setStore(e.target.checked)} /> Store prompts and responses
            (needed for Reproduce)
          </label>
          <Button
            variant="secondary"
            disabled={saveEv.isPending || days < 1 || days > 3650}
            onClick={() => saveEv.mutate({ retention_days: days, store_payloads: store }, { onSuccess: () => toast.success("AI evidence retention saved.") })}
          >
            Save retention
          </Button>
        </div>
        {!store && <Alert tone="warning">Without stored prompts, new AI decisions cannot be reproduced; only their hashes and conclusions are kept.</Alert>}
      </Card>
    </section>
  );
}

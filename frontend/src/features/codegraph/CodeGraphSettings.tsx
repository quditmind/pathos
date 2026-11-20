import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Card, Input, Label } from "@/components/ui/primitives";
import { LoadingSkeleton } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useCodeGraphSettings, useSaveCodeGraphSettings, type CodeGraphSettings } from "./api";

type Form = Omit<CodeGraphSettings, "updated_at">;

/**
 * Organization-wide CodeGraph settings (GET/PUT /api/v1/codegraph/settings):
 * automatic rediscovery after scans, its minimum interval and how many
 * snapshots each repository keeps. Shown to administrators with
 * settings.manage; the API enforces it.
 */
export function CodeGraphSettingsCard() {
  const settings = useCodeGraphSettings();
  const save = useSaveCodeGraphSettings();
  const [form, setForm] = useState<Form>();
  useEffect(() => {
    if (settings.data) setForm({ auto_rebuild: settings.data.auto_rebuild, min_interval_minutes: settings.data.min_interval_minutes, keep_snapshots: settings.data.keep_snapshots });
  }, [settings.data]);

  const invalid =
    !form ||
    !Number.isInteger(form.min_interval_minutes) ||
    form.min_interval_minutes < 0 ||
    form.min_interval_minutes > 10080 ||
    !Number.isInteger(form.keep_snapshots) ||
    form.keep_snapshots < 1 ||
    form.keep_snapshots > 1000;

  return (
    <Card className="mt-4 p-4">
      <h2 className="text-[14px] font-semibold">CodeGraph settings</h2>
      <p className="mb-3 text-[12px] text-muted-foreground">For the whole organization. Builds after scans need a graph worker online.</p>
      {settings.isError ? (
        <ErrorPanel error={settings.error} title="Could not load the CodeGraph settings" onVerify={() => settings.refetch()} />
      ) : !form ? (
        <LoadingSkeleton rows={3} label="Loading the CodeGraph settings" />
      ) : (
        <form
          className="grid max-w-xl gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (invalid) return;
            save.mutate(form, { onSuccess: () => toast.success("CodeGraph settings saved.") });
          }}
        >
          <label className="flex items-center gap-2 text-[13px]">
            <input type="checkbox" className="accent-[var(--primary)]" checked={form.auto_rebuild} onChange={(e) => setForm({ ...form, auto_rebuild: e.target.checked })} />
            Rebuild the graph after each successful scan of a new commit
          </label>
          <div>
            <Label htmlFor="cg-min-interval" hint="0–10,080">
              Minimum minutes between automatic builds of a repository
            </Label>
            <Input
              id="cg-min-interval"
              type="number"
              min={0}
              max={10080}
              value={form.min_interval_minutes}
              disabled={!form.auto_rebuild}
              onChange={(e) => setForm({ ...form, min_interval_minutes: e.target.valueAsNumber })}
            />
          </div>
          <div>
            <Label htmlFor="cg-keep" hint="1–1,000; older ones are archived">
              Snapshots kept per repository
            </Label>
            <Input id="cg-keep" type="number" min={1} max={1000} value={form.keep_snapshots} onChange={(e) => setForm({ ...form, keep_snapshots: e.target.valueAsNumber })} />
          </div>
          {save.isError && <ErrorPanel error={save.error} title="Could not save the CodeGraph settings" />}
          <div>
            <Button type="submit" size="sm" disabled={invalid || save.isPending}>
              Save settings
            </Button>
          </div>
        </form>
      )}
    </Card>
  );
}

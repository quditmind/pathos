import { useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Alert, Badge, Card, Input, PageHeader, Table, Td, Th } from "@/components/ui/primitives";
import { FeatureDisabled, LoadingSkeleton, PermissionDenied } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { useSession } from "@/features/auth/session";
import { useFeatureFlags } from "@/features/shell/meta";
import { useReaSettings, useReaTools, useSaveReaSettings, type DecompiledCodeAI, type InputPolicy, type ReaSettings } from "./api";

export const MEMORY_MIN = 512;
export const MEMORY_MAX = 16384;
export const TIMEOUT_MIN = 5;
export const TIMEOUT_MAX = 230;

/** Validation of the form (the server checks the same limits). */
export function settingsProblem(s: Pick<ReaSettings, "memory_mb" | "timeout_minutes" | "enabled_tools" | "decompiled_code_ai">, aiSendCodeAllowed: boolean): string | undefined {
  if (!Number.isInteger(s.memory_mb) || s.memory_mb < MEMORY_MIN || s.memory_mb > MEMORY_MAX) return `Memory must be between ${MEMORY_MIN} and ${MEMORY_MAX} MB.`;
  if (!Number.isInteger(s.timeout_minutes) || s.timeout_minutes < TIMEOUT_MIN || s.timeout_minutes > TIMEOUT_MAX)
    return `The time limit must be between ${TIMEOUT_MIN} and ${TIMEOUT_MAX} minutes.`;
  if (!s.enabled_tools.length) return "Enable at least one tool.";
  if (s.decompiled_code_ai === "cloud" && !aiSendCodeAllowed) return "Cloud models may see decompiled code only when the AI settings allow sending code.";
  return undefined;
}

const policies: { value: InputPolicy; label: string; help: string }[] = [
  {
    value: "own_builds_or_authorized",
    label: "Own builds; others only with an authorisation (default)",
    help: "Artifacts with a verified signature or provenance from your own builds are analysed. Any other artifact is refused unless someone with the rea.authorize permission authorises that exact file with a reason (audited).",
  },
  {
    value: "own_builds_only",
    label: "Own builds only",
    help: "Only artifacts with a verified signature or provenance are analysed. Authorising untrusted artifacts is switched off.",
  },
];

const aiChoices: { value: DecompiledCodeAI; label: string; help: string }[] = [
  { value: "none", label: "No AI model (default)", help: "Decompiled code and disassembly are never sent to an AI model." },
  { value: "local", label: "Local models only", help: "Only self-hosted models (for example Ollama) may see decompiled code." },
  { value: "cloud", label: "Local and cloud models", help: "Cloud providers may see decompiled code. Needs explicit permission in the AI settings." },
];

/** /configurations/reverse-engineering: tools, limits, input policy and AI exposure of decompiled code. */
export function ReaSettingsPage() {
  const { flags, isPending } = useFeatureFlags();
  const { can } = useSession();
  const enabled = flags.reverse_engineering === true;
  const settings = useReaSettings(enabled);
  const tools = useReaTools(enabled);
  const save = useSaveReaSettings();
  const [form, setForm] = useState<ReaSettings | undefined>();
  useEffect(() => {
    if (settings.data) setForm(settings.data);
  }, [settings.data]);
  const header = (
    <PageHeader
      title="Reverse engineering tools"
      description="Which binary analysis tools run, their memory and time limits, which artifacts may be analysed, and which AI models may see decompiled code."
    />
  );
  if (isPending) return <>{header}<LoadingSkeleton rows={4} /></>;
  if (!enabled) return <>{header}<FeatureDisabled flag="reverse_engineering" feature="Reverse engineering" /></>;
  if (!can("scanners.read")) return <>{header}<PermissionDenied permission="scanners.read" what="Viewing the reverse-engineering configuration" /></>;
  if (settings.isError) {
    if (settings.error instanceof ApiError && settings.error.status === 403) return <>{header}<PermissionDenied permission="scanners.read" what="Viewing the reverse-engineering configuration" /></>;
    return <>{header}<ErrorPanel error={settings.error} title="Could not load the configuration" onVerify={() => settings.refetch()} /></>;
  }
  if (settings.isPending || !form) return <>{header}<LoadingSkeleton rows={6} label="Loading the configuration" /></>;
  const manage = can("scanners.manage");
  const aiAllowed = settings.data.ai_send_code_allowed === true;
  const problem = settingsProblem(form, aiAllowed);
  const toggleTool = (key: string, on: boolean) =>
    setForm({ ...form, enabled_tools: on ? [...form.enabled_tools.filter((t) => t !== key), key] : form.enabled_tools.filter((t) => t !== key) });
  const onSave = () =>
    save.mutate(
      { enabled_tools: form.enabled_tools, memory_mb: form.memory_mb, timeout_minutes: form.timeout_minutes, input_policy: form.input_policy, decompiled_code_ai: form.decompiled_code_ai },
      { onSuccess: () => toast.success("Reverse engineering configuration saved. It applies to analyses started from now on.") },
    );
  return (
    <>
      {header}
      <div className="max-w-4xl space-y-4">
        {!manage && <Alert tone="warning">You can view this configuration. Changing it needs the scanners.manage permission.</Alert>}
        <Card className="space-y-2 p-4">
          <h2 className="text-[14px] font-semibold">Tools</h2>
          <p className="text-[12px] text-muted-foreground">
            The tools run in the reverse-engineering worker image, in its sandbox runner: no network, read-only, no privileges, never running the artifact.
            Optional tools are in the image only when it was built with them.
          </p>
          {tools.isError ? (
            <ErrorPanel error={tools.error} title="Could not load the tools" onVerify={() => tools.refetch()} />
          ) : tools.isPending ? (
            <LoadingSkeleton rows={4} label="Loading tools" />
          ) : (
            <>
              {!tools.data.worker_online && (
                <Alert tone="warning">No reverse-engineering worker is online, so installed versions are unknown and analyses wait in the queue (PTH-REA-1002).</Alert>
              )}
              <Table>
                <thead>
                  <tr>
                    <Th>Enabled</Th>
                    <Th>Tool</Th>
                    <Th>Purpose</Th>
                    <Th>Licence</Th>
                    <Th>Installed</Th>
                  </tr>
                </thead>
                <tbody>
                  {tools.data.tools.map((t) => (
                    <tr key={t.key} data-testid="rea-tool-row">
                      <Td>
                        <input
                          type="checkbox"
                          aria-label={`Enable ${t.name}`}
                          disabled={!manage}
                          checked={form.enabled_tools.includes(t.key)}
                          onChange={(e) => toggleTool(t.key, e.target.checked)}
                        />
                      </Td>
                      <Td>
                        {t.name} {t.optional && <Badge>Optional</Badge>}
                      </Td>
                      <Td>{t.purpose}</Td>
                      <Td>{t.license}</Td>
                      <Td>{t.installed ? (t.version ?? "yes") : <span className="text-muted-foreground">Not in the image</span>}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </>
          )}
        </Card>
        <Card className="grid gap-3 p-4 sm:grid-cols-2">
          <h2 className="text-[14px] font-semibold sm:col-span-2">Limits</h2>
          <label className="space-y-1 text-[13px]">
            <span className="block font-medium">Memory per analysis (MB)</span>
            <Input
              type="number"
              aria-label="Memory per analysis (MB)"
              min={MEMORY_MIN}
              max={MEMORY_MAX}
              disabled={!manage}
              value={form.memory_mb}
              onChange={(e) => setForm({ ...form, memory_mb: Number(e.target.value) })}
            />
            <span className="block text-[12px] text-muted-foreground">Passed to each tool; the sandbox container's own limit is the hard cap.</span>
          </label>
          <label className="space-y-1 text-[13px]">
            <span className="block font-medium">Time limit (minutes)</span>
            <Input
              type="number"
              aria-label="Time limit (minutes)"
              min={TIMEOUT_MIN}
              max={TIMEOUT_MAX}
              disabled={!manage}
              value={form.timeout_minutes}
              onChange={(e) => setForm({ ...form, timeout_minutes: Number(e.target.value) })}
            />
          </label>
        </Card>
        <Card className="space-y-2 p-4">
          <fieldset className="space-y-2">
            <legend className="text-[14px] font-semibold">Input policy</legend>
            {policies.map((p) => (
              <label key={p.value} className="flex gap-2 text-[13px]">
                <input type="radio" name="input_policy" value={p.value} disabled={!manage} checked={form.input_policy === p.value} onChange={() => setForm({ ...form, input_policy: p.value })} />
                <span>
                  <span className="font-medium">{p.label}</span>
                  <span className="block text-[12px] text-muted-foreground">{p.help}</span>
                </span>
              </label>
            ))}
          </fieldset>
        </Card>
        <Card className="space-y-2 p-4">
          <fieldset className="space-y-2">
            <legend className="text-[14px] font-semibold">AI models that may see decompiled code</legend>
            {!aiAllowed && (
              <p className="text-[12px] text-muted-foreground">
                Cloud models are unavailable: the default AI configuration does not allow sending code. Change it in{" "}
                <Link to="/admin/ai" className="text-primary underline">
                  AI settings
                </Link>{" "}
                first.
              </p>
            )}
            {aiChoices.map((c) => {
              const disabled = !manage || (c.value === "cloud" && !aiAllowed);
              return (
                <label key={c.value} className={"flex gap-2 text-[13px] " + (disabled && c.value === "cloud" ? "opacity-60" : "")}>
                  <input
                    type="radio"
                    name="decompiled_code_ai"
                    value={c.value}
                    aria-label={c.label}
                    disabled={disabled}
                    checked={form.decompiled_code_ai === c.value}
                    onChange={() => setForm({ ...form, decompiled_code_ai: c.value })}
                  />
                  <span>
                    <span className="font-medium">{c.label}</span>
                    <span className="block text-[12px] text-muted-foreground">{c.help}</span>
                  </span>
                </label>
              );
            })}
          </fieldset>
        </Card>
        {save.isError && <ErrorPanel error={save.error} title="Could not save the configuration" />}
        {manage && (
          <div className="flex items-center gap-3">
            <Button onClick={onSave} disabled={!!problem || save.isPending}>
              {save.isPending ? "Saving…" : "Save"}
            </Button>
            {problem && <span className="text-[12px] text-danger">{problem}</span>}
          </div>
        )}
      </div>
    </>
  );
}

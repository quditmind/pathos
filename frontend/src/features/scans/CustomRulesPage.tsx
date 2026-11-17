import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, FileCode2, Plus, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Skeleton } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { cn, formatDateTime } from "@/lib/utils";

interface CustomRule {
  id: string;
  engine: string;
  name: string;
  description: string;
  content?: string;
  rule_ids: string[];
  enabled: boolean;
  version: number;
  updated_by: string | null;
  updated_at: string;
}

interface RuleVersion {
  version: number;
  enabled: boolean;
  change_note: string;
  created_by: string | null;
  created_at: string;
}

const template = `rules:
  - id: acme.java.hardcoded-secret-key
    languages: [java]
    severity: ERROR
    message: A hard-coded key is passed to SecretKeySpec.
    metadata:
      cwe: ["CWE-798: Use of Hard-coded Credentials"]
    pattern: new javax.crypto.spec.SecretKeySpec("...".getBytes(), $ALG)
`;

const editorCls =
  "h-80 w-full rounded-md border border-border bg-surface px-3 py-2 font-mono text-[12px] leading-relaxed text-foreground focus-visible:outline-2 focus-visible:outline-ring disabled:opacity-70";

function Editor({ rule, editable, onSaved }: { rule: CustomRule | null; editable: boolean; onSaved: (id: string) => void }) {
  const qc = useQueryClient();
  const full = useQuery({ queryKey: ["custom-rule", rule?.id], queryFn: () => api<CustomRule>(`/api/v1/custom-rules/${rule!.id}`), enabled: !!rule });
  const versions = useQuery({
    queryKey: ["custom-rule", rule?.id, "versions"],
    queryFn: () => api<{ items: RuleVersion[] }>(`/api/v1/custom-rules/${rule!.id}/versions`).then((r) => r.items),
    enabled: !!rule,
  });
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [content, setContent] = useState(template);
  const [note, setNote] = useState("");
  const [enabled, setEnabled] = useState(true);
  useEffect(() => {
    if (!rule) {
      setName("");
      setDesc("");
      setContent(template);
      setEnabled(true);
    } else if (full.data) {
      setName(full.data.name);
      setDesc(full.data.description);
      setContent(full.data.content ?? "");
      setEnabled(full.data.enabled);
    }
    setNote("");
  }, [rule, full.data]);
  const validate = useMutation({ mutationFn: () => api<{ valid: boolean; rule_ids: string[] }>("/api/v1/custom-rules/validate", { method: "POST", body: { content } }) });
  const save = useMutation({
    mutationFn: () =>
      rule
        ? api<CustomRule>(`/api/v1/custom-rules/${rule.id}`, { method: "PUT", body: { name, description: desc, content, enabled, change_note: note } })
        : api<CustomRule>("/api/v1/custom-rules", { method: "POST", body: { name, description: desc, content, enabled, change_note: note } }),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ["custom-rules"] });
      void qc.invalidateQueries({ queryKey: ["custom-rule", r.id] });
      onSaved(r.id);
    },
  });
  if (rule && full.isPending) return <Skeleton className="h-96" />;
  return (
    <Card className="p-4">
      <fieldset disabled={!editable} className="space-y-3">
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <Label htmlFor="rule-name">Name</Label>
            <Input id="rule-name" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="rule-desc" hint="(optional)">Description</Label>
            <Input id="rule-desc" value={desc} maxLength={2000} onChange={(e) => setDesc(e.target.value)} />
          </div>
        </div>
        <div>
          <Label htmlFor="rule-content" hint="(Opengrep / Semgrep rule syntax; ids must be unique and must not start with pathos.)">Rules (YAML)</Label>
          <textarea id="rule-content" spellCheck={false} className={editorCls} value={content} onChange={(e) => { setContent(e.target.value); validate.reset(); }} />
        </div>
        {validate.error && <Alert>{validate.error.message}</Alert>}
        {validate.data && (
          <Alert tone="success">
            <span className="inline-flex items-center gap-1"><CheckCircle2 className="size-4" /> Valid: {validate.data.rule_ids.join(", ")}</span>
          </Alert>
        )}
        {save.error && <Alert>{save.error.message}</Alert>}
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex items-center gap-1.5 text-[13px]">
            <input type="checkbox" className="accent-[var(--primary)]" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled in new scans
          </label>
          {rule && (
            <div className="min-w-56 flex-1">
              <Label htmlFor="rule-note" hint="(optional)">Change note</Label>
              <Input id="rule-note" value={note} onChange={(e) => setNote(e.target.value)} />
            </div>
          )}
          <Button type="button" variant="secondary" disabled={validate.isPending} onClick={() => validate.mutate()}>Validate</Button>
          <Button type="button" disabled={save.isPending || !name.trim()} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : rule ? "Save new version" : "Create rule file"}
          </Button>
        </div>
      </fieldset>
      {rule && versions.data && (
        <div className="mt-4 border-t border-border pt-3">
          <h3 className="mb-1 text-[12px] font-semibold">Versions</h3>
          <ul className="space-y-0.5 text-[12px]">
            {versions.data.map((v) => (
              <li key={v.version} className="flex gap-2">
                <span className="tabular w-8">v{v.version}</span>
                <span className="text-muted-foreground">{formatDateTime(v.created_at)} · {v.created_by ?? "—"}{v.enabled ? "" : " · disabled"}</span>
                {v.change_note && <span>— {v.change_note}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}

export function CustomRulesPage() {
  const { canOrgWide } = useSession();
  const editable = canOrgWide("profiles.manage");
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["custom-rules"], queryFn: () => api<{ items: CustomRule[] }>("/api/v1/custom-rules").then((r) => r.items) });
  const [selected, setSelected] = useState<string | "new" | null>(null);
  const [del, setDel] = useState<CustomRule | null>(null);
  const remove = useMutation({
    mutationFn: (id: string) => api(`/api/v1/custom-rules/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      setDel(null);
      setSelected(null);
      void qc.invalidateQueries({ queryKey: ["custom-rules"] });
    },
  });
  const current = list.data?.find((r) => r.id === selected) ?? null;
  return (
    <>
      <PageHeader
        title="Custom rules"
        description="Your own Opengrep detection rules. Enabled rule files run in every new scan alongside the PATHOS baseline rules; each scan records the rule versions it used."
        actions={editable && <Button onClick={() => setSelected("new")}><Plus /> New rule file</Button>}
      />
      <div className="grid gap-4 lg:grid-cols-[300px_minmax(0,1fr)]">
        <Card>
          {list.isError ? (
            <div className="p-3"><Alert>{list.error.message}</Alert></div>
          ) : list.isPending ? (
            <Skeleton className="m-3 h-24" />
          ) : !list.data?.length ? (
            <EmptyState icon={<FileCode2 />} title="No custom rules">Add rules for your frameworks, internal APIs and coding standards.</EmptyState>
          ) : (
            <ul className="divide-y divide-border">
              {list.data.map((r) => (
                <li key={r.id} className={cn("flex items-start gap-2 px-3 py-2", selected === r.id && "bg-primary/5")}>
                  <button type="button" className="min-w-0 flex-1 text-left" onClick={() => setSelected(r.id)}>
                    <div className="flex items-center gap-2 text-[13px] font-medium">
                      <span className="truncate">{r.name}</span>
                      <Badge tone={r.enabled ? "success" : "neutral"}>{r.enabled ? "on" : "off"}</Badge>
                    </div>
                    <div className="text-[11.5px] text-muted-foreground">
                      {r.rule_ids.length} rule{r.rule_ids.length === 1 ? "" : "s"} · v{r.version} · {formatDateTime(r.updated_at)}
                    </div>
                  </button>
                  {editable && (
                    <Button size="icon" variant="ghost" aria-label={`Delete ${r.name}`} onClick={() => setDel(r)}>
                      <Trash2 />
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>
        {selected ? (
          <Editor rule={selected === "new" ? null : current} editable={editable} onSaved={(id) => setSelected(id)} />
        ) : (
          <Card className="p-6 text-[13px] text-muted-foreground">Select a rule file{editable ? " or create a new one" : ""}.</Card>
        )}
      </div>
      <ConfirmDialog
        open={!!del}
        onOpenChange={(o) => !o && setDel(null)}
        title={`Delete ${del?.name ?? "rule file"}?`}
        confirmLabel="Delete"
        pending={remove.isPending}
        error={remove.error?.message}
        onConfirm={() => del && remove.mutate(del.id)}
      >
        New scans stop using these rules. Findings already reported are kept.
      </ConfirmDialog>
    </>
  );
}

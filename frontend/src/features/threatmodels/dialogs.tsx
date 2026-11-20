import { useId, useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Alert, Input, Label, Select } from "@/components/ui/primitives";
import { toast } from "@/components/ui/toast";
import { useApplications, useRepositories } from "@/features/repos/api";
import {
  categoryLabel,
  importFormats,
  importLabel,
  threatCategories,
  threatSeverities,
  useAddThreat,
  useCreateModel,
  useImportModel,
  type ImportFormat,
  type ThreatCategory,
  type ThreatSeverity,
} from "./api";

/** Optional repository narrowing of a model: the application's repositories. */
function RepositoryPicker({ applicationId, value, onChange, id }: { applicationId: string; value: string; onChange: (v: string) => void; id: string }) {
  const repos = useRepositories({ application_id: applicationId });
  const items = repos.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <Select id={id} value={value} onChange={(e) => onChange(e.target.value)} disabled={!applicationId}>
      <option value="">The whole application</option>
      {items.map((r) => (
        <option key={r.id} value={r.id}>
          {r.display_name || r.full_name}
        </option>
      ))}
    </Select>
  );
}

function ApplicationPicker({ value, onChange, id }: { value: string; onChange: (v: string) => void; id: string }) {
  const apps = useApplications();
  return (
    <Select id={id} value={value} onChange={(e) => onChange(e.target.value)} required>
      <option value="">Choose an application…</option>
      {(apps.data ?? []).map((a) => (
        <option key={a.id} value={a.id}>
          {a.name}
        </option>
      ))}
    </Select>
  );
}

export function CreateModelDialog({ open, onOpenChange, applicationId }: { open: boolean; onOpenChange: (o: boolean) => void; applicationId?: string }) {
  const ids = useId();
  const [app, setApp] = useState(applicationId ?? "");
  const [repo, setRepo] = useState("");
  const [title, setTitle] = useState("");
  const [generate, setGenerate] = useState(true);
  const create = useCreateModel();
  const navigate = useNavigate();
  const apps = useApplications();
  const appName = apps.data?.find((a) => a.id === app)?.name;
  const submit = () =>
    create.mutate(
      { application_id: app, repository_id: repo || undefined, title: title.trim() || `${appName ?? "Application"} threat model`, generate },
      {
        onSuccess: (m) => {
          toast.success(generate ? "Threat model created and generated." : "Threat model created.");
          onOpenChange(false);
          void navigate({ to: "/threat-models/$modelId", params: { modelId: m.id } });
        },
      },
    );
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="New threat model"
      description="PATHOS builds the model from the application's latest CodeGraph snapshots and its attack paths. You can edit and approve it afterwards."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!app || create.isPending}>
            Create
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {!applicationId && (
          <div>
            <Label htmlFor={`${ids}-app`}>Application</Label>
            <ApplicationPicker id={`${ids}-app`} value={app} onChange={(v) => (setApp(v), setRepo(""))} />
          </div>
        )}
        <div>
          <Label htmlFor={`${ids}-repo`} hint="(optional)">
            Repository
          </Label>
          <RepositoryPicker id={`${ids}-repo`} applicationId={app} value={repo} onChange={setRepo} />
        </div>
        <div>
          <Label htmlFor={`${ids}-title`}>Title</Label>
          <Input id={`${ids}-title`} value={title} maxLength={200} placeholder={`${appName ?? "Application"} threat model`} onChange={(e) => setTitle(e.target.value)} />
        </div>
        <label className="flex items-center gap-2 text-[13px]">
          <input type="checkbox" checked={generate} onChange={(e) => setGenerate(e.target.checked)} />
          Generate threats now (needs a finished CodeGraph snapshot)
        </label>
        {create.isError && <ErrorPanel error={create.error} title="Could not create the threat model" />}
      </div>
    </Dialog>
  );
}

const MAX_IMPORT = 10 * 1024 * 1024;

export function ImportModelDialog({ open, onOpenChange, applicationId }: { open: boolean; onOpenChange: (o: boolean) => void; applicationId?: string }) {
  const ids = useId();
  const [app, setApp] = useState(applicationId ?? "");
  const [repo, setRepo] = useState("");
  const [format, setFormat] = useState<ImportFormat>("threat_dragon");
  const [title, setTitle] = useState("");
  const [doc, setDoc] = useState<unknown>();
  const [fileError, setFileError] = useState<string>();
  const imp = useImportModel();
  const navigate = useNavigate();
  const onFile = async (f: File | undefined) => {
    setDoc(undefined);
    setFileError(undefined);
    if (!f) return;
    if (f.size > MAX_IMPORT) return setFileError("The file is larger than 10 MB.");
    try {
      setDoc(JSON.parse(await f.text()));
    } catch {
      setFileError("The file is not valid JSON.");
    }
  };
  const submit = () =>
    imp.mutate(
      { application_id: app, repository_id: repo || undefined, format, title: title.trim() || undefined, document: doc },
      {
        onSuccess: (m) => {
          toast.success("Threat model imported. Imported threats are unverified until you link them to evidence.");
          onOpenChange(false);
          void navigate({ to: "/threat-models/$modelId", params: { modelId: m.id } });
        },
      },
    );
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Import a threat model"
      description="Imported threats are labelled “imported, unverified” until they are linked to CodeGraph elements or findings."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!app || doc === undefined || imp.isPending}>
            Import
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {!applicationId && (
          <div>
            <Label htmlFor={`${ids}-app`}>Application</Label>
            <ApplicationPicker id={`${ids}-app`} value={app} onChange={(v) => (setApp(v), setRepo(""))} />
          </div>
        )}
        <div>
          <Label htmlFor={`${ids}-repo`} hint="(optional)">
            Repository
          </Label>
          <RepositoryPicker id={`${ids}-repo`} applicationId={app} value={repo} onChange={setRepo} />
        </div>
        <div>
          <Label htmlFor={`${ids}-format`}>Format</Label>
          <Select id={`${ids}-format`} value={format} onChange={(e) => setFormat(e.target.value as ImportFormat)}>
            {importFormats.map((f) => (
              <option key={f} value={f}>
                {importLabel[f]}
              </option>
            ))}
          </Select>
          <p className="mt-1 text-[12px] text-muted-foreground">pytm models are Python code; PATHOS exports them but never runs them, so they cannot be imported.</p>
        </div>
        <div>
          <Label htmlFor={`${ids}-file`}>File (JSON, up to 10 MB)</Label>
          <input id={`${ids}-file`} type="file" accept=".json,application/json" className="block text-[13px]" onChange={(e) => void onFile(e.target.files?.[0])} />
          {fileError && (
            <p role="alert" className="mt-1 text-[12px] text-danger">
              {fileError}
            </p>
          )}
        </div>
        <div>
          <Label htmlFor={`${ids}-title`} hint="(optional, else the file's title)">
            Title
          </Label>
          <Input id={`${ids}-title`} value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} />
        </div>
        {imp.isError && <ErrorPanel error={imp.error} title="Could not import the threat model" />}
      </div>
    </Dialog>
  );
}

/** "repository_id key" or "key" per line → element keys (key-only lines use the default repository). */
export function parseElementKeys(text: string, defaultRepo?: string): { repository_id: string; key: string }[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const m = /^([0-9a-fA-F-]{36})\s+(.+)$/.exec(l);
      return m && m[1] && m[2] ? { repository_id: m[1], key: m[2].trim() } : { repository_id: defaultRepo ?? "", key: l };
    });
}

export const parseIds = (text: string) =>
  text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);

export function AddThreatDialog({ open, onOpenChange, modelId, defaultRepo }: { open: boolean; onOpenChange: (o: boolean) => void; modelId: string; defaultRepo?: string }) {
  const ids = useId();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState<ThreatCategory>("spoofing");
  const [severity, setSeverity] = useState<ThreatSeverity>("medium");
  const [mitigation, setMitigation] = useState("");
  const [keys, setKeys] = useState("");
  const [findings, setFindings] = useState("");
  const add = useAddThreat(modelId);
  const elementKeys = useMemo(() => parseElementKeys(keys, defaultRepo), [keys, defaultRepo]);
  const missingRepo = elementKeys.some((k) => !k.repository_id);
  const submit = () =>
    add.mutate(
      {
        title: title.trim(),
        description,
        category,
        severity,
        mitigation,
        element_keys: elementKeys.length ? elementKeys : undefined,
        finding_ids: parseIds(findings).length ? parseIds(findings) : undefined,
      },
      {
        onSuccess: () => {
          toast.success("Manual threat added.");
          onOpenChange(false);
          setTitle("");
          setDescription("");
          setMitigation("");
          setKeys("");
          setFindings("");
        },
      },
    );
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="lg"
      title="Add a manual threat"
      description="Manual threats are labelled “manual”. They are verified when linked to CodeGraph elements or findings; otherwise “manual, unverified”."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!title.trim() || missingRepo || add.isPending}>
            Add threat
          </Button>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label htmlFor={`${ids}-t`}>Title</Label>
          <Input id={`${ids}-t`} value={title} maxLength={300} onChange={(e) => setTitle(e.target.value)} />
        </div>
        <div>
          <Label htmlFor={`${ids}-c`}>Category</Label>
          <Select id={`${ids}-c`} value={category} onChange={(e) => setCategory(e.target.value as ThreatCategory)}>
            {threatCategories.map((c) => (
              <option key={c} value={c}>
                {categoryLabel[c]}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor={`${ids}-s`}>Severity</Label>
          <Select id={`${ids}-s`} value={severity} onChange={(e) => setSeverity(e.target.value as ThreatSeverity)}>
            {threatSeverities.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </Select>
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor={`${ids}-d`}>Description</Label>
          <textarea id={`${ids}-d`} className="min-h-16 w-full rounded-md border border-border bg-surface px-2 py-1 text-[13px]" value={description} maxLength={8000} onChange={(e) => setDescription(e.target.value)} />
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor={`${ids}-m`}>Mitigation</Label>
          <textarea id={`${ids}-m`} className="min-h-16 w-full rounded-md border border-border bg-surface px-2 py-1 text-[13px]" value={mitigation} maxLength={8000} onChange={(e) => setMitigation(e.target.value)} />
        </div>
        <div>
          <Label htmlFor={`${ids}-k`} hint="(one per line: “<repository id> <key>”, or a key)">
            CodeGraph element keys
          </Label>
          <textarea id={`${ids}-k`} className="min-h-16 w-full rounded-md border border-border bg-surface px-2 py-1 font-mono text-[12px]" value={keys} onChange={(e) => setKeys(e.target.value)} />
          {missingRepo && <p className="text-[12px] text-danger">Give the repository id with each key (the model covers several repositories).</p>}
        </div>
        <div>
          <Label htmlFor={`${ids}-f`} hint="(ids, comma or space separated)">
            Findings
          </Label>
          <textarea id={`${ids}-f`} className="min-h-16 w-full rounded-md border border-border bg-surface px-2 py-1 font-mono text-[12px]" value={findings} onChange={(e) => setFindings(e.target.value)} />
        </div>
        {add.isError && (
          <div className="sm:col-span-2">
            <ErrorPanel error={add.error} title="Could not add the threat" />
          </div>
        )}
        {!keys.trim() && !findings.trim() && (
          <div className="sm:col-span-2">
            <Alert tone="warning">Without evidence the threat is “manual, unverified” and must be linked before the model can be submitted.</Alert>
          </div>
        )}
      </div>
    </Dialog>
  );
}

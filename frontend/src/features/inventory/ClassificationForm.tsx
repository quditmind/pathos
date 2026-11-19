import { useEffect, useMemo, useState, type ReactElement, type ReactNode } from "react";
import { Sparkles } from "lucide-react";
import type { ClassificationKind, User } from "@/api/types";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Alert, Input, Select } from "@/components/ui/primitives";
import { catalog, useAssetSettings } from "@/features/assets/api";
import { useSession } from "@/features/auth/session";
import { buTree, FormField, Textarea } from "@/features/repos/metadata/fields";
import { TagPicker } from "@/features/repos/metadata/TagPicker";
import { useBusinessUnits, useRegions, useUsers } from "@/features/users/api";
import { cn } from "@/lib/utils";
import { fieldLabels, saveClassification, useInventoryMutation, type ApplicationProfile, type ClassificationPatch } from "./api";

/** Form values: strings for selects ("" = none), comma lists for free text. */
export interface ClassificationDraft {
  description: string;
  business_unit_id: string;
  owner_user_id: string;
  security_owner_user_id: string;
  technical_owner_user_id: string;
  criticality: string;
  environment: string;
  lifecycle: string;
  application_type: string;
  languages: string;
  frameworks: string;
  runtimes: string;
  data_classification: string;
  internet_exposure: string;
  compliance_scopes: string[];
  authentication_model: string;
  hosting_region: string;
  data_residency_region_id: string;
  tag_ids: string[];
}

export const splitList = (s: string) =>
  s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

export function draftFrom(a: ApplicationProfile): ClassificationDraft {
  return {
    description: a.description,
    business_unit_id: a.business_unit?.id ?? "",
    owner_user_id: a.owner?.id ?? "",
    security_owner_user_id: a.security_owner?.id ?? "",
    technical_owner_user_id: a.technical_owner?.id ?? "",
    criticality: a.criticality,
    environment: a.environment,
    lifecycle: a.lifecycle,
    application_type: a.application_type,
    languages: a.languages.join(", "),
    frameworks: a.frameworks.join(", "),
    runtimes: a.runtimes.join(", "),
    data_classification: a.data_classification,
    internet_exposure: a.internet_exposure,
    compliance_scopes: a.compliance_scopes,
    authentication_model: a.authentication_model,
    hosting_region: a.hosting_region,
    data_residency_region_id: a.data_residency_region?.id ?? "",
    tag_ids: a.tags.map((t) => t.id),
  };
}

const sameList = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * The patch between the saved application and the form: only changed
 * fields are sent, so untouched detected values keep their "detected" mark.
 */
export function patchFrom(a: ApplicationProfile, d: ClassificationDraft, canPickUsers: boolean): ClassificationPatch {
  const o = draftFrom(a);
  const p: ClassificationPatch = {};
  const nul = (v: string) => v || null;
  if (d.description !== o.description) p.description = d.description;
  if (d.business_unit_id !== o.business_unit_id) p.business_unit_id = nul(d.business_unit_id);
  if (canPickUsers) {
    if (d.owner_user_id !== o.owner_user_id) p.owner_user_id = nul(d.owner_user_id);
    if (d.security_owner_user_id !== o.security_owner_user_id) p.security_owner_user_id = nul(d.security_owner_user_id);
    if (d.technical_owner_user_id !== o.technical_owner_user_id) p.technical_owner_user_id = nul(d.technical_owner_user_id);
  }
  for (const k of ["criticality", "environment", "lifecycle", "application_type", "data_classification", "internet_exposure", "authentication_model", "hosting_region"] as const) {
    if (d[k] !== o[k]) p[k] = d[k];
  }
  for (const k of ["languages", "frameworks", "runtimes"] as const) {
    if (!sameList(splitList(d[k]), splitList(o[k]))) p[k] = splitList(d[k]);
  }
  if (!sameList([...d.compliance_scopes].sort(), [...o.compliance_scopes].sort())) p.compliance_scopes = d.compliance_scopes;
  if (d.data_residency_region_id !== o.data_residency_region_id) p.data_residency_region_id = nul(d.data_residency_region_id);
  if (!sameList([...d.tag_ids].sort(), [...o.tag_ids].sort())) p.tag_ids = d.tag_ids;
  return p;
}

const groups: { key: string; title: string; fields: string[] }[] = [
  { key: "business", title: "Business", fields: ["owner", "business_unit", "criticality", "security_owner", "technical_owner", "description"] },
  { key: "technical", title: "Technical", fields: ["application_type", "languages", "frameworks", "runtimes"] },
  { key: "security", title: "Security", fields: ["data_classification", "internet_exposure", "compliance_scopes", "authentication_model"] },
  { key: "geography", title: "Geography", fields: ["hosting_region", "data_residency"] },
  { key: "environment", title: "Environment", fields: ["environment", "lifecycle"] },
];

/** "detected" marker with the source as an accessible description. */
function DetectedBadge({ detail, source }: { detail: string; source: string }) {
  const label = { repository: "repository metadata", sbom: "the SBOM", scm: "the provider" }[source] ?? source;
  return (
    <span className="ml-1.5 inline-flex items-center gap-0.5 rounded bg-success-soft px-1 text-[10.5px] font-medium text-success" title={`${detail} (from ${label})`}>
      <Sparkles className="size-3" aria-hidden /> detected<span className="sr-only">{` from ${label}: ${detail}`}</span>
    </span>
  );
}

/**
 * Classification of an application (business, technical, security,
 * geography, environment and tags). Used by the onboarding flow (Tag &
 * classify) and the profile's Classification & tags tab.
 */
export function ClassificationForm({
  app,
  required,
  onSaved,
  saveLabel = "Save",
  extraActions,
}: {
  app: ApplicationProfile;
  required: string[];
  onSaved?: (a: ApplicationProfile) => void;
  saveLabel?: string;
  extraActions?: ReactNode;
}) {
  const { canOrgWide } = useSession();
  const canPickUsers = canOrgWide("users.read");
  const editable = app.can_manage;
  const settings = useAssetSettings();
  const bus = useBusinessUnits();
  const regions = useRegions();
  const users = useUsers("", "active");
  const userList: User[] = users.data?.pages.flatMap((p) => p.items) ?? [];
  const [d, setD] = useState<ClassificationDraft>(() => draftFrom(app));
  const [saved, setSaved] = useState(false);
  useEffect(() => setD(draftFrom(app)), [app]);
  const save = useInventoryMutation((body: ClassificationPatch) => saveClassification(app.id, body));
  const patch = useMemo(() => patchFrom(app, d, canPickUsers), [app, d, canPickUsers]);
  const dirty = Object.keys(patch).length > 0;
  const fieldErrors = save.error instanceof ApiError ? (save.error.fields ?? {}) : {};
  const set = (p: Partial<ClassificationDraft>) => {
    setD((x) => ({ ...x, ...p }));
    setSaved(false);
  };

  const req = new Set(required);
  const missing = new Set(app.progress.missing);
  const label = (f: string, fallback?: string) => fieldLabels[f] ?? fallback ?? f;
  const detected = (f: string) => {
    const det = app.detected[f];
    return det ? <DetectedBadge detail={det.detail} source={det.source} /> : null;
  };
  const autoCls = (f: string) => (app.detected[f] ? "bg-success-soft/60" : undefined);
  const cat = (kind: ClassificationKind) => catalog(settings.data, kind);

  const catalogSelect = (f: keyof ClassificationDraft, kind: ClassificationKind) => (
    <Select className={cn("w-full", autoCls(f))} value={d[f] as string} disabled={!editable} onChange={(e) => set({ [f]: e.target.value } as Partial<ClassificationDraft>)}>
      <option value="">Not set</option>
      {cat(kind).map((c) => (
        <option key={c.key} value={c.key}>
          {c.label}
        </option>
      ))}
    </Select>
  );
  const userSelect = (f: "owner_user_id" | "security_owner_user_id" | "technical_owner_user_id", current: { name: string } | null) =>
    canPickUsers ? (
      <Select className="w-full" value={d[f]} disabled={!editable} onChange={(e) => set({ [f]: e.target.value } as Partial<ClassificationDraft>)}>
        <option value="">Unassigned</option>
        {userList.map((u) => (
          <option key={u.id} value={u.id}>
            {u.display_name || u.email}
          </option>
        ))}
      </Select>
    ) : (
      <Input value={current?.name ?? "Unassigned"} disabled readOnly />
    );

  const control: Record<string, () => ReactNode> = {
    owner: () => userSelect("owner_user_id", app.owner),
    security_owner: () => userSelect("security_owner_user_id", app.security_owner),
    technical_owner: () => userSelect("technical_owner_user_id", app.technical_owner),
    business_unit: () => (
      <Select className="w-full" value={d.business_unit_id} disabled={!editable} onChange={(e) => set({ business_unit_id: e.target.value })}>
        <option value="">None (organization)</option>
        {buTree(bus.data ?? []).map(({ unit, depth }) => (
          <option key={unit.id} value={unit.id}>
            {"  ".repeat(depth) + unit.name}
          </option>
        ))}
      </Select>
    ),
    criticality: () => (
      <Select className="w-full capitalize" value={d.criticality} disabled={!editable} onChange={(e) => set({ criticality: e.target.value })}>
        {["critical", "high", "medium", "low"].map((v) => (
          <option key={v} value={v}>
            {v}
          </option>
        ))}
      </Select>
    ),
    description: () => <Textarea rows={2} maxLength={2000} value={d.description} disabled={!editable} onChange={(e) => set({ description: e.target.value })} />,
    application_type: () => catalogSelect("application_type", "application_type"),
    languages: () => (
      <Input className={autoCls("languages")} value={d.languages} placeholder="Go, TypeScript" disabled={!editable} onChange={(e) => set({ languages: e.target.value })} />
    ),
    frameworks: () => (
      <Input className={autoCls("frameworks")} value={d.frameworks} placeholder="chi, React" disabled={!editable} onChange={(e) => set({ frameworks: e.target.value })} />
    ),
    runtimes: () => (
      <Input className={autoCls("runtimes")} value={d.runtimes} placeholder="Go, Node.js" disabled={!editable} onChange={(e) => set({ runtimes: e.target.value })} />
    ),
    data_classification: () => catalogSelect("data_classification", "data_classification"),
    internet_exposure: () => catalogSelect("internet_exposure", "internet_exposure"),
    authentication_model: () => catalogSelect("authentication_model", "authentication_model" as ClassificationKind),
    compliance_scopes: () => (
      <div role="group" className="flex flex-wrap gap-x-3 gap-y-1 rounded-md border border-border px-2.5 py-1.5">
        {cat("compliance").map((c) => (
          <label key={c.key} className="flex items-center gap-1.5 text-[12.5px]">
            <input
              type="checkbox"
              className="accent-[var(--primary)]"
              disabled={!editable}
              checked={d.compliance_scopes.includes(c.key)}
              onChange={(e) =>
                set({ compliance_scopes: e.target.checked ? [...d.compliance_scopes, c.key] : d.compliance_scopes.filter((k) => k !== c.key) })
              }
            />
            {c.label}
          </label>
        ))}
        {!cat("compliance").length && <span className="text-[12px] text-muted-foreground">No compliance scopes configured</span>}
      </div>
    ),
    hosting_region: () => catalogSelect("hosting_region", "hosting_region"),
    data_residency: () => (
      <Select className={cn("w-full", autoCls("data_residency"))} value={d.data_residency_region_id} disabled={!editable} onChange={(e) => set({ data_residency_region_id: e.target.value })}>
        <option value="">Not set</option>
        {(regions.data ?? []).map((r) => (
          <option key={r.id} value={r.id}>
            {r.name}
          </option>
        ))}
      </Select>
    ),
    environment: () => (
      <Select className="w-full capitalize" value={d.environment} disabled={!editable} onChange={(e) => set({ environment: e.target.value })}>
        {["production", "staging", "development", "test", "other"].map((v) => (
          <option key={v} value={v}>
            {v}
          </option>
        ))}
      </Select>
    ),
    lifecycle: () => (
      <Select className="w-full capitalize" value={d.lifecycle} disabled={!editable} onChange={(e) => set({ lifecycle: e.target.value })}>
        {["planned", "development", "active", "maintenance", "deprecated", "retired"].map((v) => (
          <option key={v} value={v}>
            {v}
          </option>
        ))}
      </Select>
    ),
  };

  const mandatoryTags = app.progress.missing_tag_categories;
  return (
    <form
      className="space-y-5"
      aria-label="Classification"
      onSubmit={(e) => {
        e.preventDefault();
        if (!dirty) return;
        save.mutate(patch, {
          onSuccess: (a) => {
            setSaved(true);
            onSaved?.(a);
          },
        });
      }}
    >
      {!editable && <Alert tone="warning">You can view this classification; changing it requires the repository management permission for the application.</Alert>}
      {groups.map((g) => (
        <fieldset key={g.key} className="space-y-2">
          <legend className="mb-1 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">{g.title}</legend>
          <div className="grid gap-3 sm:grid-cols-2">
            {g.fields.map((f) => (
              <FormField
                key={f}
                label={label(f)}
                required={req.has(f)}
                error={fieldErrors[f]}
                className={f === "description" || f === "compliance_scopes" ? "sm:col-span-2" : undefined}
                hint={
                  <>
                    {detected(f)}
                    {req.has(f) && missing.has(f) && <span className="ml-1 text-warning">Needed to save to the inventory</span>}
                  </>
                }
              >
                {control[f]!() as ReactElement<{ id?: string; "aria-invalid"?: boolean; "aria-describedby"?: string; "aria-required"?: boolean }>}
              </FormField>
            ))}
          </div>
        </fieldset>
      ))}
      <fieldset>
        <legend className="mb-1 text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">Tags</legend>
        {mandatoryTags.length > 0 && (
          <p className="mb-2 text-[12px] text-warning">A tag is required in: {mandatoryTags.map((c) => c.name).join(", ")}</p>
        )}
        <TagPicker value={d.tag_ids} onChange={(ids) => set({ tag_ids: ids })} disabled={!editable} error={fieldErrors.tags} />
        {app.tags.some((t) => t.source === "rule") && (
          <p className="mt-1 text-[11.5px] text-muted-foreground">
            Tags marked by a rule were added automatically: {app.tags.filter((t) => t.source === "rule").map((t) => `${t.category_name}: ${t.name}`).join(", ")}.
          </p>
        )}
      </fieldset>
      {save.isError && <ErrorPanel error={save.error} />}
      {saved && !dirty && <Alert tone="success">Saved.</Alert>}
      {editable && (
        <div className="flex flex-wrap justify-end gap-2">
          {extraActions}
          <Button type="button" variant="secondary" disabled={!dirty || save.isPending} onClick={() => setD(draftFrom(app))}>
            Reset
          </Button>
          <Button type="submit" disabled={!dirty || save.isPending}>
            {save.isPending ? "Saving…" : saveLabel}
          </Button>
        </div>
      )}
    </form>
  );
}

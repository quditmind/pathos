import { useId, useState } from "react";
import { Info, Plus, X } from "lucide-react";
import type { AssetField, AssetSettings, ClassificationKind, FieldErrors, PublicExposure } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Combobox, type ComboOption } from "@/components/ui/combobox";
import { ColorPicker } from "@/components/ui/color-picker";
import { Input, Select } from "@/components/ui/primitives";
import { catalog, directoryTeams, directoryUsers } from "@/features/assets/api";
import { useBusinessUnits, useRegions } from "@/features/users/api";
import { cn } from "@/lib/utils";
import { useApplications } from "../api";
import { buTree, descendants, FormField, Textarea } from "./fields";
import { errorFor, fieldLabels, maxEndpoints, type EndpointListKey, type MetadataDraft, type PersonRef, type SectionKey } from "./model";
import { TagPicker } from "./TagPicker";

export interface SectionProps {
  draft: MetadataDraft;
  set: (patch: Partial<MetadataDraft>) => void;
  errors: FieldErrors;
  required: Set<AssetField>;
  settings?: AssetSettings;
  /** Read-only: every control disabled. */
  disabled?: boolean;
  /** Business unit, department and country need repos.manage (Repository.can_manage). */
  placementLocked?: boolean;
  /** Show display name / asset name inputs (single asset). */
  names?: boolean;
}

export function MetadataSection({ section, ...p }: SectionProps & { section: SectionKey }) {
  switch (section) {
    case "general":
      return <GeneralSection {...p} />;
    case "ownership":
      return <OwnershipSection {...p} />;
    case "geography":
      return <GeographySection {...p} />;
    case "classification":
      return <ClassificationSection {...p} />;
    case "tags":
      return <TagsSection {...p} />;
    case "lifecycle":
      return <LifecycleSection {...p} />;
  }
}

const grid = "grid gap-x-4 gap-y-3 sm:grid-cols-2";

function req(p: SectionProps, f: AssetField) {
  return p.required.has(f);
}

type ControlProps = { id?: string; "aria-invalid"?: boolean; "aria-describedby"?: string; "aria-required"?: boolean };

function CatalogSelect({
  kind,
  value,
  onChange,
  settings,
  disabled,
  emptyLabel = "Not set",
  exclude,
  ...aria
}: ControlProps & { kind: ClassificationKind; value: string; onChange: (v: string) => void; settings?: AssetSettings; disabled?: boolean; emptyLabel?: string; exclude?: string[] }) {
  const entries = catalog(settings, kind).filter((c) => !exclude?.includes(c.key));
  const current = settings?.classifications?.[kind]?.find((c) => c.key === value);
  return (
    <Select {...aria} className="w-full" disabled={disabled} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{emptyLabel}</option>
      {entries.map((c) => (
        <option key={c.id} value={c.key}>
          {c.label}
        </option>
      ))}
      {value && !entries.some((c) => c.key === value) && <option value={value}>{current ? `${current.label} (archived)` : value}</option>}
    </Select>
  );
}

function catalogHint(settings: AssetSettings | undefined, kind: ClassificationKind, key: string) {
  return settings?.classifications?.[kind]?.find((c) => c.key === key)?.description || undefined;
}

const userOption = (u: { id: string; name: string; email?: string }): ComboOption => ({ value: u.id, label: u.name || u.email || u.id, description: u.email });

export function PersonPicker({ value, onChange, disabled, ...aria }: ControlProps & { value: PersonRef | null; onChange: (v: PersonRef | null) => void; disabled?: boolean }) {
  return (
    <Combobox
      {...aria}
      queryKey="directory-users"
      placeholder="Search people…"
      disabled={disabled}
      value={value ? userOption(value) : null}
      onChange={(o) => onChange(o ? { id: o.value, name: o.label, email: o.description } : null)}
      load={(q, signal) => directoryUsers(q, signal).then((us) => us.map((u) => userOption(u)))}
      emptyText="No matching people"
    />
  );
}

function TeamPicker({ value, onChange, disabled, ...aria }: ControlProps & { value: { id: string; name: string } | null; onChange: (v: { id: string; name: string } | null) => void; disabled?: boolean }) {
  return (
    <Combobox
      {...aria}
      queryKey="directory-teams"
      placeholder="Search teams…"
      disabled={disabled}
      value={value ? { value: value.id, label: value.name } : null}
      onChange={(o) => onChange(o ? { id: o.value, name: o.label } : null)}
      load={(q, signal) =>
        directoryTeams(q, signal).then((ts) => ts.map((t) => ({ value: t.id, label: t.name, description: `${t.member_count} member${t.member_count === 1 ? "" : "s"}` })))
      }
      emptyText="No matching teams"
    />
  );
}

function GeneralSection(p: SectionProps) {
  const { draft: d, set, errors } = p;
  const apps = useApplications();
  const appError = errorFor(errors, "application");
  return (
    <div className="space-y-4">
      {p.names && (
        <div className={grid}>
          <FormField label="Display name" required error={errors.display_name}>
            <Input disabled={p.disabled} value={d.display_name} maxLength={200} onChange={(e) => set({ display_name: e.target.value })} />
          </FormField>
          <FormField label="Asset name" required error={errors.asset_name} hint="Unique identifier: lower-case letters, digits and hyphens.">
            <Input disabled={p.disabled} value={d.asset_name} maxLength={100} className="font-mono" onChange={(e) => set({ asset_name: e.target.value })} />
          </FormField>
        </div>
      )}
      <FormField label={fieldLabels.description} required={req(p, "description")} error={errorFor(errors, "description")}>
        <Textarea disabled={p.disabled} value={d.description} maxLength={2000} onChange={(e) => set({ description: e.target.value })} />
      </FormField>
      <fieldset className="space-y-2" disabled={p.disabled}>
        <legend className="mb-1 text-[12px] font-medium">
          {fieldLabels.application}
          {req(p, "application") && <span className="ml-0.5 text-danger" aria-hidden>*</span>}
        </legend>
        <div className="flex flex-wrap gap-4 text-[13px]">
          {(["existing", "new"] as const).map((m) => (
            <label key={m} className="flex items-center gap-1.5">
              <input type="radio" name="application_mode" className="accent-[var(--primary)]" checked={d.application_mode === m} onChange={() => set({ application_mode: m })} />
              {m === "existing" ? "Existing application" : "Create a new application"}
            </label>
          ))}
        </div>
        {d.application_mode === "existing" ? (
          <FormField label="Select application" error={appError} required={req(p, "application")}>
            <Combobox
              placeholder={apps.isPending ? "Loading applications…" : "Search applications…"}
              disabled={p.disabled}
              value={d.application ? { value: d.application.id, label: d.application.name } : null}
              onChange={(o) => set({ application: o ? { id: o.value, name: o.label } : null })}
              options={(apps.data ?? []).filter((a) => !a.archived_at).map((a) => ({ value: a.id, label: a.name, description: a.business_unit?.name }))}
              emptyText="No applications. Create a new one instead."
            />
          </FormField>
        ) : (
          <div className={grid}>
            <FormField label="New application name" required error={errors["new_application.name"] ?? appError}>
              <Input value={d.new_app_name} maxLength={200} onChange={(e) => set({ new_app_name: e.target.value })} />
            </FormField>
            <FormField label="Application ID" hint="CMDB or enterprise application identifier (optional)." error={errors["new_application.external_ref"]}>
              <Input value={d.new_app_ref} maxLength={100} onChange={(e) => set({ new_app_ref: e.target.value })} />
            </FormField>
          </div>
        )}
      </fieldset>
      <div className={grid}>
        <FormField label={fieldLabels.application_type} required={req(p, "application_type")} error={errorFor(errors, "application_type")}
          hint={catalogHint(p.settings, "application_type", d.application_type)}>
          <CatalogSelect kind="application_type" settings={p.settings} disabled={p.disabled} value={d.application_type} onChange={(v) => set({ application_type: v })} />
        </FormField>
      </div>
      <FormField label={fieldLabels.business_purpose} required={req(p, "business_purpose")} error={errorFor(errors, "business_purpose")}>
        <Textarea disabled={p.disabled} value={d.business_purpose} maxLength={2000} rows={2} onChange={(e) => set({ business_purpose: e.target.value })} />
      </FormField>
      <div className="space-y-2">
        <div className={grid}>
          <FormField label={fieldLabels.staging_url} required={req(p, "staging_url")} error={errorFor(errors, "staging_url")}>
            <Input type="url" inputMode="url" placeholder="https://" disabled={p.disabled} value={d.staging_url} maxLength={2048} onChange={(e) => set({ staging_url: e.target.value })} />
          </FormField>
          <FormField label={fieldLabels.production_url} required={req(p, "production_url")} error={errorFor(errors, "production_url")}>
            <Input type="url" inputMode="url" placeholder="https://" disabled={p.disabled} value={d.production_url} maxLength={2048} onChange={(e) => set({ production_url: e.target.value })} />
          </FormField>
        </div>
        <p className="flex items-start gap-1.5 text-[12px] text-muted-foreground">
          <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          Application URLs are where the running application is reached; they differ from the source repository URL. PATHOS records them as metadata and never contacts them.
        </p>
      </div>
    </div>
  );
}

function OwnershipSection(p: SectionProps) {
  const { draft: d, set, errors } = p;
  const bus = useBusinessUnits();
  const tree = buTree(bus.data ?? []);
  const depts = d.business_unit_id ? descendants(bus.data ?? [], d.business_unit_id) : [];
  const indent = (n: number) => "   ".repeat(n);
  const placementDisabled = p.disabled || p.placementLocked;
  const lockHint = p.placementLocked && !p.disabled ? "Changing placement requires repository management permission." : undefined;
  return (
    <div className="space-y-4">
      <div className={grid}>
        <FormField label={fieldLabels.business_owner} required={req(p, "business_owner")} error={errorFor(errors, "business_owner")}>
          <PersonPicker disabled={p.disabled} value={d.business_owner} onChange={(v) => set({ business_owner: v })} />
        </FormField>
        <FormField label={fieldLabels.technical_owner} required={req(p, "technical_owner")} error={errorFor(errors, "technical_owner")}>
          <PersonPicker disabled={p.disabled} value={d.technical_owner} onChange={(v) => set({ technical_owner: v })} />
        </FormField>
        <FormField label={fieldLabels.application_owner} required={req(p, "application_owner")} error={errorFor(errors, "application_owner")}>
          <PersonPicker disabled={p.disabled} value={d.application_owner} onChange={(v) => set({ application_owner: v })} />
        </FormField>
      </div>
      <div className={grid}>
        <FormField label={fieldLabels.business_unit} required={req(p, "business_unit")} error={errorFor(errors, "business_unit")} hint={lockHint}>
          <Select
            className="w-full"
            disabled={placementDisabled}
            value={d.business_unit_id}
            onChange={(e) => {
              const id = e.target.value;
              const keep = id && descendants(bus.data ?? [], id).some((x) => x.unit.id === d.department_id);
              set({ business_unit_id: id, department_id: keep ? d.department_id : "" });
            }}
          >
            <option value="">{bus.isPending ? "Loading…" : "Not set"}</option>
            {tree.map(({ unit, depth }) => (
              <option key={unit.id} value={unit.id}>
                {indent(depth)}
                {unit.name}
              </option>
            ))}
          </Select>
        </FormField>
        <FormField
          label={fieldLabels.department}
          required={req(p, "department")}
          error={errorFor(errors, "department")}
          hint={!d.business_unit_id ? "Choose a business unit first." : !depts.length ? "This business unit has no sub-units." : undefined}
        >
          <Select className="w-full" disabled={placementDisabled || !depts.length} value={d.department_id} onChange={(e) => set({ department_id: e.target.value })}>
            <option value="">Not set</option>
            {depts.map(({ unit, depth }) => (
              <option key={unit.id} value={unit.id}>
                {indent(depth)}
                {unit.name}
              </option>
            ))}
          </Select>
        </FormField>
        <FormField label={fieldLabels.responsible_team} required={req(p, "responsible_team")} error={errorFor(errors, "responsible_team")}>
          <TeamPicker disabled={p.disabled} value={d.responsible_team} onChange={(v) => set({ responsible_team: v })} />
        </FormField>
        <FormField label={fieldLabels.supporting_team} required={req(p, "supporting_team")} error={errorFor(errors, "supporting_team")}>
          <TeamPicker disabled={p.disabled} value={d.supporting_team} onChange={(v) => set({ supporting_team: v })} />
        </FormField>
        <FormField label={fieldLabels.cost_centre} required={req(p, "cost_centre")} error={errorFor(errors, "cost_centre")}>
          <Input disabled={p.disabled} value={d.cost_centre} maxLength={100} onChange={(e) => set({ cost_centre: e.target.value })} />
        </FormField>
      </div>
    </div>
  );
}

function GeographySection(p: SectionProps) {
  const { draft: d, set, errors } = p;
  const regions = useRegions();
  const [allCountries, setAllCountries] = useState(false);
  const list = regions.data ?? [];
  const inRegion = list.find((r) => r.id === d.business_region_id);
  const countryRegions = inRegion && !allCountries ? [inRegion] : list;
  const selectedOutside = d.country_id && inRegion && !allCountries && !inRegion.countries.some((c) => c.id === d.country_id);
  return (
    <div className="space-y-4">
      <div className={grid}>
        <FormField label={fieldLabels.business_region} required={req(p, "business_region")} error={errorFor(errors, "business_region")}
          hint="The region of the business that owns the asset.">
          <Select className="w-full" disabled={p.disabled} value={d.business_region_id} onChange={(e) => set({ business_region_id: e.target.value })}>
            <option value="">{regions.isPending ? "Loading…" : "Not set"}</option>
            {list.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </Select>
        </FormField>
        <div>
          <FormField label={fieldLabels.country} required={req(p, "country")} error={errorFor(errors, "country")}
            hint={p.placementLocked && !p.disabled ? "Changing placement requires repository management permission." : undefined}>
            <Select className="w-full" disabled={p.disabled || p.placementLocked} value={d.country_id} onChange={(e) => set({ country_id: e.target.value })}>
              <option value="">Not set</option>
              {selectedOutside && (
                <option value={d.country_id}>
                  {list.flatMap((r) => r.countries).find((c) => c.id === d.country_id)?.name ?? "Current country"}
                </option>
              )}
              {countryRegions.map((r) => (
                <optgroup key={r.id} label={r.name}>
                  {[...r.countries].sort((a, b) => a.name.localeCompare(b.name)).map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                    </option>
                  ))}
                </optgroup>
              ))}
            </Select>
          </FormField>
          {inRegion && (
            <label className="mt-1 flex items-center gap-1.5 text-[12px] text-muted-foreground">
              <input type="checkbox" className="accent-[var(--primary)]" checked={allCountries} onChange={(e) => setAllCountries(e.target.checked)} disabled={p.disabled} />
              Show countries outside {inRegion.name}
            </label>
          )}
        </div>
        <FormField label={fieldLabels.hosting_region} required={req(p, "hosting_region")} error={errorFor(errors, "hosting_region")}
          hint="Where the workload runs (e.g. cloud region). Independent of the business region.">
          <CatalogSelect kind="hosting_region" settings={p.settings} disabled={p.disabled} value={d.hosting_region} onChange={(v) => set({ hosting_region: v })} />
        </FormField>
        <FormField label={fieldLabels.data_residency_region} required={req(p, "data_residency_region")} error={errorFor(errors, "data_residency_region")}
          hint="Where the data must remain.">
          <Select className="w-full" disabled={p.disabled} value={d.data_residency_region_id} onChange={(e) => set({ data_residency_region_id: e.target.value })}>
            <option value="">Not set</option>
            {list.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </Select>
        </FormField>
        <FormField label={fieldLabels.operational_location} required={req(p, "operational_location")} error={errorFor(errors, "operational_location")}
          hint="City, site or data centre.">
          <Input disabled={p.disabled} value={d.operational_location} maxLength={200} onChange={(e) => set({ operational_location: e.target.value })} />
        </FormField>
      </div>
    </div>
  );
}

const defaultCriticality = [
  { key: "low", label: "Low", description: "Limited business impact.", color: "" },
  { key: "medium", label: "Medium", description: "Moderate business impact.", color: "" },
  { key: "high", label: "High", description: "Significant business impact.", color: "" },
  { key: "critical", label: "Critical", description: "Business-critical: outages or breaches have severe impact.", color: "" },
];
const sevVar: Record<string, string> = { low: "var(--sev-low)", medium: "var(--sev-medium)", high: "var(--sev-high)", critical: "var(--sev-critical)" };

const exposureChoices: { value: PublicExposure; label: string; description: string }[] = [
  { value: "yes", label: "Yes", description: "Reachable from the internet" },
  { value: "no", label: "No", description: "Internal or private only" },
  { value: "unknown", label: "Unknown", description: "Not assessed yet" },
];

const endpointLists: { key: EndpointListKey; label: string; item: string; add: string; placeholder: string; hint?: string }[] = [
  { key: "public_urls", label: "Public-facing URLs", item: "Public-facing URL", add: "Add URL", placeholder: "https://app.example.com" },
  { key: "public_domains", label: "Public domain names", item: "Public domain name", add: "Add domain", placeholder: "app.example.com", hint: "Wildcards such as *.example.com are allowed." },
  { key: "public_ips", label: "Public IP addresses", item: "Public IP address", add: "Add IP address", placeholder: "203.0.113.10", hint: "Public IPv4 or IPv6 addresses only." },
];

/** Repeatable text inputs (add / remove rows). */
export function EndpointList({
  label,
  item,
  addLabel,
  placeholder,
  hint,
  rows,
  onChange,
  error,
  disabled,
  type = "text",
}: {
  label: string;
  item: string;
  addLabel: string;
  placeholder?: string;
  hint?: string;
  rows: string[];
  onChange: (rows: string[]) => void;
  error?: string;
  disabled?: boolean;
  type?: "text" | "url";
}) {
  const id = useId();
  const errId = error ? `${id}-err` : undefined;
  const hintId = hint ? `${id}-hint` : undefined;
  return (
    <div role="group" aria-labelledby={`${id}-label`} aria-describedby={[hintId, errId].filter(Boolean).join(" ") || undefined}>
      <div id={`${id}-label`} className="mb-1 text-[12px] font-medium">
        {label}
      </div>
      {rows.length === 0 && <p className="mb-1 text-[12px] text-muted-foreground">None added.</p>}
      <ul className="space-y-1.5">
        {rows.map((v, i) => (
          <li key={i} className="flex items-center gap-1.5">
            <Input
              type={type}
              aria-label={`${item} ${i + 1}`}
              aria-invalid={error && v.trim() ? true : undefined}
              placeholder={placeholder}
              disabled={disabled}
              value={v}
              maxLength={2048}
              onChange={(e) => onChange(rows.map((r, j) => (j === i ? e.target.value : r)))}
            />
            <Button
              type="button"
              variant="ghost"
              size="icon"
              disabled={disabled}
              aria-label={`Remove ${item} ${i + 1}`}
              onClick={() => onChange(rows.filter((_, j) => j !== i))}
            >
              <X />
            </Button>
          </li>
        ))}
      </ul>
      <Button type="button" variant="ghost" size="sm" className="mt-1" disabled={disabled || rows.length >= maxEndpoints} onClick={() => onChange([...rows, ""])}>
        <Plus /> {addLabel}
      </Button>
      {hint && (
        <p id={hintId} className="text-[11.5px] text-muted-foreground">
          {hint}
        </p>
      )}
      {error && (
        <p id={errId} role="alert" className="mt-1 text-[12px] text-danger">
          {error}
        </p>
      )}
    </div>
  );
}

const hasEndpoints = (d: MetadataDraft) => d.public_urls.some((x) => x.trim()) || d.public_domains.some((x) => x.trim()) || d.public_ips.some((x) => x.trim());

function ExposureQuestion(p: SectionProps) {
  const { draft: d, set, errors } = p;
  const id = useId();
  const err = errors.public_exposure;
  const detailErr = errorFor(errors, "internet_exposure");
  const choose = (v: PublicExposure) => {
    const patch: Partial<MetadataDraft> = { public_exposure: v };
    if (v === "yes") {
      patch.internet_exposure = "public";
      if (!d.public_urls.length && !d.public_domains.length && !d.public_ips.length) patch.public_urls = [""];
    } else if (v === "unknown") patch.internet_exposure = "unknown";
    else patch.internet_exposure = d.internet_exposure === "public" || d.internet_exposure === "unknown" ? "" : d.internet_exposure;
    set(patch);
  };
  return (
    <div className="space-y-3 rounded-md border border-border p-3">
      <div
        role="radiogroup"
        aria-labelledby={`${id}-q`}
        aria-required
        aria-invalid={err ? true : undefined}
        aria-describedby={[`${id}-info`, err ? `${id}-err` : ""].filter(Boolean).join(" ")}
      >
        <div id={`${id}-q`} className="mb-1.5 text-[13px] font-medium">
          Is this application or asset publicly exposed to the internet?
          <span className="ml-0.5 text-danger" aria-hidden>
            *
          </span>
        </div>
        <div className="grid gap-2 sm:grid-cols-3">
          {exposureChoices.map((c) => {
            const checked = d.public_exposure === c.value;
            return (
              <label
                key={c.value}
                className={cn(
                  "flex cursor-pointer items-start gap-2 rounded-md border p-2.5 text-[12px] has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-ring",
                  checked ? "border-primary bg-primary/5" : err ? "border-danger" : "border-border hover:bg-surface-muted/60",
                  p.disabled && "cursor-default opacity-60",
                )}
              >
                <input
                  type="radio"
                  name={`${id}-public-exposure`}
                  value={c.value}
                  className="mt-0.5 accent-[var(--primary)]"
                  checked={checked}
                  disabled={p.disabled}
                  onChange={() => choose(c.value)}
                />
                <span>
                  <span className="block text-[13px] font-medium">{c.label}</span>
                  <span className="text-muted-foreground">{c.description}</span>
                </span>
              </label>
            );
          })}
        </div>
        <p id={`${id}-info`} className="mt-1.5 flex items-start gap-1.5 text-[12px] text-muted-foreground">
          <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          Answering Yes records metadata only; PATHOS does not crawl or scan these addresses.
        </p>
        {err && (
          <p id={`${id}-err`} role="alert" className="mt-1 text-[12px] text-danger">
            {err}
          </p>
        )}
      </div>

      {d.public_exposure === "yes" && (
        <div className="grid gap-3 lg:grid-cols-3">
          {endpointLists.map((l) => (
            <EndpointList
              key={l.key}
              label={l.label}
              item={l.item}
              addLabel={l.add}
              placeholder={l.placeholder}
              hint={l.hint}
              type={l.key === "public_urls" ? "url" : "text"}
              rows={d[l.key]}
              onChange={(rows) => set({ [l.key]: rows } as Partial<MetadataDraft>)}
              error={errors[l.key]}
              disabled={p.disabled}
            />
          ))}
        </div>
      )}
      {d.public_exposure === "no" && (
        <div className={grid}>
          <FormField
            label={fieldLabels.internet_exposure}
            required={req(p, "internet_exposure")}
            error={detailErr}
            hint={catalogHint(p.settings, "internet_exposure", d.internet_exposure) ?? "Optional: how the asset is reachable inside your network."}
          >
            <CatalogSelect
              kind="internet_exposure"
              exclude={["public"]}
              settings={p.settings}
              disabled={p.disabled}
              value={d.internet_exposure}
              onChange={(v) => set({ internet_exposure: v })}
            />
          </FormField>
        </div>
      )}
      {d.public_exposure !== "no" && detailErr && (
        <p role="alert" className="text-[12px] text-danger">
          {fieldLabels.internet_exposure}: {detailErr}
        </p>
      )}
      {d.public_exposure && d.public_exposure !== "yes" && hasEndpoints(d) && (
        <p className="text-[12px] text-muted-foreground">The public endpoints entered earlier are removed when you save. Choose Yes to keep them.</p>
      )}
      {d.public_exposure && (
        <FormField label="Exposure notes" error={errors.exposure_notes} hint="Optional context, e.g. WAF or CDN in front, or who confirmed the answer.">
          <Textarea disabled={p.disabled} value={d.exposure_notes} rows={2} maxLength={2000} onChange={(e) => set({ exposure_notes: e.target.value })} />
        </FormField>
      )}
    </div>
  );
}

function ClassificationSection(p: SectionProps) {
  const { draft: d, set, errors } = p;
  const crit = catalog(p.settings, "criticality");
  const levels = crit.length ? crit : defaultCriticality;
  const compliance = catalog(p.settings, "compliance");
  const critErr = errorFor(errors, "criticality");
  const compErr = errorFor(errors, "compliance_scopes");
  return (
    <div className="space-y-4">
      <ExposureQuestion {...p} />
      <fieldset disabled={p.disabled} aria-describedby={critErr ? "crit-err" : undefined}>
        <legend className="mb-1.5 text-[12px] font-medium">
          {fieldLabels.criticality}
          {req(p, "criticality") && <span className="ml-0.5 text-danger" aria-hidden>*</span>}
        </legend>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {levels.map((c) => {
            const color = c.color || sevVar[c.key] || "var(--primary)";
            const checked = d.criticality === c.key;
            return (
              <label
                key={c.key}
                className={cn(
                  "flex cursor-pointer flex-col gap-1 rounded-md border p-2.5 text-[12px] has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-ring",
                  checked ? "border-primary bg-primary/5" : "border-border hover:bg-surface-muted/60",
                )}
              >
                <span className="flex items-center gap-2 text-[13px] font-medium">
                  <input type="radio" name="criticality" className="sr-only" checked={checked} onChange={() => set({ criticality: c.key })} />
                  <span className="size-2.5 rounded-full" style={{ backgroundColor: color }} aria-hidden />
                  {c.label}
                </span>
                {c.description && <span className="text-muted-foreground">{c.description}</span>}
              </label>
            );
          })}
        </div>
        {critErr && <p id="crit-err" role="alert" className="mt-1 text-[12px] text-danger">{critErr}</p>}
      </fieldset>
      <div className={grid}>
        <FormField label={fieldLabels.data_classification} required={req(p, "data_classification")} error={errorFor(errors, "data_classification")}
          hint={catalogHint(p.settings, "data_classification", d.data_classification)}>
          <CatalogSelect kind="data_classification" settings={p.settings} disabled={p.disabled} value={d.data_classification} onChange={(v) => set({ data_classification: v })} />
        </FormField>
        <FormField label={fieldLabels.environment} required={req(p, "environment")} error={errorFor(errors, "environment")}
          hint={catalogHint(p.settings, "environment", d.environment)}>
          <CatalogSelect kind="environment" settings={p.settings} disabled={p.disabled} value={d.environment} onChange={(v) => set({ environment: v })} />
        </FormField>
      </div>
      <fieldset disabled={p.disabled}>
        <legend className="mb-1.5 text-[12px] font-medium">
          {fieldLabels.compliance_scopes}
          {req(p, "compliance_scopes") && <span className="ml-0.5 text-danger" aria-hidden>*</span>}
        </legend>
        {compliance.length ? (
          <div className="grid gap-1.5 sm:grid-cols-2">
            {compliance.map((c) => (
              <label key={c.id} className="flex items-start gap-2 text-[13px]" title={c.description}>
                <input
                  type="checkbox"
                  className="mt-0.5 accent-[var(--primary)]"
                  checked={d.compliance_scopes.includes(c.key)}
                  onChange={(e) =>
                    set({ compliance_scopes: e.target.checked ? [...d.compliance_scopes, c.key] : d.compliance_scopes.filter((k) => k !== c.key) })
                  }
                />
                <span>
                  {c.label}
                  {c.description && <span className="block text-[11.5px] text-muted-foreground">{c.description}</span>}
                </span>
              </label>
            ))}
          </div>
        ) : (
          <p className="text-[12px] text-muted-foreground">No compliance scopes are configured (Administration → Asset settings).</p>
        )}
        <p className="mt-2 flex items-center gap-1.5 text-[12px] text-muted-foreground">
          <Info className="size-3.5 shrink-0" aria-hidden /> Compliance scope indicates applicability, not certification.
        </p>
        {compErr && <p role="alert" className="mt-1 text-[12px] text-danger">{compErr}</p>}
      </fieldset>
    </div>
  );
}

function TagsSection(p: SectionProps) {
  const { draft: d, set, errors } = p;
  const swatches = (p.settings?.suggested_colors ?? []).map((s) => ({ value: s.color, label: s.label }));
  return (
    <div className="space-y-5">
      <TagPicker value={d.tag_ids} onChange={(tag_ids) => set({ tag_ids })} disabled={p.disabled} required={req(p, "tags")} error={errorFor(errors, "tags")} />
      <div>
        <div className="mb-1 text-[12px] font-medium">Asset colour</div>
        <ColorPicker label="Asset colour" value={d.color} onChange={(color) => set({ color })} swatches={swatches} allowNone disabled={p.disabled} invalid={!!errors.color} />
        {errors.color && <p role="alert" className="mt-1 text-[12px] text-danger">{errors.color}</p>}
        <p className="mt-1.5 text-[12px] text-muted-foreground">The colour is a visual indicator in lists and charts only; it does not change risk or access.</p>
      </div>
    </div>
  );
}

function LifecycleSection(p: SectionProps) {
  const { draft: d, set, errors } = p;
  return (
    <div className={grid}>
      <FormField label={fieldLabels.lifecycle_status} required={req(p, "lifecycle_status")} error={errorFor(errors, "lifecycle_status")}
        hint={catalogHint(p.settings, "lifecycle_status", d.lifecycle_status)}>
        <CatalogSelect kind="lifecycle_status" settings={p.settings} disabled={p.disabled} value={d.lifecycle_status} onChange={(v) => set({ lifecycle_status: v })} />
      </FormField>
      <div />
      <FormField label="Go-live date" error={errors.go_live_date}>
        <Input type="date" disabled={p.disabled} value={d.go_live_date} onChange={(e) => set({ go_live_date: e.target.value })} />
      </FormField>
      <FormField label="Retirement date" error={errors.retirement_date} hint="On or after the go-live date.">
        <Input type="date" disabled={p.disabled} min={d.go_live_date || undefined} value={d.retirement_date} onChange={(e) => set({ retirement_date: e.target.value })} />
      </FormField>
    </div>
  );
}

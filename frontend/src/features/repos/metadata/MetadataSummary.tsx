import type { ReactNode } from "react";
import type { AssetSettings } from "@/api/types";
import { ColorDot, CriticalityBadge, TagChip } from "@/components/data/TagChip";
import { catalogEntry, catalogLabel } from "@/features/assets/api";
import { useBusinessUnits, useRegions } from "@/features/users/api";
import { useTagCategories } from "../api";
import { ExternalUrl, PublicExposureBadge } from "../badges";
import { countryName } from "./fields";
import { sections, type MetadataDraft, type SectionKey } from "./model";

const filled = (xs: string[]) => xs.some((x) => x.trim());

function List({ items, link }: { items: string[]; link?: boolean }) {
  const xs = items.map((x) => x.trim()).filter(Boolean);
  if (!xs.length) return null;
  return (
    <ul className="space-y-0.5">
      {xs.map((x) => (
        <li key={x} className="min-w-0">
          {link ? <ExternalUrl href={x} /> : <span className="font-mono text-[12px]">{x}</span>}
        </li>
      ))}
    </ul>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  const empty = children == null || children === "" || (Array.isArray(children) && !children.length);
  return (
    <div className="min-w-0">
      <dt className="text-[12px] text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 break-words text-[13px]">{empty ? <span className="text-muted-foreground">—</span> : children}</dd>
    </div>
  );
}

const fmtDate = (d: string) => (d ? new Date(`${d}T00:00:00`).toLocaleDateString(undefined, { dateStyle: "medium" }) : "");

/** Read-only view of the metadata, grouped like the wizard sections. */
export function MetadataSummary({
  draft: d,
  settings,
  only,
  showNames,
  onEditSection,
}: {
  draft: MetadataDraft;
  settings?: AssetSettings;
  only?: SectionKey[];
  showNames?: boolean;
  onEditSection?: (s: SectionKey) => void;
}) {
  const bus = useBusinessUnits();
  const regions = useRegions();
  const cats = useTagCategories();
  const bu = (id: string) => bus.data?.find((b) => b.id === id)?.name ?? (id ? "…" : "");
  const region = (id: string) => regions.data?.find((r) => r.id === id)?.name ?? (id ? "…" : "");
  const country = countryName(regions.data, d.country_id);
  const tags = (cats.data ?? []).flatMap((c) => c.tags.filter((t) => d.tag_ids.includes(t.id)).map((t) => ({ ...t, category: c.name })));
  const crit = catalogEntry(settings, "criticality", d.criticality);

  const body: Record<SectionKey, ReactNode> = {
    general: (
      <>
        {showNames && <Row label="Display name">{d.display_name}</Row>}
        {showNames && <Row label="Asset name"><span className="font-mono text-[12px]">{d.asset_name}</span></Row>}
        <Row label="Application">
          {d.application_mode === "new" && d.new_app_name ? `${d.new_app_name} (new${d.new_app_ref ? ` · ${d.new_app_ref}` : ""})` : d.application?.name}
        </Row>
        <Row label="Application type">{catalogLabel(settings, "application_type", d.application_type)}</Row>
        <div className="sm:col-span-2"><Row label="Description">{d.description}</Row></div>
        <div className="sm:col-span-2"><Row label="Business purpose">{d.business_purpose}</Row></div>
        <Row label="Staging URL">{d.staging_url.trim() ? <ExternalUrl href={d.staging_url.trim()} /> : null}</Row>
        <Row label="Production URL">{d.production_url.trim() ? <ExternalUrl href={d.production_url.trim()} /> : null}</Row>
      </>
    ),
    ownership: (
      <>
        <Row label="Business owner">{d.business_owner?.name}</Row>
        <Row label="Technical owner">{d.technical_owner?.name}</Row>
        <Row label="Application owner">{d.application_owner?.name}</Row>
        <Row label="Business unit">{bu(d.business_unit_id)}</Row>
        <Row label="Department">{bu(d.department_id)}</Row>
        <Row label="Responsible team">{d.responsible_team?.name}</Row>
        <Row label="Supporting team">{d.supporting_team?.name}</Row>
        <Row label="Cost centre">{d.cost_centre}</Row>
      </>
    ),
    geography: (
      <>
        <Row label="Business region">{region(d.business_region_id)}</Row>
        <Row label="Country">{country ? `${country.country.name} (${country.region.name})` : d.country_id ? "…" : ""}</Row>
        <Row label="Hosting region">{catalogLabel(settings, "hosting_region", d.hosting_region)}</Row>
        <Row label="Data residency region">{region(d.data_residency_region_id)}</Row>
        <Row label="Primary operational location">{d.operational_location}</Row>
      </>
    ),
    classification: (
      <>
        <Row label="Publicly exposed to the internet">{d.public_exposure ? <PublicExposureBadge value={d.public_exposure} /> : null}</Row>
        {d.public_exposure === "no" ? <Row label="Network reachability detail">{catalogLabel(settings, "internet_exposure", d.internet_exposure)}</Row> : null}
        {d.public_exposure === "yes" && (
          <>
            <Row label="Public-facing URLs">{filled(d.public_urls) ? <List items={d.public_urls} link /> : null}</Row>
            <Row label="Public domain names">{filled(d.public_domains) ? <List items={d.public_domains} /> : null}</Row>
            <Row label="Public IP addresses">{filled(d.public_ips) ? <List items={d.public_ips} /> : null}</Row>
          </>
        )}
        {d.exposure_notes.trim() && <div className="sm:col-span-2"><Row label="Exposure notes"><span className="whitespace-pre-wrap">{d.exposure_notes}</span></Row></div>}
        <Row label="Criticality">{d.criticality && <CriticalityBadge value={d.criticality} label={crit?.label} color={crit?.color} />}</Row>
        <Row label="Data classification">{catalogLabel(settings, "data_classification", d.data_classification)}</Row>
        <Row label="Environment">{catalogLabel(settings, "environment", d.environment)}</Row>
        <div className="sm:col-span-2">
          <Row label="Compliance scope">{d.compliance_scopes.map((k) => catalogLabel(settings, "compliance", k)).join(", ")}</Row>
        </div>
      </>
    ),
    tags: (
      <>
        <div className="sm:col-span-2">
          <Row label="Tags">
            {tags.length ? (
              <span className="flex flex-wrap gap-1">
                {tags.map((t) => (
                  <TagChip key={t.id} name={t.name} category={t.category} color={t.color} />
                ))}
              </span>
            ) : null}
          </Row>
        </div>
        <Row label="Asset colour">
          {d.color ? (
            <span className="inline-flex items-center gap-1.5">
              <ColorDot color={d.color} /> <span className="font-mono text-[12px]">{d.color}</span>
            </span>
          ) : null}
        </Row>
      </>
    ),
    lifecycle: (
      <>
        <Row label="Lifecycle status">{catalogLabel(settings, "lifecycle_status", d.lifecycle_status)}</Row>
        <Row label="Go-live date">{fmtDate(d.go_live_date)}</Row>
        <Row label="Retirement date">{fmtDate(d.retirement_date)}</Row>
      </>
    ),
  };

  return (
    <div className="space-y-4">
      {sections
        .filter((s) => !only || only.includes(s.key))
        .map((s) => (
          <section key={s.key} aria-label={s.title}>
            <div className="mb-1.5 flex items-center justify-between">
              <h3 className="text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">{s.title}</h3>
              {onEditSection && (
                <button type="button" className="text-[12px] text-primary hover:underline" onClick={() => onEditSection(s.key)}>
                  Edit
                </button>
              )}
            </div>
            <dl className="grid gap-x-4 gap-y-2.5 sm:grid-cols-2">{body[s.key]}</dl>
          </section>
        ))}
    </div>
  );
}

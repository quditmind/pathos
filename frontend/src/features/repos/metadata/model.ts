// Form model shared by the onboarding wizard and the repository drawer:
// draft state, conversion to/from the API's AssetMetadata, required-field
// checks and mapping of server field errors to inputs and wizard sections.

import type { AssetField, AssetMetadata, FieldErrors, PublicExposure, Ref, Repository, TagCategory } from "@/api/types";

export interface PersonRef {
  id: string;
  name: string;
  email?: string;
}

export interface MetadataDraft {
  display_name: string;
  asset_name: string;
  description: string;
  application_mode: "existing" | "new";
  application: Ref | null;
  new_app_name: string;
  new_app_ref: string;
  application_type: string;
  business_purpose: string;
  business_owner: PersonRef | null;
  technical_owner: PersonRef | null;
  application_owner: PersonRef | null;
  business_unit_id: string;
  department_id: string;
  responsible_team: Ref | null;
  supporting_team: Ref | null;
  cost_centre: string;
  business_region_id: string;
  country_id: string;
  hosting_region: string;
  data_residency_region_id: string;
  operational_location: string;
  criticality: string;
  data_classification: string;
  environment: string;
  internet_exposure: string;
  compliance_scopes: string[];
  tag_ids: string[];
  color: string;
  lifecycle_status: string;
  go_live_date: string;
  retirement_date: string;
  staging_url: string;
  production_url: string;
  /** "" until answered (new assets have no default). */
  public_exposure: PublicExposure | "";
  /** Editable rows; blank rows are dropped when sent. */
  public_urls: string[];
  public_domains: string[];
  public_ips: string[];
  exposure_notes: string;
}

/** Endpoint list keys of the draft (and of AssetMetadata). */
export type EndpointListKey = "public_urls" | "public_domains" | "public_ips";
export const endpointListKeys: EndpointListKey[] = ["public_urls", "public_domains", "public_ips"];
export const maxEndpoints = 50;

export function emptyDraft(): MetadataDraft {
  return {
    display_name: "", asset_name: "", description: "", application_mode: "existing", application: null, new_app_name: "", new_app_ref: "",
    application_type: "", business_purpose: "", business_owner: null, technical_owner: null, application_owner: null, business_unit_id: "",
    department_id: "", responsible_team: null, supporting_team: null, cost_centre: "", business_region_id: "", country_id: "", hosting_region: "",
    data_residency_region_id: "", operational_location: "", criticality: "", data_classification: "", environment: "", internet_exposure: "",
    compliance_scopes: [], tag_ids: [], color: "", lifecycle_status: "", go_live_date: "", retirement_date: "",
    staging_url: "", production_url: "", public_exposure: "", public_urls: [], public_domains: [], public_ips: [], exposure_notes: "",
  };
}

export function draftFromRepository(r: Repository): MetadataDraft {
  return {
    display_name: r.display_name ?? "",
    asset_name: r.asset_name ?? "",
    description: r.description ?? "",
    application_mode: "existing",
    application: r.application,
    new_app_name: "",
    new_app_ref: "",
    application_type: r.application_type ?? "",
    business_purpose: r.business_purpose ?? "",
    business_owner: r.business_owner,
    technical_owner: r.technical_owner,
    application_owner: r.application_owner,
    business_unit_id: r.business_unit?.id ?? "",
    department_id: r.department?.id ?? "",
    responsible_team: r.responsible_team,
    supporting_team: r.supporting_team,
    cost_centre: r.cost_centre ?? "",
    business_region_id: r.business_region?.id ?? "",
    country_id: r.country?.id ?? "",
    hosting_region: r.hosting_region ?? "",
    data_residency_region_id: r.data_residency_region?.id ?? "",
    operational_location: r.operational_location ?? "",
    criticality: r.criticality ?? "",
    data_classification: r.data_classification ?? "",
    environment: r.environment ?? "",
    internet_exposure: r.internet_exposure ?? "",
    compliance_scopes: [...(r.compliance_scopes ?? [])],
    tag_ids: (r.tags ?? []).map((t) => t.id),
    color: r.color ?? "",
    lifecycle_status: r.lifecycle_status ?? "",
    go_live_date: r.go_live_date?.slice(0, 10) ?? "",
    retirement_date: r.retirement_date?.slice(0, 10) ?? "",
    staging_url: r.staging_url ?? "",
    production_url: r.production_url ?? "",
    // Repositories registered before the question existed count as "unknown".
    public_exposure: r.public_exposure || "unknown",
    public_urls: [...(r.public_urls ?? [])],
    public_domains: [...(r.public_domains ?? [])],
    public_ips: [...(r.public_ips ?? [])],
    exposure_notes: r.exposure_notes ?? "",
  };
}

const cleanList = (xs: string[]) => xs.map((x) => x.trim()).filter(Boolean);

/**
 * The exposure part of the payload. Endpoints are only kept for "yes"; the
 * detailed network exposure follows the answer (yes → public, unknown →
 * unknown, no → the optional non-public detail).
 */
export function exposurePayload(d: MetadataDraft): Pick<AssetMetadata, "public_exposure" | "public_urls" | "public_domains" | "public_ips" | "exposure_notes" | "internet_exposure"> {
  if (!d.public_exposure) return {};
  const yes = d.public_exposure === "yes";
  return {
    public_exposure: d.public_exposure,
    public_urls: yes ? cleanList(d.public_urls) : [],
    public_domains: yes ? cleanList(d.public_domains) : [],
    public_ips: yes ? cleanList(d.public_ips) : [],
    exposure_notes: d.exposure_notes.trim(),
    internet_exposure: yes ? "public" : d.public_exposure === "unknown" ? "unknown" : d.internet_exposure === "public" ? "" : d.internet_exposure.trim(),
  };
}

/** Full metadata payload for an import (unset values omitted). Names are sent per item. */
export function draftToMetadata(d: MetadataDraft, opts: { includeNames?: boolean } = {}): AssetMetadata {
  const m: AssetMetadata = {};
  const str = <K extends keyof AssetMetadata>(k: K, v: string) => {
    if (v.trim()) (m as Record<string, unknown>)[k] = v.trim();
  };
  if (opts.includeNames) {
    str("display_name", d.display_name);
    str("asset_name", d.asset_name);
  }
  str("description", d.description);
  if (d.application_mode === "new" && d.new_app_name.trim()) {
    m.new_application = { name: d.new_app_name.trim(), ...(d.new_app_ref.trim() ? { external_ref: d.new_app_ref.trim() } : {}) };
  } else if (d.application_mode === "existing" && d.application) m.application_id = d.application.id;
  str("application_type", d.application_type);
  str("business_purpose", d.business_purpose);
  if (d.business_owner) m.business_owner_id = d.business_owner.id;
  if (d.technical_owner) m.technical_owner_id = d.technical_owner.id;
  if (d.application_owner) m.application_owner_id = d.application_owner.id;
  str("business_unit_id", d.business_unit_id);
  str("department_id", d.department_id);
  if (d.responsible_team) m.responsible_team_id = d.responsible_team.id;
  if (d.supporting_team) m.supporting_team_id = d.supporting_team.id;
  str("cost_centre", d.cost_centre);
  str("business_region_id", d.business_region_id);
  str("country_id", d.country_id);
  str("hosting_region", d.hosting_region);
  str("data_residency_region_id", d.data_residency_region_id);
  str("operational_location", d.operational_location);
  if (d.criticality) m.criticality = d.criticality as AssetMetadata["criticality"];
  str("data_classification", d.data_classification);
  str("environment", d.environment);
  str("staging_url", d.staging_url);
  str("production_url", d.production_url);
  const exp = exposurePayload(d);
  if (exp.public_exposure) {
    m.public_exposure = exp.public_exposure;
    m.public_urls = exp.public_urls;
    m.public_domains = exp.public_domains;
    m.public_ips = exp.public_ips;
    if (exp.exposure_notes) m.exposure_notes = exp.exposure_notes;
    if (exp.internet_exposure) m.internet_exposure = exp.internet_exposure;
  } else str("internet_exposure", d.internet_exposure);
  if (d.compliance_scopes.length) m.compliance_scopes = [...d.compliance_scopes];
  if (d.tag_ids.length) m.tag_ids = [...d.tag_ids];
  str("color", d.color);
  str("lifecycle_status", d.lifecycle_status);
  str("go_live_date", d.go_live_date);
  str("retirement_date", d.retirement_date);
  return m;
}

/** PATCH body with only the changed fields; cleared optional values become null / "". */
export function diffMetadata(orig: MetadataDraft, d: MetadataDraft): AssetMetadata {
  const out: Record<string, unknown> = {};
  const nul = (v: string) => (v.trim() === "" ? null : v.trim());
  const s = (k: keyof MetadataDraft & keyof AssetMetadata) => {
    if ((orig[k] as string) !== (d[k] as string)) out[k] = (d[k] as string).trim();
  };
  const idField = (k: keyof MetadataDraft, apiKey: string) => {
    if ((orig[k] as string) !== (d[k] as string)) out[apiKey] = nul(d[k] as string);
  };
  const refField = (k: "business_owner" | "technical_owner" | "application_owner" | "responsible_team" | "supporting_team") => {
    if ((orig[k]?.id ?? "") !== (d[k]?.id ?? "")) out[`${k}_id`] = d[k]?.id ?? null;
  };
  s("display_name");
  s("asset_name");
  s("description");
  if (d.application_mode === "new" && d.new_app_name.trim()) {
    out.new_application = { name: d.new_app_name.trim(), ...(d.new_app_ref.trim() ? { external_ref: d.new_app_ref.trim() } : {}) };
  } else if ((orig.application?.id ?? "") !== (d.application?.id ?? "")) out.application_id = d.application?.id ?? null;
  s("application_type");
  s("business_purpose");
  refField("business_owner");
  refField("technical_owner");
  refField("application_owner");
  idField("business_unit_id", "business_unit_id");
  idField("department_id", "department_id");
  refField("responsible_team");
  refField("supporting_team");
  s("cost_centre");
  idField("business_region_id", "business_region_id");
  idField("country_id", "country_id");
  s("hosting_region");
  idField("data_residency_region_id", "data_residency_region_id");
  s("operational_location");
  if (orig.criticality !== d.criticality && d.criticality) out.criticality = d.criticality;
  s("data_classification");
  s("environment");
  s("staging_url");
  s("production_url");
  // Exposure fields travel together so the server can check them as a whole.
  const eo = exposurePayload(orig);
  const en = exposurePayload(d);
  if (JSON.stringify(eo) !== JSON.stringify(en)) Object.assign(out, en);
  else s("internet_exposure");
  if ([...orig.compliance_scopes].sort().join() !== [...d.compliance_scopes].sort().join()) out.compliance_scopes = [...d.compliance_scopes];
  if ([...orig.tag_ids].sort().join() !== [...d.tag_ids].sort().join()) out.tag_ids = [...d.tag_ids];
  s("color");
  s("lifecycle_status");
  idField("go_live_date", "go_live_date");
  idField("retirement_date", "retirement_date");
  return out as AssetMetadata;
}

export type SectionKey = "general" | "ownership" | "geography" | "classification" | "tags" | "lifecycle";

export const sections: { key: SectionKey; title: string; description: string; fields: AssetField[] }[] = [
  { key: "general", title: "General", description: "What this asset is and which application it belongs to.", fields: ["description", "application", "application_type", "business_purpose", "staging_url", "production_url"] },
  {
    key: "ownership",
    title: "Business ownership",
    description: "Who is accountable for the asset, and where it sits in the organization.",
    fields: ["business_owner", "technical_owner", "application_owner", "business_unit", "department", "responsible_team", "supporting_team", "cost_centre"],
  },
  {
    key: "geography",
    title: "Geography",
    description: "Business region, country and where the workload is hosted. Business region and hosting region are independent.",
    fields: ["business_region", "country", "hosting_region", "data_residency_region", "operational_location"],
  },
  {
    key: "classification",
    title: "Classification",
    description: "Criticality, data sensitivity, environment and exposure drive risk prioritisation.",
    fields: ["public_exposure", "criticality", "data_classification", "environment", "internet_exposure", "compliance_scopes"],
  },
  { key: "tags", title: "Tags & colour", description: "Tags group assets for reporting; the colour is a visual indicator only.", fields: ["tags"] },
  { key: "lifecycle", title: "Lifecycle", description: "Where the asset is in its life.", fields: ["lifecycle_status"] },
];

export const fieldLabels: Record<AssetField, string> = {
  description: "Description",
  application: "Application",
  application_type: "Application type",
  business_purpose: "Business purpose",
  business_owner: "Business owner",
  technical_owner: "Technical owner",
  application_owner: "Application owner",
  business_unit: "Business unit",
  department: "Department",
  responsible_team: "Responsible team",
  supporting_team: "Supporting team",
  cost_centre: "Cost centre",
  business_region: "Business region",
  country: "Country",
  hosting_region: "Hosting region",
  data_residency_region: "Data residency region",
  operational_location: "Primary operational location",
  criticality: "Criticality",
  data_classification: "Data classification",
  environment: "Environment",
  internet_exposure: "Network reachability detail",
  compliance_scopes: "Compliance scope",
  tags: "Tags",
  lifecycle_status: "Lifecycle status",
  staging_url: "Staging URL",
  production_url: "Production URL",
  public_exposure: "Public exposure",
};

/** Simple client-side checks; the server is authoritative (and normalizes). */
export function urlProblem(v: string): string | null {
  let u: URL;
  try {
    u = new URL(v.trim());
  } catch {
    return "Enter an absolute http:// or https:// URL";
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return "Enter an absolute http:// or https:// URL";
  if (u.username || u.password) return "URLs must not contain user names or passwords";
  return null;
}

export function domainProblem(v: string): string | null {
  const d = v.trim().replace(/\.$/, "");
  const body = d.startsWith("*.") ? d.slice(2) : d;
  if (!body.includes(".") || /[\s/:@*?#]/.test(body) || body.split(".").some((l) => !l || l.length > 63 || l.startsWith("-") || l.endsWith("-")))
    return `"${v.trim()}" is not a valid domain name`;
  return null;
}

export function ipProblem(v: string): string | null {
  const ip = v.trim();
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (m) {
    const o = m.slice(1).map(Number);
    if (o.some((n) => n > 255)) return `"${ip}" is not an IP address`;
    const [a, b] = o as [number, number, number, number];
    if (a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127))
      return `${ip} is not a public address (private, loopback and link-local addresses are not allowed)`;
    return null;
  }
  if (/^[0-9a-f:.]+$/i.test(ip) && ip.includes(":") && ip.split("::").length <= 2) {
    const l = ip.toLowerCase();
    if (l === "::1" || l === "::" || /^fe[89ab]/.test(l) || /^f[cd]/.test(l)) return `${ip} is not a public address (private, loopback and link-local addresses are not allowed)`;
    return null;
  }
  return `"${ip}" is not an IP address`;
}

const listChecks: Record<EndpointListKey, (v: string) => string | null> = { public_urls: urlProblem, public_domains: domainProblem, public_ips: ipProblem };

/** First problem of an endpoint row list (blank rows are ignored). */
export function listProblem(key: EndpointListKey, rows: string[]): string | null {
  const vals = rows.map((r) => r.trim()).filter(Boolean);
  if (vals.length > maxEndpoints) return `At most ${maxEndpoints} entries`;
  for (const v of vals) {
    const p = listChecks[key](v);
    if (p) return p;
  }
  return null;
}

export const exposureLabels: Record<PublicExposure, string> = { yes: "Public", no: "Not public", unknown: "Unknown" };

export function isFieldSet(d: MetadataDraft, f: AssetField): boolean {
  switch (f) {
    case "application":
      return d.application_mode === "new" ? !!d.new_app_name.trim() : !!d.application;
    case "business_owner":
    case "technical_owner":
    case "application_owner":
    case "responsible_team":
    case "supporting_team":
      return !!d[f];
    case "business_unit":
      return !!d.business_unit_id;
    case "department":
      return !!d.department_id;
    case "business_region":
      return !!d.business_region_id;
    case "country":
      return !!d.country_id;
    case "data_residency_region":
      return !!d.data_residency_region_id;
    case "compliance_scopes":
      return d.compliance_scopes.length > 0;
    case "tags":
      return d.tag_ids.length > 0;
    case "public_exposure":
      return !!d.public_exposure;
    case "internet_exposure":
      // Implied by the Yes / Unknown answers; a detail only exists for No.
      return d.public_exposure === "yes" || d.public_exposure === "unknown" || !!d.internet_exposure.trim();
    default:
      return !!(d[f] as string).trim();
  }
}

/**
 * Client-side checks for a section (or all sections): required fields,
 * mandatory tag categories, date order, colour format. Keys are AssetField
 * names (or "display_name" / "asset_name" / "retirement_date" / "color").
 */
export function clientErrors(
  d: MetadataDraft,
  required: Set<AssetField>,
  opts: { section?: SectionKey; categories?: TagCategory[]; names?: boolean } = {},
): FieldErrors {
  const errs: FieldErrors = {};
  const secs = opts.section ? sections.filter((s) => s.key === opts.section) : sections;
  for (const s of secs) {
    for (const f of s.fields) if (required.has(f) && !isFieldSet(d, f)) errs[f] = `${fieldLabels[f]} is required`;
    if (s.key === "general") {
      for (const f of ["staging_url", "production_url"] as const) {
        const p = d[f].trim() ? urlProblem(d[f]) : null;
        if (p && !errs[f]) errs[f] = p;
      }
    }
    if (s.key === "classification") {
      // Always mandatory, whatever the policy says: "unknown" is an explicit answer.
      if (!d.public_exposure) errs.public_exposure = "Answer whether the application or asset is publicly exposed to the internet";
      if (d.public_exposure === "yes") {
        for (const k of endpointListKeys) {
          const p = listProblem(k, d[k]);
          if (p) errs[k] = p;
        }
        if (!errs.public_urls && endpointListKeys.every((k) => !cleanList(d[k]).length))
          errs.public_urls = "Add at least one public URL, domain name or IP address";
      }
      if (d.exposure_notes.length > 2000) errs.exposure_notes = "At most 2000 characters";
    }
    if (s.key === "general") {
      if (opts.names) {
        if (!d.display_name.trim()) errs.display_name = "Display name is required";
        if (!d.asset_name.trim()) errs.asset_name = "Asset name is required";
      }
      if (d.application_mode === "new" && !d.new_app_name.trim() && (required.has("application") || d.new_app_ref.trim()))
        errs.application = "Enter a name for the new application";
    }
    if (s.key === "tags") {
      const selected = new Set(d.tag_ids);
      const missing = (opts.categories ?? []).filter((c) => c.is_mandatory && !c.tags.some((t) => selected.has(t.id)));
      if (missing.length && !errs.tags) errs.tags = `Choose a tag in: ${missing.map((c) => c.name).join(", ")}`;
      if (d.color && !/^#[0-9a-f]{6}$/i.test(d.color)) errs.color = "Use the form #rrggbb";
    }
    if (s.key === "lifecycle" && d.go_live_date && d.retirement_date && d.retirement_date < d.go_live_date)
      errs.retirement_date = "Retirement date must be on or after the go-live date";
  }
  return errs;
}

/** Server error keys (AssetMetadata names) that belong to each form field. */
const aliases: Record<string, string[]> = {
  application: ["application", "application_id", "new_application", "new_application.name", "new_application.external_ref"],
  tags: ["tags", "tag_ids"],
};

export function errorFor(errors: FieldErrors | undefined, field: string): string | undefined {
  if (!errors) return undefined;
  for (const k of aliases[field] ?? [field, `${field}_id`, `${field}_ids`]) if (errors[k]) return errors[k];
  return undefined;
}

/** Wizard section that shows a (server or client) error key; null when unknown. */
export function sectionForKey(key: string): SectionKey | null {
  const base = key.replace(/\..*$/, "");
  if (["display_name", "asset_name", "new_application"].includes(base)) return "general";
  if (["go_live_date", "retirement_date"].includes(base)) return "lifecycle";
  if (["public_urls", "public_domains", "public_ips", "exposure_notes"].includes(base)) return "classification";
  if (base === "color") return "tags";
  for (const s of sections) {
    for (const f of s.fields) {
      const keys = aliases[f] ?? [f, `${f}_id`, `${f}_ids`];
      if (keys.includes(key) || keys.includes(base)) return s.key;
    }
  }
  return null;
}

/** "my Repo.v2" → "my-repo-v2" (asset names are slugs). */
export function slugify(s: string): string {
  return s
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 100);
}

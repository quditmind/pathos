import { Label, Select } from "@/components/ui/primitives";
import type { ScopeType } from "@/api/types";
import { useBusinessUnits, useRegions, useRoles, type RoleGrant } from "./api";

export const scopeLabels: Record<ScopeType, string> = {
  organization: "Entire organization",
  region: "Region",
  business_unit: "Business unit",
  repository: "Repository",
};

/** Role + scope selector used by the invite dialog and the user drawer. */
export function RoleScopePicker({ value, onChange, idPrefix }: { value: RoleGrant; onChange: (v: RoleGrant) => void; idPrefix: string }) {
  const roles = useRoles();
  const regions = useRegions();
  const bus = useBusinessUnits();

  const scopeOptions =
    value.scope_type === "region"
      ? (regions.data ?? []).map((r) => ({ id: r.id, name: r.name }))
      : value.scope_type === "business_unit"
        ? (bus.data ?? []).map((b) => ({ id: b.id, name: b.name }))
        : [];

  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <div>
        <Label htmlFor={`${idPrefix}-role`}>Role</Label>
        <Select
          id={`${idPrefix}-role`}
          className="w-full"
          value={value.role_key}
          onChange={(e) => onChange({ ...value, role_key: e.target.value })}
        >
          <option value="">Select a role…</option>
          {(roles.data ?? []).map((r) => (
            <option key={r.key} value={r.key} title={r.description}>
              {r.name}
            </option>
          ))}
        </Select>
      </div>
      <div>
        <Label htmlFor={`${idPrefix}-scope-type`}>Scope</Label>
        <Select
          id={`${idPrefix}-scope-type`}
          className="w-full"
          value={value.scope_type}
          onChange={(e) => onChange({ ...value, scope_type: e.target.value as ScopeType, scope_id: undefined })}
        >
          {(["organization", "region", "business_unit"] as const).map((s) => (
            <option key={s} value={s}>
              {scopeLabels[s]}
            </option>
          ))}
        </Select>
      </div>
      {value.scope_type !== "organization" && (
        <div>
          <Label htmlFor={`${idPrefix}-scope-id`}>{scopeLabels[value.scope_type]}</Label>
          <Select
            id={`${idPrefix}-scope-id`}
            className="w-full"
            value={value.scope_id ?? ""}
            onChange={(e) => onChange({ ...value, scope_id: e.target.value || undefined })}
          >
            <option value="">{scopeOptions.length ? "Select…" : "None defined"}</option>
            {scopeOptions.map((o) => (
              <option key={o.id} value={o.id}>
                {o.name}
              </option>
            ))}
          </Select>
        </div>
      )}
    </div>
  );
}

export function grantIsComplete(g: RoleGrant) {
  return !!g.role_key && (g.scope_type === "organization" || !!g.scope_id);
}

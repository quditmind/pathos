import type { AuthField, AuthMethod } from "@/api/types";
import { Input } from "@/components/ui/primitives";
import { FormField, Textarea } from "@/features/repos/metadata/fields";

/** Renders the fields an auth method declares (GET /scm-providers). */
export function AuthFields({
  fields,
  values,
  onChange,
  errors,
  optionalSecrets,
}: {
  fields: AuthField[];
  values: Record<string, string>;
  onChange: (name: string, value: string) => void;
  errors?: Record<string, string>;
  /** Rotation: secrets may be left blank to keep the stored value. */
  optionalSecrets?: boolean;
}) {
  return (
    <div className="space-y-3">
      {fields.map((f) => {
        const v = values[f.name] ?? "";
        const required = f.required && !(optionalSecrets && f.secret);
        const common = { name: f.name, value: v, autoComplete: "off" as const, spellCheck: false };
        let control;
        if (f.type === "textarea") {
          control = (
            <Textarea
              {...common}
              rows={f.secret ? 6 : 3}
              className="font-mono text-[11px]"
              placeholder={f.secret ? "-----BEGIN …-----" : undefined}
              onChange={(e) => onChange(f.name, e.target.value)}
            />
          );
        } else if (f.type === "list") {
          control = <Textarea {...common} rows={3} placeholder="One per line" onChange={(e) => onChange(f.name, e.target.value)} />;
        } else {
          const type = f.secret || f.type === "password" ? "password" : f.type === "number" ? "number" : "text";
          control = <Input {...common} type={type} inputMode={f.type === "number" ? "numeric" : undefined} onChange={(e) => onChange(f.name, e.target.value)} />;
        }
        const hint = [f.help, f.type === "list" ? "One entry per line." : "", optionalSecrets && f.secret ? "Leave blank to keep the current value." : ""].filter(Boolean).join(" ");
        return (
          <FormField key={f.name} label={f.label} required={required} error={errors?.[f.name]} hint={hint || undefined}>
            {control}
          </FormField>
        );
      })}
    </div>
  );
}

/** Converts form strings to the request body (numbers, lists); blank optional values are omitted. */
export function authFieldBody(fields: AuthField[], values: Record<string, string>, opts: { skipBlankSecrets?: boolean } = {}): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    const raw = (values[f.name] ?? "").trim();
    if (!raw) {
      if (opts.skipBlankSecrets && f.secret) continue;
      if (!f.required) continue;
    }
    if (f.type === "number") out[f.name] = raw === "" ? undefined : Number(raw);
    else if (f.type === "list")
      out[f.name] = raw
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
    else out[f.name] = f.type === "textarea" ? (values[f.name] ?? "") : raw;
  }
  return out;
}

export function missingAuthFields(fields: AuthField[], values: Record<string, string>): string[] {
  return fields.filter((f) => f.required && !(values[f.name] ?? "").trim()).map((f) => f.label);
}

export const isOAuth = (m: AuthMethod | undefined) => !!m?.oauth;

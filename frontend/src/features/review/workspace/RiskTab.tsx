import { useMemo, useState } from "react";
import { ExternalLink } from "lucide-react";
import type { Severity } from "@/api/types";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { Alert, Input, Label, Select } from "@/components/ui/primitives";
import { reviewApi, useCatalog, useReviewMutation } from "../api";
import { buildVector, metricsFor, parseVector, score31, severityForScore, type CvssVersion } from "../lib/cvss";
import { humanize, severities } from "../shared";
import type { ReviewDetail } from "../types";
import { textareaCls } from "./actions";
import { KV, Panel, SaveBar, useSections } from "./section";

export function RiskTab({ d }: { d: ReviewDetail }) {
  const cat = useCatalog();
  const editable = d.can.assess;
  const parsed = parseVector(d.assessed_cvss_vector);
  const [version, setVersion] = useState<CvssVersion>(parsed?.version ?? "3.1");
  const [metrics, setMetrics] = useState<Record<string, string>>(parsed?.metrics ?? {});
  const [score40, setScore40] = useState(parsed?.version === "4.0" && d.assessed_cvss != null ? String(d.assessed_cvss) : "");
  const [severity, setSeverity] = useState<Severity | "">(d.assessed_severity ?? "");
  const [justification, setJustification] = useState(d.severity_justification);
  const s = useSections(d, ["risk"]);
  const vector = buildVector(version, metrics);
  const score = useMemo(() => (version === "3.1" ? score31(metrics) : score40 !== "" ? Number(score40) : null), [version, metrics, score40]);
  const suggested = score != null && !Number.isNaN(score) ? severityForScore(score) : null;
  const m = useReviewMutation(() =>
    reviewApi.severity(d.id, { severity: severity || suggested || "", cvss_vector: vector ?? "", cvss_score: vector || score40 ? score : null, justification }),
  );
  const finalSeverity = severity || suggested;
  const changed = finalSeverity !== d.assessed_severity || justification !== d.severity_justification || (vector ?? "") !== d.assessed_cvss_vector;

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Scanner assessment (preserved)">
          <KV
            rows={[
              ["Severity", <SeverityBadge value={d.original.severity} />],
              ["Score", d.original.cvss != null ? d.original.cvss.toFixed(1) : "Not reported"],
              ["CVSS vector", d.original.cvss_vector ? <span className="font-mono text-[11.5px]">{d.original.cvss_vector}</span> : "Not reported by the scanner"],
            ]}
          />
        </Panel>
        <Panel title="Human assessment (current)">
          <KV
            rows={[
              ["Severity", d.assessed_severity ? <SeverityBadge value={d.assessed_severity} /> : "Not assessed"],
              ["CVSS score", d.assessed_cvss != null ? d.assessed_cvss.toFixed(1) : "—"],
              ["CVSS vector", d.assessed_cvss_vector ? <span className="break-all font-mono text-[11.5px]">{d.assessed_cvss_vector}</span> : "—"],
              ["Justification", d.severity_justification || "—"],
            ]}
          />
        </Panel>
      </div>

      <Panel
        title="Reassess severity"
        actions={
          <a href={version === "4.0" ? "https://www.first.org/cvss/calculator/4.0" : "https://www.first.org/cvss/calculator/3.1"} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-[12px] text-primary hover:underline">
            FIRST calculator <ExternalLink className="size-3" />
          </a>
        }
      >
        <fieldset disabled={!editable} className="space-y-3">
          <div className="flex flex-wrap items-center gap-3 text-[12.5px]">
            <span className="font-medium">CVSS version</span>
            {(["3.1", "4.0"] as const).map((v) => (
              <label key={v} className="flex items-center gap-1.5">
                <input type="radio" className="accent-[var(--primary)]" checked={version === v} onChange={() => { setVersion(v); setMetrics({}); }} /> CVSS {v}
              </label>
            ))}
          </div>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            {metricsFor(version).map((mt) => (
              <div key={mt.key}>
                <Label htmlFor={`cvss-${mt.key}`}>{mt.label} ({mt.key})</Label>
                <Select id={`cvss-${mt.key}`} className="w-full" value={metrics[mt.key] ?? ""} onChange={(e) => setMetrics({ ...metrics, [mt.key]: e.target.value })}>
                  <option value="">—</option>
                  {mt.values.map((v) => <option key={v.v} value={v.v}>{v.label}</option>)}
                </Select>
              </div>
            ))}
          </div>
          <div className="flex flex-wrap items-end gap-4 text-[12.5px]">
            <div>
              <div className="text-muted-foreground">Vector</div>
              <div className="font-mono text-[12px]">{vector ?? "Select every base metric"}</div>
            </div>
            {version === "3.1" ? (
              <div>
                <div className="text-muted-foreground">Base score</div>
                <div className="tabular text-lg font-semibold">{score != null ? score.toFixed(1) : "—"}</div>
              </div>
            ) : (
              <div>
                <Label htmlFor="cvss40-score" hint="(from the FIRST calculator)">CVSS 4.0 score</Label>
                <Input id="cvss40-score" type="number" step="0.1" min={0} max={10} className="w-24" value={score40} onChange={(e) => setScore40(e.target.value)} />
              </div>
            )}
            {suggested && <div>Score band: <SeverityBadge value={suggested} /></div>}
          </div>
          <div className="grid gap-3 md:grid-cols-[200px_1fr]">
            <div>
              <Label htmlFor="assessed-sev">Human-assessed severity</Label>
              <Select id="assessed-sev" className="w-full" value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "")}>
                <option value="">{suggested ? `From score (${suggested})` : "Choose…"}</option>
                {severities.map((x) => <option key={x} value={x}>{humanize(x)}</option>)}
              </Select>
            </div>
            <div>
              <Label htmlFor="sev-just" hint="(required, at least 10 characters)">Risk adjustment justification</Label>
              <textarea id="sev-just" rows={3} className={textareaCls} value={justification} onChange={(e) => setJustification(e.target.value)} aria-required />
            </div>
          </div>
          {m.error && <Alert>{m.error.message}</Alert>}
          {editable && (
            <Button disabled={!finalSeverity || justification.trim().length < 10 || !changed || m.isPending} onClick={() => m.mutate(undefined)}>
              {m.isPending ? "Saving…" : "Save severity assessment"}
            </Button>
          )}
          <p className="text-[11.5px] text-muted-foreground">The scanner's severity and score are never changed; the human assessment is stored separately and every change is recorded in the history.</p>
        </fieldset>
      </Panel>

      <Panel title="Context">
        <div className="grid gap-3 md:grid-cols-2">
          {(cat.data?.risk_fields ?? []).map((f) =>
            f.options ? (
              <div key={f.key}>
                <Label htmlFor={`risk-${f.key}`}>{f.label}</Label>
                <Select id={`risk-${f.key}`} className="w-full" disabled={!editable} value={s.draft.risk?.[f.key] ?? ""} onChange={(e) => s.set("risk", f.key, e.target.value)}>
                  <option value="">Not assessed</option>
                  {f.options.map((o) => <option key={o} value={o}>{humanize(o)}</option>)}
                </Select>
              </div>
            ) : (
              <div key={f.key} className="md:col-span-2">
                <Label htmlFor={`risk-${f.key}`}>{f.label}</Label>
                <textarea id={`risk-${f.key}`} rows={3} className={textareaCls} disabled={!editable} value={s.draft.risk?.[f.key] ?? ""} onChange={(e) => s.set("risk", f.key, e.target.value)} />
              </div>
            ),
          )}
        </div>
        <div className="mt-3"><SaveBar s={s} editable={editable} d={d} /></div>
      </Panel>
    </div>
  );
}

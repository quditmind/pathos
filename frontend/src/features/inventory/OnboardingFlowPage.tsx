import { useEffect, useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { ArrowLeft, ArrowRight, Check, Link2, Plus, Radar, Rocket } from "lucide-react";
import { ApiError } from "@/api/client";
import type { AssetMetadata, CreateImportRequest, FieldErrors } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ErrorPanel } from "@/components/ui/error-panel";
import { Alert, Badge, Card, Input, Label, PageHeader, Select } from "@/components/ui/primitives";
import { FeatureDisabled, LoadingSkeleton } from "@/components/ui/states";
import { useSession } from "@/features/auth/session";
import { slugify } from "@/features/repos/metadata/model";
import { createImport, validateImport } from "@/features/repos/onboarding/api";
import { emptyScmState, ScmSource, type ScmState } from "@/features/repos/onboarding/ScmSource";
import { useConnections } from "@/features/repos/api";
import { startScans } from "@/features/scans/api";
import { useProviders } from "@/features/settings/scmApi";
import { useFeatureFlag, useFeatureFlags } from "@/features/shell/meta";
import { useRegions } from "@/features/users/api";
import { randomId } from "@/lib/useDebounced";
import { cn } from "@/lib/utils";
import {
  completeOnboarding,
  conflictApplication,
  fieldLabels,
  matchSources,
  moveDecision,
  registerOnboarding,
  startDiscovery,
  useApplicationSettings,
  useInvalidateInventory,
  useOnboarding,
  type ApplicationProfile,
  type MatchResult,
  type Onboarding,
  type SourceRef,
} from "./api";
import { ClassificationForm } from "./ClassificationForm";

/** The seven steps of the combined flow (concept wireframe B). */
export const onboardingSteps = [
  "Connect",
  "Discover repositories",
  "Find existing asset",
  "Register",
  "Tag & classify",
  "Save to inventory",
  "Start discovery",
] as const;

export function validateOnboardingFlowSearch(s: Record<string, unknown>): { app?: string } {
  return { app: typeof s.app === "string" && /^[0-9a-f-]{36}$/i.test(s.app) ? s.app : undefined };
}

function Steps({ current, done }: { current: number; done: number }) {
  return (
    <ol className="mb-5 grid grid-cols-2 gap-1.5 sm:grid-cols-4 lg:grid-cols-7" aria-label="Onboarding steps">
      {onboardingSteps.map((s, i) => {
        const isDone = i < done;
        const isCur = i === current;
        return (
          <li
            key={s}
            aria-current={isCur ? "step" : undefined}
            className={cn(
              "rounded-md border bg-surface px-2.5 py-1.5 text-[12px]",
              isDone && "border-success/60",
              isCur && "border-primary ring-1 ring-primary",
              !isDone && !isCur && "border-border text-muted-foreground",
            )}
          >
            <div className="font-mono text-[10.5px] text-muted-foreground">
              {String(i + 1).padStart(2, "0")} {isDone && <Check className="inline size-3 text-success" aria-label="done" />}
            </div>
            {s}
          </li>
        );
      })}
    </ol>
  );
}

/**
 * /onboarding (flag "onboarding"): connect → discover repositories → find
 * existing asset → register → tag and classify → save to inventory → start
 * discovery. Steps 1–2 reuse the repository import wizard's SCM source
 * picker; the registration of new repositories reuses the import pipeline.
 * ?app=<id> resumes the onboarding of a draft application.
 */
export function OnboardingFlowPage() {
  const { isPending: flagsPending } = useFeatureFlags();
  const enabled = useFeatureFlag("onboarding");
  const search = useSearch({ strict: false }) as { app?: string };
  if (flagsPending) return <LoadingSkeleton rows={4} />;
  if (!enabled) {
    return (
      <>
        <PageHeader title="Onboard an application" />
        <FeatureDisabled flag="onboarding" feature="Application onboarding" />
        <p className="mt-3 text-[13px]">
          Repositories can still be added with{" "}
          <Link to="/repositories/import" className="text-primary hover:underline">
            Add repositories
          </Link>
          .
        </p>
      </>
    );
  }
  return search.app ? <ResumeFlow appId={search.app} /> : <NewFlow />;
}

function Header() {
  const connectors = useFeatureFlag("connectors");
  const { canOrgWide } = useSession();
  return (
    <PageHeader
      title="Onboard an application"
      description="Connect a source, find what PATHOS already knows, register or link, classify, and start discovery. You can save a draft at any point."
      actions={
        canOrgWide("scm.manage") && (
          <Button variant="secondary" asChild>
            {connectors ? <Link to={"/connectors" as never}>Manage connectors</Link> : <Link to="/admin/scm">Manage SCM connections</Link>}
          </Button>
        )
      }
    />
  );
}

function NewFlow() {
  const navigate = useNavigate();
  const conns = useConnections();
  const providers = useProviders();
  const [category, setCategory] = useState<"git" | "devops">("git");
  const [scm, setScm] = useState<ScmState>(emptyScmState);
  const [match, setMatch] = useState<MatchResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [name, setName] = useState("");
  // Repositories of other applications the person chose to move (unticked by default).
  const [move, setMove] = useState<Set<string>>(new Set());

  const refs: SourceRef[] = scm.items.map((it) => ({
    scm_connection_id: scm.connectionId,
    external_id: it.repo.external_id,
    full_name: it.repo.full_name,
    url: it.repo.url || it.repo.clone_url,
    organization: it.repo.organization || scm.organization,
    project: it.repo.project || scm.project,
    language: it.repo.language,
  }));
  const step = match ? 2 : scm.items.length ? 1 : 0;

  const findExisting = async () => {
    setBusy(true);
    setError(null);
    try {
      const m = await matchSources({ repositories: refs });
      setMatch(m);
      setName(m.suggested_name);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const register = async (mode: "link" | "new", applicationId?: string) => {
    setBusy(true);
    setError(null);
    try {
      // Linking to the application a repository already belongs to is no move.
      const moving = (match?.sources ?? [])
        .filter((s) => s.existing_repository?.application && move.has(s.existing_repository.id) && s.existing_repository.application.id !== applicationId)
        .map((s) => s.existing_repository!.id);
      const o = await registerOnboarding(
        mode === "link"
          ? { mode, application_id: applicationId, repositories: refs, move_repositories: moving }
          : { mode, application: { name: name.trim() }, repositories: refs, move_repositories: moving },
      );
      void navigate({ to: "/onboarding", search: { app: o.application.id } as never, replace: true });
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const blocked = match?.sources.filter((s) => s.onboarding || s.registered_elsewhere) ?? [];
  const conflictApp = conflictApplication(error);

  return (
    <>
      <Header />
      <Steps current={step} done={step} />
      {!match ? (
        <Card className="space-y-4 p-4">
          <div role="radiogroup" aria-label="Source type" className="flex gap-2">
            {(["git", "devops"] as const).map((c) => (
              <Button key={c} type="button" size="sm" variant={category === c ? "primary" : "secondary"} aria-pressed={category === c}
                onClick={() => {
                  setCategory(c);
                  setScm(emptyScmState);
                }}>
                {c === "git" ? "Git providers" : "DevOps projects"}
              </Button>
            ))}
          </div>
          <ScmSource category={category} connections={conns.data} providers={providers.data} state={scm} setState={setScm} />
          {error != null && <ErrorPanel error={error} />}
          <div className="flex justify-end">
            <Button disabled={!refs.length || busy} onClick={() => void findExisting()}>
              Find existing assets <ArrowRight />
            </Button>
          </div>
        </Card>
      ) : (
        <div className="space-y-4">
          <Card className="p-4">
            <h2 className="mb-2 text-[14px] font-semibold">Repositories</h2>
            <ul className="space-y-1.5 text-[13px]">
              {match.sources.map((s) => (
                <li key={s.source_key} className="flex flex-wrap items-center gap-2">
                  <span className="font-mono">{s.full_name}</span>
                  {s.existing_repository && (
                    <Badge tone="primary">
                      Already in PATHOS{s.existing_repository.application ? ` (in ${s.existing_repository.application.name})` : ""}: it will be linked, not imported again
                    </Badge>
                  )}
                  {s.registered_elsewhere && <Badge tone="danger">Registered in a scope you cannot see</Badge>}
                  {s.onboarding && (
                    <Badge tone="warning">
                      Already being onboarded{s.onboarding.application_name ? ` into ${s.onboarding.application_name}` : ""}
                    </Badge>
                  )}
                  {!s.existing_repository && !s.registered_elsewhere && !s.onboarding && <Badge>New to PATHOS</Badge>}
                  {s.existing_repository?.application && !s.onboarding && (
                    <MoveChoice
                      repo={s.full_name}
                      from={s.existing_repository.application.name}
                      to={name.trim() || "the application you register or link below"}
                      checked={move.has(s.existing_repository.id)}
                      onChange={(on) => {
                        const n = new Set(move);
                        if (on) n.add(s.existing_repository!.id);
                        else n.delete(s.existing_repository!.id);
                        setMove(n);
                      }}
                    />
                  )}
                </li>
              ))}
            </ul>
          </Card>
          {blocked.length > 0 ? (
            <Alert tone="warning">
              {blocked.map((b) => b.full_name).join(", ")} cannot be onboarded again.{" "}
              {blocked.find((b) => b.onboarding?.application_id) && (
                <Link to="/onboarding" search={{ app: blocked.find((b) => b.onboarding?.application_id)!.onboarding!.application_id } as never} className="underline">
                  Continue the existing onboarding
                </Link>
              )}{" "}
              Or go back and deselect them.
            </Alert>
          ) : (
            <>
              {match.candidates.length > 0 && (
                <Card className="border-dashed border-warning bg-warning-soft/40 p-4">
                  <h2 className="mb-2 text-[14px] font-semibold">Possible existing applications</h2>
                  <ul className="space-y-3">
                    {match.candidates.map((c) => (
                      <li key={c.id} className="flex flex-wrap items-start justify-between gap-2">
                        <div className="min-w-0 text-[13px]">
                          <div className="font-medium">
                            {c.name} <span className="font-mono text-[11.5px] text-muted-foreground">{c.application_key}</span>{" "}
                            <span className="text-[12px] text-muted-foreground">
                              · {c.repository_count} repositories · match {Math.round(c.score * 100)}%
                            </span>
                          </div>
                          <ul className="text-[12px] text-muted-foreground">
                            {c.reasons.map((r) => (
                              <li key={r}>{r}</li>
                            ))}
                          </ul>
                        </div>
                        <Button size="sm" disabled={busy} onClick={() => void register("link", c.id)}>
                          <Link2 /> Link to {c.application_key}
                        </Button>
                      </li>
                    ))}
                  </ul>
                </Card>
              )}
              <Card className="p-4">
                <h2 className="mb-2 text-[14px] font-semibold">Register as new</h2>
                <form
                  className="flex flex-wrap items-end gap-2"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void register("new");
                  }}
                >
                  <div className="min-w-64 flex-1">
                    <Label htmlFor="onb-name">Application name</Label>
                    <Input id="onb-name" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} required />
                  </div>
                  <Button type="submit" variant={match.candidates.length ? "secondary" : "primary"} disabled={busy || !name.trim()}>
                    <Plus /> Register as new
                  </Button>
                </form>
              </Card>
            </>
          )}
          {error != null && <ErrorPanel error={error} />}
          {conflictApp && (
            <p className="text-[13px]">
              <Link to="/onboarding" search={{ app: conflictApp } as never} className="text-primary hover:underline">
                Open the existing application
              </Link>
            </p>
          )}
          <div className="flex justify-between">
            <Button variant="ghost" onClick={() => setMatch(null)}>
              <ArrowLeft /> Back to repositories
            </Button>
          </div>
        </div>
      )}
    </>
  );
}

function ResumeFlow({ appId }: { appId: string }) {
  const o = useOnboarding(appId);
  const settings = useApplicationSettings();
  const [stage, setStage] = useState<"classify" | "save" | "discover" | null>(null);
  useEffect(() => {
    if (o.data && stage === null) {
      const started = o.data.sources.some((s) => s.status === "discovery_started");
      setStage(o.data.application.onboarding_status === "draft" ? "classify" : started ? "discover" : "save");
    }
  }, [o.data, stage]);
  if (o.isPending || settings.isPending) return <LoadingSkeleton rows={6} label="Loading the onboarding" />;
  if (o.isError) return <ErrorPanel error={o.error} title="Could not load the onboarding" onVerify={() => o.refetch()} />;
  const a = o.data.application;
  const current = stage === "classify" ? 4 : stage === "save" ? 5 : 6;
  const done = a.onboarding_status === "complete" ? (stage === "discover" ? 7 : 5) : 4;
  return (
    <>
      <Header />
      <Steps current={current} done={done} />
      <div className="mb-3 flex flex-wrap items-center gap-2 text-[13px]">
        <span className="font-semibold">{a.name}</span>
        <span className="font-mono text-[12px] text-muted-foreground">{a.application_key}</span>
        <Badge tone={a.onboarding_status === "draft" ? "warning" : "success"}>{a.progress.label}</Badge>
        <Link to="/applications/$id" params={{ id: a.id }} className="text-primary hover:underline">
          Open the application profile
        </Link>
      </div>
      {stage === "classify" && (
        <Card className="p-4">
          <p className="mb-4 text-[12.5px] text-muted-foreground">
            Green fields came from repository metadata, the provider or the SBOM. Fill only the gaps. You can save at any point; the application stays in the
            inventory with the status <strong>{a.progress.label}</strong>.
          </p>
          <ClassificationForm
            app={a}
            required={settings.data?.required_fields ?? []}
            saveLabel="Save as draft"
            extraActions={
              <Button type="button" variant="ghost" onClick={() => setStage("save")}>
                Continue <ArrowRight />
              </Button>
            }
          />
        </Card>
      )}
      {stage === "save" && <SaveStep o={o.data} onBack={() => setStage("classify")} onDone={() => setStage("discover")} />}
      {stage === "discover" && <DiscoveryDone o={o.data} />}
    </>
  );
}

/** Registration metadata for the repositories still to import, from the application's classification. */
export function importMetadata(a: ApplicationProfile, extra: { business_region_id: string; public_exposure: string }): AssetMetadata {
  const m: Record<string, unknown> = { application_id: a.id, criticality: a.criticality, environment: a.environment };
  if (a.business_unit) m.business_unit_id = a.business_unit.id;
  if (a.owner) m.business_owner_id = a.owner.id;
  if (a.technical_owner) m.technical_owner_id = a.technical_owner.id;
  if (a.data_classification) m.data_classification = a.data_classification;
  if (a.internet_exposure) m.internet_exposure = a.internet_exposure;
  if (a.compliance_scopes.length) m.compliance_scopes = a.compliance_scopes;
  if (a.hosting_region) m.hosting_region = a.hosting_region;
  if (a.data_residency_region) m.data_residency_region_id = a.data_residency_region.id;
  if (a.application_type) m.application_type = a.application_type;
  if (a.tags.length) m.tag_ids = a.tags.map((t) => t.id);
  if (extra.business_region_id) m.business_region_id = extra.business_region_id;
  if (extra.public_exposure) m.public_exposure = extra.public_exposure;
  return m as AssetMetadata;
}

/**
 * "<repo> belongs to <App X>. Move it to <this app>?" — unticked by default;
 * unticked, the repository stays where it is ("kept in <App X>").
 */
export function MoveChoice({ repo, from, to, checked, onChange }: { repo: string; from: string; to: string; checked: boolean; onChange: (on: boolean) => void }) {
  return (
    <span className="flex flex-wrap items-center gap-2 text-[12.5px]">
      <label className="flex items-center gap-1.5">
        <input type="checkbox" className="accent-[var(--primary)]" checked={checked} onChange={(e) => onChange(e.target.checked)} />
        {`${repo} belongs to ${from}. Move it to ${to}?`}
      </label>
      {!checked && <Badge>{`kept in ${from}`}</Badge>}
    </span>
  );
}

function SaveStep({ o, onBack, onDone }: { o: Onboarding; onBack: () => void; onDone: () => void }) {
  const a = o.application;
  const invalidate = useInvalidateInventory();
  const regions = useRegions();
  const { can } = useSession();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [fields, setFields] = useState<FieldErrors>({});
  const [region, setRegion] = useState("");
  const [exposure, setExposure] = useState("unknown");
  const [idem] = useState(randomId);
  const toImport = o.sources.filter((s) => !s.repository_id && s.scm_connection_id);
  // Repositories of other applications: moved only when ticked (prefilled from registration).
  const others = o.sources.filter((s) => s.repository_id && s.current_application && s.status !== "kept");
  const [move, setMove] = useState<Set<string>>(() => new Set(others.filter((s) => s.move_requested).map((s) => s.repository_id!)));
  const linked = o.sources.filter((s) => s.repository_id && s.status !== "kept" && !s.current_application);
  const conns = [...new Set(toImport.map((s) => s.scm_connection_id!))];

  const saveToInventory = async () => {
    setBusy(true);
    setError(null);
    try {
      await completeOnboarding(a.id, moveDecision(o.sources, move));
      invalidate();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const discover = async () => {
    setBusy(true);
    setError(null);
    setFields({});
    try {
      let jobId: string | undefined;
      // One import job per connection (the import pipeline is per source).
      for (const c of conns) {
        const req: CreateImportRequest = {
          source: "git",
          scm_connection_id: c,
          idempotency_key: `${idem}-${c}`.slice(0, 100),
          metadata: importMetadata(a, { business_region_id: region, public_exposure: exposure }),
          items: toImport
            .filter((s) => s.scm_connection_id === c)
            .map((s) => ({
              ref: { external_id: s.external_id, full_name: s.full_name, organization: s.organization || undefined, project: s.project || undefined },
              branch: "",
              full_history: false,
              display_name: s.full_name.split("/").pop() ?? s.full_name,
              asset_name: slugify(s.full_name),
            })),
          start_scan: true,
        };
        const v = await validateImport(req);
        if (Object.keys(v.fields ?? {}).length) {
          setFields(v.fields);
          return;
        }
        const job = await createImport(req);
        jobId ??= job.id;
      }
      if (linked.length && can("scans.run")) await startScans({ repository_ids: linked.map((s) => s.repository_id!), trigger: "onboarding" });
      await startDiscovery(a.id, jobId);
      invalidate();
      onDone();
    } catch (e) {
      if (e instanceof ApiError && e.fields && Object.keys(e.fields).length) setFields(e.fields);
      else setError(e);
    } finally {
      setBusy(false);
    }
  };

  if (a.onboarding_status === "draft") {
    return (
      <Card className="space-y-3 p-4">
        <h2 className="text-[14px] font-semibold">Save to inventory</h2>
        <p className="text-[13px]">
          {a.progress.filled} of {a.progress.required} mandatory fields are filled.
          {a.progress.missing.length > 0 && <> Missing: {a.progress.missing.map((f) => fieldLabels[f] ?? f).join(", ")}.</>}
          {a.progress.missing_tag_categories.length > 0 && <> A tag is required in: {a.progress.missing_tag_categories.map((c) => c.name).join(", ")}.</>}
        </p>
        {others.length > 0 && (
          <ul className="space-y-1.5 text-[13px]" aria-label="Repositories of other applications">
            {others.map((s) => (
              <li key={s.id} className="flex flex-wrap items-center gap-2">
                <MoveChoice
                  repo={s.full_name}
                  from={s.current_application!.name}
                  to={a.name}
                  checked={move.has(s.repository_id!)}
                  onChange={(on) => {
                    const n = new Set(move);
                    if (on) n.add(s.repository_id!);
                    else n.delete(s.repository_id!);
                    setMove(n);
                  }}
                />
              </li>
            ))}
          </ul>
        )}
        <p className="text-[12.5px] text-muted-foreground">
          {linked.length > 0 && `${linked.length} existing repositories will be linked to the application. `}
          {toImport.length > 0 && `${toImport.length} new repositories are registered in the next step through the import pipeline.`}
        </p>
        {error != null && <ErrorPanel error={error} />}
        <div className="flex justify-between">
          <Button variant="ghost" onClick={onBack}>
            <ArrowLeft /> Back to classification
          </Button>
          <Button disabled={busy} onClick={() => void saveToInventory()}>
            Save to inventory
          </Button>
        </div>
      </Card>
    );
  }
  return (
    <Card className="space-y-3 p-4">
      <h2 className="text-[14px] font-semibold">Start discovery</h2>
      <Alert tone="success">The application is registered in the inventory.</Alert>
      {toImport.length > 0 ? (
        <>
          <p className="text-[13px]">
            {toImport.length} repositories are registered with the application's classification and scanned once imported ({toImport.map((s) => s.full_name).join(", ")}).
            Repository registration needs two more answers:
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label htmlFor="onb-region">Business region</Label>
              <Select id="onb-region" className="w-full" value={region} onChange={(e) => setRegion(e.target.value)}>
                <option value="">Choose a region</option>
                {(regions.data ?? []).map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
              </Select>
              {fields.business_region_id && <p className="mt-1 text-[12px] text-danger">{fields.business_region_id}</p>}
            </div>
            <div>
              <Label htmlFor="onb-exposure">Publicly exposed?</Label>
              <Select id="onb-exposure" className="w-full" value={exposure} onChange={(e) => setExposure(e.target.value)}>
                <option value="unknown">Not known yet</option>
                <option value="no">No</option>
              </Select>
              {fields.public_exposure && <p className="mt-1 text-[12px] text-danger">{fields.public_exposure}</p>}
            </div>
          </div>
          {Object.keys(fields).filter((f) => f !== "business_region_id" && f !== "public_exposure").length > 0 && (
            <Alert tone="warning">
              The repository registration needs more fields:{" "}
              {Object.entries(fields)
                .filter(([f]) => f !== "business_region_id" && f !== "public_exposure")
                .map(([f, m]) => `${f}: ${m}`)
                .join("; ")}
              .{" "}
              <Link to="/repositories/import/$source" params={{ source: "git" }} className="underline">
                Complete the registration in the import wizard
              </Link>{" "}
              (choose this application there).
            </Alert>
          )}
        </>
      ) : (
        <p className="text-[13px]">{linked.length} existing repositories are linked. Discovery starts a scan of each (SBOM, components and findings).</p>
      )}
      {error != null && <ErrorPanel error={error} />}
      <div className="flex justify-end">
        <Button disabled={busy} onClick={() => void discover()}>
          <Rocket /> Start discovery
        </Button>
      </div>
    </Card>
  );
}

function DiscoveryDone({ o }: { o: Onboarding }) {
  const a = o.application;
  const jobs = [...new Set(o.sources.map((s) => s.import_job_id).filter(Boolean))] as string[];
  return (
    <Card className="space-y-3 p-4">
      <h2 className="text-[14px] font-semibold">Discovery started</h2>
      <p className="text-[13px]">
        {a.name} is in the inventory. Repositories are being registered and scanned; the profile shows each phase as data arrives. CodeGraph discovery arrives in M4.
      </p>
      <ul className="space-y-1 text-[13px]">
        {jobs.map((j) => (
          <li key={j}>
            <Link to="/repositories/imports/$id" params={{ id: j }} className="text-primary hover:underline">
              Follow the import job
            </Link>
          </li>
        ))}
        <li>
          <Link to="/scans" className="inline-flex items-center gap-1 text-primary hover:underline">
            <Radar className="size-3.5" aria-hidden /> Scans
          </Link>
        </li>
      </ul>
      <div className="flex gap-2">
        <Button asChild>
          <Link to="/applications/$id" params={{ id: a.id }}>
            Open the application profile
          </Link>
        </Button>
        <Button variant="secondary" asChild>
          <Link to="/onboarding">Onboard another application</Link>
        </Button>
      </div>
    </Card>
  );
}



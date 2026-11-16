import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, Check, Loader2, Rocket } from "lucide-react";
import { ApiError } from "@/api/client";
import type { AssetField, CreateImportRequest, FieldErrors, ImportValidation } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Card, Skeleton } from "@/components/ui/primitives";
import { ProgressBar } from "@/components/ui/progress";
import { useAssetSettings } from "@/features/assets/api";
import { useProviders } from "@/features/settings/scmApi";
import { randomId } from "@/lib/useDebounced";
import { cn } from "@/lib/utils";
import { useConnections, useTagCategories } from "../api";
import { MetadataSection } from "../metadata/MetadataSections";
import { clientErrors, draftToMetadata, emptyDraft, sectionForKey, sections, type MetadataDraft, type SectionKey } from "../metadata/model";
import { createImport, validateImport } from "./api";
import { LocalSource } from "./LocalSource";
import { ReviewStep, type ReviewItem } from "./ReviewStep";
import { emptyScmState, ScmSource, type ScmState } from "./ScmSource";
import { useLocalUploads } from "./useLocalUploads";

export type WizardSource = "local" | "git" | "devops";
type StepKey = "source" | SectionKey | "review";

const stepTitles: Record<StepKey, string> = {
  source: "Source",
  ...(Object.fromEntries(sections.map((s) => [s.key, s.title])) as Record<SectionKey, string>),
  review: "Review",
};

/**
 * The shared onboarding wizard: source selection (upload or SCM), the six
 * metadata sections, server validation and submission of an import job.
 * Renders inside any container (page or large dialog).
 */
export function OnboardingWizard({
  source,
  targetRepositoryId,
  onSubmitted,
}: {
  source: WizardSource;
  /** Upload a new snapshot to an existing uploaded repository (no metadata steps). */
  targetRepositoryId?: string;
  onSubmitted: (jobId: string) => void;
}) {
  const settings = useAssetSettings();
  const cats = useTagCategories();
  const conns = useConnections();
  const providers = useProviders();
  const uploads = useLocalUploads({ maxBytes: settings.data?.upload.max_bytes ?? 0, single: !!targetRepositoryId });
  const [scm, setScm] = useState<ScmState>(emptyScmState);
  const [draft, setDraftState] = useState<MetadataDraft>(emptyDraft);
  const [errors, setErrors] = useState<FieldErrors>({});
  const [idx, setIdx] = useState(0);
  const [visited, setVisited] = useState(0);
  const [validation, setValidation] = useState<ImportValidation | null>(null);
  const [validatedSig, setValidatedSig] = useState("");
  const [allowDup, setAllowDup] = useState<Set<number>>(new Set());
  const [startScan, setStartScan] = useState(true);
  const [busy, setBusy] = useState<"validating" | "submitting" | null>(null);
  const [flowError, setFlowError] = useState<string | null>(null);
  // One key per wizard instance: a retried submission returns the same job.
  const [idempotencyKey] = useState(randomId);
  const heading = useRef<HTMLHeadingElement>(null);

  const steps: StepKey[] = targetRepositoryId ? ["source", "review"] : ["source", ...sections.map((s) => s.key), "review"];
  const step = steps[idx]!;
  const required = useMemo(
    () => new Set<AssetField>([...(settings.data?.required_fields ?? []), ...(settings.data?.always_required ?? [])]),
    [settings.data],
  );

  // Unified view of the items for names, review and the request.
  const items: ReviewItem[] =
    source === "local"
      ? uploads.items.map((it) => ({
          key: it.key,
          label: it.label,
          detail: it.kind === "folder" ? `Folder · ${it.fileCount} files` : "Archive",
          size: it.size,
          display_name: it.display_name,
          asset_name: it.asset_name,
        }))
      : scm.items.map((it) => ({
          key: it.repo.external_id,
          label: it.repo.full_name,
          detail: `${it.branch || `${it.repo.default_branch || "default"} (default)`}${it.full_history ? " · full history" : ""}`,
          size: it.repo.size_bytes || null,
          display_name: it.display_name,
          asset_name: it.asset_name,
        }));
  const single = items.length === 1 && !targetRepositoryId;

  const renameItem = (i: number, p: { display_name?: string; asset_name?: string }) => {
    if (source === "local") uploads.rename(uploads.items[i]!.key, p);
    else setScm({ ...scm, items: scm.items.map((it, j) => (j === i ? { ...it, ...p } : it)) });
  };
  const removeItem = (i: number) => {
    if (source === "local") void uploads.remove(uploads.items[i]!.key);
    else setScm({ ...scm, items: scm.items.filter((_, j) => j !== i) });
    setAllowDup(new Set());
  };

  // With a single asset the General section edits its names directly.
  const viewDraft: MetadataDraft = single ? { ...draft, display_name: items[0]!.display_name, asset_name: items[0]!.asset_name } : draft;
  const setDraft = (patch: Partial<MetadataDraft>) => {
    const { display_name, asset_name, ...rest } = patch;
    if (single && (display_name !== undefined || asset_name !== undefined)) {
      renameItem(0, { ...(display_name !== undefined ? { display_name } : {}), ...(asset_name !== undefined ? { asset_name } : {}) });
    }
    if (Object.keys(rest).length) setDraftState((d) => ({ ...d, ...rest }));
    // Clear errors of edited fields.
    setErrors((e) => {
      const next = { ...e };
      for (const k of Object.keys(patch)) {
        delete next[k];
        delete next[`${k}_id`];
        delete next[`${k.replace(/_id$/, "")}`];
      }
      if ("tag_ids" in patch) delete next.tags;
      if ("application" in patch || "new_app_name" in patch || "application_mode" in patch) {
        delete next.application;
        delete next.application_id;
        delete next.new_application;
        delete next["new_application.name"];
      }
      if ("business_owner" in patch) delete next.business_owner_id;
      if ("technical_owner" in patch) delete next.technical_owner_id;
      if ("application_owner" in patch) delete next.application_owner_id;
      if ("responsible_team" in patch) delete next.responsible_team_id;
      if ("supporting_team" in patch) delete next.supporting_team_id;
      return next;
    });
  };

  const sourceProblem = (): string | null => {
    if (source === "local") {
      if (!uploads.items.length) return targetRepositoryId ? "Choose the archive with the new version." : "Add at least one archive or folder.";
      if (uploads.items.some((x) => x.state === "error")) return "Retry or remove the uploads that failed.";
    } else {
      if (!scm.connectionId) return "Choose a connection.";
      if (!scm.items.length) return "Select at least one repository.";
    }
    if (!targetRepositoryId) {
      if (items.some((i) => !i.display_name.trim() || !i.asset_name.trim())) return "Every repository needs a display name and an asset name.";
      const names = items.map((i) => i.asset_name.trim().toLowerCase());
      if (new Set(names).size !== names.length) return "Asset names must be unique.";
    }
    return null;
  };

  const goto = (i: number) => {
    setIdx(i);
    setVisited((v) => Math.max(v, i));
  };
  useEffect(() => heading.current?.focus(), [idx]);

  const sig = JSON.stringify([items.map((i) => [i.key, i.display_name, i.asset_name]), [...allowDup]]);

  const buildRequest = (): CreateImportRequest => ({
    source: source === "local" ? "upload" : source,
    ...(source !== "local" ? { scm_connection_id: scm.connectionId } : {}),
    idempotency_key: idempotencyKey,
    metadata: targetRepositoryId ? {} : draftToMetadata(draft),
    items:
      source === "local"
        ? uploads.items.map((it, i) => ({
            upload_id: it.uploadId,
            ...(targetRepositoryId ? { target_repository_id: targetRepositoryId } : { display_name: it.display_name.trim(), asset_name: it.asset_name.trim() }),
            ...(allowDup.has(i) ? { allow_duplicate: true } : {}),
          }))
        : scm.items.map((it, i) => ({
            ref: {
              external_id: it.repo.external_id,
              full_name: it.repo.full_name,
              organization: it.repo.organization || scm.organization || undefined,
              project: it.repo.project || scm.project || undefined,
            },
            branch: it.branch,
            full_history: it.full_history,
            display_name: it.display_name.trim(),
            asset_name: it.asset_name.trim(),
            ...(allowDup.has(i) ? { allow_duplicate: true } : {}),
          })),
    ...(settings.data?.scan_on_import ? { start_scan: startScan } : {}),
  });

  /** Shows field errors and moves to the first section that has one. */
  const showFieldErrors = (fields: FieldErrors) => {
    setErrors(fields);
    const keys = Object.keys(fields);
    const target = keys.map(sectionForKey).find((s): s is SectionKey => !!s);
    if (target && steps.includes(target)) goto(steps.indexOf(target));
    else setFlowError(`Please correct: ${keys.map((k) => `${k}: ${fields[k]}`).join("; ")}`);
  };

  const runValidation = async (navigate: boolean) => {
    if (source === "local" && !uploads.allDone) {
      setFlowError(`Waiting for ${uploads.pendingCount} upload${uploads.pendingCount === 1 ? "" : "s"} to finish before checking the import.`);
      return;
    }
    setBusy("validating");
    setFlowError(null);
    try {
      const res = await validateImport(buildRequest());
      setValidation(res);
      setValidatedSig(sig);
      if (Object.keys(res.fields ?? {}).length) showFieldErrors(res.fields);
      else if (navigate) goto(steps.indexOf("review"));
    } catch (e) {
      if (e instanceof ApiError && e.fields && Object.keys(e.fields).length) showFieldErrors(e.fields);
      else setFlowError(`Could not check the import: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(null);
    }
  };

  // Re-check when items change while on the review step (e.g. one was removed).
  useEffect(() => {
    if (step === "review" && validatedSig && sig !== validatedSig && busy === null && items.length) void runValidation(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, sig]);

  const next = async () => {
    setFlowError(null);
    if (step === "source") {
      const p = sourceProblem();
      if (p) return setFlowError(p);
      if (steps[idx + 1] === "review") return runValidation(true);
      return goto(idx + 1);
    }
    if (step === "review") return;
    const errs = clientErrors(viewDraft, required, { section: step, categories: cats.data, names: single });
    if (Object.keys(errs).length) {
      setErrors((e) => ({ ...e, ...errs }));
      setFlowError("Complete the required fields in this section.");
      return;
    }
    if (steps[idx + 1] !== "review") return goto(idx + 1);
    const all = clientErrors(viewDraft, required, { categories: cats.data, names: single });
    if (Object.keys(all).length) return showFieldErrors(all);
    return runValidation(true);
  };

  const blocking = (validation?.items ?? []).filter((p) => !(p.code === "duplicate" && allowDup.has(p.index)));

  const submit = async () => {
    setBusy("submitting");
    setFlowError(null);
    try {
      const job = await createImport(buildRequest());
      onSubmitted(job.id);
    } catch (e) {
      if (e instanceof ApiError && e.fields && Object.keys(e.fields).length) showFieldErrors(e.fields);
      else
        setFlowError(
          `The import could not be started: ${e instanceof Error ? e.message : String(e)}. You can safely try again; a repeated submission does not create a second job.`,
        );
    } finally {
      setBusy(null);
    }
  };

  if (settings.isPending) return <Skeleton className="h-96" />;
  if (settings.isError)
    return (
      <Alert>
        Could not load asset settings: {settings.error.message}{" "}
        <button className="underline" onClick={() => void settings.refetch()}>
          Try again
        </button>
      </Alert>
    );

  const sectionDef = sections.find((s) => s.key === step);
  const uploadsBusy = source === "local" && uploads.items.length > 0 && !uploads.allDone;

  return (
    <div className="space-y-4">
      <nav aria-label="Onboarding steps">
        <ol className="flex flex-wrap gap-1.5">
          {steps.map((s, i) => {
            const done = i < idx;
            const reachable = i <= visited && i !== idx && busy === null;
            return (
              <li key={s}>
                <button
                  type="button"
                  disabled={!reachable}
                  aria-current={i === idx ? "step" : undefined}
                  onClick={() => goto(i)}
                  className={cn(
                    "flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[12px] transition-colors",
                    i === idx ? "border-primary bg-primary text-primary-foreground" : done ? "border-primary/40 text-primary hover:bg-primary/5" : "border-border text-muted-foreground",
                    !reachable && i !== idx && "cursor-default",
                  )}
                >
                  <span
                    className={cn(
                      "flex size-4 items-center justify-center rounded-full text-[10px] font-semibold",
                      i === idx ? "bg-primary-foreground/20" : done ? "bg-primary/15" : "bg-surface-muted",
                    )}
                    aria-hidden
                  >
                    {done ? <Check className="size-3" /> : i + 1}
                  </span>
                  {stepTitles[s]}
                  <span className="sr-only">{done ? " (completed)" : i === idx ? " (current)" : ""}</span>
                </button>
              </li>
            );
          })}
        </ol>
      </nav>

      <Card className="p-5">
        <h2 ref={heading} tabIndex={-1} className="text-[15px] font-semibold focus:outline-none">
          {step === "source"
            ? targetRepositoryId
              ? "Upload a new version"
              : source === "local"
                ? "Choose source code"
                : "Choose repositories"
            : stepTitles[step]}
        </h2>
        <p className="mb-4 mt-0.5 text-[13px] text-muted-foreground">
          {step === "source"
            ? targetRepositoryId
              ? "The archive becomes a new snapshot of the existing repository; its metadata is unchanged."
              : "Each selected archive, folder or repository becomes one asset. They all share the metadata entered in the next steps."
            : step === "review"
              ? "Check the summary, then start the import. It runs in the background; you can follow its progress."
              : sectionDef?.description}
          {sectionDef && !single && items.length > 1 && step === "general" && " Names are set per repository in the Source step."}
        </p>

        {step === "source" &&
          (source === "local" ? (
            <LocalSource uploads={uploads} settings={settings.data} single={!!targetRepositoryId} showNames={!targetRepositoryId} />
          ) : (
            <ScmSource category={source} connections={conns.data} providers={providers.data} state={scm} setState={setScm} />
          ))}
        {sectionDef && (
          <MetadataSection
            section={sectionDef.key}
            draft={viewDraft}
            set={setDraft}
            errors={errors}
            required={required}
            settings={settings.data}
            names={single}
          />
        )}
        {step === "review" && (
          <ReviewStep
            items={items}
            validation={validation}
            validating={busy === "validating"}
            allowDup={allowDup}
            setAllowDup={setAllowDup}
            onRemove={removeItem}
            draft={viewDraft}
            settings={settings.data}
            showMetadata={!targetRepositoryId}
            onEditSection={(s) => goto(steps.indexOf(s))}
            startScan={startScan}
            setStartScan={setStartScan}
          />
        )}
      </Card>

      {flowError && <Alert>{flowError}</Alert>}

      <div className="flex flex-wrap items-center gap-3">
        <Button variant="secondary" disabled={idx === 0 || busy !== null} onClick={() => goto(idx - 1)}>
          <ArrowLeft /> Back
        </Button>
        {uploadsBusy && (
          <div className="flex min-w-48 flex-1 items-center gap-2 text-[12px] text-muted-foreground">
            <ProgressBar value={uploads.progress} label="Overall upload progress" className="max-w-48" />
            {uploads.pendingCount} upload{uploads.pendingCount === 1 ? "" : "s"} in progress
          </div>
        )}
        <div className="ml-auto flex items-center gap-2">
          {step !== "review" ? (
            <Button onClick={() => void next()} disabled={busy !== null}>
              {busy === "validating" ? <Loader2 className="animate-spin" /> : null}
              {steps[idx + 1] === "review" ? (busy === "validating" ? "Checking…" : "Check and review") : "Next"}
              {busy === null && <ArrowRight />}
            </Button>
          ) : (
            <Button
              onClick={() => void submit()}
              disabled={busy !== null || !validation || blocking.length > 0 || !items.length}
              title={blocking.length ? "Resolve or remove the repositories with problems first" : undefined}
            >
              {busy === "submitting" ? <Loader2 className="animate-spin" /> : <Rocket />}
              {busy === "submitting" ? "Starting…" : `Start import (${items.length})`}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

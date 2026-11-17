import { useState } from "react";
import { Download, FileText, ImageIcon, Paperclip, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm";
import { Alert, Badge, EmptyState, Input, Label, Select, Skeleton } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { ApiError } from "@/api/client";
import { evidenceUrl, reviewApi, uploadEvidence, useCatalog, useEvidence, useReviewMutation } from "../api";
import { evidenceTypeLabel, humanize } from "../shared";
import type { Evidence, ReviewDetail } from "../types";
import { textareaCls } from "./actions";
import { Panel, SaveBar, useSections } from "./section";

const fmtSize = (n: number) => (n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KB` : `${(n / (1 << 20)).toFixed(1)} MB`);

function UploadForm({ d, allowed, filesEnabled }: { d: ReviewDetail; allowed: string[]; filesEnabled: boolean }) {
  const [mode, setMode] = useState<"file" | "text">(filesEnabled ? "file" : "text");
  const [type, setType] = useState("screenshot");
  const [classification, setClassification] = useState("confidential");
  const [description, setDescription] = useState("");
  const [comments, setComments] = useState("");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [formKey, setFormKey] = useState(0);
  const m = useReviewMutation(() => {
    const fd = new FormData();
    fd.set("evidence_type", type);
    fd.set("classification", classification);
    fd.set("description", description);
    if (comments) fd.set("comments", comments);
    if (mode === "file" && file) fd.set("file", file);
    else fd.set("text", text);
    return uploadEvidence(d.id, fd);
  });
  const fields = m.error instanceof ApiError ? m.error.fields : undefined;
  const ok = description.trim() && (mode === "file" ? !!file : text.trim());
  return (
    <form
      key={formKey}
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        m.mutate(undefined, {
          onSuccess: () => {
            setDescription("");
            setComments("");
            setText("");
            setFile(null);
            setFormKey((k) => k + 1);
          },
        });
      }}
    >
      {m.error && <Alert>{fields ? Object.values(fields).join(" ") : m.error.message}</Alert>}
      {m.isSuccess && <Alert tone="success">Evidence added.</Alert>}
      <div className="flex gap-3 text-[12.5px]" role="radiogroup" aria-label="Evidence form">
        <label className="flex items-center gap-1.5">
          <input type="radio" className="accent-[var(--primary)]" checked={mode === "file"} disabled={!filesEnabled} onChange={() => setMode("file")} /> Upload a file
        </label>
        <label className="flex items-center gap-1.5">
          <input type="radio" className="accent-[var(--primary)]" checked={mode === "text"} onChange={() => setMode("text")} /> Paste text (request, response, output, log)
        </label>
      </div>
      {!filesEnabled && <p className="text-[12px] text-muted-foreground">File uploads are unavailable: this deployment has no encrypted object store configured.</p>}
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <Label htmlFor="ev-type">Evidence type</Label>
          <Select id="ev-type" className="w-full" value={type} onChange={(e) => setType(e.target.value)}>
            {Object.entries(evidenceTypeLabel).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="ev-class">Classification</Label>
          <Select id="ev-class" className="w-full" value={classification} onChange={(e) => setClassification(e.target.value)}>
            {["internal", "confidential", "restricted"].map((c) => <option key={c} value={c}>{humanize(c)}</option>)}
          </Select>
        </div>
      </div>
      <div>
        <Label htmlFor="ev-desc">Description</Label>
        <Input id="ev-desc" value={description} onChange={(e) => setDescription(e.target.value)} aria-invalid={!!fields?.description} maxLength={2000} />
      </div>
      {mode === "file" ? (
        <div>
          <Label htmlFor="ev-file" hint={`(${allowed.join(", ")})`}>File</Label>
          <input
            id="ev-file"
            type="file"
            accept={allowed.join(",")}
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            className="block text-[12.5px] file:mr-2 file:rounded-md file:border file:border-border file:bg-surface file:px-2 file:py-1"
          />
        </div>
      ) : (
        <div>
          <Label htmlFor="ev-text">Content</Label>
          <textarea id="ev-text" rows={6} className={`${textareaCls} font-mono text-[12px]`} value={text} onChange={(e) => setText(e.target.value)} />
        </div>
      )}
      <div>
        <Label htmlFor="ev-comments" hint="(optional)">Comments</Label>
        <Input id="ev-comments" value={comments} onChange={(e) => setComments(e.target.value)} />
      </div>
      <Button type="submit" disabled={!ok || m.isPending}>
        <Paperclip /> {m.isPending ? "Uploading…" : "Add evidence"}
      </Button>
    </form>
  );
}

function EvidenceRow({ d, e, onDelete }: { d: ReviewDetail; e: Evidence; onDelete: (e: Evidence) => void }) {
  const isImage = e.is_file && e.content_type.startsWith("image/");
  return (
    <li className="py-3">
      <div className="flex flex-wrap items-start gap-3">
        <div className="mt-0.5 text-muted-foreground">{isImage ? <ImageIcon className="size-4" /> : <FileText className="size-4" />}</div>
        <div className="min-w-0 flex-1 text-[12.5px]">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[11.5px]">{e.evidence_key}</span>
            <Badge>{evidenceTypeLabel[e.evidence_type] ?? e.evidence_type}</Badge>
            <Badge tone={e.classification === "restricted" ? "danger" : "warning"}>{humanize(e.classification)}</Badge>
            {e.round !== d.round && <Badge>round {e.round}</Badge>}
            {e.deleted_at && <Badge tone="danger">deleted</Badge>}
          </div>
          <div className="mt-1 font-medium">{e.description}</div>
          {e.comments && <div className="text-muted-foreground">{e.comments}</div>}
          <div className="mt-1 text-[11.5px] text-muted-foreground">
            {e.uploaded_by_name} · {formatDateTime(e.created_at)}
            {e.is_file && ` · ${e.file_name} · ${fmtSize(e.size_bytes)}`} · SHA-256 <span className="font-mono">{e.sha256.slice(0, 16)}…</span> · finding {e.finding_id.slice(0, 8)}
          </div>
          {e.deleted_at && (
            <div className="mt-1 text-[11.5px] text-danger">
              Deleted by {e.deleted_by_name} on {formatDateTime(e.deleted_at)}: {e.delete_reason}
            </div>
          )}
          {!e.deleted_at && e.text != null && (
            <pre className="mt-2 max-h-60 overflow-auto whitespace-pre-wrap rounded-md bg-surface-muted p-2 font-mono text-[11.5px]">{e.text}</pre>
          )}
          {!e.deleted_at && isImage && (
            <img src={evidenceUrl(d.id, e.id, true)} alt={e.description} className="mt-2 max-h-64 rounded border border-border" loading="lazy" />
          )}
        </div>
        {!e.deleted_at && (
          <div className="flex gap-1">
            {e.is_file && (
              <Button variant="ghost" size="icon" asChild>
                <a href={evidenceUrl(d.id, e.id)} download aria-label={`Download ${e.file_name}`}>
                  <Download />
                </a>
              </Button>
            )}
            {d.can.assess && (
              <Button variant="ghost" size="icon" onClick={() => onDelete(e)} aria-label={`Delete ${e.evidence_key}`}>
                <Trash2 />
              </Button>
            )}
          </div>
        )}
      </div>
    </li>
  );
}

export function EvidenceTab({ d }: { d: ReviewDetail }) {
  const ev = useEvidence(d.id);
  const cat = useCatalog();
  const s = useSections(d, ["reproduction"]);
  const [del, setDel] = useState<Evidence | null>(null);
  const [reason, setReason] = useState("");
  const rm = useReviewMutation(() => reviewApi.deleteEvidence(d.id, del!.id, reason));
  const items = ev.data?.items ?? [];
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
      <div className="min-w-0 space-y-4">
        <Panel title={`Evidence (${items.filter((x) => !x.deleted_at).length})`}>
          {ev.isError ? (
            <Alert>{ev.error.message}</Alert>
          ) : ev.isPending ? (
            <Skeleton className="h-24" />
          ) : items.length === 0 ? (
            <EmptyState icon={<Paperclip />} title="No evidence yet">Screenshots, HTTP requests and responses, command output, logs and reproduction results.</EmptyState>
          ) : (
            <ul className="divide-y divide-border">{items.map((e) => <EvidenceRow key={e.id} d={d} e={e} onDelete={(x) => { setReason(""); setDel(x); }} />)}</ul>
          )}
        </Panel>
        <Panel title="Reproduction">
          <div className="grid gap-3 md:grid-cols-2">
            {(cat.data?.reproduction_fields ?? []).map((f) => (
              <div key={f.key} className={f.key === "steps" ? "md:col-span-2" : undefined}>
                <Label htmlFor={`rep-${f.key}`}>{f.label}</Label>
                <textarea
                  id={`rep-${f.key}`}
                  rows={f.key === "steps" ? 6 : 3}
                  className={textareaCls}
                  disabled={!d.can.assess}
                  value={s.draft.reproduction?.[f.key] ?? ""}
                  onChange={(e) => s.set("reproduction", f.key, e.target.value)}
                />
              </div>
            ))}
          </div>
          <div className="mt-3"><SaveBar s={s} editable={d.can.assess} d={d} /></div>
        </Panel>
      </div>
      <div>
        {d.can.assess ? (
          <Panel title="Add evidence">
            <UploadForm d={d} allowed={ev.data?.allowed_extensions ?? []} filesEnabled={!!ev.data?.uploads_enabled && d.can.upload_files} />
          </Panel>
        ) : (
          <p className="text-[12px] text-muted-foreground">Only the analyst working on the review can add evidence.</p>
        )}
      </div>
      <ConfirmDialog
        open={!!del}
        onOpenChange={(o) => !o && setDel(null)}
        title={`Delete ${del?.evidence_key ?? "evidence"}?`}
        confirmLabel="Delete evidence"
        pending={rm.isPending}
        error={rm.error?.message}
        onConfirm={() => reason.trim().length >= 5 && rm.mutate(undefined, { onSuccess: () => setDel(null) })}
      >
        <p>The content is removed; the record and your reason stay in the history.</p>
        <Label htmlFor="del-reason" hint="(at least 5 characters)">Reason</Label>
        <Input id="del-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
      </ConfirmDialog>
    </div>
  );
}

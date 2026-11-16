import { useEffect, useRef, useState, type DragEvent } from "react";
import { FileArchive, FolderOpen, FolderUp, Pause, Play, RotateCcw, Trash2, Upload } from "lucide-react";
import type { AssetSettings } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Input } from "@/components/ui/primitives";
import { ProgressBar } from "@/components/ui/progress";
import { formatBytes } from "@/lib/uploader";
import { cn } from "@/lib/utils";
import { groupFolderInput, readDrop, type LocalItem, type useLocalUploads } from "./useLocalUploads";

const folderSupported = typeof document !== "undefined" && "webkitdirectory" in document.createElement("input");

const stateLabel: Record<LocalItem["state"], string> = {
  queued: "Waiting",
  hashing: "Computing checksum",
  uploading: "Uploading",
  paused: "Paused",
  completing: "Finalising",
  done: "Uploaded",
  error: "Failed",
};

export function LocalSource({
  uploads,
  settings,
  single,
  showNames,
}: {
  uploads: ReturnType<typeof useLocalUploads>;
  settings?: AssetSettings;
  /** Only one archive (new version of an existing repository). */
  single?: boolean;
  /** Per-item name inputs (hidden for a new version). */
  showNames: boolean;
}) {
  const fileInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const maxBytes = settings?.upload.max_bytes ?? 0;
  const chunk = settings?.upload.chunk_size ?? 0;

  useEffect(() => {
    folderInput.current?.setAttribute("webkitdirectory", "");
    folderInput.current?.setAttribute("directory", "");
  }, []);

  const onDrop = async (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const { files, folders } = await readDrop(e.dataTransfer);
    if (files.length) uploads.addFiles(single ? files.slice(0, 1) : files);
    if (!single) for (const f of folders) uploads.addFolder(f.name, f.files);
  };

  return (
    <div className="space-y-4">
      <div
        role="group"
        aria-label="Drop archives or folders here"
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => void onDrop(e)}
        className={cn(
          "flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors",
          dragging ? "border-primary bg-primary/5" : "border-border bg-surface-muted/40",
        )}
      >
        <Upload className="size-8 text-muted-foreground" aria-hidden />
        <div>
          <p className="text-sm font-medium">{single ? "Drop the new archive here" : "Drag and drop archives or folders here"}</p>
          <p className="mt-0.5 text-[12px] text-muted-foreground">
            .zip, .tar, .tar.gz or .tgz{maxBytes ? ` · up to ${formatBytes(maxBytes)} each` : ""}
            {!single && " · each archive or folder becomes one repository"}
          </p>
        </div>
        <div className="flex flex-wrap justify-center gap-2">
          <Button type="button" variant="secondary" onClick={() => fileInput.current?.click()}>
            <FileArchive /> Choose {single ? "archive" : "archives"}
          </Button>
          {folderSupported && !single && (
            <Button type="button" variant="secondary" onClick={() => folderInput.current?.click()}>
              <FolderUp /> Choose folder
            </Button>
          )}
        </div>
        <input
          ref={fileInput}
          type="file"
          className="sr-only"
          tabIndex={-1}
          aria-label="Choose archives"
          accept=".zip,.tar,.tar.gz,.tgz,application/zip,application/x-tar,application/gzip"
          multiple={!single}
          onChange={(e) => {
            uploads.addFiles(Array.from(e.target.files ?? []));
            e.target.value = "";
          }}
        />
        <input
          ref={folderInput}
          type="file"
          className="sr-only"
          tabIndex={-1}
          aria-label="Choose folder"
          multiple
          onChange={(e) => {
            for (const g of groupFolderInput(e.target.files ?? [])) uploads.addFolder(g.name, g.files);
            e.target.value = "";
          }}
        />
        {folderSupported && !single && <p className="text-[11.5px] text-muted-foreground">Folders are packed into a tar archive in your browser before upload.</p>}
      </div>

      {uploads.rejected.length > 0 && (
        <Alert tone="warning">
          <ul className="list-inside list-disc">
            {uploads.rejected.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        </Alert>
      )}

      {uploads.items.length > 0 && (
        <ul className="divide-y divide-border rounded-md border border-border" aria-label="Selected sources">
          {uploads.items.map((it) => (
            <li key={it.key} className="space-y-2 p-3">
              <div className="flex flex-wrap items-center gap-2">
                {it.kind === "folder" ? <FolderOpen className="size-4 text-muted-foreground" aria-hidden /> : <FileArchive className="size-4 text-muted-foreground" aria-hidden />}
                <span className="min-w-0 flex-1 truncate text-[13px] font-medium" title={it.label}>
                  {it.label}
                </span>
                <span className="tabular text-[12px] text-muted-foreground">
                  {formatBytes(it.size)}
                  {it.fileCount != null && ` · ${it.fileCount} files`}
                  {chunk > 0 && ` · ${Math.max(1, Math.ceil(it.size / chunk))} parts`}
                </span>
                <Badge tone={it.state === "done" ? "success" : it.state === "error" ? "danger" : it.state === "paused" ? "warning" : "neutral"}>{stateLabel[it.state]}</Badge>
                <div className="flex items-center gap-1">
                  {(it.state === "hashing" || it.state === "uploading") && (
                    <Button type="button" size="sm" variant="ghost" onClick={() => uploads.pause(it.key)} aria-label={`Pause ${it.label}`}>
                      <Pause />
                    </Button>
                  )}
                  {it.state === "paused" && (
                    <Button type="button" size="sm" variant="ghost" onClick={() => uploads.resume(it.key)} aria-label={`Resume ${it.label}`}>
                      <Play />
                    </Button>
                  )}
                  {it.state === "error" && (
                    <Button type="button" size="sm" variant="ghost" onClick={() => uploads.resume(it.key)} aria-label={`Retry ${it.label}`}>
                      <RotateCcw /> Retry
                    </Button>
                  )}
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    className="text-danger"
                    onClick={() => void uploads.remove(it.key)}
                    aria-label={it.state === "done" ? `Remove ${it.label}` : `Cancel and remove ${it.label}`}
                  >
                    <Trash2 />
                  </Button>
                </div>
              </div>
              {it.state !== "done" && (
                <ProgressBar
                  value={it.progress}
                  label={`${stateLabel[it.state]} ${it.label}`}
                  tone={it.state === "error" ? "danger" : it.state === "paused" ? "warning" : it.state === "hashing" ? "muted" : "primary"}
                />
              )}
              {it.error && <p className="text-[12px] text-danger">{it.error}</p>}
              {showNames && (
                <div className="grid gap-2 sm:grid-cols-2">
                  <label className="text-[12px]">
                    <span className="mb-0.5 block text-muted-foreground">Display name</span>
                    <Input value={it.display_name} maxLength={200} onChange={(e) => uploads.rename(it.key, { display_name: e.target.value })} aria-invalid={!it.display_name.trim() || undefined} />
                  </label>
                  <label className="text-[12px]">
                    <span className="mb-0.5 block text-muted-foreground">Asset name</span>
                    <Input className="font-mono" value={it.asset_name} maxLength={100} onChange={(e) => uploads.rename(it.key, { asset_name: e.target.value })} aria-invalid={!it.asset_name.trim() || undefined} />
                  </label>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

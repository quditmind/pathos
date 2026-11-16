import { useCallback, useEffect, useRef, useState } from "react";
import { createTar } from "@/lib/tar";
import { archiveFormat, cancelUpload, formatBytes, isAbort, stripArchiveExt, uploadSource } from "@/lib/uploader";
import { slugify } from "../metadata/model";

export type LocalState = "queued" | "hashing" | "uploading" | "paused" | "completing" | "done" | "error";

export interface LocalItem {
  key: string;
  kind: "archive" | "folder";
  /** File or folder name as chosen. */
  label: string;
  /** Name sent to the server (folders become "<name>.tar"). */
  filename: string;
  file: Blob;
  size: number;
  fileCount?: number;
  display_name: string;
  asset_name: string;
  state: LocalState;
  /** 0..1 of the current phase. */
  progress: number;
  error?: string;
  uploadId?: string;
  sha256?: string;
}

export interface FolderFile {
  path: string;
  file: File;
}

const storeKey = (it: { filename: string; size: number; lastModified?: number }) => `pathos-upload:${it.filename}:${it.size}:${it.lastModified ?? 0}`;

function remember(key: string, v: { id: string; sha256: string } | null) {
  try {
    if (v) sessionStorage.setItem(key, JSON.stringify(v));
    else sessionStorage.removeItem(key);
  } catch {
    /* storage unavailable */
  }
}

function recall(key: string): { id: string; sha256: string } | null {
  try {
    const raw = sessionStorage.getItem(key);
    return raw ? (JSON.parse(raw) as { id: string; sha256: string }) : null;
  } catch {
    return null;
  }
}

let seq = 0;

/**
 * Upload queue for the Local source: validates files, packs folders into a
 * tar, uploads one item at a time (parts in parallel), supports pause,
 * resume, retry and cancel.
 */
export function useLocalUploads(limits: { maxBytes: number; single?: boolean }) {
  const [items, setItems] = useState<LocalItem[]>([]);
  const itemsRef = useRef(items);
  itemsRef.current = items;
  const [rejected, setRejected] = useState<string[]>([]);
  const controllers = useRef(new Map<string, AbortController>());
  const storeKeys = useRef(new Map<string, string>());

  const patch = useCallback((key: string, p: Partial<LocalItem>) => setItems((xs) => xs.map((x) => (x.key === key ? { ...x, ...p } : x))), []);

  const add = useCallback(
    (next: Omit<LocalItem, "key" | "state" | "progress" | "display_name" | "asset_name">[], lastModified: (number | undefined)[]) => {
      const errs: string[] = [];
      const accepted: LocalItem[] = [];
      next.forEach((n, i) => {
        if (n.size === 0) errs.push(`${n.label}: the file is empty.`);
        else if (limits.maxBytes && n.size > limits.maxBytes) errs.push(`${n.label}: ${formatBytes(n.size)} exceeds the ${formatBytes(limits.maxBytes)} limit.`);
        else {
          const key = `item-${++seq}`;
          const sk = storeKey({ filename: n.filename, size: n.size, lastModified: lastModified[i] });
          storeKeys.current.set(key, sk);
          const saved = recall(sk);
          const base = n.kind === "folder" ? n.label : stripArchiveExt(n.label);
          accepted.push({ ...n, key, state: "queued", progress: 0, display_name: base, asset_name: slugify(base), uploadId: saved?.id, sha256: saved?.sha256 });
        }
      });
      const room = limits.single ? Math.max(0, 1 - itemsRef.current.length) : accepted.length;
      if (accepted.length > room) errs.push("Only one archive can be uploaded as a new version.");
      setRejected(errs);
      setItems((xs) => [...xs, ...accepted.slice(0, room)]);
    },
    [limits.maxBytes, limits.single],
  );

  const addFiles = useCallback(
    (files: File[]) => {
      const ok = files.filter((f) => archiveFormat(f.name));
      const bad = files.filter((f) => !archiveFormat(f.name));
      add(
        ok.map((f) => ({ kind: "archive", label: f.name, filename: f.name, file: f, size: f.size })),
        ok.map((f) => f.lastModified),
      );
      if (bad.length) setRejected((r) => [...r, ...bad.map((f) => `${f.name}: unsupported format. Use .zip, .tar, .tar.gz or .tgz, or choose a folder.`)]);
    },
    [add],
  );

  const addFolder = useCallback(
    (name: string, files: FolderFile[]) => {
      if (!files.length) {
        setRejected([`${name}: the folder is empty.`]);
        return;
      }
      const tar = createTar(files.map((f) => ({ path: f.path, data: f.file, mtime: f.file.lastModified })));
      add([{ kind: "folder", label: name, filename: `${name}.tar`, file: tar, size: tar.size, fileCount: files.length }], [undefined]);
    },
    [add],
  );

  // Process the queue: one item at a time.
  useEffect(() => {
    if (items.some((x) => x.state === "hashing" || x.state === "uploading" || x.state === "completing")) return;
    const next = items.find((x) => x.state === "queued");
    if (!next) return;
    const ctl = new AbortController();
    controllers.current.set(next.key, ctl);
    patch(next.key, { state: next.uploadId ? "uploading" : "hashing", error: undefined });
    const sk = storeKeys.current.get(next.key)!;
    uploadSource({
      file: next.file,
      filename: next.filename,
      resumeId: next.uploadId,
      sha256: next.sha256,
      signal: ctl.signal,
      onSession: (s, sha) => {
        remember(sk, { id: s.id, sha256: sha });
        patch(next.key, { uploadId: s.id, sha256: sha });
      },
      onProgress: (p) =>
        !ctl.signal.aborted &&
        patch(next.key, {
          state: p.phase === "done" ? "done" : p.phase,
          progress: p.total ? p.bytes / p.total : 1,
        }),
    })
      .then((s) => {
        if (!ctl.signal.aborted) patch(next.key, { state: "done", progress: 1, uploadId: s.id });
      })
      .catch((e: unknown) => {
        if (isAbort(e)) return; // pause or cancel already updated the state
        patch(next.key, { state: "error", error: e instanceof Error ? e.message : String(e) });
      })
      .finally(() => controllers.current.delete(next.key));
  }, [items, patch]);

  // Abort in-flight uploads when the wizard unmounts (sessions stay resumable).
  useEffect(() => () => controllers.current.forEach((c) => c.abort()), []);

  const pause = (key: string) => {
    controllers.current.get(key)?.abort();
    patch(key, { state: "paused" });
  };
  const resume = (key: string) => patch(key, { state: "queued", error: undefined });
  const remove = async (key: string) => {
    const it = items.find((x) => x.key === key);
    controllers.current.get(key)?.abort();
    setItems((xs) => xs.filter((x) => x.key !== key));
    const sk = storeKeys.current.get(key);
    if (sk) remember(sk, null);
    if (it?.uploadId && it.state !== "done") await cancelUpload(it.uploadId).catch(() => undefined);
  };
  const rename = (key: string, p: { display_name?: string; asset_name?: string }) => patch(key, p);

  const pending = items.filter((x) => x.state !== "done");
  return {
    items,
    rejected,
    clearRejected: () => setRejected([]),
    addFiles,
    addFolder,
    pause,
    resume,
    remove,
    rename,
    allDone: items.length > 0 && pending.length === 0,
    pendingCount: pending.length,
    progress: items.length ? items.reduce((n, x) => n + (x.state === "done" ? 1 : x.state === "uploading" ? x.progress : 0), 0) / items.length : 0,
  };
}

/** Reads dropped files and folders (folders via the File and Directory Entries API). */
export async function readDrop(dt: DataTransfer): Promise<{ files: File[]; folders: { name: string; files: FolderFile[] }[] }> {
  const files: File[] = [];
  const folders: { name: string; files: FolderFile[] }[] = [];
  const entries = Array.from(dt.items ?? [])
    .map((i) => (typeof i.webkitGetAsEntry === "function" ? i.webkitGetAsEntry() : null))
    .filter((e): e is FileSystemEntry => !!e);
  if (!entries.length) return { files: Array.from(dt.files ?? []), folders };
  const fileOf = (e: FileSystemFileEntry) => new Promise<File>((res, rej) => e.file(res, rej));
  const readAll = async (dir: FileSystemDirectoryEntry): Promise<FileSystemEntry[]> => {
    const reader = dir.createReader();
    const out: FileSystemEntry[] = [];
    for (;;) {
      const batch = await new Promise<FileSystemEntry[]>((res, rej) => reader.readEntries(res, rej));
      if (!batch.length) return out;
      out.push(...batch);
    }
  };
  const walk = async (dir: FileSystemDirectoryEntry, prefix: string, acc: FolderFile[]) => {
    for (const e of await readAll(dir)) {
      if (e.isFile) acc.push({ path: `${prefix}/${e.name}`, file: await fileOf(e as FileSystemFileEntry) });
      else if (e.isDirectory) await walk(e as FileSystemDirectoryEntry, `${prefix}/${e.name}`, acc);
    }
  };
  for (const e of entries) {
    if (e.isFile) files.push(await fileOf(e as FileSystemFileEntry));
    else if (e.isDirectory) {
      const acc: FolderFile[] = [];
      await walk(e as FileSystemDirectoryEntry, e.name, acc);
      folders.push({ name: e.name, files: acc });
    }
  }
  return { files, folders };
}

/** Groups files from an <input webkitdirectory> by their top-level folder. */
export function groupFolderInput(list: FileList | File[]): { name: string; files: FolderFile[] }[] {
  const groups = new Map<string, FolderFile[]>();
  for (const f of Array.from(list)) {
    const rel = (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name;
    const top = rel.includes("/") ? rel.split("/")[0]! : "upload";
    groups.set(top, [...(groups.get(top) ?? []), { path: rel.includes("/") ? rel : `${top}/${rel}`, file: f }]);
  }
  return [...groups].map(([name, files]) => ({ name, files }));
}

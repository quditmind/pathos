// Resumable, chunked source upload (POST /source-uploads, PUT parts with a
// per-part SHA-256, POST complete). Pausing is aborting: resuming calls
// uploadSource again with the session id, which skips the parts the server
// already has.

import { api, ApiError, getCsrfToken } from "@/api/client";
import type { SourceUpload } from "@/api/types";
import { hashBlob, readBlob, sha256Hex } from "./sha256";

export interface UploadProgress {
  phase: "hashing" | "uploading" | "completing" | "done";
  /** Bytes hashed (hashing) or confirmed uploaded (uploading). */
  bytes: number;
  total: number;
  partsDone: number;
  partsTotal: number;
}

export interface UploadOptions {
  file: Blob;
  filename: string;
  /** Whole-file SHA-256 if already known (e.g. when resuming). */
  sha256?: string;
  /** Existing upload session to resume. */
  resumeId?: string;
  signal?: AbortSignal;
  onProgress?: (p: UploadProgress) => void;
  /** Called once the session is known (persist the id to resume later). */
  onSession?: (s: SourceUpload, sha256: string) => void;
  concurrency?: number;
  /** Attempts per part, including the first. */
  maxAttempts?: number;
  baseDelayMs?: number;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
}

const sleepDefault = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(t);
      reject(new DOMException("Aborted", "AbortError"));
    }, { once: true });
  });

export function isAbort(e: unknown) {
  return e instanceof DOMException ? e.name === "AbortError" : (e as { name?: string })?.name === "AbortError";
}

function retryable(status: number) {
  return status >= 500 || status === 429 || status === 408;
}

export const uploadsPath = "/api/v1/source-uploads";

/** Sends one part, retrying network errors and 5xx/429 with exponential backoff. */
export async function putPart(
  uploadId: string,
  n: number,
  bytes: Uint8Array,
  opts: Pick<UploadOptions, "signal" | "maxAttempts" | "baseDelayMs" | "sleep"> = {},
): Promise<void> {
  const maxAttempts = opts.maxAttempts ?? 5;
  const base = opts.baseDelayMs ?? 500;
  const sleep = opts.sleep ?? sleepDefault;
  const digest = await sha256Hex(bytes);
  for (let attempt = 1; ; attempt++) {
    let status = 0;
    let err: unknown;
    try {
      const res = await fetch(`${uploadsPath}/${uploadId}/parts/${n}`, {
        method: "PUT",
        credentials: "same-origin",
        headers: { "Content-Type": "application/octet-stream", "X-Content-SHA256": digest, "X-CSRF-Token": getCsrfToken() },
        body: bytes as Uint8Array<ArrayBuffer>,
        signal: opts.signal,
      });
      if (res.ok) return;
      status = res.status;
      const data = await res.json().catch(() => ({}));
      const e = data?.error ?? {};
      err = new ApiError(res.status, e.code ?? "error", e.message ?? res.statusText, data?.request_id);
      if (!retryable(status)) throw err;
    } catch (e) {
      if (isAbort(e)) throw e;
      if (e instanceof ApiError && !retryable(e.status)) throw e;
      err = e;
    }
    if (attempt >= maxAttempts) throw err instanceof Error ? err : new Error(`Part ${n} failed`);
    await sleep(base * 2 ** (attempt - 1), opts.signal);
  }
}

/** Creates or resumes an upload session, sends missing parts and completes it. */
export async function uploadSource(opts: UploadOptions): Promise<SourceUpload> {
  const { file, signal } = opts;
  const total = file.size;
  const report = (p: Omit<UploadProgress, "total">) => opts.onProgress?.({ ...p, total });

  let session: SourceUpload | null = null;
  let sha = opts.sha256;
  if (opts.resumeId) {
    try {
      const s = await api<SourceUpload>(`${uploadsPath}/${opts.resumeId}`, { signal });
      if (s.size === total && (!sha || s.sha256 === sha)) {
        if (s.status === "complete") {
          report({ phase: "done", bytes: total, partsDone: 0, partsTotal: 0 });
          return s;
        }
        if (s.status === "uploading") {
          session = s;
          sha = s.sha256;
        }
      }
    } catch (e) {
      if (isAbort(e)) throw e;
      if (!(e instanceof ApiError && (e.status === 404 || e.status === 410))) throw e;
    }
  }
  if (!session) {
    if (!sha) {
      report({ phase: "hashing", bytes: 0, partsDone: 0, partsTotal: 0 });
      sha = await hashBlob(file, { signal, onProgress: (b) => report({ phase: "hashing", bytes: b, partsDone: 0, partsTotal: 0 }) });
    }
    session = await api<SourceUpload>(uploadsPath, { method: "POST", body: { filename: opts.filename, size: total, sha256: sha }, signal });
  }
  opts.onSession?.(session, sha!);

  const chunk = session.chunk_size;
  const partsTotal = Math.max(1, Math.ceil(total / chunk));
  const partSize = (n: number) => Math.min(chunk, total - n * chunk);
  const received = new Set(session.received_parts);
  let partsDone = 0;
  let bytes = 0;
  for (const n of received) {
    if (n < partsTotal) {
      partsDone++;
      bytes += partSize(n);
    }
  }
  report({ phase: "uploading", bytes, partsDone, partsTotal });

  const queue: number[] = [];
  for (let n = 0; n < partsTotal; n++) if (!received.has(n)) queue.push(n);
  const id = session.id;
  const worker = async () => {
    for (;;) {
      const n = queue.shift();
      if (n === undefined) return;
      if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
      const data = await readBlob(file.slice(n * chunk, n * chunk + partSize(n)));
      await putPart(id, n, data, opts);
      partsDone++;
      bytes += data.length;
      report({ phase: "uploading", bytes, partsDone, partsTotal });
    }
  };
  const workers = Array.from({ length: Math.min(opts.concurrency ?? 3, queue.length) }, worker);
  await Promise.all(workers);

  report({ phase: "completing", bytes: total, partsDone, partsTotal });
  const done = await api<SourceUpload>(`${uploadsPath}/${id}/complete`, { method: "POST", signal });
  report({ phase: "done", bytes: total, partsDone, partsTotal });
  return done;
}

export function cancelUpload(id: string) {
  return api<void>(`${uploadsPath}/${id}`, { method: "DELETE" });
}

/** Accepted archive extensions → server format. */
export function archiveFormat(name: string): "zip" | "tar" | "tar.gz" | null {
  const n = name.toLowerCase();
  if (n.endsWith(".zip")) return "zip";
  if (n.endsWith(".tar.gz") || n.endsWith(".tgz")) return "tar.gz";
  if (n.endsWith(".tar")) return "tar";
  return null;
}

export function stripArchiveExt(name: string) {
  return name.replace(/\.(zip|tar\.gz|tgz|tar)$/i, "");
}

export function formatBytes(n: number | null | undefined): string {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}

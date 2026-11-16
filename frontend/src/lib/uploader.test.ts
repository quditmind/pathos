import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setCsrfToken } from "@/api/client";
import type { SourceUpload } from "@/api/types";
import { sha256Hex } from "./sha256";
import { archiveFormat, uploadSource } from "./uploader";

const enc = new TextEncoder();

function session(over: Partial<SourceUpload> = {}): SourceUpload {
  return {
    id: "up1", filename: "repo.zip", format: "zip", size: 10, sha256: "", chunk_size: 4, status: "uploading",
    received_parts: [], received_bytes: 0, expires_at: "2030-01-01T00:00:00Z", ...over,
  };
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("chunked uploader", () => {
  beforeEach(() => setCsrfToken("csrf-1"));
  afterEach(() => vi.unstubAllGlobals());

  it("creates a session, sends every part with checksum and CSRF headers, then completes", async () => {
    const data = enc.encode("0123456789");
    const sha = await sha256Hex(data);
    const calls: { url: string; method: string; headers: Record<string, string>; body?: unknown }[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, method: init.method ?? "GET", headers: init.headers as Record<string, string>, body: init.body });
      if (url === "/api/v1/source-uploads" && init.method === "POST") return json(session({ sha256: sha }));
      if (url.includes("/parts/")) return new Response(null, { status: 204 });
      if (url.endsWith("/complete")) return json(session({ sha256: sha, status: "complete" }));
      return json({}, 404);
    }));

    const result = await uploadSource({ file: new Blob([data]), filename: "repo.zip", concurrency: 1 });
    expect(result.status).toBe("complete");
    const create = calls[0]!;
    expect(JSON.parse(create.body as string)).toEqual({ filename: "repo.zip", size: 10, sha256: sha });
    const parts = calls.filter((c) => c.url.includes("/parts/"));
    expect(parts.map((p) => p.url)).toEqual([
      "/api/v1/source-uploads/up1/parts/0",
      "/api/v1/source-uploads/up1/parts/1",
      "/api/v1/source-uploads/up1/parts/2",
    ]);
    for (const [i, p] of parts.entries()) {
      expect(p.method).toBe("PUT");
      expect(p.headers["Content-Type"]).toBe("application/octet-stream");
      expect(p.headers["X-CSRF-Token"]).toBe("csrf-1");
      const chunk = data.subarray(i * 4, i * 4 + 4);
      expect(p.headers["X-Content-SHA256"]).toBe(await sha256Hex(chunk));
      expect(Array.from(p.body as Uint8Array)).toEqual(Array.from(chunk));
    }
    expect(calls.at(-1)!.url).toBe("/api/v1/source-uploads/up1/complete");
  });

  it("resumes a session and skips parts the server already received", async () => {
    const data = enc.encode("0123456789");
    const sha = await sha256Hex(data);
    const urls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
      urls.push(`${init.method ?? "GET"} ${url}`);
      if (url === "/api/v1/source-uploads/up1" && (init.method ?? "GET") === "GET") return json(session({ sha256: sha, received_parts: [0, 2], received_bytes: 6 }));
      if (url.includes("/parts/")) return new Response(null, { status: 204 });
      if (url.endsWith("/complete")) return json(session({ sha256: sha, status: "complete" }));
      return json({}, 404);
    }));
    const progress: number[] = [];
    await uploadSource({ file: new Blob([data]), filename: "repo.zip", resumeId: "up1", onProgress: (p) => p.phase === "uploading" && progress.push(p.bytes) });
    expect(urls).toEqual(["GET /api/v1/source-uploads/up1", "PUT /api/v1/source-uploads/up1/parts/1", "POST /api/v1/source-uploads/up1/complete"]);
    expect(urls.some((u) => u.startsWith("POST /api/v1/source-uploads "))).toBe(false);
    expect(progress[0]).toBe(6);
    expect(progress.at(-1)).toBe(10);
  });

  it("retries a failed part with exponential backoff", async () => {
    const data = enc.encode("abcd");
    let attempts = 0;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
      if (url === "/api/v1/source-uploads" && init.method === "POST") return json(session({ size: 4 }));
      if (url.includes("/parts/0")) {
        attempts++;
        if (attempts === 1) throw new TypeError("network down");
        if (attempts === 2) return json({ error: { code: "unavailable", message: "busy" } }, 503);
        return new Response(null, { status: 204 });
      }
      if (url.endsWith("/complete")) return json(session({ size: 4, status: "complete" }));
      return json({}, 404);
    }));
    const delays: number[] = [];
    await uploadSource({ file: new Blob([data]), filename: "repo.zip", baseDelayMs: 100, sleep: async (ms) => void delays.push(ms) });
    expect(attempts).toBe(3);
    expect(delays).toEqual([100, 200]);
  });

  it("does not retry client errors", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
      if (url === "/api/v1/source-uploads" && init.method === "POST") return json(session({ size: 4 }));
      if (url.includes("/parts/")) return json({ error: { code: "checksum_mismatch", message: "bad part" } }, 400);
      return json({}, 404);
    }));
    const sleep = vi.fn(async () => undefined);
    await expect(uploadSource({ file: new Blob([enc.encode("abcd")]), filename: "repo.zip", sleep })).rejects.toMatchObject({ code: "checksum_mismatch" });
    expect(sleep).not.toHaveBeenCalled();
  });

  it("recognises archive formats", () => {
    expect(archiveFormat("a.ZIP")).toBe("zip");
    expect(archiveFormat("a.tgz")).toBe("tar.gz");
    expect(archiveFormat("a.tar.gz")).toBe("tar.gz");
    expect(archiveFormat("a.tar")).toBe("tar");
    expect(archiveFormat("a.rar")).toBeNull();
  });
});

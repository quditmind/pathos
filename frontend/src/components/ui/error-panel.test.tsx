import { afterEach, describe, expect, it, vi } from "vitest";
import { act, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ApiError } from "@/api/client";
import { mockApi, renderApp } from "@/test/harness";
import { ErrorPanel, parseTroubleshoot } from "./error-panel";
import { EmptyStateCard, FeatureDisabled, LoadingSkeleton, PartialData, PermissionDenied } from "./states";
import { toast, Toaster } from "./toast";
import { UnmanagedPage } from "@/features/posture/UnmanagedPage";
import { jsonResponse } from "@/test/harness";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  toast.clear();
});

const envelope = {
  code: "conflict",
  error_code: "PTH-CONN-1004",
  title: "Connection uses an untrusted certificate",
  message: "x509: certificate signed by unknown authority",
  cause: { confirmed: true, text: "The server certificate is signed by a private CA." },
  probable_causes: ["The CA bundle was not mounted."],
  impact: "Repositories of this connection cannot sync.",
  actions: ["Add the CA certificate to the trust store.", { text: "Open SCM connections", href: "/admin/scm" }],
  verify: ["Test the connection."],
  docs_url: "/help/troubleshooting/conn#PTH-CONN-1004",
  request_id: "reqabc",
};
const apiErr = (err: Record<string, unknown> = envelope) => new ApiError(409, String(err.code), String(err.message), "top-rid", undefined, err);

describe("ErrorPanel", () => {
  it("keeps the one-line alert for old-style errors", async () => {
    renderApp(<ErrorPanel error={new ApiError(403, "forbidden", "nope")} title="Could not load" />);
    const a = await screen.findByRole("alert");
    expect(a).toHaveTextContent("Could not load: nope");
    expect(screen.queryByRole("button", { name: "Verify" })).toBeNull();
  });

  it("handles plain errors and strings", async () => {
    renderApp(
      <>
        <ErrorPanel error={new Error("boom")} />
        <ErrorPanel error="text" />
      </>,
    );
    expect((await screen.findAllByRole("alert")).map((a) => a.textContent)).toEqual(["boom", "text"]);
  });

  it("renders the envelope: code, request id, confirmed cause, impact, numbered fixes and docs", async () => {
    renderApp(<ErrorPanel error={apiErr()} />);
    const panel = await screen.findByRole("alert", { name: envelope.title });
    expect(within(panel).getByText("PTH-CONN-1004")).toBeInTheDocument();
    expect(within(panel).getByText("reqabc")).toBeInTheDocument();
    expect(within(panel).getByText("Confirmed cause")).toBeInTheDocument();
    expect(within(panel).getByText(envelope.cause.text)).toBeInTheDocument();
    expect(within(panel).getByText("Other possible causes")).toBeInTheDocument();
    expect(within(panel).getByText(envelope.impact)).toBeInTheDocument();
    const fixes = within(panel).getByText("How to fix it").parentElement!.querySelector("ol")!;
    expect(within(fixes).getAllByRole("listitem")).toHaveLength(2);
    expect(within(fixes).getByRole("link", { name: "Open SCM connections" })).toHaveAttribute("href", "/admin/scm");
    expect(within(panel).getByRole("link", { name: /Read the docs/ })).toHaveAttribute("href", "/help/troubleshooting/conn#PTH-CONN-1004");
    expect(within(panel).getByRole("link", { name: /Troubleshooting centre/ })).toHaveAttribute("href", "/help/troubleshooting?q=PTH-CONN-1004");
  });

  it("labels an unconfirmed cause as probable", async () => {
    renderApp(<ErrorPanel error={apiErr({ ...envelope, cause: { confirmed: false, text: "Maybe the proxy." } })} />);
    expect(await screen.findByText("Probable causes (not confirmed)")).toBeInTheDocument();
    expect(screen.getByText("Maybe the proxy.")).toBeInTheDocument();
    expect(screen.queryByText("Confirmed cause")).toBeNull();
  });

  it("copies the code and the request id", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    renderApp(<ErrorPanel error={apiErr()} />);
    await userEvent.click(await screen.findByRole("button", { name: "Copy code PTH-CONN-1004" }));
    await userEvent.click(screen.getByRole("button", { name: "Copy request id reqabc" }));
    expect(writeText.mock.calls).toEqual([["PTH-CONN-1004"], ["reqabc"]]);
  });

  it("Verify re-runs the failed check", async () => {
    const onVerify = vi.fn().mockResolvedValue(undefined);
    renderApp(<ErrorPanel error={apiErr()} onVerify={onVerify} />);
    await userEvent.click(await screen.findByRole("button", { name: /Verify/ }));
    expect(onVerify).toHaveBeenCalledOnce();
  });

  it("Troubleshoot with AI sends error_code (not the slug) and labels an AI answer", async () => {
    const api = mockApi({
      "POST /api/v1/diagnostics/troubleshoot": () => ({ ...envelope, cause: { confirmed: false, text: "AI thinks the CA expired." }, source: "ai" }),
    });
    renderApp(<ErrorPanel error={apiErr({ ...envelope, message: "failed with token=abc123secret" })} />);
    await userEvent.click(await screen.findByRole("button", { name: /Troubleshoot with AI/ }));
    expect(await screen.findByText("AI-inferred: check before acting")).toBeInTheDocument();
    expect(screen.getByText("AI thinks the CA expired.")).toBeInTheDocument();
    const body = api.calls.find((c) => c.method === "POST")!.body as { code: string; request_id: string; context: { message: string } };
    expect(body.code).toBe("PTH-CONN-1004");
    expect(body.request_id).toBe("reqabc");
    expect(body.context.message).not.toContain("abc123secret");
  });

  it("shows the catalogue answer when AI is off", async () => {
    mockApi({ "POST /api/v1/diagnostics/troubleshoot": () => ({ error: { ...envelope }, source: "catalogue" }) });
    renderApp(<ErrorPanel error={apiErr()} />);
    await userEvent.click(await screen.findByRole("button", { name: /Troubleshoot with AI/ }));
    expect(await screen.findByText("From the error catalogue (AI not used)")).toBeInTheDocument();
  });

  it("keeps the catalogue steps when troubleshooting fails", async () => {
    mockApi({});
    renderApp(<ErrorPanel error={apiErr()} />);
    await userEvent.click(await screen.findByRole("button", { name: /Troubleshoot with AI/ }));
    expect(await screen.findByText(/Troubleshooting is unavailable/)).toBeInTheDocument();
    expect(screen.getByText(envelope.impact)).toBeInTheDocument();
  });

  it("parses troubleshoot answers flat or wrapped", () => {
    expect(parseTroubleshoot({ code: "PTH-AI-0001", title: "t", source: "ai" }, "PTH-X-0000")).toMatchObject({ error_code: "PTH-AI-0001", source: "ai" });
    expect(parseTroubleshoot({ error: { title: "t" } }, "PTH-SCAN-0001")).toMatchObject({ error_code: "PTH-SCAN-0001", source: "catalogue" });
    expect(parseTroubleshoot(null, "PTH-SCAN-0001")).toBeUndefined();
  });

  it("ignores a non-catalogue error_code and unsafe links", () => {
    expect(apiErr({ code: "x", error_code: "nope", message: "m" }).envelope).toBeUndefined();
    const env = apiErr({ ...envelope, docs_url: "javascript:alert(1)", actions: [{ text: "bad", href: "https://evil.example" }] }).envelope!;
    expect(env.docs_url).toBe("");
    expect(env.actions).toEqual([{ text: "bad", href: undefined }]);
    expect(env.request_id).toBe("reqabc");
    expect(apiErr({ ...envelope, request_id: undefined }).envelope!.request_id).toBe("top-rid");
  });
});

describe("shared states", () => {
  it("loading skeleton is a busy status, not a spinner", async () => {
    renderApp(<LoadingSkeleton rows={4} label="Loading scans" />);
    const s = await screen.findByRole("status", { name: "Loading scans" });
    expect(s).toHaveAttribute("aria-busy", "true");
    expect(s.querySelectorAll(".animate-pulse")).toHaveLength(4);
  });

  it("empty, partial, permission denied and feature disabled name what is missing", async () => {
    renderApp(
      <>
        <EmptyStateCard title="No scans yet" action={<button>Start a scan</button>}>
          Scans you start appear here.
        </EmptyStateCard>
        <PartialData missing={["trend", "owners"]} />
        <PermissionDenied permission="scans.read" what="The scan list" />
        <FeatureDisabled flag="codegraph" feature="CodeGraph" />
      </>,
    );
    expect(await screen.findByText("No scans yet")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start a scan" })).toBeInTheDocument();
    expect(screen.getByText(/Not loaded: trend, owners/)).toBeInTheDocument();
    expect(screen.getByText("scans.read")).toBeInTheDocument();
    expect(screen.getByText(/The scan list needs the/)).toBeInTheDocument();
    expect(screen.getByText("CodeGraph is not enabled")).toBeInTheDocument();
    expect(screen.getByText("codegraph")).toBeInTheDocument();
    expect(screen.getByText(/settings\.manage permission can turn it on/)).toBeInTheDocument();
  });

  it("success toast states what happened and disappears", async () => {
    renderApp(<Toaster timeout={50} />);
    await screen.findByRole("status");
    act(() => {
      toast.success("Scan profile saved");
    });
    expect(await screen.findByText("Scan profile saved")).toBeInTheDocument();
    await act(() => new Promise((r) => setTimeout(r, 80)));
    expect(screen.queryByText("Scan profile saved")).toBeNull();
  });
});

describe("pages render ErrorPanel for envelope errors", () => {
  it("a page with a failed query shows the panel, and Verify re-runs it", async () => {
    let calls = 0;
    mockApi({
      "GET /api/v1/posture/unmanaged": () => {
        calls++;
        return jsonResponse({ error: { ...envelope, code: "unavailable", error_code: "PTH-SYNC-3002", title: "Inventory sync failed" }, request_id: "r9" }, 503);
      },
    });
    renderApp(<UnmanagedPage />, { permissions: ["repos.read"] });
    const panel = await screen.findByRole("alert", { name: "Inventory sync failed" }, { timeout: 4000 });
    expect(within(panel).getByText("PTH-SYNC-3002")).toBeInTheDocument();
    const before = calls;
    await userEvent.click(within(panel).getByRole("button", { name: /Verify/ }));
    await vi.waitFor(() => expect(calls).toBeGreaterThan(before));
  });

  it("old error JSON still shows its message", async () => {
    mockApi({ "GET /api/v1/posture/unmanaged": () => jsonResponse({ error: { code: "forbidden", message: "you do not have permission" }, request_id: "r1" }, 403) });
    renderApp(<UnmanagedPage />, { permissions: ["repos.read"] });
    expect(await screen.findByText("you do not have permission", {}, { timeout: 4000 })).toBeInTheDocument();
  });
});

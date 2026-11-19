import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { groups } from "@/components/layout/AppShell";
import { RuntimePage } from "./RuntimePage";
import { FindingRuntime } from "./FindingRuntime";
import { RiskPanel } from "@/features/vuln/intel";
import type { RuntimeCluster, Workload } from "./api";

afterEach(() => vi.unstubAllGlobals());

const summary = { clusters: 1, registries: 0, workloads: 1, internet_exposed_workloads: 1, privileged_workloads: 0, running_images: 1, linked_images: 1,
  deployed_findings: 2, exposed_findings: 2, not_deployed_findings: 0, matched_runtime_alerts: 1 };

const cluster: RuntimeCluster = {
  id: "c1", name: "prod-eu", api_server: "https://k8s.example.com", auth_type: "token", has_ca_cert: true, namespaces: [], allow_private: false, enabled: true,
  sync_interval_minutes: 60, sync_requested_at: null, last_sync_at: "2026-11-19T08:00:00Z", last_status: "succeeded", last_error: "", workloads: 1,
  internet_exposed_workloads: 1, privileged_workloads: 0, namespace_count: 3, created_at: "2026-11-19T07:00:00Z",
};

const workload: Workload = {
  id: "w1", cluster_id: "c1", cluster: "prod-eu", namespace: "shop", kind: "Deployment", name: "web", labels: { app: "web" }, replicas: 2, ready_replicas: 2,
  privileged: false, host_network: false, host_pid: false, run_as_root: "no", internet_exposed: true,
  exposure: [{ via: "ingress", service: "web", ingress: "shop", host: "shop.example.com", path: "/", internet: true, detail: "Ingress shop routes https://shop.example.com/" }],
  network_policies: ["default-deny"], application_id: "a1", application_name: "Shop", application_basis: "mapping: namespace shop",
  images: [{ container: "web", init: false, image: "ghcr.io/acme/shop:1.0", digest: "sha256:" + "1".repeat(64),
    links: [{ basis: "digest", detail: "image scan target ghcr.io/acme/shop:1.0: running digest sha256:111111 is the scanned image", scan_target_id: "t1", scan_target_name: "shop image", repository_id: "r1", repository_name: "acme/shop" }] }],
  findings: { total: 2, critical: 1, high: 1 }, runtime_alerts: 1, last_seen_at: "2026-11-19T08:00:00Z",
};

describe("runtime navigation", () => {
  it("lists Runtime under Assets", () => {
    const g = groups.find((x) => x.label === "Assets")!;
    expect(g.items.map((i) => i.to)).toContain("/runtime");
  });
});

describe("runtime page", () => {
  it("explains how to connect a cluster when none is connected (no invented data)", async () => {
    const api = mockApi({
      "GET /api/v1/runtime/summary": () => ({ ...summary, clusters: 0, workloads: 0, internet_exposed_workloads: 0, running_images: 0, linked_images: 0, deployed_findings: 0, exposed_findings: 0, matched_runtime_alerts: 0 }),
      "GET /api/v1/runtime/clusters": () => ({ items: [], can_manage: true }),
    });
    renderApp(<RuntimePage />, { permissions: ["findings.read", "settings.manage"] });
    expect(await screen.findByText("No Kubernetes cluster connected")).toBeInTheDocument();
    expect(screen.getByText(/deploy\/kubernetes\/pathos-reader-clusterrole.yaml/)).toBeInTheDocument();
    expect(screen.queryByText("Workloads", { selector: "div" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Add cluster/ }));
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "prod-eu" } });
    fireEvent.change(screen.getByLabelText("API server URL"), { target: { value: "https://k8s.example.com" } });
    fireEvent.change(screen.getByLabelText(/^Token/), { target: { value: "sa-token" } });
    api.fn.mockClear();
    mockApi({
      "GET /api/v1/runtime/summary": () => summary,
      "GET /api/v1/runtime/clusters": () => ({ items: [], can_manage: true }),
      "POST /api/v1/runtime/clusters": (_u, init) => {
        expect(init.json).toMatchObject({ name: "prod-eu", auth_type: "token", api_server: "https://k8s.example.com", token: "sa-token", namespaces: [] });
        return cluster;
      },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("lists workloads with images, links, exposure and finding counts", async () => {
    mockApi({
      "GET /api/v1/runtime/summary": () => summary,
      "GET /api/v1/runtime/clusters": () => ({ items: [cluster], can_manage: false }),
      "GET /api/v1/runtime/workloads": () => ({ items: [workload], truncated: false }),
      "GET /api/v1/runtime/workloads/w1": () => ({ workload, alerts: [{ finding_id: "f9", title: "Terminal shell in container", severity: "medium", location: "shop/web-abc-zzzzz", basis: "pod_name_pattern" }] }),
    });
    renderApp(<RuntimePage />, { permissions: ["findings.read"] });
    expect(await screen.findByText("web")).toBeInTheDocument();
    expect(screen.getByText("Internet-exposed", { selector: "span" })).toBeInTheDocument();
    expect(screen.getByText("shop.example.com")).toBeInTheDocument();
    expect(screen.getByText(/1 critical, 1 high/)).toBeInTheDocument();
    expect(screen.getByText("1 alert")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "web" }));
    expect(await screen.findByText("Terminal shell in container")).toBeInTheDocument();
    expect(screen.getByText("Ingress shop routes https://shop.example.com/")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "shop image findings" })).toHaveAttribute("href", expect.stringContaining("scan_target_id=t1"));
    expect(screen.getByText(/Shop \(mapping: namespace shop\)/)).toBeInTheDocument();
  });

  it("requests a sync without contacting the cluster from the browser", async () => {
    const api = mockApi({
      "GET /api/v1/runtime/summary": () => summary,
      "GET /api/v1/runtime/clusters": () => ({ items: [cluster], can_manage: true }),
      "GET /api/v1/runtime/workloads": () => ({ items: [], truncated: false }),
      "POST /api/v1/runtime/clusters/c1/sync": () => ({ sync_requested_at: "2026-11-19T09:00:00Z" }),
    });
    renderApp(<RuntimePage />, { permissions: ["findings.read", "settings.manage"] });
    fireEvent.click(await screen.findByRole("tab", { name: "Clusters" }));
    fireEvent.click(await screen.findByRole("button", { name: /Sync now/ }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/runtime/clusters/c1/sync")).toBe(true));
  });
});

describe("finding drawer", () => {
  it("shows where a finding runs with the evidence", async () => {
    mockApi({
      "GET /api/v1/findings/f1/runtime": () => ({
        status: "deployed", internet_exposed: true, privileged: true, runtime_alert: false, clusters_connected: 1,
        context: { status: "deployed", total_deployments: 1, clusters: ["prod-eu"], deployments: [{
          cluster_id: "c1", cluster: "prod-eu", workload_id: "w1", namespace: "shop", kind: "Deployment", workload: "web", container: "web", image: "ghcr.io/acme/shop:1.0",
          digest: "sha256:" + "1".repeat(64), basis: "digest", basis_detail: "running digest is the scanned image", internet_exposed: true, privileged: true,
          host_network: false, host_pid: false, run_as_root: "no", exposure: [{ via: "ingress", service: "web", host: "shop.example.com", internet: true, detail: "Ingress shop routes https://shop.example.com/" }],
        }] },
      }),
    });
    renderApp(<FindingRuntime findingId="f1" />, { permissions: ["findings.read"] });
    expect(await screen.findByText("prod-eu / shop / Deployment web")).toBeInTheDocument();
    expect(screen.getByText("Internet-exposed")).toBeInTheDocument();
    expect(screen.getByText("Privileged workload")).toBeInTheDocument();
    expect(screen.getByText(/Ingress shop routes https:\/\/shop.example.com\//)).toBeInTheDocument();
    expect(screen.getByText(/same digest as the scanned image/)).toBeInTheDocument();
  });

  it("says when no cluster is connected and when a finding is not deployed", async () => {
    mockApi({ "GET /api/v1/findings/f2/runtime": () => ({ status: "", internet_exposed: false, privileged: false, runtime_alert: false, clusters_connected: 0, context: null }) });
    renderApp(<FindingRuntime findingId="f2" />, { permissions: ["findings.read"] });
    expect(await screen.findByText(/No Kubernetes cluster is connected/)).toBeInTheDocument();
    vi.unstubAllGlobals();
    mockApi({ "GET /api/v1/findings/f3/runtime": () => ({ status: "not_deployed", internet_exposed: false, privileged: false, runtime_alert: false, clusters_connected: 1,
      context: { status: "not_deployed", deployments: [], total_deployments: 0, clusters: ["prod-eu"], not_deployed_reason: "no workload in the 1 connected cluster(s) (prod-eu) runs ghcr.io/acme/idle:2" } }) });
    renderApp(<FindingRuntime findingId="f3" />, { permissions: ["findings.read"] });
    expect(await screen.findByText("Not deployed")).toBeInTheDocument();
    expect(screen.getByText(/runs ghcr.io\/acme\/idle:2/)).toBeInTheDocument();
  });

  it("lists the evidence of runtime risk factors", async () => {
    mockApi({
      "GET /api/v1/findings/f1/risk": () => ({
        risk_score: 70, band: "high", scored_at: "2026-11-19T09:00:00Z", pending: false, cve: "", epss: null, epss_percentile: null, kev: false, kev_due_date: null,
        confidence: "high", reachability: "unknown", cvss_version: "", cvss_vector: "",
        explanation: { score: 70, base: 7.5, model_version: 0, factors: [
          { key: "deployed", label: "Deployed", value: "running in a connected cluster", weight: 1.1, evidence: ["cluster prod-eu, namespace shop, Deployment web (container web)"] },
        ] },
      }),
    });
    renderApp(<RiskPanel findingId="f1" />, { permissions: ["findings.read"] });
    expect(await screen.findByText("cluster prod-eu, namespace shop, Deployment web (container web)")).toBeInTheDocument();
  });
});

import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

export type SyncStatus = "" | "running" | "succeeded" | "partial" | "failed";

export interface RuntimeCluster {
  id: string;
  name: string;
  api_server: string;
  auth_type: "token" | "kubeconfig";
  has_ca_cert: boolean;
  namespaces: string[];
  allow_private: boolean;
  enabled: boolean;
  sync_interval_minutes: number;
  sync_requested_at: string | null;
  last_sync_at: string | null;
  last_status: SyncStatus;
  last_error: string;
  workloads: number;
  internet_exposed_workloads: number;
  privileged_workloads: number;
  namespace_count: number;
  created_at: string;
}

export interface RegistryConnection {
  id: string;
  name: string;
  base_url: string;
  repositories: string[];
  auth_type: "none" | "basic" | "bearer";
  username: string;
  max_tags: number;
  allow_private: boolean;
  /** Private CA bundle (PEM) added to the system trust store for this registry. */
  ca_bundle_pem?: string;
  enabled: boolean;
  sync_interval_minutes: number;
  sync_requested_at: string | null;
  last_sync_at: string | null;
  last_status: SyncStatus;
  last_error: string;
  images: number;
  images_with_source: number;
  created_at: string;
}

export interface Exposure {
  via: "ingress" | "loadbalancer" | "nodeport" | "external_ip";
  service: string;
  ingress?: string;
  host?: string;
  path?: string;
  address?: string;
  internet: boolean;
  detail: string;
}

export interface ImageLink {
  basis: "digest" | "tag" | "oci_source";
  detail: string;
  scan_target_id: string | null;
  scan_target_name: string | null;
  repository_id: string | null;
  repository_name: string | null;
}

export interface WorkloadImage {
  container: string;
  init: boolean;
  image: string;
  digest: string;
  links: ImageLink[];
}

export interface Workload {
  id: string;
  cluster_id: string;
  cluster: string;
  namespace: string;
  kind: string;
  name: string;
  labels: Record<string, string> | null;
  replicas: number | null;
  ready_replicas: number | null;
  privileged: boolean;
  host_network: boolean;
  host_pid: boolean;
  run_as_root: "yes" | "no" | "unknown";
  internet_exposed: boolean;
  exposure: Exposure[];
  network_policies: string[];
  application_id: string | null;
  application_name: string | null;
  application_basis: string;
  images: WorkloadImage[];
  findings: { total: number; critical: number; high: number };
  runtime_alerts: number;
  last_seen_at: string;
}

export interface RuntimeAlert {
  finding_id: string;
  title: string;
  severity: string;
  location: string;
  basis: "pod_name" | "pod_name_pattern";
}

export interface RuntimeSummary {
  clusters: number;
  registries: number;
  workloads: number;
  internet_exposed_workloads: number;
  privileged_workloads: number;
  running_images: number;
  linked_images: number;
  deployed_findings: number;
  exposed_findings: number;
  not_deployed_findings: number;
  matched_runtime_alerts: number;
}

export interface RuntimeMapping {
  id: string;
  cluster_id: string | null;
  cluster_name: string | null;
  namespace: string;
  label_key: string;
  label_value: string;
  application_id: string;
  application_name: string;
  application_workloads: number;
  created_at: string;
}

export interface SyncRun {
  id: string;
  started_at: string;
  finished_at: string | null;
  status: SyncStatus;
  stats: Record<string, number | string[]>;
  error: string;
}

export interface DeploymentEvidence {
  cluster_id: string;
  cluster: string;
  workload_id: string;
  namespace: string;
  kind: string;
  workload: string;
  container: string;
  image: string;
  digest?: string;
  basis: "digest" | "tag" | "oci_source";
  basis_detail: string;
  internet_exposed: boolean;
  exposure?: Exposure[];
  privileged: boolean;
  host_network: boolean;
  host_pid: boolean;
  run_as_root: string;
  alerts?: RuntimeAlert[];
}

export interface FindingRuntimeResponse {
  status: "" | "deployed" | "not_deployed";
  internet_exposed: boolean;
  privileged: boolean;
  runtime_alert: boolean;
  clusters_connected: number;
  context: {
    status: string;
    deployments: DeploymentEvidence[];
    total_deployments: number;
    not_deployed_reason?: string;
    images?: string[];
    clusters: string[];
  } | null;
}

export const basisLabel: Record<string, string> = {
  digest: "same digest as the scanned image",
  tag: "same tag (digest not confirmed)",
  oci_source: "OCI source label",
};

export const useRuntimeSummary = () =>
  useQuery({ queryKey: ["runtime", "summary"], queryFn: () => api<RuntimeSummary>("/api/v1/runtime/summary"), retry: false });

export const useClusters = () =>
  useQuery({
    queryKey: ["runtime", "clusters"],
    queryFn: () => api<{ items: RuntimeCluster[]; can_manage: boolean }>("/api/v1/runtime/clusters"),
    retry: false,
    // A requested sync runs in the jobs service within a minute.
    refetchInterval: (q) => (q.state.data?.items.some((c) => c.sync_requested_at || c.last_status === "running") ? 10_000 : false),
  });

export const useRegistries = () =>
  useQuery({
    queryKey: ["runtime", "registries"],
    queryFn: () => api<{ items: RegistryConnection[]; can_manage: boolean }>("/api/v1/runtime/registries"),
    retry: false,
    refetchInterval: (q) => (q.state.data?.items.some((c) => c.sync_requested_at || c.last_status === "running") ? 10_000 : false),
  });

export type WorkloadFilters = { cluster_id?: string; namespace?: string; exposed?: string; privileged?: string; with_findings?: string; q?: string };

export const useWorkloads = (f: WorkloadFilters) =>
  useQuery({
    queryKey: ["runtime", "workloads", f],
    queryFn: () => {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(f)) if (v) p.set(k, v);
      return api<{ items: Workload[]; truncated: boolean }>(`/api/v1/runtime/workloads?${p}`);
    },
    retry: false,
  });

export const useMappings = () =>
  useQuery({ queryKey: ["runtime", "mappings"], queryFn: () => api<{ items: RuntimeMapping[] }>("/api/v1/runtime/mappings").then((r) => r.items), retry: false });

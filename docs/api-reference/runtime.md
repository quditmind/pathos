---
title: Runtime context
section: api-reference
order: 7
version: "2.0"
updated: 2026-11-19
summary: Kubernetes clusters and container registries (read-only inventories), workloads with images, exposure and finding counts, application mappings, and where a finding runs.
---
# Runtime context

Read-only inventories of Kubernetes clusters and container registries, and the runtime facts of findings. The [user guide](../user-guide/runtime.md#how-findings-are-linked-to-what-runs) explains the linking rules and the risk factors.

None of these endpoints contacts a cluster or a registry. Synchronisations run in the **jobs** service: when a connection is due, or within a minute of a `POST …/sync` request.

## Permissions

| Operation | Permission |
|---|---|
| Read the inventory (summary, clusters, registries, registry images, workloads, mappings) | `findings.read` **organization-wide** (or `settings.manage` organization-wide). The inventory spans every application and is not scoped by business unit |
| Add, change, delete and synchronise connections; manage mappings; read sync history | `settings.manage` organization-wide |
| `GET /api/v1/findings/{id}/runtime` | `findings.read` on the finding's repository |

Readers without `settings.manage` get clusters without `api_server` and `last_error`, and registries without `username` and `last_error`.

## Summary

`GET /api/v1/runtime/summary`

```json
{ "clusters": 1, "registries": 1, "workloads": 42, "internet_exposed_workloads": 5, "privileged_workloads": 3, "running_images": 51,
  "linked_images": 30, "deployed_findings": 120, "exposed_findings": 18, "not_deployed_findings": 64, "matched_runtime_alerts": 2 }
```

`running_images` counts distinct digests (or references without a digest); `linked_images` the running images linked to an image scan target or a repository; the finding counts include open findings only.

## Clusters

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/runtime/clusters` | `{ items: [Cluster], can_manage }` |
| `POST` | `/api/v1/runtime/clusters` | Add a cluster (201). A first synchronisation is requested |
| `PUT` | `/api/v1/runtime/clusters/{id}` | Change a cluster. Credentials are kept unless new ones are sent |
| `DELETE` | `/api/v1/runtime/clusters/{id}` | Delete the cluster, its credential and its inventory (204); runtime facts of findings are recomputed |
| `POST` | `/api/v1/runtime/clusters/{id}/sync` | Request a synchronisation (202 `{ sync_requested_at, message }`; 409 when disabled) |
| `GET` | `/api/v1/runtime/clusters/{id}/runs` | The last 30 synchronisations: `{ items: [{ id, started_at, finished_at, status, stats, error }] }` |

Request body (`POST`, `PUT`):

| Field | Description |
|---|---|
| `name` | 1–120 characters, unique (case-insensitive) |
| `auth_type` | `token` (service-account bearer token) or `kubeconfig` |
| `api_server` | `token` only: `https://` URL of the API server. Loopback, link-local and metadata addresses are refused; RFC 1918/ULA addresses need `allow_private` |
| `token` | `token` only: the bearer token (required on create), stored encrypted |
| `ca_cert` | `token` only, optional: PEM CA certificate of the API server (public CAs when empty). On `PUT`, an empty value keeps the stored certificate |
| `kubeconfig` | `kubeconfig` only (required on create): YAML or JSON with inline credentials (`token`, or `client-certificate-data` and `client-key-data`) and `certificate-authority-data`. `exec`, `auth-provider`, file references, `proxy-url` and `insecure-skip-tls-verify` are refused (400). Only the selected context's server, CA and credential are stored, encrypted |
| `context` | `kubeconfig` only, optional: context name (default `current-context`) |
| `namespaces` | Optional list of namespace names to read (default: every namespace the role can list), at most 200 |
| `allow_private` | Allow an RFC 1918 or ULA API server address |
| `enabled` | Default `true`; disabled clusters are not synchronised and their inventory is ignored |
| `sync_interval_minutes` | 15–1440, default 60 |

Cluster object:

```json
{ "id": "…", "name": "prod-eu", "api_server": "https://k8s.example.com:6443", "auth_type": "token", "has_ca_cert": true,
  "namespaces": [], "allow_private": true, "enabled": true, "sync_interval_minutes": 60, "sync_requested_at": null,
  "last_sync_at": "…", "last_status": "succeeded", "last_error": "", "workloads": 42, "internet_exposed_workloads": 5,
  "privileged_workloads": 3, "namespace_count": 12, "created_at": "…" }
```

`last_status`: `""` (never), `running`, `succeeded`, `partial` (some resources could not be listed, see the run's `stats.warnings`; nothing was removed) or `failed`. Run `stats`: `namespaces`, `workloads`, `images`, `services`, `ingresses`, `network_policies`, `internet_exposed`, `privileged`, `skipped`, `warnings`.

## Registries

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/runtime/registries` | `{ items: [Registry], can_manage }` |
| `POST` | `/api/v1/runtime/registries` | Add a registry (201); a first synchronisation is requested |
| `PUT` | `/api/v1/runtime/registries/{id}` | Change a registry; the secret is kept unless a new one is sent |
| `DELETE` | `/api/v1/runtime/registries/{id}` | Delete it and its images (204) |
| `POST` | `/api/v1/runtime/registries/{id}/sync` | Request a synchronisation (202) |
| `GET` | `/api/v1/runtime/registries/{id}/runs` | The last 30 synchronisations (`stats`: `repositories`, `tags`, `warnings`) |
| `GET` | `/api/v1/runtime/registries/{id}/images` | Up to 2,000 images: `{ items: [{ registry, repository, tag, digest, media_type, source_url, revision, created, last_seen_at, running }] }`; `running` is true when a connected cluster runs the digest |

Request body: `name`, `base_url` (`https://`; `http://` only with `PATHOS_SCM_ALLOW_HTTP=true`), `repositories` (1–100 OCI repository names, `namespace/name`), `auth_type` (`none`, `basic` with `username` and `secret`, or `bearer` with `secret`), `max_tags` (1–500, default 50), `allow_private`, `enabled`, `sync_interval_minutes` (15–10080, default 360), `ca_bundle_pem` (2.2.2; see [private CA bundles](#private-ca-bundles)).

### Private CA bundles

Registry connections, [outbound webhooks](notifications.md#outbound-webhooks) and [ticket connections](integrations-reporting.md) take `ca_bundle_pem`: one or more PEM `CERTIFICATE` blocks (at most 20, 64 KiB) of the private CA that issued the server's certificate. The bundle is **added** to the system trust store for that connection only; certificate verification is never disabled and TLS 1.2 is the minimum. It is configuration, not a secret (CA certificates are public): responses return `ca_bundle_pem` and `ca_certificates` (`subject`, `issuer`, `not_after`, `sha256_fingerprint`, `is_ca`, `expired`) so administrators can compare fingerprints. On update, an absent field keeps the stored bundle and `""` removes it. Anything but certificates (a private key, garbage) is refused with `400` and `error.error_code` `PTH-CONN-1701`. A connection to a server whose certificate is not trusted fails with a message that starts with `PTH-CONN-1702` and names this field.

Only `GET` requests are sent: `/v2/<repository>/tags/list` (with `Link` pagination on the same host), `/v2/<repository>/manifests/<tag>` and, for the labels, the platform manifest and the image configuration blob. Token challenges (`WWW-Authenticate: Bearer`) are answered with `pull` scope; the realm must use `https`.

## Workloads

`GET /api/v1/runtime/workloads` — at most 1,000 workloads (`truncated: true` beyond), ordered by exposure, then critical findings, then open findings.

| Parameter | Description |
|---|---|
| `cluster_id`, `namespace`, `application_id` | Exact match |
| `exposed` | `true` or `false` |
| `privileged` | `true`: privileged container, `hostNetwork` or `hostPID` |
| `with_findings` | `true`: at least one open finding deployed in it |
| `q` | Substring of the name, namespace or an image |

```json
{ "id": "…", "cluster_id": "…", "cluster": "prod-eu", "namespace": "shop", "kind": "Deployment", "name": "web",
  "labels": { "app": "web" }, "replicas": 2, "ready_replicas": 2, "privileged": false, "host_network": false, "host_pid": false,
  "run_as_root": "no", "internet_exposed": true,
  "exposure": [ { "via": "ingress", "service": "web", "ingress": "shop", "host": "shop.example.com", "path": "/", "address": "203.0.113.10",
                  "internet": true, "detail": "Ingress shop routes https://shop.example.com/" } ],
  "network_policies": ["default-deny"], "application_id": "…", "application_name": "Shop", "application_basis": "mapping: namespace shop",
  "images": [ { "container": "web", "init": false, "image": "ghcr.io/acme/shop:1.0", "digest": "sha256:…",
                "links": [ { "basis": "digest", "detail": "image scan target ghcr.io/acme/shop:1.0: running digest sha256:1111… is the scanned image",
                             "scan_target_id": "…", "scan_target_name": "shop image", "repository_id": "…", "repository_name": "acme/shop" } ] } ],
  "findings": { "total": 12, "critical": 1, "high": 4 }, "runtime_alerts": 1, "last_seen_at": "…" }
```

`kind`: `Deployment`, `StatefulSet`, `DaemonSet`, `CronJob`, `Job` (without a CronJob) or `Pod` (without a known controller). `exposure[].via`: `ingress`, `loadbalancer`, `nodeport` or `external_ip`; only `internet: true` entries make the workload internet-exposed. `links[].basis`: `digest`, `tag` or `oci_source`. `findings` counts the open findings of the linked image scan targets and, for linked repositories, of the repository's code (not IaC, CI/CD, compliance, runtime, DAST, API, mobile or fuzzing findings).

`GET /api/v1/runtime/workloads/{id}` returns `{ workload, alerts: [{ finding_id, title, severity, location, basis }] }` (`basis`: `pod_name` or `pod_name_pattern`).

## Application mappings

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/runtime/mappings` | `{ items: [{ id, cluster_id, cluster_name, namespace, label_key, label_value, application_id, application_name, application_workloads, created_at }] }` |
| `POST` | `/api/v1/runtime/mappings` | `{ cluster_id?, namespace?, label_key?, label_value?, application_id }` (201). A namespace, a label key or both are required; `label_value` empty means "the label exists". Workloads are re-mapped at once |
| `DELETE` | `/api/v1/runtime/mappings/{id}` | 204 |

The most specific matching mapping wins: a cluster condition counts most, then a label, then a namespace.

## Where a finding runs

`GET /api/v1/findings/{id}/runtime`

```json
{ "status": "deployed", "internet_exposed": true, "privileged": false, "runtime_alert": true, "clusters_connected": 1,
  "context": { "status": "deployed", "total_deployments": 1, "clusters": ["prod-eu"], "images": ["ghcr.io/acme/shop:1.0"],
    "deployments": [ { "cluster_id": "…", "cluster": "prod-eu", "workload_id": "…", "namespace": "shop", "kind": "Deployment",
      "workload": "web", "container": "web", "image": "ghcr.io/acme/shop:1.0", "digest": "sha256:…", "basis": "digest",
      "basis_detail": "image scan target ghcr.io/acme/shop:1.0: running digest sha256:1111… is the scanned image",
      "internet_exposed": true, "exposure": [ … ], "privileged": false, "host_network": false, "host_pid": false, "run_as_root": "no",
      "alerts": [ { "finding_id": "…", "title": "Terminal shell in container", "severity": "medium",
                    "location": "shop/web-7d9f8c6b5-zzzzz (web)", "basis": "pod_name_pattern" } ] } ] } }
```

`status`: `""` (unknown), `deployed` or `not_deployed` (then `context.not_deployed_reason` names the clusters and images checked). At most 25 deployments are kept per finding (`total_deployments` counts all). The same facts are on the [finding object](findings.md#the-finding-object) (`runtime_status`, `runtime_exposed`) and filter the findings list (`deployed`, `internet_exposed`); the [risk explanation](risk-intelligence.md#risk-explanation) lists them as factors with evidence.

### Images built from a repository (2.2.2)

An image scan target is attached to a repository record, but that does not make the image the repository's build output. Repository **code** findings are linked to the workloads that run an image only when the image target has `config.built_from_repository: true` (*This image is built from the repository's code*) or when the registry image's OCI source label (`org.opencontainers.image.source`) names the repository. The target's own findings (image CVEs) are linked in any case. A tag match (no digest) needs a successful scan of the target. Before 2.2.2 every image target linked its repository's code findings, which marked thousands of unrelated findings as deployed.

## Image scan digests

When a Trivy scan of an image target succeeds, the digests it resolved the reference to (`repoDigests` in the SARIF run properties) are stored with the target, so a running digest is linked to the exact scan. Older scans have no recorded digest; their targets link by tag until scanned again.

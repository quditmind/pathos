---
title: Runtime context (Kubernetes and registries)
section: user-guide
group: inventory, discover
order: 19
version: "2.0"
updated: 2026-11-19
summary: Connect Kubernetes clusters (read-only) and container registries so PATHOS knows which images run where, which workloads the internet can reach, and ranks findings by what is actually deployed.
---
# Runtime context (Kubernetes and registries)

A scanner tells you what is wrong in an image or in code. **Runtime context** tells you whether that image runs, where, and whether the internet can reach it. PATHOS reads your Kubernetes clusters and, optionally, your container registries, links the running images to image scan findings and repositories, and uses the result in the [contextual risk](vulnerability-intelligence.md#contextual-risk) score.

Both connectors are optional and off until an administrator adds a connection. They only read. The **jobs** service contacts the clusters and registries on a schedule; the PATHOS API server never does.

## What PATHOS reads from a cluster

| Object | What is kept |
|---|---|
| Namespaces | Name and labels |
| Deployments, StatefulSets, DaemonSets, CronJobs, Jobs, Pods | One **workload** per controller (pods roll up to their Deployment through the ReplicaSet, and to their CronJob through the Job; pods without a controller are workloads themselves): pod template labels, replicas, the names of its current pods |
| Container images | The image reference of each container and the **digest** the kubelet reports for each running container (one entry per running digest, so a rollout in progress shows both) |
| Pod security context | Privileged containers, `hostNetwork`, `hostPID`, and whether a container runs as root (`yes` when a UID 0 is set; `no` when `runAsNonRoot` or a non-zero UID is set for every container; `unknown` when the image's `USER` decides) |
| Services | Type (ClusterIP, NodePort, LoadBalancer), selector, ports, load balancer addresses, `externalIPs`, and the cloud annotations that make a load balancer internal |
| Ingresses | Hosts, paths, backend Services, TLS hosts, the ingress class and load balancer addresses |
| NetworkPolicies | Name, pod selector and policy types (shown as evidence; not used in the score) |

PATHOS never reads Secrets, ConfigMaps, pod logs or environment variables, and the shipped role cannot.

### Internet exposure

A workload is **internet-exposed** when:

- an **Ingress** routes a host (or every host, for an Ingress without a host) to a Service that selects the workload's pods; or
- a Service of type **LoadBalancer** selects them.

It is **not** counted as internet-exposed when the load balancer carries an internal annotation (AWS, Azure, GCP, Oracle, OpenStack, DigitalOcean, IBM), when the ingress class name contains `internal`, or when an AWS load balancer controller Ingress has `alb.ingress.kubernetes.io/scheme: internal`. **NodePort** Services and `externalIPs` are listed as exposure but not counted as internet exposure, because PATHOS cannot tell whether the nodes are reachable from the internet. Gateway API routes, service meshes and cloud firewalls are not read.

Every exposure is stored with its evidence, for example *Ingress shop routes https://shop.example.com/*.

## Connect a cluster

You need `settings.manage` for the whole organization.

1. Apply the read-only role shipped with PATHOS in the cluster:

   ```bash
   kubectl apply -f deploy/kubernetes/pathos-reader-clusterrole.yaml
   ```

   It creates the `pathos-reader` namespace, a service account, a long-lived token for it and a ClusterRole that grants `get`, `list` and `watch` on the objects above, and nothing else. Details are in [OPERATIONS.md](https://github.com/quditmind/pathos/blob/main/docs/OPERATIONS.md#kubernetes-runtime-inventory).
2. Copy the token and the CA certificate:

   ```bash
   kubectl -n pathos-reader get secret pathos-reader-token -o jsonpath='{.data.token}' | base64 -d
   kubectl -n pathos-reader get secret pathos-reader-token -o jsonpath='{.data.ca\.crt}' | base64 -d
   ```

3. Open **Assets → Runtime → Clusters → Add cluster**, enter a name, the API server URL (`https://…:6443`), the token and the CA certificate. Alternatively choose **Kubeconfig** and paste a kubeconfig whose user has an inline `token` or `client-certificate-data` / `client-key-data`.
4. Optional: list the **Namespaces** to read (empty means every namespace the role can list). To limit PATHOS to some namespaces in the cluster too, bind the ClusterRole with one RoleBinding per namespace instead of the ClusterRoleBinding.
5. Tick **The API server is on a private network address** when the API server has an RFC 1918 or ULA address. Loopback, link-local and cloud metadata addresses are always refused.
6. Save. The first synchronisation is requested immediately and runs within a minute; then every **Sync every** minutes (default 60).

Credentials are stored encrypted and never shown again. PATHOS refuses kubeconfigs with `exec` or `auth-provider` plugins, credentials in files (`tokenFile`, `client-certificate`) and `insecure-skip-tls-verify`. For managed clusters that normally use an exec plugin (EKS, GKE, AKS), use the service-account token from step 2.

**Sync now** records a request; the jobs service carries it out within a minute and the page refreshes the status. **History** shows the last 30 synchronisations with counts and warnings. A resource the role does not grant (for example CronJobs) makes the synchronisation *Partial*: what was read is kept, and nothing is removed until a complete read.

## Connect a container registry (optional)

A registry connection lists the tags and digests of the repositories you name, through the OCI distribution API (`GET /v2/…`, read-only), and reads the `org.opencontainers.image.source` and `org.opencontainers.image.revision` labels (or annotations) of each image. That tells PATHOS which built images exist and which repository and commit each digest was built from.

1. **Assets → Runtime → Registries → Add registry**.
2. Enter the registry URL (`https://ghcr.io`, `https://registry.example.com`), the repositories (`namespace/name`, one per line; the catalog API is not used) and the credentials: anonymous, user and password or token, or a bearer token. Registries that use token authentication (Docker Hub, GHCR, Harbor, GitLab) are supported; PATHOS asks the token service for `pull` scope only.
3. **Tags to read** limits the tags per repository (default 50). Requests are spaced 200 ms apart.

For multi-platform images, the labels of the `linux/amd64` image are read (or the first image that is not an attestation). Open a registry row to see its images, their digests, their source and revision, and whether the digest runs in a connected cluster.

## How findings are linked to what runs

The linker runs after every synchronisation, after every scan (when a cluster is connected) and hourly:

| Link | Basis shown | Rule |
|---|---|---|
| Running image → image scan target | **same digest as the scanned image** | The running digest equals the digest pinned in the target's reference or a digest the target's Trivy scan resolved to (`repoDigests`). Exact |
| Running image → image scan target | **same tag (digest not confirmed)** | Same registry, repository and tag, and either no pod reports a digest yet or no scan of the target has recorded a digest. Scan the target again for an exact match |
| Running image → repository | **OCI source label** | A registry image with the running digest has `org.opencontainers.image.source` equal to the repository's URL (scheme, `.git`, case and `git@host:` form are ignored) |
| Image scan target → repository | (implied) | The target belongs to its repository |

A running digest that differs from every digest a target's scans recorded is **not** linked: the findings belong to another build. Re-scan the image target to link it.

A finding is **deployed** when:

- it is a finding of an image scan target linked to a running image; or
- it is a finding of the repository's own code (not of a scan target) and the repository is linked to a running image, except infrastructure-as-code, CI/CD, compliance, runtime, DAST, API, mobile and fuzzing findings, which are not part of the image.

A finding is **not deployed** when PATHOS knows which image ships it (an image scan target, or a repository with an image scan target or a registry image whose source label names it), at least one cluster had a successful synchronisation in the last 7 days, and no workload in the connected clusters runs that image. Otherwise its deployment is **unknown** and the score is unchanged. PATHOS cannot see clusters you have not connected: if the image also runs elsewhere (another cluster, a VM, a serverless platform), connect that cluster or set the *not deployed* weight to 1 in the risk model.

### Runtime alerts

Imported [Falco, Tetragon and Tracee](scanning.md) alerts have a location `namespace/pod`. PATHOS matches the alert to the workload that owns the pod: by the pod name seen at the last synchronisation, or by the name pattern the controller gives its pods (`<deployment>-<hash>-<suffix>`, `<statefulset>-<n>`, `<daemonset>-<suffix>`, `<cronjob>-<time>-<suffix>`), because alerts often outlive the pod. Alerts do not name the cluster; an alert matches a workload of that namespace and pod in any connected cluster. Only open alerts count.

### Applications

Under **Application mappings**, map workloads to applications by namespace, by a pod template label (for example `app.kubernetes.io/part-of=shop`), or both, optionally for one cluster. The most specific mapping wins. The mapping groups workloads in the Runtime view; it does not by itself mark a repository's findings as deployed (only images do).

## Risk factors

When a cluster is connected, the [contextual risk](vulnerability-intelligence.md#contextual-risk) explanation gains these factors, each listed with its evidence (cluster, namespace, workload, container, image and how it was linked):

| Factor | Default weight | Applies when |
|---|---|---|
| **Deployed** | × 1.1 | The finding runs in a connected cluster |
| **Deployed** (not running) | × 0.7 | The finding is *not deployed* (see above); it lowers priority but never hides the finding |
| **Internet-exposed in a cluster** | × 1.3 | A workload that runs it is internet-exposed. It **replaces** the declared *Internet exposure* of the repository (shown with weight 1), so exposure is not counted twice. The evidence names the Ingress host or load balancer |
| **Privileged workload** | × 1.15 | A workload that runs it has a privileged container, `hostNetwork` or `hostPID` |
| **Runtime alert seen** | × 1.3 | An open runtime alert matched a workload that runs it |

Administrators change the weights under **Administration → Risk & intelligence** (*Deployment multiplier*, *Internet-exposed in a cluster*, *Runs in a privileged workload*, *Runtime alert matched to the workload*). Running as root is shown as evidence but does not change the score.

## The Runtime view

**Assets → Runtime** (organization-wide `findings.read`) shows:

- totals: workloads, internet-exposed and privileged workloads, running images linked to scans, and open findings that are deployed and internet-exposed;
- **Workloads**: every workload with its cluster, namespace, kind, readiness, application, images, exposure, security context, runtime alerts and the number of open findings it carries (critical and high in brackets). Filter by cluster, exposure, security context and findings, or search by name, namespace or image. Open a workload for its exposure evidence, NetworkPolicies, application mapping, each image's links (with a link to the findings) and the matched alerts;
- **Clusters**, **Registries** and **Application mappings** (managed with `settings.manage`).

When no cluster is connected, the page explains how to connect one; it shows no sample data.

## In the findings list and the finding drawer

- Filter the [findings list](findings.md#the-findings-list) with **Deployed** (*Deployed (running in a cluster)* or *Not deployed*) and **Internet-exposed** (*Internet-exposed in a cluster*). The **Runtime** column (hidden by default, always exported) shows the same.
- The finding drawer has **Where it runs**: each cluster, namespace and workload that runs the finding, the image and digest, how it was linked, the exposure (Ingress host, load balancer), the security context and matched alerts. When the finding is not deployed it says which images and clusters were checked; when no cluster is connected it says so.
- [Attack paths](posture.md) include paths observed in clusters: *Internet → Ingress host → workload → image → finding*.

## Limits

- PATHOS does not watch clusters continuously; it lists them on the schedule. Changes between synchronisations are not seen.
- Up to 20,000 objects per resource kind are read per synchronisation; beyond that the synchronisation is partial.
- Exposure covers Ingress and LoadBalancer Services only (not Gateway API, service meshes, `hostPort` or cloud firewalls). NetworkPolicies are shown, not evaluated.
- The OCI source label must name the repository's URL as registered in PATHOS.

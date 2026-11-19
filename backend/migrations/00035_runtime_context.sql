-- +goose Up
-- PATHOS 2.0 runtime context: read-only Kubernetes inventory and container
-- registry connectors (both optional, nothing is contacted until an
-- administrator adds a connection), the link from running images to image
-- scan findings and repositories, and the runtime facts the risk model uses
-- (deployed, internet-exposed, privileged workload, runtime alert seen).
-- Credentials are stored in the encrypted secrets table (kind integration).

-- ------------------------------------------------------------ connections
CREATE TABLE runtime_clusters (
    id                    uuid PRIMARY KEY,
    organization_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                  text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    -- API server URL (from the kubeconfig for kubeconfig credentials).
    api_server            text NOT NULL CHECK (length(api_server) BETWEEN 1 AND 500),
    -- token: a service-account bearer token (+ CA certificate);
    -- kubeconfig: a kubeconfig with inline credentials.
    auth_type             text NOT NULL CHECK (auth_type IN ('token', 'kubeconfig')),
    secret_id             uuid NOT NULL REFERENCES secrets(id),
    -- PEM CA bundle of the API server (token credentials; public data).
    ca_cert               text NOT NULL DEFAULT '' CHECK (length(ca_cert) <= 65536),
    -- Namespaces to read ({} = every namespace the role can list).
    namespaces            text[] NOT NULL DEFAULT '{}' CHECK (cardinality(namespaces) <= 200),
    allow_private         boolean NOT NULL DEFAULT false,
    enabled               boolean NOT NULL DEFAULT true,
    sync_interval_minutes integer NOT NULL DEFAULT 60 CHECK (sync_interval_minutes BETWEEN 15 AND 1440),
    -- "Sync now": the jobs service picks the request up (the API server
    -- never calls the cluster).
    sync_requested_at     timestamptz,
    sync_started_at       timestamptz,
    last_sync_at          timestamptz,
    last_status           text NOT NULL DEFAULT '' CHECK (last_status IN ('', 'running', 'succeeded', 'partial', 'failed')),
    last_error            text NOT NULL DEFAULT '' CHECK (length(last_error) <= 2000),
    created_by            uuid,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX runtime_clusters_name_uq ON runtime_clusters (organization_id, lower(name));

CREATE TABLE registry_connections (
    id                    uuid PRIMARY KEY,
    organization_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                  text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    -- OCI distribution API base URL (https://registry.example.com).
    base_url              text NOT NULL CHECK (length(base_url) BETWEEN 1 AND 500),
    -- Repositories to list (namespace/name); the catalog API is not used.
    repositories          text[] NOT NULL CHECK (cardinality(repositories) BETWEEN 1 AND 100),
    auth_type             text NOT NULL DEFAULT 'none' CHECK (auth_type IN ('none', 'basic', 'bearer')),
    username              text NOT NULL DEFAULT '' CHECK (length(username) <= 200),
    secret_id             uuid REFERENCES secrets(id),
    max_tags              integer NOT NULL DEFAULT 50 CHECK (max_tags BETWEEN 1 AND 500),
    allow_private         boolean NOT NULL DEFAULT false,
    enabled               boolean NOT NULL DEFAULT true,
    sync_interval_minutes integer NOT NULL DEFAULT 360 CHECK (sync_interval_minutes BETWEEN 15 AND 10080),
    sync_requested_at     timestamptz,
    sync_started_at       timestamptz,
    last_sync_at          timestamptz,
    last_status           text NOT NULL DEFAULT '' CHECK (last_status IN ('', 'running', 'succeeded', 'partial', 'failed')),
    last_error            text NOT NULL DEFAULT '' CHECK (length(last_error) <= 2000),
    created_by            uuid,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    CHECK (auth_type = 'none' OR secret_id IS NOT NULL)
);
CREATE UNIQUE INDEX registry_connections_name_uq ON registry_connections (organization_id, lower(name));

-- History of synchronisations (one connection per row).
CREATE TABLE runtime_sync_runs (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cluster_id      uuid REFERENCES runtime_clusters(id) ON DELETE CASCADE,
    registry_id     uuid REFERENCES registry_connections(id) ON DELETE CASCADE,
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    status          text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'succeeded', 'partial', 'failed')),
    stats           jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(stats) = 'object' AND pg_column_size(stats) <= 8192),
    error           text NOT NULL DEFAULT '' CHECK (length(error) <= 2000),
    CHECK ((cluster_id IS NULL) <> (registry_id IS NULL))
);
CREATE INDEX runtime_sync_runs_cluster_idx ON runtime_sync_runs (cluster_id, started_at DESC) WHERE cluster_id IS NOT NULL;
CREATE INDEX runtime_sync_runs_registry_idx ON runtime_sync_runs (registry_id, started_at DESC) WHERE registry_id IS NOT NULL;

-- ------------------------------------------------------------- inventory
CREATE TABLE runtime_namespaces (
    organization_id uuid NOT NULL,
    cluster_id      uuid NOT NULL REFERENCES runtime_clusters(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 253),
    labels          jsonb NOT NULL DEFAULT '{}' CHECK (pg_column_size(labels) <= 16384),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cluster_id, name)
);

-- Workloads: Deployments, StatefulSets, DaemonSets, CronJobs, Jobs without
-- a CronJob and Pods without a controller. Exposure and security context
-- are computed at sync time and kept with their evidence.
CREATE TABLE runtime_workloads (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cluster_id         uuid NOT NULL REFERENCES runtime_clusters(id) ON DELETE CASCADE,
    namespace          text NOT NULL CHECK (length(namespace) BETWEEN 1 AND 253),
    kind               text NOT NULL CHECK (kind IN ('Deployment', 'StatefulSet', 'DaemonSet', 'CronJob', 'Job', 'Pod')),
    name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 253),
    labels             jsonb NOT NULL DEFAULT '{}' CHECK (pg_column_size(labels) <= 16384),
    replicas           integer,
    ready_replicas     integer,
    -- Names of the workload's pods at the last sync (runtime alert matching).
    pod_names          text[] NOT NULL DEFAULT '{}' CHECK (cardinality(pod_names) <= 500),
    privileged         boolean NOT NULL DEFAULT false,
    host_network       boolean NOT NULL DEFAULT false,
    host_pid           boolean NOT NULL DEFAULT false,
    -- yes: a container runs as UID 0 or runAsNonRoot is not set and no
    -- runAsUser is given (image default); no: runAsNonRoot or a non-zero UID.
    run_as_root        text NOT NULL DEFAULT 'unknown' CHECK (run_as_root IN ('yes', 'no', 'unknown')),
    internet_exposed   boolean NOT NULL DEFAULT false,
    -- [{via, service, host, path, detail, internet}] (Ingress, LoadBalancer, NodePort).
    exposure           jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(exposure) = 'array' AND pg_column_size(exposure) <= 65536),
    network_policies   text[] NOT NULL DEFAULT '{}' CHECK (cardinality(network_policies) <= 200),
    application_id     uuid REFERENCES applications(id) ON DELETE SET NULL,
    application_basis  text NOT NULL DEFAULT '' CHECK (length(application_basis) <= 500),
    first_seen_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cluster_id, namespace, kind, name)
);
CREATE INDEX runtime_workloads_org_idx ON runtime_workloads (organization_id, cluster_id);
CREATE INDEX runtime_workloads_app_idx ON runtime_workloads (application_id) WHERE application_id IS NOT NULL;

-- Container images of a workload: the reference in the pod spec and the
-- digest the kubelet reports for the running containers.
CREATE TABLE runtime_workload_images (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    workload_id     uuid NOT NULL REFERENCES runtime_workloads(id) ON DELETE CASCADE,
    container       text NOT NULL CHECK (length(container) BETWEEN 1 AND 253),
    init            boolean NOT NULL DEFAULT false,
    image           text NOT NULL CHECK (length(image) BETWEEN 1 AND 1000),
    -- Normalised reference: registry host, repository path, tag, digest.
    registry        text NOT NULL DEFAULT '' CHECK (length(registry) <= 255),
    repository      text NOT NULL DEFAULT '' CHECK (length(repository) <= 500),
    tag             text NOT NULL DEFAULT '' CHECK (length(tag) <= 128),
    digest          text NOT NULL DEFAULT '' CHECK (digest ~ '^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})?$'),
    UNIQUE (workload_id, container, image, digest)
);
CREATE INDEX runtime_workload_images_digest_idx ON runtime_workload_images (organization_id, digest) WHERE digest <> '';
CREATE INDEX runtime_workload_images_repo_idx ON runtime_workload_images (organization_id, registry, repository);

-- Services, Ingresses and NetworkPolicies, kept for the evidence shown in
-- the Runtime view (only the fields PATHOS uses, never annotations values
-- other than the internal load balancer markers).
CREATE TABLE runtime_network_objects (
    organization_id uuid NOT NULL,
    cluster_id      uuid NOT NULL REFERENCES runtime_clusters(id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('Service', 'Ingress', 'NetworkPolicy')),
    namespace       text NOT NULL CHECK (length(namespace) BETWEEN 1 AND 253),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 253),
    data            jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(data) = 'object' AND pg_column_size(data) <= 65536),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cluster_id, kind, namespace, name)
);

-- Workload → application mapping configured by an administrator: by
-- namespace, by a pod template label, or both (optionally per cluster).
CREATE TABLE runtime_app_mappings (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cluster_id      uuid REFERENCES runtime_clusters(id) ON DELETE CASCADE,
    namespace       text NOT NULL DEFAULT '' CHECK (length(namespace) <= 253),
    label_key       text NOT NULL DEFAULT '' CHECK (length(label_key) <= 317),
    label_value     text NOT NULL DEFAULT '' CHECK (length(label_value) <= 63),
    application_id  uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (namespace <> '' OR label_key <> ''),
    CHECK (label_key <> '' OR label_value = '')
);
CREATE INDEX runtime_app_mappings_org_idx ON runtime_app_mappings (organization_id);

-- Images and digests in the configured registry repositories, with the
-- OCI source and revision labels of their configuration.
CREATE TABLE registry_images (
    organization_id uuid NOT NULL,
    registry_id     uuid NOT NULL REFERENCES registry_connections(id) ON DELETE CASCADE,
    registry        text NOT NULL CHECK (length(registry) <= 255),
    repository      text NOT NULL CHECK (length(repository) BETWEEN 1 AND 500),
    tag             text NOT NULL CHECK (length(tag) BETWEEN 1 AND 128),
    digest          text NOT NULL CHECK (digest ~ '^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$'),
    media_type      text NOT NULL DEFAULT '' CHECK (length(media_type) <= 200),
    source_url      text NOT NULL DEFAULT '' CHECK (length(source_url) <= 1000),
    revision        text NOT NULL DEFAULT '' CHECK (length(revision) <= 200),
    created         text NOT NULL DEFAULT '' CHECK (length(created) <= 100),
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (registry_id, repository, tag)
);
CREATE INDEX registry_images_digest_idx ON registry_images (organization_id, digest);

-- Digests an image scan target resolved to (Trivy's repoDigests), so a
-- running digest is matched to the scan that saw exactly that image.
CREATE TABLE image_scan_digests (
    organization_id uuid NOT NULL,
    scan_target_id  uuid NOT NULL,
    digest          text NOT NULL CHECK (digest ~ '^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$'),
    reference       text NOT NULL DEFAULT '' CHECK (length(reference) <= 1000),
    scan_job_id     uuid REFERENCES scan_jobs(id) ON DELETE SET NULL,
    scanned_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scan_target_id, digest),
    FOREIGN KEY (organization_id, scan_target_id) REFERENCES scan_targets(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX image_scan_digests_digest_idx ON image_scan_digests (organization_id, digest);

-- ------------------------------------------------------------- linking
-- A running image linked to an image scan target and/or a repository,
-- with the basis of the link (recomputed after every sync and hourly).
CREATE TABLE runtime_deployments (
    organization_id uuid NOT NULL,
    workload_id     uuid NOT NULL REFERENCES runtime_workloads(id) ON DELETE CASCADE,
    image_id        uuid NOT NULL REFERENCES runtime_workload_images(id) ON DELETE CASCADE,
    scan_target_id  uuid REFERENCES scan_targets(id) ON DELETE CASCADE,
    repository_id   uuid REFERENCES repositories(id) ON DELETE CASCADE,
    -- digest | tag | oci_source
    basis           text NOT NULL CHECK (basis IN ('digest', 'tag', 'oci_source')),
    detail          text NOT NULL DEFAULT '' CHECK (length(detail) <= 1000),
    computed_at     timestamptz NOT NULL DEFAULT now(),
    CHECK (scan_target_id IS NOT NULL OR repository_id IS NOT NULL)
);
CREATE INDEX runtime_deployments_target_idx ON runtime_deployments (scan_target_id) WHERE scan_target_id IS NOT NULL;
CREATE INDEX runtime_deployments_repo_idx ON runtime_deployments (repository_id) WHERE repository_id IS NOT NULL;
CREATE INDEX runtime_deployments_workload_idx ON runtime_deployments (workload_id);

-- Imported runtime alerts (Falco, Tetragon, Tracee: "namespace/pod") matched
-- to the workload that owns the pod.
CREATE TABLE runtime_alert_matches (
    organization_id uuid NOT NULL,
    finding_id      uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    workload_id     uuid NOT NULL REFERENCES runtime_workloads(id) ON DELETE CASCADE,
    basis           text NOT NULL CHECK (basis IN ('pod_name', 'pod_name_pattern')),
    PRIMARY KEY (finding_id, workload_id)
);
CREATE INDEX runtime_alert_matches_workload_idx ON runtime_alert_matches (workload_id);

-- Runtime facts of a finding, maintained by the linker; the risk engine
-- turns them into explained factors. runtime_status: '' (unknown: no
-- cluster connected or no image known for the finding), deployed,
-- not_deployed. runtime_context holds the evidence (clusters, namespaces,
-- workloads, images, ingress hosts, alerts).
ALTER TABLE findings
    ADD COLUMN runtime_status     text NOT NULL DEFAULT '' CHECK (runtime_status IN ('', 'deployed', 'not_deployed')),
    ADD COLUMN runtime_exposed    boolean NOT NULL DEFAULT false,
    ADD COLUMN runtime_privileged boolean NOT NULL DEFAULT false,
    ADD COLUMN runtime_alert      boolean NOT NULL DEFAULT false,
    ADD COLUMN runtime_context    jsonb CHECK (runtime_context IS NULL OR (jsonb_typeof(runtime_context) = 'object' AND pg_column_size(runtime_context) <= 65536));
CREATE INDEX findings_runtime_idx ON findings (organization_id, runtime_status) WHERE runtime_status <> '';
CREATE INDEX findings_runtime_exposed_idx ON findings (organization_id) WHERE runtime_exposed;

SELECT pathos_apply_app_grants();

-- +goose Down
DROP INDEX IF EXISTS findings_runtime_exposed_idx;
DROP INDEX IF EXISTS findings_runtime_idx;
ALTER TABLE findings DROP COLUMN IF EXISTS runtime_context, DROP COLUMN IF EXISTS runtime_alert, DROP COLUMN IF EXISTS runtime_privileged,
    DROP COLUMN IF EXISTS runtime_exposed, DROP COLUMN IF EXISTS runtime_status;
DROP TABLE IF EXISTS runtime_alert_matches;
DROP TABLE IF EXISTS runtime_deployments;
DROP TABLE IF EXISTS image_scan_digests;
DROP TABLE IF EXISTS registry_images;
DROP TABLE IF EXISTS runtime_app_mappings;
DROP TABLE IF EXISTS runtime_network_objects;
DROP TABLE IF EXISTS runtime_workload_images;
DROP TABLE IF EXISTS runtime_workloads;
DROP TABLE IF EXISTS runtime_namespaces;
DROP TABLE IF EXISTS runtime_sync_runs;
CREATE TEMP TABLE pathos_tmp_runtime_secrets AS
    SELECT secret_id AS id FROM runtime_clusters UNION SELECT secret_id FROM registry_connections WHERE secret_id IS NOT NULL;
DROP TABLE IF EXISTS registry_connections;
DROP TABLE IF EXISTS runtime_clusters;
DELETE FROM secrets WHERE id IN (SELECT id FROM pathos_tmp_runtime_secrets);
DROP TABLE pathos_tmp_runtime_secrets;

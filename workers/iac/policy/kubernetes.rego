# PATHOS Conftest policies for Kubernetes manifests. Each result carries an
# id and a severity (read by the PATHOS conftest parser). Workload pod
# specs are found in Pods, workload controllers and CronJobs.
package pathos.kubernetes

import rego.v1

pod_spec := input.spec if input.kind == "Pod"

pod_spec := input.spec.template.spec if input.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController"}

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

containers contains c if some c in pod_spec.containers

containers contains c if some c in pod_spec.initContainers

name := sprintf("%s %s", [input.kind, object.get(input, ["metadata", "name"], "")])

deny contains {"msg": sprintf("%s: container %s runs privileged", [name, c.name]), "id": "PATHOS-K8S-001", "severity": "high"} if {
	some c in containers
	c.securityContext.privileged == true
}

deny contains {"msg": sprintf("%s: shares the host's %s namespace", [name, ns]), "id": "PATHOS-K8S-002", "severity": "high"} if {
	some field, ns in {"hostNetwork": "network", "hostPID": "process", "hostIPC": "IPC"}
	pod_spec[field] == true
}

deny contains {"msg": sprintf("%s: mounts the host path %s", [name, v.hostPath.path]), "id": "PATHOS-K8S-003", "severity": "medium"} if {
	some v in pod_spec.volumes
	v.hostPath
}

warn contains {"msg": sprintf("%s: container %s uses image %s without a fixed tag or digest", [name, c.name, c.image]), "id": "PATHOS-K8S-004", "severity": "medium"} if {
	some c in containers
	not contains(c.image, "@sha256:")
	untagged(c.image)
}

deny contains {"msg": sprintf("%s: container %s runs as user 0 (root)", [name, c.name]), "id": "PATHOS-K8S-005", "severity": "medium"} if {
	some c in containers
	c.securityContext.runAsUser == 0
}

untagged(image) if endswith(image, ":latest")

untagged(image) if not contains(last_segment(image), ":")

last_segment(image) := s if {
	parts := split(image, "/")
	s := parts[count(parts) - 1]
}

package pathos.kubernetes_test

import rego.v1

import data.pathos.kubernetes

deployment := {
	"kind": "Deployment",
	"metadata": {"name": "web"},
	"spec": {"template": {"spec": {
		"hostNetwork": true,
		"containers": [{"name": "web", "image": "nginx:latest", "securityContext": {"privileged": true, "runAsUser": 0}}],
		"volumes": [{"name": "sock", "hostPath": {"path": "/var/run/docker.sock"}}],
	}}},
}

ids(set) := {r.id | some r in set}

test_insecure_deployment if {
	ids(kubernetes.deny) with input as deployment == {"PATHOS-K8S-001", "PATHOS-K8S-002", "PATHOS-K8S-003", "PATHOS-K8S-005"}
	ids(kubernetes.warn) with input as deployment == {"PATHOS-K8S-004"}
}

test_hardened_pod if {
	pod := {"kind": "Pod", "metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "image": "registry.example/app:1.2.3", "securityContext": {"runAsUser": 10001}}]}}
	count(kubernetes.deny) == 0 with input as pod
	count(kubernetes.warn) == 0 with input as pod
}

test_registry_port_is_not_a_tag if {
	pod := {"kind": "Pod", "metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "image": "registry.example:5000/app"}]}}
	ids(kubernetes.warn) with input as pod == {"PATHOS-K8S-004"}
}

test_cronjob if {
	cj := {"kind": "CronJob", "metadata": {"name": "j"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "c", "image": "a@sha256:00", "securityContext": {"privileged": true}}]}}}}}}
	ids(kubernetes.deny) with input as cj == {"PATHOS-K8S-001"}
}

test_other_documents_are_ignored if {
	count(kubernetes.deny) == 0 with input as {"kind": "Service", "spec": {"type": "NodePort"}}
	count(kubernetes.deny) == 0 with input as {"resource": {"aws_s3_bucket": {}}}
}

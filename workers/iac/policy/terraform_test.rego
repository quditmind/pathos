package pathos.terraform_test

import rego.v1

import data.pathos.terraform

ids(set) := {r.id | some r in set}

test_insecure_resources if {
	tf := {"resource": {
		"aws_security_group": {"ssh": [{"ingress": [{"from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]}]}]},
		"aws_s3_bucket_acl": {"data": [{"acl": "public-read"}]},
		"aws_db_instance": {"db": [{"publicly_accessible": true}]},
	}}
	ids(terraform.deny) with input as tf == {"PATHOS-TF-001", "PATHOS-TF-002", "PATHOS-TF-003"}
	ids(terraform.warn) with input as tf == {"PATHOS-TF-004"}
}

test_restricted_resources if {
	tf := {"resource": {
		"aws_security_group": {"web": [{"ingress": [{"from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}]}]},
		"aws_db_instance": {"db": [{"publicly_accessible": false, "storage_encrypted": true}]},
	}}
	count(terraform.deny) == 0 with input as tf
	count(terraform.warn) == 0 with input as tf
}

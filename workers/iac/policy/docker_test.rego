package pathos.docker_test

import rego.v1

import data.pathos.docker

ids(set) := {r.id | some r in set}

test_root_user_and_remote_add if {
	df := [
		{"Cmd": "from", "Value": ["ubuntu"], "Flags": []},
		{"Cmd": "add", "Value": ["https://example.com/t.tgz", "/opt/"], "Flags": []},
		{"Cmd": "user", "Value": ["root"], "Flags": []},
	]
	ids(docker.deny) with input as df == {"PATHOS-DOCKER-001", "PATHOS-DOCKER-003"}
	ids(docker.warn) with input as df == {"PATHOS-DOCKER-004"}
}

test_no_user if {
	df := [{"Cmd": "from", "Value": ["debian:13@sha256:00"], "Flags": []}]
	ids(docker.warn) with input as df == {"PATHOS-DOCKER-002"}
	count(docker.deny) == 0 with input as df
}

test_hardened if {
	df := [
		{"Cmd": "from", "Value": ["golang:1.27", "AS", "build"], "Flags": []},
		{"Cmd": "from", "Value": ["build"], "Flags": []},
		{"Cmd": "add", "Value": ["https://example.com/t.tgz", "/opt/"], "Flags": ["--checksum=sha256:00"]},
		{"Cmd": "user", "Value": ["10001"], "Flags": []},
	]
	count(docker.deny) == 0 with input as df
	count(docker.warn) == 0 with input as df
}

test_other_documents_are_ignored if {
	count(docker.deny) == 0 with input as {"kind": "Pod"}
	count(docker.warn) == 0 with input as {"kind": "Pod"}
}

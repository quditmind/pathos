# PATHOS Conftest policies for Dockerfiles (conftest parses a Dockerfile
# into a list of instructions with Cmd and Value).
package pathos.docker

import rego.v1

instructions := [i | some i in input; is_object(i); i.Cmd]

users := [i | some i in instructions; i.Cmd == "user"]


deny contains {"msg": "the image runs as root: the last USER instruction sets root", "id": "PATHOS-DOCKER-001", "severity": "medium"} if {
	count(users) > 0
	last := users[count(users) - 1]
	lower(last.Value[0]) in {"root", "0", "root:root", "0:0"}
}

warn contains {"msg": "the Dockerfile has no USER instruction: the image runs as root", "id": "PATHOS-DOCKER-002", "severity": "low"} if {
	count(instructions) > 0
	some i in instructions
	i.Cmd == "from"
	count(users) == 0
}

deny contains {"msg": sprintf("ADD downloads %s without verification; use curl with a checksum or ADD --checksum", [i.Value[0]]), "id": "PATHOS-DOCKER-003", "severity": "medium"} if {
	some i in instructions
	i.Cmd == "add"
	regex.match(`^https?://`, i.Value[0])
	not checksummed(i)
}

warn contains {"msg": sprintf("FROM %s uses the latest tag or no tag", [i.Value[0]]), "id": "PATHOS-DOCKER-004", "severity": "low"} if {
	some i in instructions
	i.Cmd == "from"
	image := i.Value[0]
	not contains(image, "@sha256:")
	lower(image) != "scratch"
	not stage_name(image)
	untagged(image)
}

checksummed(i) if {
	some f in i.Flags
	startswith(f, "--checksum=")
}

stage_name(image) if {
	some i in instructions
	i.Cmd == "from"
	count(i.Value) >= 3
	lower(i.Value[1]) == "as"
	i.Value[2] == image
}

untagged(image) if endswith(image, ":latest")

untagged(image) if {
	parts := split(image, "/")
	not contains(parts[count(parts) - 1], ":")
}

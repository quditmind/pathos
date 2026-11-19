# PATHOS Conftest policies for Terraform (conftest parses .tf files with its
# HCL2 parser: input.resource.<type>.<name> is a list of blocks; nested
# blocks such as ingress are lists too).
package pathos.terraform

import rego.v1

admin_ports := {22, 3389}

# blocks(type) yields [name, block] for every resource block of a type.
blocks(type) := [[name, b] | some name, v in object.get(input, ["resource", type], {}); some b in as_list(v)]

deny contains {"msg": sprintf("aws_security_group %s allows port %d from the internet (0.0.0.0/0)", [name, port]), "id": "PATHOS-TF-001", "severity": "high"} if {
	some [name, sg] in blocks("aws_security_group")
	some rule in as_list(object.get(sg, "ingress", []))
	"0.0.0.0/0" in rule.cidr_blocks
	some port in admin_ports
	rule.from_port <= port
	rule.to_port >= port
}

deny contains {"msg": sprintf("aws_s3_bucket_acl %s grants %s", [name, acl.acl]), "id": "PATHOS-TF-002", "severity": "high"} if {
	some [name, acl] in blocks("aws_s3_bucket_acl")
	acl.acl in {"public-read", "public-read-write"}
}

deny contains {"msg": sprintf("aws_db_instance %s is publicly accessible", [name]), "id": "PATHOS-TF-003", "severity": "high"} if {
	some [name, db] in blocks("aws_db_instance")
	db.publicly_accessible == true
}

warn contains {"msg": sprintf("aws_db_instance %s is not encrypted at rest", [name]), "id": "PATHOS-TF-004", "severity": "medium"} if {
	some [name, db] in blocks("aws_db_instance")
	not db.storage_encrypted
}

as_list(x) := x if is_array(x)

as_list(x) := [x] if is_object(x)

# TFLint configuration of the worker-iac image (passed with --config, so a
# repository's own .tflint.hcl cannot make TFLint download plugins). The
# Terraform ruleset bundled with TFLint, recommended preset; local modules
# are evaluated, remote modules are never downloaded.
config {
  call_module_type = "local"
  force            = false
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

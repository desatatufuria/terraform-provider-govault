# Parameters are non-secret configuration. The value is stored in clear in
# Terraform state. Use the govault_secret ephemeral resource for secrets.
data "govault_parameter" "log_level" {
  name = "app/log-level"
  # version = 2 # optional; omit for the current version
}

output "log_level" {
  value = data.govault_parameter.log_level.value
}

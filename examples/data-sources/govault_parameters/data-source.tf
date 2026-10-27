# Every parameter whose name starts with "app/". Omit prefix to read them all.
# Values are non-secret and are stored in clear in Terraform state.
data "govault_parameters" "app" {
  prefix = "app/"
}

output "region" {
  value = data.govault_parameters.app.values["app/region"]
}

output "versions" {
  value = { for p in data.govault_parameters.app.parameters : p.name => p.version }
}

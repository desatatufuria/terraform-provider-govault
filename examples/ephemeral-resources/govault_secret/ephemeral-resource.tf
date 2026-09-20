ephemeral "govault_secret" "example" {
  path = "infrastructure/example"
}

output "secret_version" {
  value     = ephemeral.govault_secret.example.resolved_version
  ephemeral = true
  sensitive = true
}

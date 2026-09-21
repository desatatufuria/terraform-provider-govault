terraform {
  required_version = ">= 1.10.0"

  required_providers {
    govault = {
      source = "desatatufuria/govault"
    }
  }
}

# Export GOVAULT_ROLE_ID and GOVAULT_SECRET_ID before Terraform starts.
# Never place either credential in HCL.
provider "govault" {
  address     = "https://govault.example.com"
  auth_method = "approle"

  # Optional non-secret locator for an AppRole outside the root namespace.
  # approle_namespace = "team-a"

  ca_cert_file = "/etc/govault/ca.pem"
}

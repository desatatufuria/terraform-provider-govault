terraform {
  required_version = ">= 1.10.0"

  required_providers {
    govault = {
      source = "desatatufuria/govault"
    }
  }
}

provider "govault" {
  address                = "https://govault.example.com"
  auth_method            = "workload"
  workload_role_ref      = "terraform-production"
  workload_assertion_env = "GOVAULT_WORKLOAD_ASSERTION"
  ca_cert_file           = "/etc/govault/ca.pem"
}
